from __future__ import annotations

import logging
import re
import struct
import contextlib
import threading
import copy
from collections import deque
from collections.abc import Mapping
from concurrent.futures import Future
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar
from urllib.parse import urlparse
from random import uniform
from time import monotonic

from http.client import IncompleteRead
from urllib3.exceptions import ProtocolError

from requests import Response
from requests.exceptions import ChunkedEncodingError, ConnectionError, ContentDecodingError, InvalidSchema

from streamlink.buffers import RingBuffer
from streamlink.exceptions import StreamError
from streamlink.session import Streamlink
from streamlink.stream.ffmpegmux import FFMPEGMuxer, MuxedStream
from streamlink.stream.filtered import FilteredStream
from streamlink.stream.hls.m3u8 import M3U8, M3U8Parser, parse_m3u8
from streamlink.stream.hls.segment import ByteRange, HLSPlaylist, HLSSegment, Key, Map, Media
from streamlink.stream.http import HTTPStream
from streamlink.stream.segmented import SegmentedStreamReader, SegmentedStreamWorker, SegmentedStreamWriter
from streamlink.utils.cache import LRUCache
from streamlink.utils.crypto import AES, unpad
from streamlink.utils.formatter import Formatter
from streamlink.utils.l10n import Language
from streamlink.utils.times import now


if TYPE_CHECKING:
    try:
        from typing import Self  # type: ignore[attr-defined]
    except ImportError:
        from typing_extensions import Self


log = logging.getLogger(".".join(__name__.split(".")[:-1]))


class ByteRangeOffset:
    sequence: int | None = None
    offset: int | None = None

    @staticmethod
    def _calc_end(start: int, size: int) -> int:
        return start + max(size - 1, 0)

    def cached(self, sequence: int, byterange: ByteRange) -> tuple[int, int]:
        if byterange.offset is not None:
            bytes_start = byterange.offset
        elif self.offset is not None and self.sequence == sequence - 1:
            bytes_start = self.offset
        else:
            raise StreamError("Missing BYTERANGE offset")

        bytes_end = self._calc_end(bytes_start, byterange.range)

        self.sequence = sequence
        self.offset = bytes_end + 1

        return bytes_start, bytes_end

    def uncached(self, byterange: ByteRange) -> tuple[int, int]:
        bytes_start = byterange.offset
        if bytes_start is None:
            raise StreamError("Missing BYTERANGE offset")

        return bytes_start, self._calc_end(bytes_start, byterange.range)


class HLSStreamWriter(SegmentedStreamWriter[HLSSegment, Response]):
    reader: HLSStreamReader
    stream: HLSStream

    # Limit of consecutive failures that triggers abort
    SEGMENT_ERROR_LIMIT = 3

    # Consolidated set of client + server codes we treat uniformly.
    # Rationale:
    # - 4xx (auth/access/not found/gone, media type, legal) usually won't recover without outside action.
    # - Selected 5xx / CDN (500/502/503/504/520/522/524) are transient.
    SEGMENT_ERROR_CODES = {
        401, 402, 403, 404, 410, 415, 451,
        500, 502, 503, 504, 520, 522, 524
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        options = self.session.options

        self.byterange: ByteRangeOffset = ByteRangeOffset()
        self.map_cache: LRUCache[str, Future] = LRUCache(self.threads)
        self.key_data: bytes | bytearray | memoryview = b""
        self.key_uri: str | None = None
        self.key_uri_override = options.get("hls-segment-key-uri")
        self.stream_data = options.get("hls-segment-stream-data")
        self.chunk_size = options.get("chunk-size")
        self.client_info = options.get("client-info")
        self.segment_failures: int = 0
        self._seg_fail_lock = threading.Lock()

        self.ignore_names: re.Pattern | None = None
        ignore_names = {*options.get("hls-segment-ignore-names")}
        if ignore_names:
            segments = "|".join(map(re.escape, ignore_names))
            # noinspection RegExpUnnecessaryNonCapturingGroup
            self.ignore_names = re.compile(rf"(?:{segments})\.ts", re.IGNORECASE)

    @staticmethod
    def _safe_close(resp: Response | None):
        if resp is None:
            return
        with contextlib.suppress(Exception):
            resp.close()

    @staticmethod
    def num_to_iv(n: int) -> bytes:
        return struct.pack(">8xq", n)

    def create_decryptor(self, key: Key, num: int):
        if key.method != "AES-128":
            raise StreamError(f"Unable to decrypt cipher {key.method}")

        if not self.key_uri_override and not key.uri:
            raise StreamError("Missing URI for decryption key")

        if not self.key_uri_override:
            key_uri = key.uri
        else:
            p = urlparse(key.uri)
            formatter = Formatter({
                "url": lambda: key.uri,
                "scheme": lambda: p.scheme,
                "netloc": lambda: p.netloc,
                "path": lambda: p.path,
                "query": lambda: p.query,
            })
            key_uri = formatter.format(self.key_uri_override)

        if key_uri and self.key_uri != key_uri:
            res = None
            try:
                hdrs = dict(self.reader.request_params.get("headers") or {})
                hdrs["Connection"] = "close"
                params = dict(self.reader.request_params)
                params["headers"] = hdrs
                res = self.session.http.get(
                    key_uri,
                    exception=StreamError,
                    retries=self.retries,
                    **params,
                )
                res.encoding = "binary/octet-stream"
                self.key_data = res.content
                self.key_uri = key_uri
            except StreamError as err:
                original_error = getattr(err, "err", None)
                if isinstance(original_error, InvalidSchema):
                    raise StreamError(f"Unable to find connection adapter for key URI: {key_uri}") from original_error
                raise  # pragma: no cover
            finally:
                if res is not None:
                    with contextlib.suppress(Exception):
                        res.close()

        iv = key.iv or self.num_to_iv(num)

        # Pad IV if needed
        iv = b"\x00" * (16 - len(iv)) + iv

        return AES.new(self.key_data, AES.MODE_CBC, iv)

    def create_request_params(self, num: int, segment: HLSSegment | Map, is_map: bool):
        request_params = dict(self.reader.request_params)
        headers = request_params.pop("headers", {})
        # We forcefully close each segment connection so that hanging keep-alive sockets do not accumulate
        #headers["Connection"] = "close"

        if segment.byterange:
            if is_map:
                bytes_start, bytes_end = self.byterange.uncached(segment.byterange)
            else:
                bytes_start, bytes_end = self.byterange.cached(num, segment.byterange)
            headers["Range"] = f"bytes={bytes_start}-{bytes_end}"

        request_params["headers"] = headers

        return request_params

    def put(self, segment: HLSSegment | None):
        if self.closed:
            return

        if segment is None:
            self.queue(None, None)
            return

        # queue segment-map first
        if segment.map is not None:
            # get the cached segment-map, if available
            future = self.map_cache.get(segment.map.uri)
            if future and segment.discontinuity:
                # special case: queue the cached segment map if it's set on a discontinuity segment
                self.queue(segment, future, True)
            elif not future:
                # keep the segment-map in the cache, so we can check whether we've already queued it
                future = self.executor.submit(self.fetch_map, segment)
                self.map_cache.set(segment.map.uri, future)
                self.queue(segment, future, True)

        # regular segment request
        future = self.executor.submit(self.fetch, segment)
        self.queue(segment, future, False)

    def fetch(self, segment: HLSSegment) -> Response | None:
        try:
            resp = self._fetch(
                segment.uri,
                stream=self.stream_data,
                **self.create_request_params(segment.num, segment, False),
            )
            self._reset_segment_failures_if_needed()
            return resp
        except StreamError as err:
            log.error(f"{self.client_info} Failed to fetch segment {segment.num}: {err}")

            code = self._extract_status_code(err)
            self._handle_segment_failure(code, "segment")
            return None

    def fetch_map(self, segment: HLSSegment) -> Response | None:
        segment_map: Map = segment.map  # type: ignore[assignment]  # map is not None
        try:
            resp = self._fetch(
                segment_map.uri,
                stream=False,
                **self.create_request_params(segment.num, segment_map, True),
            )
            self._reset_segment_failures_if_needed()
            return resp
        except StreamError as err:
            log.error(f"{self.client_info} Failed to fetch map for segment {segment.num}: {err}")

            code = self._extract_status_code(err)
            self._handle_segment_failure(code, "map")
            return None

    def _extract_status_code(self, err: Exception) -> int | None:
        """
        Try to extract an HTTP status code from a StreamError message.
        First looks for 'code 4xx' or 'status code 4xx', then falls back to any standalone 3-digit code.
        """
        try:
            m = re.search(r'\b(?:code|status code)\s+(\d{3})\b', str(err), re.IGNORECASE)
            if not m:
                m = re.search(r'\b(\d{3})\b', str(err))
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return None

    def _reset_segment_failures_if_needed(self):
        if self.segment_failures:
            with self._seg_fail_lock:
                self.segment_failures = 0

    def _handle_segment_failure(self, code: int | None, context: str):
        """
        Handle a failed segment or map fetch.
        context: 'segment' | 'map'
        Must be called inside an active exception handler (relies on bare raise).
        """
        if code in self.SEGMENT_ERROR_CODES:
            with self._seg_fail_lock:
                self.segment_failures += 1
                current = self.segment_failures
            log.debug(f"{self.client_info} {context.capitalize()} failure {current}/{self.SEGMENT_ERROR_LIMIT} (code {code})")
            if current >= self.SEGMENT_ERROR_LIMIT:
                log.error(f"{self.client_info} {context.capitalize()} abort: {current} failures with codes {self.SEGMENT_ERROR_CODES}")
                self.close()
                raise
        else:
            # reset sequence if we had accumulated failures but this code is not in the tracked set
            if self.segment_failures:
                with self._seg_fail_lock:
                    self.segment_failures = 0

    def _fetch(self, url: str, **request_params) -> Response | None:
        if self.closed or not self.retries:  # pragma: no cover
            return None

        return self.session.http.get(
            url,
            timeout=self.timeout,
            retries=self.retries,
            exception=StreamError,
            **request_params,
        )

    def should_filter_segment(self, segment: HLSSegment) -> bool:
        return self.ignore_names is not None and self.ignore_names.search(segment.uri) is not None

    def write(self, segment: HLSSegment, result: Response, *data):
        if not self.should_filter_segment(segment):
            #log.debug(f"{self.client_info} Writing segment {segment.num} to output")

            written_once = self.reader.buffer.written_once
            try:
                return self._write(segment, result, *data)
            finally:
                self._safe_close(result)
                is_paused = self.reader.is_paused()

                # Depending on the filtering implementation, the segment's discontinuity attribute can be missing.
                # Also check if the output will be resumed after data has already been written to the buffer before.
                if getattr(segment, "discontinuity", False) or (is_paused and written_once):
                    log.warning(
                        f"{self.client_info} Encountered a stream discontinuity. This is unsupported and will result in incoherent output data."
                    )
                    log.debug(f"{self.client_info} Discontinuity in: {self.stream.url}")
                # unblock reader thread after writing data to the buffer
                if is_paused:
                    log.warning(f"{self.client_info} Resuming stream output")
                    self.reader.resume()

        else:
            log.debug(f"{self.client_info} Discarding segment {segment.num}")

            # Read and discard any remaining HTTP response data in the response connection.
            # Unread data in the HTTPResponse connection blocks the connection from being released back to the pool.
            try:
                with contextlib.suppress(Exception):
                    result.raw.drain_conn()
            finally:
                self._safe_close(result)

            # block reader thread if filtering out segments
            if not self.reader.is_paused():
                log.warning(f"{self.client_info} Filtering out segments and pausing stream output")
                self.reader.pause()

    def _write(self, segment: HLSSegment, result: Response, is_map: bool):
        # TODO: Rewrite HLSSegment, HLSStreamWriter and HLSStreamWorker based on independent initialization section segments,
        #       similar to the DASH implementation
        key = segment.map.key if is_map and segment.map else segment.key
        attempt_start_global = monotonic()

        if key and key.method != "NONE":
            try:
                decryptor = self.create_decryptor(key, segment.num)
            except (StreamError, ValueError) as err:
                log.error(f"{self.client_info} Failed to create decryptor: {err}")
                self.close()
                return

            try:
                # Unlike plaintext segments, encrypted segments can't be written to the buffer in small chunks
                # because of the byte padding at the end of the decrypted data, which means that decrypting in
                # smaller chunks is unnecessary if the entire segment needs to be kept in memory anyway, unless
                # we defer the buffer writes by one read call and apply the unpad call only to the last read call.
                encrypted_chunk = result.content
                decrypted_chunk = decryptor.decrypt(encrypted_chunk)
                chunk = unpad(decrypted_chunk, AES.block_size, style="pkcs7")
                self.reader.buffer.write(chunk)
            except (ChunkedEncodingError, ContentDecodingError, ConnectionError, IncompleteRead, ProtocolError) as err:
                log.error(f"{self.client_info} Download of segment {segment.num} failed")
                log.debug(f"{self.client_info} Reasons for segment {segment.num} failed: {err}")
                return
            except ValueError as err:
                log.error(f"{self.client_info} Error while decrypting segment {segment.num}: {err}")
                return
            except Exception as err:
                log.error(f"{self.client_info} Unexpected error segment {segment.num}: {err}")
                return
        else:
            try:
                for chunk in result.iter_content(self.chunk_size):
                    if not chunk:
                        continue
                    self.reader.buffer.write(chunk)
            except (ChunkedEncodingError, ContentDecodingError, ConnectionError, IncompleteRead, ProtocolError) as err:
                log.error(f"{self.client_info} Download of segment {segment.num} failed")
                log.debug(f"{self.client_info} Reasons for segment {segment.num} failed: {err}")
                return
            except Exception as err:
                log.error(f"{self.client_info} Unexpected error segment {segment.num}: {err}")
                return

        # Success logs
        total_time_ms = (monotonic() - attempt_start_global) * 1000.0
        if is_map:
            log.debug(
                f"{self.client_info} + Segment initialization {segment.num} complete "
                f"(time={total_time_ms:.1f}ms)"
            )
        else:
            log.debug(
                f"{self.client_info} + Segment {segment.num} complete "
                f"(time={total_time_ms:.1f}ms)"
            )


class HLSStreamWorker(SegmentedStreamWorker[HLSSegment, Response]):
    reader: HLSStreamReader
    writer: HLSStreamWriter
    stream: HLSStream

    SEGMENT_QUEUE_TIMING_THRESHOLD_MIN = 5.0
    MIN_RELOAD_FLOOR = 1.00

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.playlist_changed = False
        self.playlist_end: int | None = None
        self.playlist_targetduration: float = 0
        self.playlist_sequence: int = -1
        self.playlist_sequence_last: datetime = now()
        self.playlist_segments: list[HLSSegment] = []
        self.playlist_type = None
        self.playlist_reload_type = ""

        self.client_info = self.session.options.get("client-info")
        self.playlist_reload_last: datetime = now()
        self.playlist_reload_time: float = 6.00
        self.playlist_reload_time_override = self.session.options.get("hls-playlist-reload-time")
        self.playlist_reload_retries = self.session.options.get("hls-playlist-reload-attempts")
        self.segment_queue_timing_threshold_factor = self.session.options.get("hls-segment-queue-threshold")
        self.segment_queue_timing_threshold_factor_start = max(
            1.0,
            (self.segment_queue_timing_threshold_factor * 0.5 + 0.5)
        )
        self.live_edge = self.session.options.get("hls-live-edge")
        self.duration_offset_start = int(self.stream.start_offset + (self.session.options.get("hls-start-offset") or 0))
        self.duration_limit = self.stream.duration or (
            int(self.session.options.get("hls-duration")) if self.session.options.get("hls-duration") else None
        )
        self.hls_live_restart = self.stream.force_restart or self.session.options.get("hls-live-restart")
        self.hls_stream_data = self.session.options.get("hls-segment-stream-data")
        self.hls_segments_queue = self.session.options.get("segments-queue")
        self.vod_start = int(self.session.options.get("vod-start") or 3)
        self.vod_queue_step = int(self.session.options.get("vod-queue-step") or 1)

        # ----------------------- Smart reload playlist settings -----------------------
        self.reload_early_offset_s: float = 0.02
        self.reload_jitter_ms: int = 30

        # Stepped three-level scheme on top of "smart" mode (live)
        # Main ratios:
        self.step3_changed_ratio: float = 1.00   # upper cap when changed
        self.step3_u1_ratio: float = 0.50        # 1st unchanged
        self.step3_u2_ratio: float = 0.50        # 2nd unchanged
        self.step3_min_ratio: float = 0.25       # 3rd+ unchanged
        # Statistics (CV):
        self.step3_cv_window: int = 8            # measurement window
        self.step3_cv_high: float = 0.25         # CV higher -> high variance
        self.step3_cv_low: float = 0.08          # CV lower -> stability
        self.step3_cv_floor_ratio: float = 0.40  # don't go lower when CV is high
        # Drift:
        self.step3_drift_target_factor: float = 1.1    # targetLatency ≈ meanDur * factor
        self.step3_drift_aggr_reduce: float = 0.05     # additional reduction of ratio with large lag
        self.step3_drift_ahead_increase: float = 0.02  # slight increase in ratio if too close/forward
        # Batch publish:
        self.step3_batch_threshold: int = 3
        self.step3_batch_follow_ratio: float = 0.60
        self.step3_batch_follow_cap_s: float = 3.5     # absolute ceiling of seconds for follow
        # Multi-level acceleration with positive drift (lag):
        self.step3_drift_lvl1: float = 0.60
        self.step3_drift_lvl2: float = 1.00
        self.step3_drift_lvl3: float = 1.40
        self.step3_drift_reduce1: float = 0.10
        self.step3_drift_reduce2: float = 0.20
        self.step3_drift_min_ratio: float = 0.35
        # Drift projection control
        self.step3_drift_projection_headroom_factor: float = 0.30  # 30% of the average duration as a reserve
        self.step3_drift_projection_min_gain_ratio: float = 0.05   # do not use if saving <5% base

        # VOD settings
        self.vod_auto_discont_boost_reloads: int = 2
        self.vod_reload_publish_slack_s: float = 0.30
        self.vod_reload_idle_min: float = 1.00

        # Gap detection timing histogram (for improved stop threshold)
        self.gap_stop_min_absolute_s: float = 10.0
        self.gap_stop_min_growth_samples: int = 3
        self.gap_small_segment_floor_s: float = 2.0
        # Gap drift guard (smart mode + step3 drift)
        self.gap_drift_guard_trigger: float = -2.0  # (base + drift) must be >= this value to allow Gap Stop

        # Replaying segment (buffer starvation mitigation)
        self.event_replay_buffer_min_s: float = 1.0
        self.event_segment_arrival_risk_threshold_s: float = 0.0   # half segment if threshold <= 0
        self.replay_cooldown_limit: int = 3  # maximum consecutive cycles with replay without real new segments

        # These are internal state variables for Smart mode
        self._reload_unchanged_streak = 0
        self._reload_prev_last_num: int | None = None
        self._smart_base: float | None = None
        self._smart_changed: bool | None = None
        self._smart_streak: int = 0
        self._smart_ratio_last: float | None = None

        self._step3_durations: list[float] = []
        self._step3_last_growth_count: int = 0
        self._step3_last_ratio_used: float | None = None
        self._step3_last_cv: float | None = None
        self._play_start_ts: datetime = now()
        self._play_logical_s: float = 0.0
        self._step3_last_drift_s: float | None = None
        self._step3_last_target_latency: float | None = None
        self._step3_last_drift_ratio: float | None = None
        self._step3_pre_drift_reload_time: float | None = None
        self._step3_pending_post_add: bool = False

        self._vod_auto_mode: str = "smart"
        self._vod_auto_prev_last_num: int | None = None
        self._vod_auto_prev_last_uri: str | None = None
        self._vod_auto_unchanged_streak: int = 0
        self._vod_auto_unchanged_threshold: int = 3
        self._vod_auto_resume_on_change: bool = True
        self._vod_auto_resumed_once: bool = False
        self._vod_auto_discont_boost_remaining: int = 0
        self._vod_auto_discont_forced: bool = False

        self._gap_worker_start_ts: datetime = now()
        self._gap_last_threshold_debug: str | None = None
        self._gap_dur_hist: list[float] = []

        self._risk_last_plan_ts: datetime | None = None
        self._risk_last_plan_drift: float | None = None
        self._risk_logged_this_cycle: bool = False
        self._risk_last_plan_base: float | None = None

        self._replay_history: deque[HLSSegment] = deque(maxlen=5)
        self._replay_stuck_flag: bool = False
        self._replay_cooldown: int = 0
        self._last_real_segment_num: int | None = None

    def _fetch_playlist(self) -> Response:
        base_params = self.reader.request_params or {}
        req_params = dict(base_params)
        headers = dict(req_params.get("headers") or {})
        headers.setdefault("Cache-Control", "max-age=0, no-cache")
        headers.setdefault("Pragma", "no-cache")
        headers["Connection"] = "close"
        req_params["headers"] = headers

        res = self.session.http.get(
            self.stream.url,
            exception=StreamError,
            retries=self.playlist_reload_retries,
            **req_params,
        )
        res.encoding = "utf-8"
        return res

    def reload_playlist(self):
        if self.closed:  # pragma: no cover
            return

        self.reader.buffer.wait_free()

        res = self._fetch_playlist()
        try:
            try:
                playlist = parse_m3u8(res, parser=self.stream.__parser__)
            except ValueError as err:
                raise StreamError(err) from err
        finally:
            with contextlib.suppress(Exception):
                res.close()

        if playlist.is_master:
            raise StreamError(f"Attempted to play a variant playlist, use 'hls://{self.stream.url}' instead")

        if playlist.iframes_only:
            raise StreamError("Streams containing I-frames only are not playable")

        self.playlist_targetduration = playlist.targetduration or 0
        self.playlist_reload_time = self._playlist_reload_time(playlist)

        if playlist.segments:
            self.process_segments(playlist)

    def _reset_reload_state(self) -> None:
        self._reload_prev_last_num = None
        self._reload_unchanged_streak = 0
        self._smart_base = None
        self._smart_changed = None
        self._smart_streak = 0

    def _add_jitter(self, value: float, floor: float) -> float:
        if self.reload_jitter_ms <= 0:
            return value
        jitter = uniform(-self.reload_jitter_ms / 1000.0, self.reload_jitter_ms / 1000.0)
        return max(floor, value + jitter)

    def _effective_offset_for_changed(self, base: float) -> float:
        off = float(self.reload_early_offset_s)
        if off >= 0.0:
            return min(off, max(0.0, base - self.MIN_RELOAD_FLOOR))
        return off

    def _playlist_reload_time(self, playlist: M3U8[HLSSegment, HLSPlaylist]) -> float:
        if (
            self.playlist_reload_time_override == "segment"
            and playlist.segments
            and playlist.segments[-1].duration is not None
        ):
            self.playlist_reload_type = "segment"
            return float(playlist.segments[-1].duration)

        if (
            self.playlist_reload_time_override == "targetduration"
            and playlist.targetduration is not None
        ):
            self.playlist_reload_type = "targetduration"
            return float(playlist.targetduration)

        # Smart mode
        if self.playlist_reload_time_override == "smart":
            last = playlist.segments[-1] if playlist.segments else None
            if last is None or last.duration is None:
                # Playlist currently unusable for smart timing, reset smart state.
                self._reset_reload_state()
            else:
                seg_dur = float(last.duration)
                base = max(self.MIN_RELOAD_FLOOR, seg_dur)

                last_num = last.num
                last_uri = last.uri

                # growth count for batch detection before upd prev_last_num
                growth_count = 1
                if last_num is not None and self._reload_prev_last_num is not None:
                    try:
                        growth_count = max(1, last_num - self._reload_prev_last_num)
                    except Exception:
                        growth_count = 1
                self._step3_last_growth_count = growth_count

                # Detect if playlist tail changed (number or uri)
                vod_like = (playlist.playlist_type == "VOD" or playlist.is_endlist)  # condition for auto-mode
                changed = False  # for original smart metrics
                if last_num is not None:
                    changed = (
                        self._reload_prev_last_num is None
                        or last_num != self._reload_prev_last_num
                    )
                # Additional URI-based check to handle broken providers
                if not changed and last_uri and self._vod_auto_prev_last_uri and last_uri != self._vod_auto_prev_last_uri:
                    changed = True

                prev_streak = self._reload_unchanged_streak

                # Update original smart streak variables (for logging) (unchanged logic)
                if changed:
                    self._reload_unchanged_streak = 0
                else:
                    self._reload_unchanged_streak += 1
                if last_num is not None:
                    self._reload_prev_last_num = last_num

                # Histogram update for gap threshold (only on real growth)
                if changed and seg_dur > 0:
                    self._gap_dur_hist.append(seg_dur)
                    if len(self._gap_dur_hist) > 5:
                        self._gap_dur_hist.pop(0)

                # Discontinuity boost
                if vod_like and self._vod_auto_discont_forced:
                    # Forced fast smart reload cycles after discontinuity
                    self.playlist_reload_type = "smart-discont"
                    fast_reload = self._add_jitter(self.vod_reload_idle_min, self.vod_reload_idle_min)

                    # Set logging metrics
                    self._smart_base = base
                    self._smart_changed = changed  # underlying change state (may be False)
                    self._smart_streak = self._vod_auto_discont_boost_remaining

                    self._vod_auto_discont_boost_remaining -= 1
                    if self._vod_auto_discont_boost_remaining <= 0:
                        # End of boost mode
                        self._vod_auto_discont_forced = False
                        # After boost we remain in smart (auto-mode smart) and let normal logic continue next cycles
                        # Reset unchanged streaks so we don't instantly flip back if tail static
                        self._vod_auto_unchanged_streak = 0
                        self._reload_unchanged_streak = 0
                        log.debug(
                            f"{self.client_info} VOD discontinuity boost ended; remaining reloads=0 (last={last_num})"
                        )
                    else:
                        log.debug(
                            f"{self.client_info} VOD discontinuity boost active: "
                            f"{self._vod_auto_discont_boost_remaining} fast reload(s) left (last={last_num})"
                        )
                    return float(fast_reload)

                # VOD auto-switch
                if vod_like:
                    if changed:
                        self._vod_auto_unchanged_streak = 0
                    else:
                        self._vod_auto_unchanged_streak += 1

                    if last_num is not None:
                        self._vod_auto_prev_last_num = last_num
                    self._vod_auto_prev_last_uri = last_uri

                    if self._vod_auto_mode == "smart":
                        if self._vod_auto_unchanged_streak >= self._vod_auto_unchanged_threshold:
                            self._vod_auto_mode = "segment-vod"
                            self.playlist_reload_type = "segment-vod"
                            log.debug(
                                f"{self.client_info} VOD auto-switch: smart -> segment-vod "
                                f"(unchanged_streak={self._vod_auto_unchanged_streak}, last={last_num})"
                            )
                            return float(seg_dur)
                    else:  # segment-vod
                        if changed and self._vod_auto_resume_on_change:
                            prev_mode = self._vod_auto_mode
                            self._vod_auto_mode = "smart"
                            self._vod_auto_unchanged_streak = 0
                            if not self._vod_auto_resumed_once:
                                self._vod_auto_resumed_once = True
                                log.debug(
                                    f"{self.client_info} VOD auto-switch: {prev_mode} -> smart "
                                    f"(growth resumed, last={last_num})"
                                )
                        elif self._vod_auto_mode == "segment-vod":
                            self.playlist_reload_type = "segment-vod"
                            return float(seg_dur)

                # Smart timing (live)
                ratio_used = None
                if not vod_like:
                    # ------------------------------------------------------------------
                    # Three-level scheme + statistical adjustments (without drift/projection).
                    # Drift / projection will be applied AFTER segments are added in iter_segments
                    # to include durations of newly queued segments in logical time.
                    # ----------- Step3 core (changed / unchanged) PRE-DRIFT -----------
                    if changed:
                        if self._step3_last_growth_count >= self.step3_batch_threshold:
                            follow_time = min(
                                base * self.step3_batch_follow_ratio,
                                base - 0.8 if base > 1.0 else base * 0.90,
                                self.step3_batch_follow_cap_s
                            )
                            reload_time = max(self.MIN_RELOAD_FLOOR, follow_time)
                        else:
                            eff_off = self._effective_offset_for_changed(base)
                            candidate_time = min(base * self.step3_changed_ratio,
                                                 max(self.MIN_RELOAD_FLOOR, base - eff_off))
                            reload_time = max(self.MIN_RELOAD_FLOOR, candidate_time)
                        streak = 0
                    else:
                        streak = self._reload_unchanged_streak
                        if streak <= 1:
                            base_ratio = self.step3_u1_ratio
                        elif streak == 2:
                            base_ratio = self.step3_u2_ratio
                        else:
                            base_ratio = self.step3_min_ratio
                        reload_time = max(self.MIN_RELOAD_FLOOR, base * base_ratio)

                    # (PRE) CV adjustments only
                    cv = None
                    if self._step3_durations:
                        durs = self._step3_durations
                        if len(durs) >= 2:
                            mean_v = sum(durs) / len(durs)
                            if mean_v > 0:
                                var = sum((x - mean_v) ** 2 for x in durs) / len(durs)
                                std = var ** 0.5
                                cv = std / mean_v
                    self._step3_last_cv = cv

                    if cv is not None:
                        if cv > self.step3_cv_high:
                            floor_ratio = self.step3_cv_floor_ratio
                            if reload_time < base * floor_ratio:
                                reload_time = base * floor_ratio
                        elif (not changed) and cv < self.step3_cv_low:
                            reload_time = min(reload_time * 1.03, base * self.step3_changed_ratio)
                            reload_time = max(self.MIN_RELOAD_FLOOR, reload_time)

                    self._step3_pre_drift_reload_time = reload_time
                    self._step3_pending_post_add = True
                    self._step3_last_ratio_used = None
                    try:
                        self._step3_early_clamp_applied = False
                    except Exception:
                        pass
                else:
                    # VOD smart timing
                    if changed:
                        eff_off = self._effective_offset_for_changed(base)
                        reload_time = max(self.MIN_RELOAD_FLOOR, base - eff_off)
                        reload_time = self._add_jitter(reload_time, self.MIN_RELOAD_FLOOR)
                    else:
                        offset_pos = max(0.0, float(self.reload_early_offset_s))
                        reload_time = max(self.vod_reload_idle_min,
                                          offset_pos + float(self.vod_reload_publish_slack_s))
                        reload_time = self._add_jitter(reload_time, self.vod_reload_idle_min)

                self._smart_base = base
                self._smart_changed = changed
                self._smart_streak = (
                    self._vod_auto_unchanged_streak
                    if (vod_like and self._vod_auto_mode == "smart")
                    else self._reload_unchanged_streak
                )
                self._smart_ratio_last = ratio_used
                self.playlist_reload_type = "smart"
                return float(reload_time)

        # Fallback
        last_dur = playlist.segments[-1].duration if playlist.segments else None
        reload_default_time = last_dur if last_dur is not None else playlist.targetduration
        if reload_default_time is not None:
            if self.playlist_reload_type == "smart":
                self._reset_reload_state()
            self.playlist_reload_type = "default"
            return float(reload_default_time)

        if self.playlist_reload_type == "smart":
            self._reset_reload_state()
        self.playlist_reload_type = "constant"
        return float(self.playlist_reload_time)

    def process_segments(self, playlist: M3U8[HLSSegment, HLSPlaylist]) -> None:
        segments = playlist.segments
        first_segment, last_segment = segments[0], segments[-1]

        if first_segment.key and first_segment.key.method != "NONE":
            log.debug(f"{self.client_info} Segments in this playlist are encrypted")

        self.playlist_changed = [s.num for s in self.playlist_segments] != [s.num for s in segments]
        self.playlist_segments = segments
        self.playlist_type = playlist.playlist_type

        if (self.playlist_type == "VOD" or playlist.is_endlist) and self.hls_live_restart:
            log.debug(f"{self.client_info} VOD: forcing hls_live_restart=False (user/live setting ignored for VOD)")
            self.hls_live_restart = False

        # If not changed and NOT smart (segment/targetduration) -> halve interval (legacy logic)
        if not self.playlist_changed:
            if self.playlist_reload_time_override != "smart":
                self.playlist_reload_time = max(self.playlist_reload_time / 2, 1)

        if playlist.is_endlist:
            self.playlist_end = last_segment.num

        if self.playlist_sequence < 0:
            if self.playlist_end is None and not self.hls_live_restart:
                edge_index = -(min(len(segments), max(int(self.live_edge), 1)))
                edge_segment = segments[edge_index]
                self.playlist_sequence = edge_segment.num
            else:
                self.playlist_sequence = first_segment.num
                # Initial VOD catchup limiting stays
                if self.playlist_type == "VOD" or self.playlist_end is not None: # VOD Catchup
                    self.playlist_segments = segments[:self.vod_start]
                    log.debug(f"{self.client_info} VOD: start limited to first {self.vod_start} segments")
        else:
            # Subsequent catchup window advance
            if self.playlist_type == "VOD" or self.playlist_end is not None: # VOD Catchup
                next_start = self.playlist_sequence
                new_segments = [s for s in segments if s.num >= next_start][:self.vod_queue_step]
                self.playlist_segments = new_segments

    def valid_segment(self, segment: HLSSegment) -> bool:
        return segment.num >= self.playlist_sequence

    def _segment_queue_timing_threshold_reached(self) -> bool:
        if self.segment_queue_timing_threshold_factor <= 0:
            return False

        now_ts = now()
        last_seg_dur = None
        if self.playlist_segments:
            try:
                dval = self.playlist_segments[-1].duration
                if dval and dval > 0:
                    last_seg_dur = float(dval)
            except Exception:
                pass

        target_td = self.playlist_targetduration if (self.playlist_targetduration and self.playlist_targetduration > 0) else None
        hist_len = len(self._gap_dur_hist)
        hist_ready = hist_len >= self.gap_stop_min_growth_samples

        avg_dur = None
        if hist_ready:
            avg_dur = sum(self._gap_dur_hist) / hist_len

        short_floor_applied = False
        if hist_ready:
            if target_td is not None:
                if avg_dur is not None and avg_dur < target_td:
                    base_raw = avg_dur
                    source = f"avg<{target_td:.3f}"
                else:
                    base_raw = target_td
                    source = "target"
            else:
                base_raw = avg_dur if avg_dur else (last_seg_dur or self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN)
                source = f"avg({hist_len})"
        else:
            if target_td is not None:
                base_raw = target_td
                source = "target(wait-samples)"
            elif last_seg_dur:
                base_raw = last_seg_dur
                source = "last-seg(wait-samples)"
            else:
                base_raw = self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN
                source = "floor(wait-samples)"

        base_norm = base_raw
        if self.gap_small_segment_floor_s and base_norm < self.gap_small_segment_floor_s:
            base_norm = self.gap_small_segment_floor_s
            short_floor_applied = True

        factor_main = self.segment_queue_timing_threshold_factor
        factor_start = self.segment_queue_timing_threshold_factor_start

        # MAIN (post-start) threshold
        threshold_core_main = max(
            self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN,
            base_norm * factor_main
        )
        if self.gap_stop_min_absolute_s > 0 and not hist_ready:
            if threshold_core_main < self.gap_stop_min_absolute_s:
                threshold_core_main = self.gap_stop_min_absolute_s

        # START-PHASE threshold (aggressive, uses reduced factor, intentionally NOT enforcing absolute min
        # to permit earlier failure if stream is dead right after start).
        threshold_core_start = max(
            self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN,
            base_norm * factor_start
        )

        target_component_used = (target_td is not None)

        # Dynamic start grace window boundary used only to SWITCH to main factor,
        # NOT to suppress detection entirely.
        # Rule (unchanged):
        #   if we have >=3 samples -> start_grace_threshold = mean * main_factor
        #   else -> start_grace_threshold = base_raw * main_factor
        if hist_len >= 3:
            recent_avg = sum(self._gap_dur_hist) / hist_len
            start_grace_src = f"avg{hist_len}"
        else:
            recent_avg = None
            start_grace_src = "base_raw"
        start_grace_threshold = (recent_avg if recent_avg is not None else base_raw) * factor_main
        start_grace_elapsed = (now_ts - self._gap_worker_start_ts).total_seconds()
        start_phase_active = start_grace_elapsed < start_grace_threshold

        # Select which threshold to apply right now
        threshold = threshold_core_start if start_phase_active else threshold_core_main
        threshold_phase = "start" if start_phase_active else "main"
        factor_used = factor_start if start_phase_active else factor_main

        # Evaluate timing
        # Time has not yet exceeded the threshold - let's continue
        if now_ts <= self.playlist_sequence_last + timedelta(seconds=threshold):
            return False

        # --- Gap drift guard ---
        if (self.playlist_reload_type == "smart"):
            drift = getattr(self, "_step3_last_drift_s", None)
            if drift is not None:
                # base_for_guard: first last segment duration, then targetduration, then avg from histogram
                if last_seg_dur:
                    base_for_guard = last_seg_dur
                elif self.playlist_targetduration and self.playlist_targetduration > 0:
                    base_for_guard = float(self.playlist_targetduration)
                else:
                    # fallback to base_norm (as an approximation)
                    base_for_guard = float(base_norm)

                metric = base_for_guard + drift  # (base + drift)
                if metric < self.gap_drift_guard_trigger:
                    try:
                        log.debug(
                            f"{self.client_info} Gap guard: suppress stop "
                            f"(metric=base+drift={metric:.2f}s < trigger={self.gap_drift_guard_trigger:.2f}s | "
                            f"drift={drift:.2f}s base_for_guard={base_for_guard:.2f}s)"
                        )
                    except Exception:
                        pass

                    self.playlist_sequence_last = now_ts
                    return False

        debug_parts = [
            f"gap_base_raw={base_raw:.3f}s",
            f"base_norm={base_norm:.3f}s",
            f"src={source}",
            f"short_floor={'Y' if short_floor_applied else 'N'}",
            f"factor_main={factor_main}",
            f"factor_start={factor_start}",
            f"factor_used={factor_used}",
            f"abs_min={self.gap_stop_min_absolute_s}",
            f"min_const={self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN}",
            f"target_part={'Y' if target_component_used else 'N'}",
            f"hist_len={hist_len}",
            f"hist_ready={'Y' if hist_ready else 'N'}",
            f"avg_dur={(avg_dur if avg_dur is not None else -1):.3f}",
            f"start_grace={start_grace_threshold:.3f}s",
            f"start_elapsed={start_grace_elapsed:.3f}s",
            f"start_phase={'Y' if start_phase_active else 'N'}",
            f"start_grace_src={start_grace_src}",
            f"threshold_phase={threshold_phase}"
        ]
        debug_line = " | ".join(debug_parts)
        self._gap_last_threshold_debug = debug_line

        log.warning(
            f"{self.client_info} => No new segments in playlist for more than {threshold:.2f}s "
            f"({base_norm:.3f}s*{factor_used} | phase={threshold_phase} src={source}). Stopping..."
        )
        log.debug(f"{self.client_info} Gap threshold full detail: {debug_line}")
        return True

    @staticmethod
    def duration_to_sequence(duration: float, segments: list[HLSSegment]) -> int:
        d = 0.0
        default = -1

        segments_order = segments if duration >= 0 else reversed(segments)

        for segment in segments_order:
            if d >= abs(duration):
                return segment.num
            d += segment.duration
            default = segment.num

        # could not skip far enough, so return the default
        return default

    def iter_segments(self):
        self.playlist_reload_last \
            = self.playlist_sequence_last \
            = now()

        try:
            self.reload_playlist()
        except StreamError as err:
            log.error(f"{self.client_info}: {err}")
            if self.reader: self.reader.close()
            return

        if self.playlist_end is None:
            if self.duration_offset_start > 0:
                log.debug(f"{self.client_info}: Time offsets negative for live streams, skipping back {self.duration_offset_start} seconds")
            # live playlist, force offset durations back to None
            self.duration_offset_start = -self.duration_offset_start

        if self.duration_offset_start != 0:
            self.playlist_sequence = self.duration_to_sequence(self.duration_offset_start, self.playlist_segments)

        if self.playlist_segments:
            log.debug(f"{self.client_info} HLS Playlist Type: {self.playlist_type}")
            log.debug(f"{self.client_info} HLS Stream Data: {self.hls_stream_data}")
            log.debug(f"{self.client_info} HLS Live Restart: {self.hls_live_restart}")
            log.debug(f"{self.client_info} HLS Segments Queue: {self.hls_segments_queue}")
            log.debug(
                "; ".join([
                    f"{self.client_info} First Sequence: {self.playlist_segments[0].num}",
                    f"Last Sequence: {self.playlist_segments[-1].num}",
                ]),
            )
            log.debug(
                "; ".join([
                    f"{self.client_info} Start offset: {self.duration_offset_start}",
                    f"Duration: {self.duration_limit}",
                    f"Start Sequence: {self.playlist_sequence}",
                    f"End Sequence: {self.playlist_end}",
                ]),
            )

        total_duration = 0
        while not self.closed:
            queued = False

            # ---------- Buffer empty RISK (pre-add segments) ----------
            if (
                not self._risk_logged_this_cycle
                and self._risk_last_plan_ts is not None
                and self._risk_last_plan_drift is not None
                and self.playlist_segments
            ):
                try:
                    arrival_ts = now()
                    delta = (arrival_ts - self._risk_last_plan_ts).total_seconds()
                    prev_drift = self._risk_last_plan_drift
                    remaining = -(prev_drift + delta)

                    segment_len = self._risk_last_plan_base or 2.0
                    half_segment_len = max(1.0, segment_len / 2)

                    threshold_window = (
                        self.event_segment_arrival_risk_threshold_s
                        if self.event_segment_arrival_risk_threshold_s > 0
                        else segment_len / 2
                    )
                    threshold_window = max(1.0, threshold_window)

                    risk_main = remaining < half_segment_len
                    risk_threshold = remaining < threshold_window

                    if risk_main or risk_threshold:
                        reason = "half_seg" if risk_main else "user"
                        if risk_main and risk_threshold and half_segment_len != threshold_window:
                            reason = "seg+usr"
                        if remaining <= self.event_replay_buffer_min_s:
                            log.warning(
                                f"{self.client_info} !!! Risk of video freezing: buffer {remaining:.2f}s "
                                f"| segment_len={segment_len:.2f}s "
                                f"buf_prev={-prev_drift:.2f}s criteria={reason}"
                            )
                            self._replay_stuck_flag = True
                        self._risk_logged_this_cycle = True
                except Exception:
                    pass

            for segment in self.playlist_segments:
                if not self.valid_segment(segment):
                    continue

                log.debug(f"{self.client_info} - Adding segment {segment.num} to queue")

                # Update duration/logical time stats before changing self.playlist_sequence so that drift only counts playable segments
                try:
                    if segment.duration and segment.duration > 0:
                        durf = float(segment.duration)
                        self._play_logical_s += durf
                        self._step3_durations.append(durf)
                        if len(self._step3_durations) > self.step3_cv_window:
                            self._step3_durations.pop(0)
                except Exception:
                    pass

                offset = segment.num - self.playlist_sequence
                if offset > 0:
                    log.warning(
                        (
                            f"{self.client_info} Skipped segments {self.playlist_sequence}-{segment.num - 1} after playlist reload. "
                            if offset > 1
                            else f"{self.client_info} Skipped segment {self.playlist_sequence} after playlist reload. "
                        )
                        + "This is unsupported and will result in incoherent output data.",
                    )

                # Discontinuity trigger
                if getattr(segment, "discontinuity", False):
                    if self._vod_auto_mode == "segment-vod":
                        # Force temporary smart fast reloads
                        self._vod_auto_mode = "smart"
                        self._vod_auto_discont_forced = True
                        self._vod_auto_discont_boost_remaining = max(1, self.vod_auto_discont_boost_reloads)
                        # Reset unchanged streaks so we don't instantly flip back
                        self._vod_auto_unchanged_streak = 0
                        self._reload_unchanged_streak = 0
                        log.debug(
                            f"{self.client_info} VOD discontinuity detected at segment {segment.num}: "
                            f"forcing smart-discont mode for {self._vod_auto_discont_boost_remaining} reload(s)"
                        )
                    elif self._vod_auto_discont_forced:
                        # Another discontinuity during boost -> extend
                        self._vod_auto_discont_boost_remaining = max(
                            self._vod_auto_discont_boost_remaining,
                            self.vod_auto_discont_boost_reloads
                        )
                        log.debug(
                            f"{self.client_info} VOD discontinuity re-trigger at segment {segment.num}: "
                            f"extending smart-discont (remaining={self._vod_auto_discont_boost_remaining})"
                        )

                yield segment
                queued = True

                # save only real segments to history
                if not getattr(segment, "replay", False):
                    self._replay_history.append(segment)
                    self._last_real_segment_num = segment.num
                    self._replay_cooldown = 0  # we are resetting because a «live» segment has arrived

                total_duration += segment.duration
                if self.duration_limit and total_duration >= self.duration_limit:
                    log.info(f"{self.client_info} Stopping stream early after {self.duration_limit}")
                    return

                if self.closed:  # pragma: no cover
                    return

                self.playlist_sequence = segment.num + 1

            # --- REPLAY BLOCK ---
            if not queued:
                if (
                    self._replay_stuck_flag
                    and self._replay_history
                    and self._replay_cooldown < self.replay_cooldown_limit
                ):
                    last_orig = self._replay_history[-1]
                    base_dur = float(getattr(last_orig, "duration", 0) or 0.0)

                    if 0 < base_dur < 4.0:
                        if len(self._replay_history) >= 2:
                            candidates = list(self._replay_history)[-2:]
                        else:
                            candidates = [last_orig, last_orig]
                    else:
                        candidates = [last_orig]

                    for idx, orig in enumerate(candidates, 1):
                        seg_replay = copy.copy(orig)
                        setattr(seg_replay, "replay", True)
                        try:
                            dur = float(getattr(seg_replay, "duration", 0) or 0.0)
                            if dur > 0:
                                self._play_logical_s += dur
                        except Exception:
                            pass
                        log.warning(
                            f"{self.client_info} -+- Replaying segment {seg_replay.num} "
                            f"(buffer starvation mitigation){' copy='+str(idx) if len(candidates)>1 else ''}"
                        )
                        yield seg_replay

                    self._replay_cooldown += 1
                    self._replay_stuck_flag = False
                    continue
            else:
                self._replay_stuck_flag = False

            # End of stream condition
            if self.closed or self.playlist_end is not None and (not queued or self.playlist_sequence > self.playlist_end):
                return

            # Apply drift & projection AFTER segments added (so logical time includes new durations)
            if (
                self.playlist_reload_type == "smart"
                and self._step3_pending_post_add
                and self._smart_base
                and self._step3_pre_drift_reload_time is not None
            ):
                try:
                    base = float(self._smart_base)
                    reload_time = float(self._step3_pre_drift_reload_time)

                    # Recompute drift with updated _play_logical_s
                    wall_elapsed = (now() - self._play_start_ts).total_seconds()
                    drift = wall_elapsed - self._play_logical_s
                    self._step3_last_drift_s = drift
                    early_clamp = False

                    # Average duration for target latency
                    mean_dur_for_target = None
                    if self._step3_durations:
                        mean_dur_for_target = sum(self._step3_durations) / len(self._step3_durations)

                    if mean_dur_for_target and mean_dur_for_target > 0:
                        target_latency = mean_dur_for_target * self.step3_drift_target_factor
                    else:
                        target_latency = base * self.step3_drift_target_factor
                    self._step3_last_target_latency = target_latency

                    if target_latency > 0:
                        drift_ratio = drift / target_latency
                    else:
                        drift_ratio = 0.0
                    self._step3_last_drift_ratio = drift_ratio

                    # EARLY CLAMP
                    try:
                        changed_flag = bool(self._smart_changed)
                        streak_flag = int(self._smart_streak or 0)
                    except Exception:
                        changed_flag = False
                        streak_flag = 0

                    if (not changed_flag) and streak_flag > 0 and drift < 0:
                        buffer_ahead = -drift
                        if buffer_ahead < base and reload_time > self.MIN_RELOAD_FLOOR + 1e-6:
                            log.debug(
                                f"{self.client_info} -> Planning Speedup: "
                                f"buffer={buffer_ahead:.2f}s < segment={base:.2f}s "
                                f"| planning_time={reload_time:.3f}s -> {self.MIN_RELOAD_FLOOR:.3f}s "

                            )
                            reload_time = self.MIN_RELOAD_FLOOR
                            early_clamp = True

                    try:
                        self._step3_early_clamp_applied = early_clamp
                    except Exception:
                        pass

                    # Multi-level acceleration (using updated drift)
                    if (not early_clamp) and drift > 0:
                        if drift_ratio >= self.step3_drift_lvl3:
                            desired_time = base * self.step3_drift_min_ratio
                            reload_time = max(self.MIN_RELOAD_FLOOR, min(reload_time, desired_time))
                        elif drift_ratio >= self.step3_drift_lvl2:
                            reload_time = max(self.MIN_RELOAD_FLOOR, reload_time - base * self.step3_drift_reduce2)
                        elif drift_ratio >= self.step3_drift_lvl1:
                            reload_time = max(self.MIN_RELOAD_FLOOR, reload_time - base * self.step3_drift_reduce1)
                        else:
                            if drift > target_latency:
                                reload_time = max(self.MIN_RELOAD_FLOOR, reload_time - base * self.step3_drift_aggr_reduce)
                    elif (not early_clamp):
                        ref = (mean_dur_for_target or base)
                        if drift < ref * 0.2:
                            reload_time = min(reload_time + base * self.step3_drift_ahead_increase,
                                              base * self.step3_changed_ratio)

                    # Projection-based early acceleration (если не clamp)
                    if (not early_clamp) and base > 0:
                        projection_target = 0.0
                        projected_drift = drift + reload_time
                        if projected_drift > projection_target:
                            desired_wait = projection_target - drift
                            desired_wait = max(self.MIN_RELOAD_FLOOR, desired_wait)
                            min_gain = base * self.step3_drift_projection_min_gain_ratio
                            gain = reload_time - desired_wait
                            if gain >= min_gain and desired_wait < reload_time:
                                reload_time = desired_wait
                                try:
                                    self._step3_projection_dbg = (projected_drift, projection_target, gain)
                                except Exception:
                                    pass
                            else:
                                try:
                                    self._step3_projection_dbg = (projected_drift, projection_target, 0.0)
                                except Exception:
                                    pass
                        else:
                            try:
                                self._step3_projection_dbg = (projected_drift, projection_target, 0.0)
                            except Exception:
                                pass
                    else:
                        try:
                            self._step3_projection_dbg = None
                        except Exception:
                            pass

                    # Jitter
                    reload_time = max(reload_time, 0.5)
                    if (not early_clamp):
                        reload_time = self._add_jitter(reload_time, self.MIN_RELOAD_FLOOR)

                    self.playlist_reload_time = float(reload_time)
                    self._step3_last_ratio_used = reload_time / base if base > 0 else 1.0
                except Exception:
                    # If anything fails, fall back to pre-drift planned time
                    if self._step3_last_ratio_used is None and self._smart_base:
                        try:
                            self._step3_last_ratio_used = self.playlist_reload_time / float(self._smart_base)
                        except Exception:
                            self._step3_last_ratio_used = None
                finally:
                    self._step3_pending_post_add = False

            if queued:
                self.playlist_sequence_last = now()
            elif self._segment_queue_timing_threshold_reached():
                return

            # Timed reload interval logic
            time_completed = now()
            time_elapsed = max(0.0, (time_completed - self.playlist_reload_last).total_seconds())
            time_wait = max(0.0, self.playlist_reload_time - time_elapsed)

            if self.playlist_reload_type == "smart":
                # We may have ratio only in one of the two fields depending on step3 phase
                have_ratio = (self._step3_last_ratio_used is not None) or (self._smart_ratio_last is not None)
                ratio_out = (
                    self._step3_last_ratio_used
                    if self._step3_last_ratio_used is not None
                    else (self._smart_ratio_last if self._smart_ratio_last is not None else 0.0)
                )
                cv_part = ""
                drift_part = ""
                if self._step3_last_cv is not None:
                    cv_part = f" | cv={self._step3_last_cv:.3f}"
                if self._step3_last_drift_s is not None:
                    drift_part = f" drift={self._step3_last_drift_s:.2f}s"
                if have_ratio:
                    log.debug(
                        "%s << Planning Reload [smart] in %.3fs: base=%.3fs ratio=%.3f changed=%s streak=%d%s%s",
                        self.client_info,
                        float(time_wait),
                        float(self._smart_base or 0.0),
                        float(ratio_out),
                        str(self._smart_changed),
                        int(self._smart_streak or 0),
                        cv_part,
                        drift_part,
                    )
                else:
                    # Fallback (should rarely happen) – still try to show drift if present
                    log.debug(
                        "%s << Planning Reload [smart] in %.3fs: base=%.3fs changed=%s streak=%d%s%s",
                        self.client_info,
                        float(time_wait),
                        float(self._smart_base or 0.0),
                        str(self._smart_changed),
                        int(self._smart_streak or 0),
                        cv_part,
                        drift_part,
                    )
                # (Buffer empty RISK) Capture planning snapshot (for both smart branches)
                self._risk_last_plan_ts = now()
                self._risk_last_plan_drift = self._step3_last_drift_s
                # Store base for potential auto window (if window == 0)
                try:
                    self._risk_last_plan_base = float(self._smart_base or 0.0)
                except Exception:
                    self._risk_last_plan_base = None
                self._risk_logged_this_cycle = False
            else:
                log.debug(
                    "%s << Planning Reload [%s] in %.3fs",
                    self.client_info,
                    self.playlist_reload_type,
                    float(time_wait),
                )

                # For Buffer empty RISK
                # Non-smart modes: clear risk snapshot (not relevant)
                self._risk_last_plan_ts = None
                self._risk_last_plan_drift = None
                self._risk_last_plan_base = None
                self._risk_logged_this_cycle = False

            if self.wait(time_wait):
                if time_wait > 0:
                    # If we had to wait, then don't call now() twice and instead reference the timestamp from before
                    # the wait() call, to prevent a shifting time offset due to the execution time.
                    self.playlist_reload_last = time_completed + timedelta(seconds=time_wait)
                else:
                    # Otherwise, get the current time, as the reload interval already has shifted.
                    self.playlist_reload_last = now()

                if self.playlist_reload_type == "smart":
                    log.debug(
                        "%s >> Reloading Playlist [smart]: base=%.3fs changed=%s streak=%d planned=%.3fs | waited=%.3fs",
                        self.client_info,
                        float(self._smart_base or 0.0),
                        str(self._smart_changed),
                        int(self._smart_streak or 0),
                        float(self.playlist_reload_time),
                        float(time_wait),
                    )
                else:
                    log.debug(
                        "%s >> Reloading Playlist [%s]: interval=%.3fs | waited=%.3fs",
                        self.client_info,
                        self.playlist_reload_type,
                        float(self.playlist_reload_time),
                        float(time_wait),
                    )

                try:
                    self.reload_playlist()
                except StreamError as err:
                    if "Client Error" in str(err):
                        log.warning(f"{self.client_info} Stoped to reload playlist: {err}")
                        return
                    log.warning(f"{self.client_info} Failed to reload playlist: {err}")

class HLSStreamReader(FilteredStream, SegmentedStreamReader[HLSSegment, Response]):
    __worker__ = HLSStreamWorker
    __writer__ = HLSStreamWriter

    worker: HLSStreamWorker
    writer: HLSStreamWriter
    stream: HLSStream
    buffer: RingBuffer

    def __init__(self, stream: HLSStream, name: str | None = None):
        self.request_params = dict(stream.args)
        # These params are reserved for internal use
        self.request_params.pop("exception", None)
        self.request_params.pop("stream", None)
        self.request_params.pop("timeout", None)
        self.request_params.pop("url", None)

        super().__init__(stream, name=name)


TMuxedHLSStream_co = TypeVar("TMuxedHLSStream_co", bound="HLSStream", covariant=True)


class MuxedHLSStream(MuxedStream[TMuxedHLSStream_co]):
    """
    Muxes multiple HLS video and audio streams into one output stream.
    """

    __shortname__ = "hls-multi"

    def __init__(
        self,
        session: Streamlink,
        video: str,
        audio: str | list[str],
        hlsstream: type[TMuxedHLSStream_co] | None = None,
        url_master: str | None = None,
        multivariant: M3U8 | None = None,
        force_restart: bool = False,
        ffmpeg_options: Mapping[str, Any] | None = None,
        **kwargs,
    ):
        """
        :param session: Streamlink session instance
        :param video: Video stream URL
        :param audio: Audio stream URL or list of URLs
        :param hlsstream: The :class:`HLSStream` class of each sub-stream
        :param url_master: The URL of the HLS playlist's multivariant playlist (deprecated)
        :param multivariant: The parsed multivariant playlist
        :param force_restart: Start from the beginning after reaching the playlist's end
        :param ffmpeg_options: Additional keyword arguments passed to :class:`ffmpegmux.FFMPEGMuxer`
        :param kwargs: Additional keyword arguments passed to :class:`HLSStream`
        """

        tracks = [video]
        maps = ["0:v?", "0:a?"]
        if audio:
            if isinstance(audio, list):
                tracks.extend(audio)
            else:
                tracks.append(audio)
        maps.extend(f"{i}:a" for i in range(1, len(tracks)))

        # https://github.com/python/mypy/issues/18017
        TStream: type[TMuxedHLSStream_co] = hlsstream if hlsstream is not None else HLSStream  # type: ignore[assignment]
        substreams = [
            TStream(session, url, force_restart=force_restart, name=None if idx == 0 else "audio", **kwargs)
            for idx, url in enumerate(tracks)
        ]
        ffmpeg_options = ffmpeg_options or {}

        super().__init__(session, *substreams, format="mpegts", maps=maps, **ffmpeg_options)
        self._url_master = url_master
        self.multivariant = multivariant if multivariant and multivariant.is_master else None

    @property
    def url_master(self):
        """Deprecated"""
        return self.multivariant.uri if self.multivariant and self.multivariant.uri else self._url_master

    def to_manifest_url(self):
        url = self.multivariant.uri if self.multivariant and self.multivariant.uri else self.url_master

        if url is None:
            return super().to_manifest_url()

        return url


class HLSStream(HTTPStream):
    """
    Implementation of the Apple HTTP Live Streaming protocol.
    """

    __shortname__ = "hls"
    __reader__: ClassVar[type[HLSStreamReader]] = HLSStreamReader
    __parser__: ClassVar[type[M3U8Parser[M3U8[HLSSegment, HLSPlaylist], HLSSegment, HLSPlaylist]]] = M3U8Parser

    def __init__(
        self,
        session: Streamlink,
        url: str,
        url_master: str | None = None,
        multivariant: M3U8 | None = None,
        name: str | None = None,
        force_restart: bool = False,
        start_offset: float = 0,
        duration: float | None = None,
        **kwargs,
    ):
        """
        :param session: Streamlink session instance
        :param url: The URL of the HLS playlist
        :param url_master: The URL of the HLS playlist's multivariant playlist (deprecated)
        :param multivariant: The parsed multivariant playlist
        :param name: Optional name suffix for the stream's worker and writer threads
        :param force_restart: Start from the beginning after reaching the playlist's end
        :param start_offset: Number of seconds to be skipped from the beginning
        :param duration: Number of seconds until ending the stream
        :param kwargs: Additional keyword arguments passed to :meth:`requests.Session.request`
        """

        super().__init__(session, url, **kwargs)
        self._url_master = url_master
        self.multivariant = multivariant if multivariant and multivariant.is_master else None
        self.name = name
        self.force_restart = force_restart
        self.start_offset = start_offset
        self.duration = duration
        self.reader = self.__reader__(self, name=self.name)

    def __json__(self):  # noqa: PLW3201
        json = super().__json__()

        try:
            json["master"] = self.to_manifest_url()
        except TypeError:
            pass

        del json["method"]
        del json["body"]

        return json

    @property
    def url_master(self):
        """Deprecated"""
        return self.multivariant.uri if self.multivariant and self.multivariant.uri else self._url_master

    def to_manifest_url(self):
        url = self.multivariant.uri if self.multivariant and self.multivariant.uri else self.url_master

        if url is None:
            return super().to_manifest_url()

        args = self.args.copy()
        args.update(url=url)

        return self.session.http.prepare_new_request(**args).url

    def open(self):
        self.reader.open()
        return self.reader

    def close(self):
        self.reader.close()
        self.reader = None

    @classmethod
    def _fetch_variant_playlist(cls, session, url: str, **request_args) -> Response:
        headers = dict(request_args.get("headers") or {})
        headers["Connection"] = "close"
        request_args["headers"] = headers
        res = session.http.get(url, exception=OSError, **request_args)
        res.encoding = "utf-8"

        return res

    @classmethod
    def parse_variant_playlist(
        cls,
        session: Streamlink,
        url: str,
        name_key: str = "name",
        name_prefix: str = "",
        check_streams: bool = False,
        force_restart: bool = False,
        name_fmt: str | None = None,
        start_offset: float = 0,
        duration: float | None = None,
        **kwargs,
    ) -> dict[str, Self | MuxedHLSStream[Self]]:
        """
        Parse a variant playlist and return its streams.

        :param session: Streamlink session instance
        :param url: The URL of the variant playlist
        :param name_key: Prefer to use this key as stream name, valid keys are: name, pixels, bitrate
        :param name_prefix: Add this prefix to the stream names
        :param check_streams: Only allow streams that are accessible
        :param force_restart: Start at the first segment even for a live stream
        :param name_fmt: A format string for the name, allowed format keys are: name, pixels, bitrate
        :param start_offset: Number of seconds to be skipped from the beginning
        :param duration: Number of second until ending the stream
        :param kwargs: Additional keyword arguments passed to :class:`HLSStream`, :class:`MuxedHLSStream`,
                       or :py:meth:`requests.Session.request`
        """

        locale = session.localization
        hls_audio_select = session.options.get("hls-audio-select")
        audio_select_any: bool = "*" in hls_audio_select
        audio_select_langs: list[Language] = []
        audio_select_codes: list[str] = []
 
        for item in hls_audio_select:
            item = item.strip().lower()
            if item == "*":
                continue
            try:
                audio_select_langs.append(Language.get(item))
            except LookupError:
                audio_select_codes.append(item)

        request_args = session.http.valid_request_args(**kwargs)
        res = cls._fetch_variant_playlist(session, url, **request_args)
        try:
            try:
                multivariant = parse_m3u8(res, parser=cls.__parser__)
            except ValueError as err:
                raise OSError(f"Failed to parse playlist: {err}") from err
        finally:
            with contextlib.suppress(Exception):
                res.close()

        stream_name: str | None
        stream: HLSStream | MuxedHLSStream
        streams: dict[str, HLSStream | MuxedHLSStream] = {}
        client_info = session.options.get("client-info")

        for playlist in multivariant.playlists:
            if playlist.is_iframe:
                continue

            names: dict[str, str | None] = dict(name=None, pixels=None, bitrate=None)
            audio_streams = []
            fallback_audio: list[Media] = []
            default_audio: list[Media] = []
            preferred_audio: list[Media] = []

            for media in playlist.media:
                if media.type == "VIDEO" and media.name:
                    names["name"] = media.name
                elif media.type == "AUDIO":
                    audio_streams.append(media)

            for media in audio_streams:
                # Media without a URI is not relevant as external audio
                if not media.uri:
                    continue

                if not fallback_audio and media.default:
                    fallback_audio = [media]

                # if the media is "autoselect" and it better matches the users preferences, use that
                # instead of default
                if not default_audio and (media.autoselect and locale.equivalent(language=media.parsed_language)):
                    default_audio = [media]

                # select the first audio stream that matches the user's explict language selection
                if (
                    # user has selected all languages
                     audio_select_any
                     # compare plain language codes first
                     or (
                         media.language is not None
                         and media.language in audio_select_codes
                     )
                     # then compare parsed language codes and user input
                     or (
                         media.parsed_language is not None
                         and media.parsed_language in audio_select_langs
                    )
                    # then compare media name attribute
                     or (
                         media.name
                         and media.name.lower() in audio_select_codes
                     )
                    # fallback: find first media playlist matching the user's locale
                    or (
                        (not preferred_audio or media.default)
                        and locale.explicit
                        and locale.equivalent(language=media.parsed_language)
                    )
                ):
                    preferred_audio.append(media)

            # final fallback on the first audio stream listed
            if not fallback_audio and audio_streams and audio_streams[0].uri:
                fallback_audio = [audio_streams[0]]

            if playlist.stream_info.resolution and playlist.stream_info.resolution.height:
                names["pixels"] = f"{playlist.stream_info.resolution.height}p"

            if playlist.stream_info.bandwidth:
                bw = playlist.stream_info.bandwidth

                if bw >= 1000:
                    names["bitrate"] = f"{int(bw / 1000.0)}k"
                else:
                    names["bitrate"] = f"{bw / 1000.0}k"

            if name_fmt:
                stream_name = name_fmt.format(**names)
            else:
                stream_name = (
                    names.get(name_key)
                    or names.get("name")
                    or names.get("pixels")
                    or names.get("bitrate")
                )

            if not stream_name:
                continue
            if name_prefix:
                stream_name = f"{name_prefix}{stream_name}"

            if stream_name in streams:  # rename duplicate streams
                stream_name = f"{stream_name}_alt"
                num_alts = len([k for k in streams.keys() if k.startswith(stream_name)])

                # We shouldn't need more than 2 alt streams
                if num_alts >= 2:
                    continue
                elif num_alts > 0:
                    stream_name = f"{stream_name}{num_alts + 1}"

            if check_streams:
                # noinspection PyBroadException
                try:
                    session.http.get(playlist.uri, **request_args)
                except KeyboardInterrupt:
                    raise
                except Exception:
                    continue

            external_audio = preferred_audio or default_audio or fallback_audio

            if external_audio and FFMPEGMuxer.is_usable(session):
                external_audio_msg = ", ".join([
                    f"(language={x.language}, name={x.name or 'N/A'})"
                    for x in external_audio
                ])
                log.info(f"{client_info} Start ffmpeg muxer: using external audio tracks for stream {stream_name} {external_audio_msg}")

                stream = MuxedHLSStream(
                    session,
                    video=playlist.uri,
                    audio=[x.uri for x in external_audio if x.uri],
                    hlsstream=cls,
                    multivariant=multivariant,
                    force_restart=force_restart,
                    start_offset=start_offset,
                    duration=duration,
                    **kwargs,
                )
            else:
                stream = cls(
                    session,
                    playlist.uri,
                    multivariant=multivariant,
                    force_restart=force_restart,
                    start_offset=start_offset,
                    duration=duration,
                    **kwargs,
                )

            streams[stream_name] = stream

        return streams
