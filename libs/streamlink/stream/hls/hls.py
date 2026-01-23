from __future__ import annotations

import logging
import re
import struct
import contextlib
import threading
import time
import gc
from datetime import timedelta, timezone, datetime
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from time import monotonic
from collections import deque

from http.client import IncompleteRead
from urllib3.exceptions import ProtocolError

from requests import Response
from requests.exceptions import ChunkedEncodingError, ConnectionError, ContentDecodingError, InvalidSchema

from streamlink.exceptions import StreamError
from streamlink.stream.ffmpegmux import FFMPEGMuxer, MuxedStream
from streamlink.stream.filtered import FilteredStream
from streamlink.stream.hls.m3u8 import M3U8Parser, parse_m3u8
from streamlink.stream.hls.segment import HLSSegment
from streamlink.stream.http import HTTPStream
from streamlink.stream.segmented import SegmentedStreamReader, SegmentedStreamWorker, SegmentedStreamWriter
from streamlink.utils.cache import LRUCache
from streamlink.utils.crypto import AES, unpad
from streamlink.utils.formatter import Formatter
from streamlink.utils.l10n import Language
from streamlink.utils.times import now


if TYPE_CHECKING:
    from collections.abc import Mapping
    from concurrent.futures import Future

    from streamlink.buffers import RingBuffer
    from streamlink.session import Streamlink
    from streamlink.stream.hls.m3u8 import M3U8
    from streamlink.stream.hls.segment import ByteRange, HLSPlaylist, Key, Map, Media

    try:
        from typing import Self  # type: ignore[attr-defined]
    except ImportError:
        from typing_extensions import Self


log = logging.getLogger(".".join(__name__.split(".")[:-1]))

# --- Minimal noise filter: drop "Closing worker/writer thread" messages (substring match) when enabled ---
class _ClosingNoiseFilter(logging.Filter):
    _SUBSTR = (
        "Closing worker thread",
        "Closing writer thread",
    )

    def filter(self, record: logging.LogRecord) -> bool:  # True -> keep, False -> drop
        try:
            msg = record.getMessage()
        except Exception:
            return True
        # Drop if any of the substrings is present (handles client_info prefixes, etc.)
        return not any(s in msg for s in self._SUBSTR)

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
        # Limit how many distinct MAPs we keep. Default small to avoid holding many large init blocks.
        try:
            _mapsz_opt = options.get("hls-map-cache-size")
            # allow explicit 0/1/2..., fallback to min(threads, 2) if not provided
            if _mapsz_opt is None:
                map_cache_size = max(1, min(int(getattr(self, "threads", 1) or 1), 2))
            else:
                map_cache_size = max(1, int(_mapsz_opt))
        except Exception:
            map_cache_size = max(1, min(int(getattr(self, "threads", 1) or 1), 2))
        self.map_cache: LRUCache[str, Future] = LRUCache(map_cache_size)
        self.key_data: bytes | bytearray | memoryview = b""
        self.key_uri: str | None = None
        self.key_uri_override = options.get("hls-segment-key-uri")
        self.stream_data = options.get("hls-segment-stream-data")
        self.chunk_size = options.get("chunk-size")
        self.client_info = options.get("client-info")
        self.seg_conn_close = options.get("hls-segment-conn-close")
        self.segment_failures: int = 0
        self._seg_fail_lock = threading.Lock()
        # Fast abort (immediate shutdown triggered by worker)
        self._fast_abort_event = threading.Event()
        self._fast_abort_lock = threading.Lock()
        self._fast_abort_done = False
        # Signals segment completion to the worker for short "grace" re-planning
        self._seg_complete_event = threading.Event()

        # -------- Partial (incomplete) read retry settings (independent from SEGMENT_ERROR_LIMIT) ----------
        # How many extra attempts (in addition to the initial one) for partial/incomplete network reads.
        self.partial_retry_max = 2
        # Base backoff (seconds) multiplied by attempt index (1..partial_retry_max)
        self.partial_retry_backoff = 0.4
        # Stats (for optional logging / diagnostics)
        self.partial_retry_stats_attempts: int = 0          # total additional attempts performed
        self.partial_retry_stats_segments: int = 0          # number of segments that required at least one retry
        # Exception classes considered "partial" (safe to retry)
        self._partial_retry_exc_classes = (
            ChunkedEncodingError,
            ContentDecodingError,
            ConnectionError,
            IncompleteRead,
            ProtocolError,
        )

        self.ignore_names: re.Pattern | None = None
        ignore_names = {*options.get("hls-segment-ignore-names")}
        if ignore_names:
            segments = "|".join(map(re.escape, ignore_names))
            self.ignore_names = re.compile(segments, re.IGNORECASE)

    # --- Aggressive memory release helpers ---
    def _release_memory(self):
        # Drop encryption key material
        try:
            self.key_data = b""
            self.key_uri = None
        except Exception:
            pass
        # Clear map cache with futures
        try:
            if hasattr(self, "map_cache") and self.map_cache:
                self.map_cache.clear()
        except Exception:
            pass
        # Best-effort: drop internal futures list reference if base left it
        try:
            futs = getattr(self, "_futures", None)
            if isinstance(futs, list):
                futs.clear()
        except Exception:
            pass

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
        if self.seg_conn_close:
            headers["Connection"] = "close"

        if not is_map:
            headers["Accept-Encoding"] = "identity"
            request_params["cookies"] = {}

        if segment.byterange:
            if is_map:
                bytes_start, bytes_end = self.byterange.uncached(segment.byterange)
            else:
                bytes_start, bytes_end = self.byterange.cached(num, segment.byterange)
            headers["Range"] = f"bytes={bytes_start}-{bytes_end}"

        request_params["headers"] = headers
        return request_params

    def _probe_segment_size(self, uri: str, base_params: dict) -> int | None:
        """
        Try to determine the total size of the segment:
        GET Range: bytes=0-0 (stream=False), read Content-Range: "bytes 0-0/total"
        Returns total (int) or None.
        """
        try:
            params = dict(base_params or {})
            hdrs = dict(params.get("headers") or {})
            hdrs["Range"] = "bytes=0-0"
            hdrs["Accept-Encoding"] = "identity"
            if self.seg_conn_close:
                hdrs["Connection"] = "close"
            params["headers"] = hdrs
            # stream=False, to get the titles/content right away
            resp = self.session.http.get(
                uri,
                timeout=self.timeout,
                retries=self.retries,
                exception=StreamError,
                stream=False,
                **params,
            )
            try:
                cr = resp.headers.get("Content-Range")
                if cr:
                    # format: "bytes 0-0/1234567"
                    total_str = cr.split("/")[-1].strip()
                    total = int(total_str)
                    return total if total > 0 else None
            finally:
                with contextlib.suppress(Exception):
                    resp.close()
        except Exception:
            return None
        return None

    def put(self, segment: HLSSegment | None):
        if self.closed:
            return
        if self._fast_abort_event.is_set():
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
                future = self.executor.submit(self.fetch_map, segment)  # future -> bytes
                self.map_cache.set(segment.map.uri, future)
                self.queue(segment, future, True)

        # regular segment request
        future = self.executor.submit(self.fetch, segment)
        self.queue(segment, future, False)

    def fetch(self, segment: HLSSegment) -> Response | None:
        # Do not proceed if fast abort is active
        if self._fast_abort_event.is_set():
            return None
        try:
            # Measure end-to-end download from the moment we begin the request (incl. connect+headers).
            # Capture a single monotonic timestamp and pass the SAME value to the worker (for elapsed checks)
            # and attach it to the Response (for completion log time), to keep both perfectly aligned.
            from time import monotonic as _mon
            _fetch_started_monotonic: float | None = None
            try:
                _fetch_started_monotonic = _mon()
            except Exception:
                _fetch_started_monotonic = None

            # Inform the worker about this exact fetch-start moment (monotonic-based)
            try:
                worker = getattr(self.reader, "worker", None)
                if worker and hasattr(worker, "_on_segment_fetch_start"):
                    worker._on_segment_fetch_start(int(segment.num), _fetch_started_monotonic)
            except Exception:
                pass

            resp = self._fetch(
                segment.uri,
                stream=self.stream_data,
                **self.create_request_params(segment.num, segment, False),
            )
            # Attach start timestamp to Response for accurate total time logging in _write()
            if resp is not None and _fetch_started_monotonic is not None:
                try:
                    setattr(resp, "_tvlink_fetch_started", _fetch_started_monotonic)
                except Exception:
                    pass
            self._reset_segment_failures_if_needed()
            return resp
        except StreamError as err:
            log.error(f"{self.client_info} Failed to fetch segment {segment.num}: {err}")

            code = self._extract_status_code(err)
            self._handle_segment_failure(code, "segment")
            return None

    def fetch_map(self, segment: HLSSegment) -> bytes | None:  # return bytes instead of Response
        """
        We download init/MAP in streaming mode, read it into memory ourselves, and close Response.
        We store only bare bytes in the cache => Future does not store Response._content.
        """
        if self._fast_abort_event.is_set():
            return None
        segment_map: Map = segment.map  # type: ignore[assignment]
        resp: Response | None = None
        try:
            # stream=True — We don't buffer all content inside requests; we read by chunk_size.
            resp = self._fetch(
                segment_map.uri,
                stream=True,
                **self.create_request_params(segment.num, segment_map, True),
            )
            if resp is None:
                return None
            self._reset_segment_failures_if_needed()
            data_parts: list[bytes] = []
            for part in resp.iter_content(self.chunk_size):
                if self._fast_abort_event.is_set():
                    return None
                if part:
                    data_parts.append(part)
            # We assemble with one join (MAP is usually small; if it's suddenly large, it's still better than keeping Response)
            return b"".join(data_parts)
        except StreamError as err:
            log.error(f"{self.client_info} Failed to fetch map for segment {segment.num}: {err}")
            code = self._extract_status_code(err)
            self._handle_segment_failure(code, "map")
            return None
        finally:
            self._safe_close(resp)

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
        # Early-exit if fast abort was requested to prevent starting new HTTP requests
        if self._fast_abort_event.is_set() or self.closed or not self.retries:  # pragma: no cover
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
        if self._fast_abort_event.is_set():
            self._safe_close(result)
            return

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
                        f"{self.client_info} Discontinuity detected at segment {segment.num}: This is unsupported and will result in incoherent output data."
                    )
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

    def _write(self, segment: HLSSegment, result: Response | bytes, is_map: bool):
        if self._fast_abort_event.is_set():
            return

        # TODO: Rewrite HLSSegment, HLSStreamWriter and HLSStreamWorker based on independent initialization section segments,
        #       similar to the DASH implementation
        key = segment.map.key if is_map and segment.map else segment.key

        # --- A shortcut for MAP, which we've already converted to bytes ---
        if is_map and isinstance(result, (bytes, bytearray, memoryview)):
            data = bytes(result)
            if key and key.method != "NONE":
                try:
                    decryptor = self.create_decryptor(key, segment.num)
                    # The length must be a multiple of the block; if not, we abandon the attempt (it will throw a ValueError and abort)
                    dec = decryptor.decrypt(data)
                    try:
                        dec = unpad(dec, AES.block_size, style="pkcs7")
                    except ValueError:
                        # If the padding is strange, we log it and still write it as is.
                        log.warning(f"{self.client_info} MAP decrypt unpad issue segment {segment.num}")
                    self.reader.buffer.write(dec)
                except Exception as e:
                    log.error(f"{self.client_info} Failed to decrypt MAP segment {segment.num}: {e}")
                    return
            else:
                self.reader.buffer.write(data)
            # Segment end signal (for smart logic to see)
            try:
                self._seg_complete_event.set()
                worker = getattr(self.reader, "worker", None)
                if worker and hasattr(worker, "_on_segment_complete"):
                    worker._on_segment_complete(int(segment.num))
            except Exception:
                pass
            return

        # Decide request parameters for potential refetch
        if is_map and segment.map:
            refetch_is_map = True
            refetch_uri = segment.map.uri
            refetch_stream = False
            refetch_params = self.create_request_params(segment.num, segment.map, True)
        else:
            refetch_is_map = False
            refetch_uri = segment.uri
            refetch_stream = self.stream_data
            refetch_params = self.create_request_params(segment.num, segment, False)

        max_attempts = 1 + (self.partial_retry_max if self.partial_retry_max > 0 else 0)
        attempt_index = 0
        had_retry = False
        global_start = monotonic()
        # Buffer and counters for resume on plain (unencrypted) segments.
        # Use chunk list to avoid an extra large copy on success (write chunks individually).
        temp_plain_chunks: list[bytes] | None = None
        bytes_have: int = 0
        try:
            can_resume_plain = (key is None or key.method == "NONE") and (not is_map)
        except Exception:
            can_resume_plain = (not is_map)

        while attempt_index < max_attempts:
            # Extra early-abort check before any heavy/blocking read
            if self._fast_abort_event.is_set():
                return
            attempt_index += 1
            attempt_start = monotonic()
            partial_exception = None
            try:
                if key and key.method != "NONE":
                    # Prepare decryptor each attempt (key might rotate theoretically)
                    try:
                        decryptor = self.create_decryptor(key, segment.num)
                    except (StreamError, ValueError) as derr:
                        log.error(f"{self.client_info} Failed to create decryptor: {derr}")
                        self.close()
                        return
                    # Encrypted segments: stream-decrypt to avoid loading the entire response into memory at once.
                    # Keep the last cipher block for PKCS#7 unpadding at the end.
                    dec_chunks: list[bytes] = []
                    enc_tail = b""
                    try:
                        for enc_part in result.iter_content(self.chunk_size):
                            if self._fast_abort_event.is_set():
                                return
                            if not enc_part:
                                continue
                            # Append to tail and decrypt all but the last block
                            enc_tail += enc_part
                            # How many full blocks we currently have
                            blocks = len(enc_tail) // AES.block_size
                            if blocks > 1:
                                cut = (blocks - 1) * AES.block_size
                                to_dec = enc_tail[:cut]
                                enc_tail = enc_tail[cut:]
                                if to_dec:
                                    dec = decryptor.decrypt(to_dec)
                                    if dec:
                                        dec_chunks.append(dec)
                        # Finish: decrypt the final block and unpad
                        if enc_tail:
                            last_dec = decryptor.decrypt(enc_tail)
                            # Remove PKCS7 padding from the final decrypted block(s)
                            last_dec = unpad(last_dec, AES.block_size, style="pkcs7")
                            if last_dec:
                                dec_chunks.append(last_dec)
                        # On success, write decrypted chunks one by one (avoid an extra big copy)
                        for dec in dec_chunks:
                            if self._fast_abort_event.is_set():
                                return
                            self.reader.buffer.write(dec)
                    finally:
                        # Help GC drop large references ASAP
                        try:
                            enc_tail = b""
                            dec_chunks.clear()
                        except Exception:
                            pass
                else:
                    # Plain segment: assemble into a chunks list to support resume on retry,
                    # but avoid creating a large contiguous copy on success.
                    if temp_plain_chunks is None:
                        temp_plain_chunks = []
                        bytes_have = 0
                    # If resuming but server ignored Range and returned 200, restart assembling
                    try:
                        st = getattr(result, "status_code", None)
                    except Exception:
                        st = None
                    if bytes_have > 0 and st == 200:
                        try:
                            temp_plain_chunks.clear()
                        except Exception:
                            pass
                        bytes_have = 0
                    for chunk in result.iter_content(self.chunk_size):
                        # Abort as soon as possible between chunks
                        if self._fast_abort_event.is_set():
                            return
                        if not chunk:
                            continue
                        temp_plain_chunks.append(chunk)
                        bytes_have += len(chunk)
                    # On success, write all collected chunks individually (no extra big copy)
                    if temp_plain_chunks:
                        for ch in temp_plain_chunks:
                            if self._fast_abort_event.is_set():
                                return
                            self.reader.buffer.write(ch)
                        # Explicitly release large chunk list
                        try:
                            temp_plain_chunks.clear()
                        except Exception:
                            pass
                        temp_plain_chunks = None
                        bytes_have = 0

                # If we've been asked to abort fast, stop right away after completion
                if self._fast_abort_event.is_set():
                    return

                # SUCCESS
                total_time_ms = (monotonic() - attempt_start) * 1000.0
                if is_map:
                    log.debug(
                        f"{self.client_info} + Segment initialization {segment.num} complete "
                        f"(time={total_time_ms:.1f}ms retries={attempt_index-1})"
                    )
                else:
                    # Prefer end-to-end time starting from HTTP request begin if available
                    try:
                        t0 = getattr(result, "_tvlink_fetch_started", None)
                        if t0 is not None:
                            total_time_ms = (monotonic() - float(t0)) * 1000.0
                    except Exception:
                        pass
                    log.debug(
                        f"{self.client_info} + Segment {segment.num} complete "
                        f"(time={total_time_ms:.1f}ms retries={attempt_index-1})"
                    )

                # --- Anchor playback start at the first real media delivery ---
                try:
                    if not is_map:
                        worker = getattr(self.reader, "worker", None)
                        if worker:
                            # If nothing has been delivered yet, set the playback start anchor now
                            if float(getattr(worker, "_play_delivered_s", 0.0) or 0.0) <= 0.0:
                                from streamlink.utils.times import now as _now
                                worker._play_start_ts = _now()
                                # also align playable-buffer timebase
                                try:
                                    worker._buffer_last_upd_monotonic = monotonic()
                                except Exception:
                                    pass
                except Exception:
                    pass
                # --- Update delivered (real) playback time only after fully successful write ---
                try:
                    if (not is_map) and (not getattr(segment, "replay", False)):
                        durv = getattr(segment, "duration", None)
                        if durv and durv > 0:
                            worker = getattr(self.reader, "worker", None)
                            if worker and hasattr(worker, "_play_delivered_s"):
                                worker._play_delivered_s += float(durv)
                                # --- Playable buffer model: consume elapsed, then add durv ---
                                try:
                                    now_m = monotonic()
                                    elapsed_m = now_m - getattr(worker, "_buffer_last_upd_monotonic", now_m)
                                    buf = getattr(worker, "_buffer_playable_s", 0.0) - elapsed_m
                                    if buf <= 0:
                                        # we fix the event of devastation (freeze moment)
                                        if getattr(worker, "_buffer_playable_s", 0.0) > 0:
                                            worker._buffer_freeze_events += 1
                                        buf = 0.0
                                    buf += float(durv)
                                    worker._buffer_playable_s = buf
                                    worker._buffer_last_upd_monotonic = now_m
                                except Exception:
                                    pass
                except Exception:
                    pass
                # --- Report download ratio to worker for adaptive wait ---
                try:
                    if (not is_map) and segment.duration and segment.duration > 0:
                        download_time_s = total_time_ms / 1000.0
                        ratio = download_time_s / float(segment.duration)
                        # sanitize
                        if 0 < ratio < 100:
                            worker = getattr(self.reader, "worker", None)
                            if worker and hasattr(worker, "update_fetch_ratio"):
                                worker.update_fetch_ratio(ratio)
                except Exception:
                    pass
                # Notify worker that a real media segment has completed (to allow a short "grace" re-plan)
                try:
                    if not is_map:
                        self._seg_complete_event.set()
                        # Mark this exact segment as completed for smart/local-VOD threshold logic
                        try:
                            worker = getattr(self.reader, "worker", None)
                            if worker and hasattr(worker, "_on_segment_complete"):
                                worker._on_segment_complete(int(segment.num))
                        except Exception:
                            pass
                except Exception:
                    pass
                break

            except self._partial_retry_exc_classes as perr:
                if self._fast_abort_event.is_set():
                    return
                partial_exception = perr
                total_time_ms = (monotonic() - attempt_start) * 1000.0
                # Track how much we already have for resume
                if temp_plain_chunks is not None:
                    try:
                        # Keep running total updated; do not recompute sum to save CPU
                        # bytes_have already tracks total appended length
                        bytes_have = int(bytes_have)
                    except Exception:
                        bytes_have = 0
                else:
                    bytes_have = 0
                # Decide to retry or fail
                if attempt_index < max_attempts:
                    if not had_retry:
                        had_retry = True
                        self.partial_retry_stats_segments += 1
                    self.partial_retry_stats_attempts += 1
                    # Reduce noise: first retry -> debug, subsequent retries -> warning
                    if attempt_index < max_attempts - 1:
                        log.debug(
                            f"{self.client_info} Partial/incomplete segment {segment.num} "
                            f"(attempt {attempt_index}/{max_attempts}) time={total_time_ms:.1f}ms "
                            f"err={partial_exception.__class__.__name__}: retrying..."
                        )
                    else:
                        log.warning(
                            f"{self.client_info} Partial/incomplete segment {segment.num} "
                            f"(attempt {attempt_index}/{max_attempts}) time={total_time_ms:.1f}ms "
                            f"err={partial_exception.__class__.__name__}: retrying..."
                        )
                    log.debug(f"{self.client_info} Reasons for segment {segment.num} partial failure: {partial_exception}")
                    # Backoff
                    backoff = max(0.0, self.partial_retry_backoff * attempt_index)
                    if backoff:
                        time.sleep(backoff)
                    # Refetch (close old response first)
                    self._safe_close(result)

                    # 1) Try to resume plain segment from bytes_have if possible
                    rp2 = dict(refetch_params)
                    h2 = dict(rp2.get("headers") or {})
                    used_resume = False
                    if can_resume_plain and bytes_have > 0 and not refetch_is_map:
                        try:
                            h2["Range"] = f"bytes={bytes_have}-"
                            h2["Accept-Encoding"] = "identity"
                            if self.seg_conn_close:
                                h2["Connection"] = "close"
                            rp2["headers"] = h2
                            result = self.session.http.get(
                                refetch_uri,
                                timeout=self.timeout,
                                retries=self.retries,
                                exception=StreamError,
                                stream=refetch_stream,
                                **rp2,
                            )
                            used_resume = True
                        except Exception:
                            used_resume = False
                    # 2) If not resumed, on first partial try exact Range probe (if allowed and not BYTERANGE)
                    did_precise_range = False
                    if (not used_resume) and (
                        attempt_index == 1
                        and not refetch_is_map
                        and not getattr(segment, "byterange", None)
                    ):
                        try:
                            total = self._probe_segment_size(refetch_uri, refetch_params)
                            if total and total > 0:
                                # Prepare exact range 0-(total-1)
                                rp2 = dict(refetch_params)
                                h2 = dict(rp2.get("headers") or {})
                                h2["Range"] = f"bytes=0-{total-1}"
                                h2["Accept-Encoding"] = "identity"
                                if self.seg_conn_close:
                                    h2["Connection"] = "close"
                                rp2["headers"] = h2
                                result = self.session.http.get(
                                    refetch_uri,
                                    timeout=self.timeout,
                                    retries=self.retries,
                                    exception=StreamError,
                                    stream=refetch_stream,
                                    **rp2,
                                )
                                did_precise_range = True
                        except Exception:
                            did_precise_range = False
                    # 3) Fallback to a regular refetch
                    if (not used_resume) and (not did_precise_range):
                        try:
                            result = self.session.http.get(
                                refetch_uri,
                                timeout=self.timeout,
                                retries=self.retries,   # use same retry policy for transport-level failures
                                exception=StreamError,  # will raise StreamError if low-level fail
                                stream=refetch_stream,
                                **refetch_params,
                            )
                        except Exception as rferr:
                            log.error(f"{self.client_info} Retry fetch failed for segment {segment.num}: {rferr}")
                            return
                    continue
                else:
                    # Final failure after retries
                    log.error(
                        f"{self.client_info} Download of segment {segment.num} failed after retries "
                        f"(time={total_time_ms:.1f}ms total_elapsed={(monotonic()-global_start)*1000.0:.1f}ms)"
                    )
                    log.debug(
                        f"{self.client_info} Reasons final for segment {segment.num} failed: {partial_exception}"
                    )
                    return
            except ValueError as derr:
                # Decryption / padding error - no retry
                log.error(f"{self.client_info} Error while decrypting segment {segment.num}: {derr}")
                return
            except Exception as uerr:
                # Unexpected error - no retry
                log.error(f"{self.client_info} Unexpected error segment {segment.num}: {uerr}")
                return
            finally:
                # On success or final failure we close only after loop exit if not reused.
                # (When retrying we close explicitly before refetch.)
                pass
        # Ensure temporary large buffers are dropped (best-effort)
        try:
            if temp_plain_chunks is not None:
                temp_plain_chunks.clear()
        except Exception:
            pass
        temp_plain_chunks = None

    def fast_abort(self):
        """
        Trigger immediate abort: stop future writes, cancel pending futures,
        and close underlying executor quickly without waiting for slow retries.
        """
        with self._fast_abort_lock:
            if self._fast_abort_done:
                return
            self._fast_abort_done = True
            self._fast_abort_event.set()
            try:
                pending = []
                try:
                    futures_attr = getattr(self, "_futures", None)
                    if futures_attr and isinstance(futures_attr, list):
                        pending = list(futures_attr)
                except Exception:
                    pass
                for f in pending:
                    try:
                        if not f.done():
                            f.cancel()
                    except Exception:
                        pass
                try:
                    self.executor.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    self.executor.shutdown(wait=False)
            except Exception:
                pass
            finally:
                # Drop caches/refs ASAP
                self._release_memory()
                try:
                    gc.collect()
                except Exception:
                    pass

    # Ensure close() also releases memory when not using fast_abort
    def close(self):
        try:
            super().close()
        finally:
            # Ensure the executor and futures are fully torn down between runs
            try:
                try:
                    # Python 3.9+: cancel_futures
                    self.executor.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    # Older signature without cancel_futures
                    self.executor.shutdown(wait=False)
            except Exception:
                pass
            # Drop any internal futures list reference if base left it populated
            try:
                futs = getattr(self, "_futures", None)
                if isinstance(futs, list):
                    futs.clear()
            except Exception:
                pass
            try:
                self._release_memory()
                gc.collect()
            except Exception:
                pass

    def is_fast_aborted(self) -> bool:
        return self._fast_abort_event.is_set()

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
        self.live_edge = self.session.options.get("hls-live-edge")
        self.duration_offset_start = int(self.stream.start_offset + (self.session.options.get("hls-start-offset") or 0))
        self.hls_live_restart = self.stream.force_restart or self.session.options.get("hls-live-restart")
        self.hls_stream_data = self.session.options.get("hls-segment-stream-data")
        self.hls_segments_queue = self.session.options.get("segments-queue")
        # Growth suppression in Smart mode
        self.growth_min_seg_in_queue: int = 2
        self.growth_target_queue_duration: float = 8.0 # Target stock in queue (sec)
        # Live buffer target multiplier (in segments' mean seconds)
        self.live_buffer_mult = float(self.session.options.get("live-buffer-mult") or 2.0)
        # VOD buffer target multiplier (in segments' mean seconds)
        self.vod_buffer_mult = float(self.session.options.get("vod-buffer-mult") or 3.0)
        # --- VOD settings ---
        self.vod_start = int(self.session.options.get("vod-start") or 3)
        self.vod_process = int(self.session.options.get("vod-process") or 1)
        self.vod_queue_step = int(self.session.options.get("vod-queue-step") or 1)
        # Shared averaging window (used by both Live and VOD)
        self.buffer_avg_window: int = 5

        # These are internal state variables for Smart mode
        self._reload_prev_last_num: int | None = None
        self._smart_base: float | None = None
        self._smart_changed: bool | None = None

        self._recent_seg_durations: list[float] = []
        self._last_wait_ratio: float | None = None
        self._play_start_ts: datetime = now()
        self._play_logical_s: float = 0.0
        self._play_delivered_s: float = 0.0
        self._buffer_playable_s: float = 0.0
        self._buffer_last_upd_monotonic: float = monotonic()
        self._buffer_freeze_events: int = 0

        # Protection against abnormal forward jumps in segment numbering (configurable)
        self.large_jump_threshold: int = 3

        # Empty VOD window protection (avoid endless advance loop if provider returns repeated empty windows)
        self._vod_empty_window_count: int = 0
        self._vod_empty_window_limit: int = 3

        # Local VOD mode state
        self._vod_local_active: bool = False
        self._vod_segments_all: list[HLSSegment] = []
        self._vod_local_pos: int = 0
        self._vod_last_end_unix: int | None = None
        self._vod_scheme: str | None = None
        self._vod_next_wait: float = 0.0
        self._vod_initial_burst_remaining: int = 0
        self._playlist_url_override: str | None = None
        # --- Adaptive wait (Local VOD) based on real download speed ---
        self._vod_adjust_wait = True
        self._fetch_ratio_ema: float | None = None   # ~ average(download_time / duration)
        self._fetch_ratio_alpha: float = 0.30        # EMA smoothing factor
        # --- Enhanced Local VOD adaptive control (robust stats, fill smoothing, slow-series, steady mode) ---
        self._vod_recent_durations: list[float] = []          # recent raw segment durations (plain EXTINF), for robust mean
        self._vod_recent_durations_window: int = 12
        self._vod_fill_ema: float | None = None               # EMA of buffer fill fraction
        self._vod_fill_alpha: float = 0.30
        self._vod_slow_series_threshold_ratio: float = 0.80   # ratio > 0.80 => "slow" fetch
        self._vod_slow_series_trigger_n: int = 6              # consecutive slow segments to enter steady mode
        self._vod_slow_series_count: int = 0
        self._vod_steady_mode_segments_left: int = 0          # countdown of segments to keep steady mode
        self._vod_steady_mode_span: int = 10                  # how many segments to remain in steady mode once triggered
        self._vod_active_fetch_soft_limit_factor: float = 0.5 # fraction of writer threads as soft cap when throttling
        self._vod_active_fetch_soft_sleep: float = 0.05       # sleep while waiting for active fetch to drop
        self._vod_cap_throttle_active: bool = False           # active throttling while draining to lower cap
        self._vod_cap_lower_eps: float = 0.50                 # stop throttle when buf <= cap + eps (seconds)

        # Short grace wait (seconds) to account for imminent "segment complete" before planning
        self.plan_completion_grace_max: float = 1.5

        # In-flight segments tracker: num -> (enqueued_at, duration_seconds)
        self._inflight_segments: dict[int, tuple[datetime, float]] = {}
        self._inflight_lock = threading.Lock()
        # Monotonic fetch-start timestamps (recorded by writer.fetch).
        # Keeps: num -> monotonic_started_at (float)
        # Used to compute "elapsed" with the SAME base as writer's "+ Segment ... time=...".
        # If missing (rare), we fall back to enqueue-time (wall clock) to avoid false positives.
        self._inflight_fetch_started_mono: dict[int, float] = {}

        # Whether playable buffer was ever positive before (used by secondary threshold rule)
        self._buf_was_positive: bool = False
        # Moment when buffer first became negative (continuous interval tracker)
        self._buf_negative_since: datetime | None = None

        # --- Buffer negative duration protection ---
        self._buf_negative_long_threshold_s: float = 60.0    # how many seconds to wait
        self._buf_negative_long_max: int = 3                 # how many times to allow
        self._buf_negative_long_count: int = 0               # long negative buffer counter
        # Sliding window of timestamps when buffer first entered a negative state
        self._buf_negative_events = deque()                  # deque[datetime]
        # Start timestamp of the current 60s window (used only for clarity/logging)
        self._buf_negative_window_start: datetime | None = None
        # Previous state flag to detect edge transitions (>=0 -> <0)
        self._buf_prev_negative: bool = False

        # Anchor: take the original URL passed by the player into Streamlink
        anchor_src = "session"
        anchor_url: str | None = None
        try:
            if hasattr(self.session, "get_entry_url"):
                anchor_url = self.session.get_entry_url()
            if not anchor_url:
                anchor_url = self.session.options.get("hls-anchor-url")
                if anchor_url:
                    anchor_src = "options"
            if (not anchor_url) and hasattr(self.stream, "args") and isinstance(self.stream.args, dict):
                anchor_url = self.stream.args.get("url");  anchor_src = "args"
            if not anchor_url:
                anchor_url = getattr(self.stream, "url", None);  anchor_src = "stream"
        except Exception:
            anchor_src = "stream";  anchor_url = getattr(self.stream, "url", None)
        self._playlist_url_anchor: str = anchor_url or ""
        #log.debug(f"{self.client_info} HLS anchor ({anchor_src}): {self._playlist_url_anchor}")

    # --- Helpers for VOD local mode and catchup URL handling ---

    def _vod_detect_scheme(self, url: str) -> str:
        """
        Detect catchup scheme from the original anchor URL:
        - shift: query contains utc= or lutc=
        - append: query contains offset= or utcstart=
        - flussonic: path contains -timeshift_rel-
        Default: 'plain' (no catchup)
        """
        try:
            p = urlparse(url or "")
            qs = (p.query or "").lower()
            path = p.path or ""
            if "utc=" in qs or "lutc=" in qs:
                return "shift"
            if "offset=" in qs or "utcstart=" in qs:
                return "append"
            if "-timeshift_rel-" in path:
                return "flussonic"
            return "plain"
        except Exception:
            return "plain"

    def _extract_url_utc_start(self, url: str) -> int | None:
        """Try to read utc=<unix> from URL query, returns int or None."""
        try:
            p = urlparse(url)
            params = dict(parse_qsl(p.query, keep_blank_values=True))
            v = params.get("utc")
            if v is not None:
                return int(v)
        except Exception:
            pass
        return None

    def _vod_compute_end_unix(self, playlist: M3U8[HLSSegment, HLSPlaylist]) -> int | None:
        """
        Compute absolute unix timestamp of the END of the last segment:
        - Prefer #EXT-X-PROGRAM-DATE-TIME anchors.
        - Fallback to URL's utc=<unix> as the playlist's start time.
        """
        segs = playlist.segments or []
        if not segs:
            return None

        # Determine initial base time
        base: datetime | None = None
        # Prefer PDT of the first (or any) segment
        for s in segs:
            pdt = getattr(s, "program_date_time", None)
            if pdt:
                # Make sure it's timezone-aware in UTC
                if pdt.tzinfo is None:
                    pdt = pdt.replace(tzinfo=timezone.utc)
                else:
                    pdt = pdt.astimezone(timezone.utc)
                base = pdt
                break

        # Fallback to URL utc param
        if base is None:
            utc0 = self._extract_url_utc_start(self._playlist_url_anchor)
            if utc0 is not None:
                base = datetime.fromtimestamp(int(utc0), tz=timezone.utc)

        if base is None:
            return None

        curr = base
        for s in segs:
            # Reset base at segment with PDT if present
            pdt = getattr(s, "program_date_time", None)
            if pdt:
                if pdt.tzinfo is None:
                    curr = pdt.replace(tzinfo=timezone.utc)
                else:
                    curr = pdt.astimezone(timezone.utc)
            dur = float(getattr(s, "duration", 0) or 0.0)
            curr = curr + timedelta(seconds=max(0.0, dur))

        try:
            return int(curr.timestamp())
        except Exception:
            # Fallback naive conversion
            return int((curr - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())

    def _vod_build_next_url(self, start_unix: int, now_unix: int) -> str | None:
        """
        Build next catchup URL for the next window starting at start_unix (END of last seg), now_unix=current time.
        Supports: shift, append, flussonic.
        """
        p_anchor = urlparse(self._playlist_url_anchor or "")
        qs = (p_anchor.query or "").lower()
        path = p_anchor.path or ""

        has_shift = ("utc=" in qs) or ("lutc=" in qs)
        has_append = ("offset=" in qs) or ("utcstart=" in qs)
        has_flussonic = ("-timeshift_rel-" in path)

        # Plain VOD without any catchup markers: don't modify URL at all
        if not (has_shift or has_append or has_flussonic):
            return None

        if has_shift:
            params = dict(parse_qsl(p_anchor.query, keep_blank_values=True))
            # Only update keys that are already present
            if "utc" in params:
                params["utc"] = str(int(start_unix))
            if "lutc" in params:
                params["lutc"] = str(int(now_unix))
            new_q = urlencode(params)
            return urlunparse(p_anchor._replace(query=new_q))

        if has_append:
            offset = max(0, int(now_unix) - int(start_unix))
            params = dict(parse_qsl(p_anchor.query, keep_blank_values=True))
            # Only update keys that are already present
            if "offset" in params:
                params["offset"] = f"-{offset}"
            if "utcstart" in params:
                params["utcstart"] = str(int(now_unix))
            new_q = urlencode(params)
            return urlunparse(p_anchor._replace(query=new_q))

        if has_flussonic:
            offset = max(0, int(now_unix) - int(start_unix))
            # Replace existing timeshift suffix if present
            new_path = re.sub(r"-timeshift_rel-\d+\.m3u8$", f"-timeshift_rel-{offset}.m3u8", path)
            if new_path == path:
                # Handle typical cases
                if path.endswith("index.m3u8"):
                    new_path = path[: -len("index.m3u8")] + f"timeshift_rel-{offset}.m3u8"
                elif path.endswith(".m3u8"):
                    new_path = path[: -len(".m3u8")] + f"-timeshift_rel-{offset}.m3u8"
                else:
                    # Fallback: append suffix
                    new_path = path + f"-timeshift_rel-{offset}.m3u8"
            return urlunparse(p_anchor._replace(path=new_path))

        # Shouldn't reach here
        return None

    def _current_playlist_url(self) -> str:
        """
        Return the effective playlist URL that should be fetched.
        Falls back to the original stream.url if no override is set.
        """
        return self._playlist_url_override or self.stream.url

    # --- END: Helpers for VOD local mode and catchup URL handling  ---

    def _buffer_seconds_signed(self) -> float:
        """
        Signed playable buffer in seconds based on actually delivered segments:
        buffer = delivered_play_time - wall_time_since_start.
        """
        try: delivered = float(getattr(self, "_play_delivered_s", 0.0))
        except Exception: delivered = 0.0
        try: wall = (now() - self._play_start_ts).total_seconds()
        except Exception: wall = 0.0
        return delivered - wall

    def _fetch_playlist(self, url: str | None = None) -> Response:
        base_params = self.reader.request_params or {}
        req_params = dict(base_params)
        headers = dict(req_params.get("headers") or {})
        headers.setdefault("Cache-Control", "max-age=0, no-cache")
        headers.setdefault("Pragma", "no-cache")
        headers["Connection"] = "close"
        req_params["headers"] = headers
        target_url = url or self._current_playlist_url()

        res = self.session.http.get(
            target_url,
            exception=StreamError,
            retries=self.playlist_reload_retries,
            **req_params,
        )
        res.encoding = "utf-8"
        return res

    def reload_playlist(self, wait_buffer: bool = True, reason: str | None = None):
        if self.closed:  # pragma: no cover
            return

        # When advancing a VOD window, don't block on buffer to avoid stalling reload
        if wait_buffer:
            self.reader.buffer.wait_free()

        eff_url = self._current_playlist_url()
        if reason:
            log.debug(f"{self.client_info} >> Reloading Playlist [{reason}]: url={eff_url}")

        res = self._fetch_playlist(eff_url)
        try:
            try:
                playlist = parse_m3u8(res, parser=self.stream.__parser__)
            except ValueError as err:
                raise StreamError(err) from err
        finally:
            with contextlib.suppress(Exception):
                res.close()

        if playlist.is_master:
            variant_url = self._select_variant_best(playlist)
            if not variant_url:
                raise StreamError("Failed to select a media variant from master playlist")

            prev_override = self._playlist_url_override
            self._playlist_url_override = variant_url
            log.debug(f"{self.client_info} Master detected: switching to media playlist -> {variant_url}")

            res2 = self._fetch_playlist(variant_url)
            try:
                try:
                    playlist = parse_m3u8(res2, parser=self.stream.__parser__)
                except ValueError as err:
                    # rollback override on parse failure
                    self._playlist_url_override = prev_override
                    raise StreamError(err) from err
            finally:
                with contextlib.suppress(Exception):
                    res2.close()

        if playlist.is_master:
            raise StreamError("Unexpected master after variant selection")

        if playlist.iframes_only:
            raise StreamError("Streams containing I-frames only are not playable")

        vod_like = (playlist.playlist_type == "VOD" or playlist.is_endlist)

        # Initialize/refresh local VOD mode state when a VOD playlist is loaded
        if vod_like:
            anchor_url = self._playlist_url_anchor
            if self._vod_scheme is None:
                self._vod_scheme = self._vod_detect_scheme(anchor_url)
            self._vod_local_active = True
            self._vod_segments_all = playlist.segments or []
            self._vod_last_end_unix = self._vod_compute_end_unix(playlist)
            # Empty window counting (for protection)
            if self._vod_local_active:
                if not self._vod_segments_all:
                    self._vod_empty_window_count += 1
                else:
                    self._vod_empty_window_count = 0
            # Use larger initial burst only on the very first window.
            # While processing subsequent windows (reason == "vod-advance"), use a separate, smaller burst.
            try:
                burst_init = int(self.vod_start or 0)
                burst_proc = int(self.vod_process or 0)
                self._vod_initial_burst_remaining = max(0, burst_proc if reason == "vod-advance" else burst_init)
            except Exception:
                self._vod_initial_burst_remaining = max(0, int(self.vod_start or 0))
            # Align sequence and local position correctly for the new window:
            # - do NOT reset to the first segment if we have already advanced further
            # - set the local pointer to the first seg with num >= current playlist_sequence
            if self._vod_segments_all:
                try:
                    first_num = self._vod_segments_all[0].num
                except Exception:
                    first_num = None
                # If current sequence is behind the new window, clamp it to the window start
                if first_num is not None and self.playlist_sequence < first_num:
                    self.playlist_sequence = first_num
                # Position local pointer to the first segment not yet enqueued
                try:
                    self._vod_local_pos = next(
                        (i for i, s in enumerate(self._vod_segments_all) if s.num >= self.playlist_sequence),
                        len(self._vod_segments_all)
                    )
                except Exception:
                    self._vod_local_pos = 0
            else:
                self._vod_local_pos = 0

            # Final VOD log with totals and the number of segments that will be enqueued (excluding already played)
            try:
                segcount = len(self._vod_segments_all)
                remaining = max(0, segcount - int(self._vod_local_pos or 0))
                lastnum = None
                try:
                    if self._vod_segments_all:
                        lastnum = self._vod_segments_all[-1].num
                except Exception:
                    lastnum = None
                suffix_reason = (f" [{reason}]" if reason else "")
                if lastnum is not None:
                    log.debug(
                        f"{self.client_info} << Playlist Reloaded{suffix_reason}: "
                        f"type={playlist.playlist_type} scheme={self._vod_scheme} "
                        f"segments={segcount} enqueue={remaining} last={lastnum}"
                    )
                else:
                    log.debug(
                        f"{self.client_info} << Playlist Reloaded{suffix_reason}: "
                        f"type={playlist.playlist_type} scheme={self._vod_scheme} "
                        f"segments={segcount} enqueue={remaining}"
                    )

                # --- Advance handling for local VOD windows ---
                # If after advancing there are no forward segments (numbering restarted), restart from the window head.
                # Close only if the new window is truly empty.
                if reason == "vod-advance":
                    # Optional: free MAP cache between Local VOD windows to avoid keeping old init blocks
                    try:
                        w = getattr(self.reader, "writer", None)
                        if w and hasattr(w, "map_cache") and w.map_cache:
                            w.map_cache.clear()
                    except Exception:
                        pass
                    if segcount == 0:
                        log.warning(f"{self.client_info} VOD local: empty window after advance, closing stream.")
                        # Deactivate local VOD mode and close worker (will propagate up)
                        self._vod_local_active = False
                        # Mark logical end so upstream logic won't loop further
                        try:
                            self.playlist_end = self.playlist_sequence
                        except Exception:
                            pass
                        # Fast abort writer
                        try:
                            w = getattr(self.reader, "writer", None)
                            if w and hasattr(w, "fast_abort"):
                                w.fast_abort()
                        except Exception:
                            pass
                        # Close worker
                        self.close()
                        return
                    if remaining < 1:
                        # No segments with num >= current sequence -> numbering reset
                        try:
                            first_num_local = self._vod_segments_all[0].num
                        except Exception:
                            first_num_local = 1
                        self.playlist_sequence = int(first_num_local or 1)
                        self._vod_local_pos = 0
                        log.info(
                            f"{self.client_info} VOD local: numbering reset/no forward segments after advance; "
                            f"restart from beginning (seq={self.playlist_sequence})."
                        )
            except Exception:
                pass

        self.playlist_targetduration = playlist.targetduration or 0
        self.playlist_reload_time = self._playlist_reload_time(playlist)

        if playlist.segments:
            self.process_segments(playlist)

    def _select_variant_best(self, multivariant: M3U8[HLSSegment, HLSPlaylist]) -> str | None:
        try:
            playlists = getattr(multivariant, "playlists", []) or []
        except Exception:
            playlists = []
        if not playlists:
            return None

        best_url = None
        best_bw = -1
        first_non_iframe = None
        for pl in playlists:
            if getattr(pl, "is_iframe", False):
                continue
            if first_non_iframe is None:
                first_non_iframe = pl.uri
            bw = 0
            si = getattr(pl, "stream_info", None)
            if si is not None and getattr(si, "bandwidth", None):
                try: bw = int(si.bandwidth)
                except Exception: bw = 0
            if bw > best_bw:
                best_bw = bw
                best_url = pl.uri
        return best_url or first_non_iframe

    def _reset_reload_state(self) -> None:
        self._reload_prev_last_num = None
        self._smart_base = None
        self._smart_changed = None

    # --- Adaptive wait: update EMA of (download_time / duration) ---
    def update_fetch_ratio(self, ratio: float):
        try:
            if ratio <= 0:
                return
            if self._fetch_ratio_ema is None:
                self._fetch_ratio_ema = ratio
            else:
                a = self._fetch_ratio_alpha
                self._fetch_ratio_ema = (1 - a) * self._fetch_ratio_ema + a * ratio

            # Slow series detector (ratio compares download_time / duration)
            if ratio > self._vod_slow_series_threshold_ratio:
                self._vod_slow_series_count += 1
                if (
                    self._vod_slow_series_count >= self._vod_slow_series_trigger_n
                    and self._vod_steady_mode_segments_left <= 0
                ):
                    # Enter steady mode for N upcoming segments
                    self._vod_steady_mode_segments_left = self._vod_steady_mode_span
            else:
                self._vod_slow_series_count = 0
        except Exception:
            pass

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

        # Smart mode (buffer-based planning baseline)
        if self.playlist_reload_time_override == "smart":
            last = playlist.segments[-1] if playlist.segments else None
            if last is None or last.duration is None:
                self._reset_reload_state()
            else:
                seg_dur = float(last.duration)
                base = max(self.MIN_RELOAD_FLOOR, seg_dur)
                last_num = last.num
                # Detect if playlist tail changed (used for diagnostics/histogram only)
                changed = False
                if last_num is not None:
                    changed = (self._reload_prev_last_num is None) or (last_num != self._reload_prev_last_num)
                    self._reload_prev_last_num = last_num

                # Baseline = segment duration (no step3 streak/unchanged logic)
                self._smart_base = base
                self._smart_changed = changed
                self.playlist_reload_type = "smart"
                return float(base)

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

    def valid_segment(self, segment: HLSSegment) -> bool:
        return segment.num >= self.playlist_sequence

    def _segment_queue_timing_threshold_reached(self) -> bool:
        if self.segment_queue_timing_threshold_factor <= 0:
            return False

        target_td = 0
        segment_td = 0
        if (self.playlist_targetduration and self.playlist_targetduration > 0):
            target_td = self.playlist_targetduration
        if self.playlist_segments:
            # Prefer the average duration of the last three segments if available,
            # otherwise fall back to the last segment's duration.
            try:
                segs_tail = self.playlist_segments[-3:]
                durations = [float(getattr(s, "duration", 0) or 0) for s in segs_tail]
                if len(segs_tail) == 3 and all(d > 0 for d in durations):
                    segment_td = (durations[0] + durations[1] + durations[2]) / 3.0
            except Exception:
                pass
            if not segment_td:
                try:
                    dval = self.playlist_segments[-1].duration
                    if dval and dval > 0:
                        segment_td = float(dval)
                except Exception:
                    pass

        duration_max = max(self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN, target_td, segment_td)
        threshold = duration_max * self.segment_queue_timing_threshold_factor
        if now() <= self.playlist_sequence_last + timedelta(seconds=threshold):
            return False

        log.warning(f"{self.client_info} => No new segments in playlist for more than {threshold:.2f}s. Stopping...")
        return True

    def _segment_queue_threshold_seconds(self) -> float:
        """
        Compute the same timing threshold (seconds) as in _segment_queue_timing_threshold_reached(),
        without performing the boolean check or logging.
        """
        try:
            factor = float(self.segment_queue_timing_threshold_factor or 0.0)
        except Exception:
            factor = 0.0
        if factor <= 0.0:
            return 0.0

        target_td = float(self.playlist_targetduration or 0.0)
        segment_td = 0.0
        if self.playlist_segments:
            try:
                segs_tail = self.playlist_segments[-3:]
                durations = [float(getattr(s, "duration", 0) or 0) for s in segs_tail]
                if len(segs_tail) == 3 and all(d > 0 for d in durations):
                    segment_td = (durations[0] + durations[1] + durations[2]) / 3.0
            except Exception:
                segment_td = 0.0
            if not segment_td:
                try:
                    dval = self.playlist_segments[-1].duration
                    if dval and dval > 0:
                        segment_td = float(dval)
                except Exception:
                    segment_td = 0.0

        duration_max = max(self.SEGMENT_QUEUE_TIMING_THRESHOLD_MIN, target_td, segment_td)
        return float(duration_max) * factor

    def _abort_writer_and_close(self, reason: str | None = None) -> None:
        """Abort writer immediately, propagate an error to the reader, and close this worker.
        This is used on Smart/VOD threshold to wake the upstream reader ASAP, instead of waiting for read timeouts.
        """
        # 1) Abort writer (cancel futures and stop downloading)
        try:
            w = getattr(self.reader, "writer", None)
            if w and hasattr(w, "fast_abort"):
                w.fast_abort()
        except Exception:
            pass

        # 2) Propagate an exception via RingBuffer to wake the consumer quickly
        try:
            buf = getattr(self.reader, "buffer", None)
            if buf is not None:
                # Prefer signaling a meaningful exception to the reader
                try:
                    if hasattr(buf, "set_exception"):
                        if reason:
                            err_reason = reason
                        else:
                            err_reason = "Aborting stream immediately"
                        buf.set_exception(StreamError(err_reason))
                    else:
                        # Fallback: close the buffer to unblock readers (will return EOF)
                        if hasattr(buf, "close"):
                            buf.close()
                except Exception:
                    # Fall back silently if buffer signaling fails
                    pass
        except Exception:
            pass

        # 3) Close this worker (thread) itself
        self.close()

    # Aggressive cleanup on worker close
    def close(self):
        try:
            super().close()
        finally:
            # Clear large containers to break reference chains
            try:
                self.playlist_segments.clear()
            except Exception:
                pass
            try:
                self._vod_segments_all.clear()
            except Exception:
                pass
            try:
                self._recent_seg_durations.clear()
            except Exception:
                pass
            try:
                self._vod_recent_durations.clear()
            except Exception:
                pass
            try:
                with self._inflight_lock:
                    self._inflight_segments.clear()
                    self._inflight_fetch_started_mono.clear()
            except Exception:
                pass
            # Drop a few potentially long-lived refs
            try:
                self._playlist_url_override = None
                self._vod_scheme = None
            except Exception:
                pass
            try:
                gc.collect()
            except Exception:
                pass

    def _on_segment_enqueued(self, segment: HLSSegment) -> None:
        """Record enqueue time and expected duration for smart/local-VOD timeout checks."""
        try:
            dur = float(getattr(segment, "duration", 0.0) or 0.0)
            if dur <= 0:
                return
            with self._inflight_lock:
                self._inflight_segments[int(segment.num)] = (now(), dur)
        except Exception:
            pass

    def _on_segment_fetch_start(self, num: int, t0_mono: float | None = None) -> None:
        """Mark the moment the HTTP request is started (monotonic) for accurate elapsed timing."""
        try:
            # If writer didn't pass a value (shouldn't happen), fall back to local monotonic
            if t0_mono is None:
                try:
                    t0_mono = monotonic()
                except Exception:
                    t0_mono = None
            with self._inflight_lock:
                if t0_mono is not None:
                    self._inflight_fetch_started_mono[int(num)] = float(t0_mono)
        except Exception:
            pass

    def _on_segment_complete(self, num: int) -> None:
        """Forget a segment once it has completed."""
        try:
            with self._inflight_lock:
                self._inflight_segments.pop(int(num), None)
                self._inflight_fetch_started_mono.pop(int(num), None)
        except Exception:
            pass

    def _inflight_count(self) -> int:
        """
        Count currently in-flight or queued (not yet completed) segments.
        Uses the internal in-flight tracker (segments enqueued and not yet marked complete).
        This is used to suppress aggressive (growth) reload planning when we already have
        enough segments queued to cover the live edge.
        """
        try:
            with self._inflight_lock:
                return len(self._inflight_segments)
        except Exception:
            return 0

    def _smart_threshold_reached(self) -> bool:
        """
        Smart/Local-VOD threshold:
        If any enqueued segment has been in-flight longer than its duration (based on enqueue time)
        AND the current buffer has dropped below zero, stop early without waiting for the download to finish.
        ---
        Secondary rule:
        If the playable buffer has EVER been positive during this session and now dropped below
        the length of the last segment (by absolute value), stop immediately as well.
        Example: buf = -5.01s and last_seg = 5.00s -> stop.
        Tertiary rule:
        If the buffer remains negative continuously for more than _buf_negative_long_threshold_s,
        and this happens _buf_negative_long_max times, stop.
        """
        try:
            now_ts = now()
            # Snapshot current buffer and remember if it was ever positive
            try:
                buf_now = float(self._buffer_seconds_signed())
            except Exception:
                buf_now = 0.0
            if buf_now > 0.0:
                self._buf_was_positive = True

            # Track continuous negative interval start/stop
            if buf_now < 0.0:
                try:
                    if self._buf_negative_since is None:
                        self._buf_negative_since = now_ts
                except Exception:
                    self._buf_negative_since = now_ts
            else:
                # Buffer became non-negative: reset only the continuous negative interval timer.
                # DO NOT reset the sliding window of negative events (requirement: positives inside the window do not clear count).
                self._buf_negative_since = None
                self._buf_prev_negative = False

            # 1. Check for timed out segments (stuck downloads)
            timed_out: list[tuple[int, float, float]] = []
            with self._inflight_lock:
                for num, (t_enq, dur) in list(self._inflight_segments.items()):
                    if dur and dur > 0:
                        # Prefer elapsed since fetch-start (monotonic), exactly same base as writer's completion time.
                        t0m = self._inflight_fetch_started_mono.get(int(num))
                        if t0m is not None:
                            try:
                                elapsed = monotonic() - float(t0m)
                            except Exception:
                                elapsed = (now_ts - t_enq).total_seconds()
                        else:
                            # Fallback to wall clock if monotonic is unknown (edge case)
                            elapsed = (now_ts - t_enq).total_seconds()
                        if elapsed > dur:
                            timed_out.append((num, dur, elapsed))
            if timed_out:
                # Log the first offender (and count of others, if any)
                num, dur, elapsed = timed_out[0]
                if buf_now < 0.0:
                    log.warning(
                        f"{self.client_info} => Segment {num} exceeded its duration while downloading: "
                        f"elapsed={elapsed:.2f}s > dur={dur:.2f}s; buf={buf_now:.1f}s (<0). Stopping..."
                    )
                    return True
                else:
                    log.debug(
                        f"{self.client_info} => Segment {num} exceeded duration but buffer still positive: "
                        f"elapsed={elapsed:.2f}s > dur={dur:.2f}s; buf={buf_now:.1f}s. Continue..."
                    )

            # 2. Secondary threshold block (Negative events / GAP window)
            if self._buf_was_positive and buf_now < 0.0:
                # Ignore minor drops if there are segments in the queue.
                # If the buffer deficit is small (> -1.5 sec) and there are active downloads, we don't consider this a failure.
                try:
                    if self._inflight_count() > 0 and buf_now > -1.5:
                        log.debug(f"{self.client_info} => Ignore Negative buffer event: buf={buf_now:.2f}s > -1.5s")
                        return False
                except Exception:
                    pass

                # GAP condition (fixed window semantics):
                # - If within the active window the number of negative transitions reaches the max -> stop.
                window_limit_s = self._buf_negative_long_threshold_s
                max_events = self._buf_negative_long_max

                # If we are entering negative state this cycle
                if not self._buf_prev_negative:
                    now_sec = now_ts
                    # Check if current window expired
                    if (
                        self._buf_negative_window_start is not None and
                        (now_sec - self._buf_negative_window_start).total_seconds() >= window_limit_s
                    ):
                        # Window expired without hitting threshold -> reset counter/events
                        if len(self._buf_negative_events) < max_events:
                            log.debug(
                                f"{self.client_info} => Negative buffer window expired "
                                f"({window_limit_s:.0f}s) without threshold; counter reset."
                            )
                        self._buf_negative_events.clear()
                        self._buf_negative_window_start = None

                    # Start a new window if none is active
                    if self._buf_negative_window_start is None:
                        self._buf_negative_window_start = now_sec

                    # Record this negative entry event
                    self._buf_negative_events.append(now_sec)
                    events_count = len(self._buf_negative_events)
                    log.debug(
                        f"{self.client_info} => Negative buffer event #{events_count} "
                        f"in current {window_limit_s:.0f}s window (buf={buf_now:.2f}s)"
                    )
                    if events_count >= max_events:
                        # Threshold reached -> stop (no need to manually clear; stream teardown will reset state)
                        log.warning(
                            f"{self.client_info} => Buffer entered negative state "
                            f"{events_count} times within {window_limit_s:.0f}s window. Stopping..."
                        )
                        return True

                # Mark that we are currently negative (prevents double counting until we go non-negative again)
                self._buf_prev_negative = True

                # Original deficit check preserved (stop if deficit exceeds last segment length)
                last_seg_len = self._last_segment_duration_estimate()
                if last_seg_len and last_seg_len > 0.0 and (-buf_now) > float(last_seg_len):
                    log.warning(
                        f"{self.client_info} => Buffer deficit exceeded last segment length: "
                        f"|buf_deficit|={-buf_now:.2f}s > last_seg={last_seg_len:.2f}s. Stopping..."
                    )
                    return True

            # 3. Tertiary threshold: buffer stayed negative longer than the "queue timing" threshold
            # Uses the exact same time window as _segment_queue_timing_threshold_reached().
            try:
                neg_since = self._buf_negative_since
                thr = self._segment_queue_threshold_seconds()
            except Exception:
                neg_since = None
                thr = 0.0
            if neg_since is not None and thr > 0.0:
                neg_elapsed = (now_ts - neg_since).total_seconds()
                if neg_elapsed > thr:
                    log.warning(f"{self.client_info} => Buffer stayed negative for more than {thr:.2f}s. Stopping...")
                    return True
        except Exception:
            # On any error, do not trigger stop by default
            return False
        return False

    def _last_segment_duration_estimate(self) -> float:
        """
        Best-effort estimate of the last segment's duration for threshold checks.
        Priority:
          1) tail of current playlist_segments
          2) last of recent segment durations (_recent_seg_durations)
          3) smart base (_smart_base)
          4) playlist targetduration
          5) MIN_RELOAD_FLOOR
        """
        try:
            if self.playlist_segments:
                d = getattr(self.playlist_segments[-1], "duration", None)
                if d and d > 0:
                    return float(d)
        except Exception:
            pass
        try:
            if self._recent_seg_durations:
                d = self._recent_seg_durations[-1]
                if d and d > 0:
                    return float(d)
        except Exception:
            pass
        try:
            if self._smart_base and self._smart_base > 0:
                return float(self._smart_base)
        except Exception:
            pass
        try:
            td = float(self.playlist_targetduration or 0.0)
            if td > 0:
                return td
        except Exception:
            pass
        return float(self.MIN_RELOAD_FLOOR)

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
        self.playlist_sequence_last = now()

        try:
            self.reload_playlist()
        except StreamError as err:
            log.error(f"{self.client_info}: {err}")
            if self.reader:
                self.reader.close()
            return

        self.playlist_reload_last = now()

        if self.playlist_end is None:
            if self.duration_offset_start > 0:
                log.debug(f"{self.client_info}: Time offsets negative for live streams, skipping back {self.duration_offset_start} seconds")
            # live playlist, force offset durations back to None
            self.duration_offset_start = -self.duration_offset_start

        if self.duration_offset_start != 0:
            self.playlist_sequence = self.duration_to_sequence(self.duration_offset_start, self.playlist_segments)

        # if VOD-local is active, move the pointer to the desired segment
        if self._vod_local_active and self._vod_segments_all:
            try:
                idx = next((i for i, s in enumerate(self._vod_segments_all) if s.num >= self.playlist_sequence), 0)
                self._vod_local_pos = idx
            except Exception:
                pass

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
                    f"Start Sequence: {self.playlist_sequence}",
                    f"End Sequence: {self.playlist_end}",
                ]),
            )

        while not self.closed:
            # Empty window protection check
            if (
                self._vod_local_active
                and self._vod_empty_window_count > self._vod_empty_window_limit
            ):
                log.warning(
                    f"{self.client_info} VOD local: exceeded empty window limit "
                    f"({self._vod_empty_window_count}>{self._vod_empty_window_limit}), stopping."
                )
                return

            queued = False

            # --- For local VOD mode, override playlist_segments to a batch (start: vod_start, then vod_queue_step) ---
            if self._vod_local_active:
                remaining = len(self._vod_segments_all) - self._vod_local_pos
                if remaining > 0:
                    # how many segments to submit now
                    batch_size = self._vod_initial_burst_remaining if self._vod_initial_burst_remaining > 0 else max(1, int(self.vod_queue_step or 1))
                    batch_size = min(batch_size, remaining)
                    # we will serve in a pack (without waiting inside the pack)
                    self.playlist_segments = self._vod_segments_all[self._vod_local_pos:self._vod_local_pos + batch_size]
                else:
                    # the window is over - immediately build a new URL and reload the playlist
                    start_unix = int(self._vod_last_end_unix or int(time.time()))
                    now_unix = int(time.time())
                    new_url = self._vod_build_next_url(start_unix, now_unix)
                    if not new_url:
                        # Plain VOD without catchup parameters: finish playback gracefully
                        log.debug(f"{self.client_info} VOD local: no catchup attributes on URL, finishing")
                        return
                    if new_url != self._playlist_url_override:
                        log.debug(f"{self.client_info} VOD local: advancing window url -> {new_url}")
                        self._playlist_url_override = new_url
                        # anchor: we update it so that subsequent end-time calculations will start from the new reference
                        self._playlist_url_anchor = new_url
                    try:
                        # Do not wait for buffer to free when advancing VOD window
                        self.reload_playlist(wait_buffer=False, reason="vod-advance")
                    except StreamError as err:
                        log.warning(f"{self.client_info} Failed to reload next VOD window: {err}")
                        return
                    continue

            batch_last_wait = 0.0  # wait by duration of the last segment in batch

            for segment in self.playlist_segments:
                if not self.valid_segment(segment):
                    continue

                    # --- Local VOD: soft throttle on active futures when buffer large ---
                    if self._vod_local_active:
                        try:
                            # Compute current robust mean & cap (best effort / lightweight)
                            cap = None
                            buf_ahead_tmp = None
                            writer_ref = getattr(self.reader, "writer", None)
                            if writer_ref:
                                # active futures count
                                futures_attr = getattr(writer_ref, "_futures", None)
                            else:
                                futures_attr = None

                            # Quick buffer ahead estimate (do not fail if missing)
                            try:
                                wall_e = (now() - self._play_start_ts).total_seconds()
                                delivered_e = float(getattr(self, "_play_delivered_s", 0.0))
                                buf_ahead_tmp = max(0.0, delivered_e - wall_e)
                            except Exception:
                                buf_ahead_tmp = None

                            # Lightweight robust_cap (reuse recent durations list)
                            if self._vod_recent_durations:
                                rds = self._vod_recent_durations[-self._vod_recent_durations_window:]
                                if len(rds) >= 3:
                                    r_sorted = sorted(rds)
                                    mid = r_sorted[len(r_sorted)//2]
                                    # p95 index
                                    p95_idx = int(round(0.95 * (len(r_sorted)-1)))
                                    p95_val = r_sorted[p95_idx]
                                    robust_mean = 0.5 * mid + 0.5 * p95_val
                                    cap = robust_mean * self.vod_buffer_mult

                            if (
                                buf_ahead_tmp is not None and cap is not None
                                and buf_ahead_tmp > cap * 0.80
                                and futures_attr and isinstance(futures_attr, list)
                            ):
                                active_fetch = sum(1 for f in futures_attr if f and not f.done())
                                soft_limit = max(1, int(getattr(writer_ref, "threads", 0) * self._vod_active_fetch_soft_limit_factor))
                                while active_fetch >= soft_limit:
                                    time.sleep(self._vod_active_fetch_soft_sleep)
                                    active_fetch = sum(1 for f in futures_attr if f and not f.done())
                        except Exception:
                            pass

                log.debug(f"{self.client_info} - Adding segment {segment.num} to queue")

                # Update duration/logical time stats before changing self.playlist_sequence so that drift only counts playable segments
                durf = None
                try:
                    if segment.duration and segment.duration > 0:
                        durf = float(segment.duration)
                        self._play_logical_s += durf
                        self._recent_seg_durations.append(durf)
                        if len(self._recent_seg_durations) > self.buffer_avg_window:
                            self._recent_seg_durations.pop(0)
                except Exception:
                    pass

                offset = segment.num - self.playlist_sequence
                if offset > 0:
                    if offset >= self.large_jump_threshold:
                        # Large forward jump detected: reset smart timing statistics to avoid drift distortion
                        try:
                            skipped_range = (f"{self.playlist_sequence}-{segment.num - 1}"
                                             if offset > 1 else f"{self.playlist_sequence}")
                            log.warning(
                                f"{self.client_info} LARGE JUMP: skipped {offset} segments ({skipped_range}). "
                                f"Resetting smart timing statistics (possible provider gap)."
                            )
                        except Exception:
                            log.warning(
                                f"{self.client_info} LARGE JUMP: skipped {offset} segments. "
                                f"Resetting smart timing statistics (possible provider gap)."
                            )
                        # Reset adaptive timing / drift related state
                        try:
                            self._recent_seg_durations.clear()
                        except Exception:
                            pass
                        self._play_start_ts = now()
                        self._play_logical_s = 0.0
                        # Reset last wait ratio
                        self._last_wait_ratio = None
                        # Also fully reset smart reload streak/base state for consistency
                        try:
                            self._reset_reload_state()
                        except Exception:
                            pass
                    else:
                        # Single short skip: downgrade to debug (less noise), multi-skip still warning
                        if offset == 1:
                            log.debug(
                                f"{self.client_info} Skipped segment {self.playlist_sequence} after playlist reload "
                                "(offset=1). Output may have a minor discontinuity."
                            )
                        else:
                            log.warning(
                                f"{self.client_info} Skipped segments {self.playlist_sequence}-{segment.num - 1} "
                                f"after playlist reload ({offset} lost). This is unsupported and may cause incoherent output."
                            )

                # Mark enqueue moment for smart/local-VOD threshold logic before yielding
                try:
                    self._on_segment_enqueued(segment)
                except Exception:
                    pass
                yield segment
                queued = True

                if self.closed:  # pragma: no cover
                    return

                self.playlist_sequence = segment.num + 1

                # advance local pointer and collect wait time for batch
                if self._vod_local_active:
                    self._vod_local_pos += 1
                    try:
                        batch_last_wait = float(segment.duration or self.MIN_RELOAD_FLOOR)
                    except Exception:
                        batch_last_wait = float(self.MIN_RELOAD_FLOOR)
                    if self._vod_initial_burst_remaining > 0:
                        self._vod_initial_burst_remaining -= 1

            # After processing a batch of segments (if something was set), we wait for the EXTINF amount
            if self._vod_local_active and queued:
                # if there are still segments of the current window ahead, we wait
                if self._vod_segments_all and self._vod_local_pos < len(self._vod_segments_all):
                    if self._vod_adjust_wait:
                        # ---------------- Adaptive Wait (robust buffer-based) ----------------
                        raw_wait = float(batch_last_wait)
                        ratio = self._fetch_ratio_ema
                        throttle_extra = 0.0

                        # Pre-grace for imminent completions (Local VOD):
                        # If we just enqueued segments (queued == True) OR there are in-flight fetches OR a completion signal is set,
                        # briefly wait so that just-finished segments get accounted into delivered buffer before we compute buf/fill.
                        try:
                            writer_ref = getattr(self.reader, "writer", None)
                            ev = getattr(writer_ref, "_seg_complete_event", None) if writer_ref else None
                            in_flight = False
                            active_count = 0
                            try:
                                futs = getattr(writer_ref, "_futures", None) if writer_ref else None
                                if futs and isinstance(futs, list):
                                    active_count = sum(1 for f in futs if f is not None and not f.done())
                                    in_flight = active_count > 0
                            except Exception:
                                in_flight = False

                            should_pregrace = bool(queued) or (ev is not None and (in_flight or ev.is_set()))
                            if should_pregrace:
                                grace_cap = max(0.0, float(getattr(self, "plan_completion_grace_max", 1.0)))
                                base = min(1.0, grace_cap)
                                try:
                                    ema = float(getattr(self, "_fetch_ratio_ema", 0.0) or 0.0)
                                except Exception:
                                    ema = 0.0
                                seg_len_vod = max(self.MIN_RELOAD_FLOOR, float(raw_wait or self.MIN_RELOAD_FLOOR))
                                est_finish = (ema * seg_len_vod) if ema > 0.0 else 0.0
                                pre_grace = min(grace_cap, max(base, est_finish))
                                if pre_grace > 0.0:
                                    if ev is not None:
                                        with contextlib.suppress(Exception):
                                            ev.clear()
                                            ev.wait(pre_grace)
                                            ev.clear()
                                    else:
                                        time.sleep(pre_grace)
                        except Exception:
                            pass

                        # Robust mean (median + p95)
                        robust_mean = None
                        try:
                            dur_list = self._vod_recent_durations[-self._vod_recent_durations_window:]
                            if len(dur_list) >= 3:
                                sdur = sorted(dur_list)
                                median_v = sdur[len(sdur)//2]
                                p95_v = sdur[int(round(0.95 * (len(sdur)-1)))]
                                robust_mean = 0.5 * median_v + 0.5 * p95_v
                        except Exception:
                            robust_mean = None

                        # Effective raw (limit very large outlier durations)
                        raw_eff = raw_wait
                        if robust_mean and robust_mean > 0 and raw_wait > robust_mean * 1.8:
                            raw_eff = robust_mean * 1.5

                        # Buffer ahead (delivered playback vs wall)
                        try:
                            wall_e = (now() - self._play_start_ts).total_seconds()
                            delivered_e = float(getattr(self, "_play_delivered_s", 0.0))
                            buf_ahead = delivered_e - wall_e
                            if buf_ahead < 0:
                                buf_ahead = 0.0
                        except Exception:
                            buf_ahead = 0.0

                        # Cap using robust mean if present else fallback to recent mean of step3 durations
                        # cap_base ~ «average» segment duration; cap = cap_base * vod_buffer_mult
                        # Upper limit = cap + cap_base (we allow «+1 segment» as a reserve).
                        # If it is exceeded, we slow down the feed (but not more than seg_len/4).
                        # This allowance will help the buffer approach the lower limit (cap).
                        if robust_mean and robust_mean > 0:
                            cap_base = robust_mean
                        else:
                            # fallback simple mean of last N (original logic)
                            recent = [d for d in self._recent_seg_durations[-self.buffer_avg_window:] if d and d > 0]
                            cap_base = sum(recent)/len(recent) if len(recent) >= 3 else raw_eff

                        cap = max(0.001, cap_base * self.vod_buffer_mult)
                        cap_upper = cap + cap_base

                        # Throttle state: start if above upper boundary, stop only after reaching lower boundary (cap + eps)
                        if buf_ahead > cap_upper:
                            self._vod_cap_throttle_active = True
                        elif self._vod_cap_throttle_active and buf_ahead <= cap + self._vod_cap_lower_eps:
                            self._vod_cap_throttle_active = False

                        if self._vod_cap_throttle_active:
                            # Aim to lower boundary: drain down to cap (not just to cap_upper)
                            overflow_to_lower = max(0.0, buf_ahead - cap)
                            throttle_extra = min(raw_eff / 4.0, overflow_to_lower)

                        # Real fill may exceed 1.0
                        fill_ratio = (buf_ahead / cap) if cap > 0 else 0.0
                        # For EMA keep clamped [0..1]
                        fill_raw = max(0.0, min(1.0, fill_ratio))

                        # EMA of fill for smoothing
                        if self._vod_fill_ema is None:
                            self._vod_fill_ema = fill_raw
                        else:
                            self._vod_fill_ema = (1 - self._vod_fill_alpha) * self._vod_fill_ema + self._vod_fill_alpha * fill_raw
                        fill = self._vod_fill_ema

                        # ---------------- Local VOD pacing aligned with Live smart ----------------
                        # Baseline segment length for pacing
                        seg_len_vod = max(self.MIN_RELOAD_FLOOR, float(raw_eff))
                        band = float(cap_base)

                        # Mode classification (same as Live smart)
                        is_startup = (self._vod_fill_ema is None)
                        if (buf_ahead > cap + band) and (not is_startup):
                            mode = "slow"
                        elif ((buf_ahead < seg_len_vod) or (buf_ahead < max(0.0, cap - band))) and (not is_startup):
                            mode = "growth"
                        else:
                            mode = "normal"

                        # Plan next wait exactly like Live smart
                        if mode == "growth":
                            fill_g = max(0.0, min(1.0, float(buf_ahead / cap) if cap > 0 else 0.0))
                            wait_s = max(self.MIN_RELOAD_FLOOR, seg_len_vod * fill_g)
                        elif mode == "slow":
                            fill_r = float(buf_ahead / cap) if cap > 0 else 1.0
                            wait_s = seg_len_vod * max(1.0, float(fill_r))
                            if cap and cap > 0:
                                wait_s = min(wait_s, float(cap))
                            wait_s = max(self.MIN_RELOAD_FLOOR, wait_s)
                        else:
                            wait_s = seg_len_vod

                        # Optional steady mode (keep stable pacing for N segments)
                        if self._vod_steady_mode_segments_left > 0:
                            wait_s = min(seg_len_vod, band)
                            self._vod_steady_mode_segments_left -= 1

                        buffer_cap_applied = (fill >= 0.99)  # purely for logging highlight

                        self._vod_next_wait = wait_s

                        # Simplified adaptive log
                        try:
                            buf_play = float(getattr(self, "_buffer_playable_s", 0.0))
                            if buf_play < 0:
                                buf_play = 0.0
                            lost_gap = max(0.0, buf_ahead - buf_play)
                            # Throttle relative to baseline seg_len (show both positive and negative)
                            throttle_s = float(wait_s - seg_len_vod)
                            throttle_part = f" thr={throttle_s:+.2f}s"
                            log.debug(
                                f"{self.client_info} << Local VOD: next enqueue adaptive in {wait_s:.2f}s "
                                f"(seg={seg_len_vod:.2f}s buf={buf_ahead:.1f}s/{cap:.1f}s){throttle_part} "
                                f"fill={fill_ratio:.2f} mode={mode})"
                            )
                        except Exception:
                            pass
                    else:
                        self._vod_next_wait = max(self.MIN_RELOAD_FLOOR, batch_last_wait)
                else:
                    # we reached the end of the window in a bunch: don't wait - at the next iteration we'll immediately move on to a new playlist
                    self._vod_next_wait = 0.0

            # End-of-stream condition is ignored for local VOD mode
            if not self._vod_local_active and (self.closed or self.playlist_end is not None and (not queued or self.playlist_sequence > self.playlist_end)):
                return

            # Local VOD timing: wait by segment duration (do NOT reload playlist between segments)
            if self._vod_local_active:
                # If we just put the last segment, immediately advance (handled at top of loop), so only wait if more segments left
                if self._vod_segments_all and self._vod_local_pos < len(self._vod_segments_all):
                    wait_s = max(0.0, float(self._vod_next_wait or self.MIN_RELOAD_FLOOR))
                    self.playlist_reload_type = "vod-local"
                    # Early-exit check for smart/local-VOD timeout while waiting between enqueues
                    try:
                        if self._smart_threshold_reached():
                            log.debug(f"{self.client_info} => Local VOD: smart threshold reached, aborting writer and worker")
                            self._abort_writer_and_close("Local VOD: smart threshold reached, aborting writer and worker")
                            return
                    except Exception:
                        pass
                    #log.debug(f"{self.client_info} << Local VOD: next enqueue in {wait_s:.3f}s")
                    if self.wait(wait_s):
                        self.playlist_reload_last = now()
                    # Loop again to enqueue next segment (no playlist reload)
                    continue
                else:
                    # Nothing to wait; the loop head will advance window immediately
                    continue

            if queued:
                self.playlist_sequence_last = now()
                # Evaluate smart/local-VOD timeout even when we DID enqueue segments.
                if self.playlist_reload_type == "smart" or self._vod_local_active:
                    try:
                        if self._smart_threshold_reached():
                            log.debug(f"{self.client_info} => Smart/VOD: threshold reached while enqueuing, aborting writer and worker")
                            self._abort_writer_and_close("Smart/VOD: threshold reached while enqueuing, aborting writer and worker")
                            return
                    except Exception:
                        pass
            else:
                # Choose appropriate threshold logic:
                # 1) smart and local VOD modes
                if self.playlist_reload_type == "smart" or self._vod_local_active:
                    try:
                        if self._smart_threshold_reached():
                            log.debug(f"{self.client_info} => Smart/VOD: threshold reached, aborting writer and worker")
                            self._abort_writer_and_close("Smart/VOD: threshold reached, aborting writer and worker")
                            return
                    except Exception:
                        pass
                else:
                    # 2) others modes ("segment", "targetduration", "constant")
                    if self._segment_queue_timing_threshold_reached():
                        return

            # Timed reload interval logic
            time_completed = now()
            time_elapsed = max(0.0, (time_completed - self.playlist_reload_last).total_seconds())
            time_wait = max(0.0, self.playlist_reload_time - time_elapsed)

            if self.playlist_reload_type == "smart":
                # Buffer-based planning: seg, buf/cap, fill, ratio, mode
                seg_len = float(self._smart_base or 1.0)
                # mean duration for capacity and band calculations
                try:
                    if self._recent_seg_durations:
                        recent_list = self._recent_seg_durations[-int(max(1, self.buffer_avg_window)):]
                        mean_dur = (sum(recent_list) / len(recent_list)) if recent_list else seg_len
                    else:
                        mean_dur = seg_len
                    if not mean_dur or mean_dur <= 0:
                        mean_dur = seg_len if seg_len > 0 else 1.0
                except Exception:
                    mean_dur = seg_len if seg_len > 0 else 1.0

                # buffer ahead and capacity (target buffer for live)
                try:
                    buf_now = self._buffer_seconds_signed()
                except Exception:
                    buf_now = 0.0
                if buf_now < 0:
                    buf_now_print = 0.0
                else:
                    buf_now_print = buf_now
                try:
                    cap = max(0.001, float(mean_dur) * float(self.live_buffer_mult))
                except Exception:
                    cap = float(mean_dur) * 2.0

                # Startup unconditional grace:
                # On the very first planning cycle, if we just enqueued segments (queued == True),
                # wait a short bounded time so that near-finished segments complete and get
                # accounted into the delivered buffer before we compute fill/mode.
                try:
                    is_startup = (self._last_wait_ratio is None)
                except Exception:
                    is_startup = True
                if is_startup and bool(queued):
                    try:
                        grace_cap = max(0.0, float(getattr(self, "plan_completion_grace_max", 1.0)))
                    except Exception:
                        grace_cap = 1.0
                    startup_grace = min(1.0, grace_cap)
                    if startup_grace > 0.0:
                        time.sleep(startup_grace)
                        time_completed = now()
                        time_elapsed = max(0.0, (time_completed - self.playlist_reload_last).total_seconds())
                        try: buf_now2 = self._buffer_seconds_signed()
                        except Exception: buf_now2 = 0.0
                        buf_now_print = 0.0 if buf_now2 < 0 else buf_now2

                # Pre-grace for imminent completions (apply in ALL modes and even if futures list is not visible):
                # If we just enqueued segments (queued == True) OR there are in-flight fetches OR a completion signal is set,
                # briefly wait so that just-finished segments get accounted into delivered buffer
                # before we compute fill/mode and plan the next reload.
                try:
                    writer_ref = getattr(self.reader, "writer", None)
                    ev = getattr(writer_ref, "_seg_complete_event", None) if writer_ref else None
                    in_flight = False
                    active_count = 0
                    try:
                        futs = getattr(writer_ref, "_futures", None) if writer_ref else None
                        if futs and isinstance(futs, list):
                            active_count = sum(1 for f in futs if f is not None and not f.done())
                            in_flight = active_count > 0
                    except Exception:
                        in_flight = False

                    # Always pre-grace if we just queued new segments this cycle
                    should_pregrace = bool(queued) or (ev is not None and (in_flight or ev.is_set()))
                    if should_pregrace:
                        # Pre-grace bounded wait:
                        # - base up to 1.0s, limited by plan_completion_grace_max
                        # - if we have EMA of fetch ratio, extend to estimated finish time if it's larger
                        grace_cap = max(0.0, float(getattr(self, "plan_completion_grace_max", 1.0)))
                        base = min(1.0, grace_cap)
                        try:
                            ema = float(getattr(self, "_fetch_ratio_ema", 0.0) or 0.0)
                        except Exception:
                            ema = 0.0
                        est_finish = (float(ema) * float(seg_len)) if ema > 0.0 else 0.0
                        # wait at least base, but not more than grace_cap
                        pre_grace = min(grace_cap, max(base, est_finish))

                        if pre_grace > 0.0:
                            if ev is not None:
                                # IMPORTANT: if the event is already set by the first completion,
                                # wait() would return immediately and we'd miss subsequent completions.
                                # Drain current signal first, then wait for the next completion or timeout.
                                with contextlib.suppress(Exception):
                                    # drain current signal
                                    ev.clear()
                                    # wait for next completion or timeout
                                    ev.wait(pre_grace)
                                    ev.clear()
                            else:
                                # No event available: bounded sleep
                                time.sleep(pre_grace)

                            # Recompute buffer and elapsed after the short pre-grace
                            time_completed = now()
                            time_elapsed = max(0.0, (time_completed - self.playlist_reload_last).total_seconds())
                            try:
                                buf_now2 = self._buffer_seconds_signed()
                            except Exception:
                                buf_now2 = 0.0
                            buf_now_print = 0.0 if buf_now2 < 0 else buf_now2
                except Exception:
                    pass

                # fill ratio (can be >1.0)
                try:
                    fill_ratio = (buf_now_print / cap) if cap > 0 else 0.0
                except Exception:
                    fill_ratio = 0.0

                # mode classification
                band = float(mean_dur)
                # First plan of the session -> force NORMAL (detect by missing previous planning snapshot)
                is_startup = (self._last_wait_ratio is None)
                if buf_now_print > cap + band and not is_startup:
                    mode = "slow"
                elif (buf_now_print < seg_len or buf_now_print < max(0.0, cap - band)) and not is_startup:
                    mode = "growth"
                else:
                    mode = "normal"

                # --- Growth suppression based on in-flight queue depth ---
                # Avoid switching to aggressive growth mode if we already have enough segments
                # being downloaded/queued to satisfy the desired live edge.
                # Requirement: treat minimal required depth to prevent too-frequent reloads at very low live_edge values.
                if mode == "growth":
                    try:
                        inflight = self._inflight_count()

                        # Dynamic calculation of the required number of segments.
                        required_segs = int(self.growth_target_queue_duration / max(0.5, float(mean_dur)))

                        # Always keep the minimum (default 2), even if the segments are very long
                        threshold = max(self.growth_min_seg_in_queue, required_segs)

                        if inflight >= threshold:
                            # Suppress growth mode; keep NORMAL pacing until in-flight depth drains.
                            mode = "normal"
                            log.debug(
                                f"{self.client_info} -- Smart growth suppressed: inflight={inflight} >= required={threshold} "
                                f"(target={self.growth_target_queue_duration}s / avg_seg={mean_dur:.2f}s)"
                            )
                    except Exception:
                        pass

                # Short "grace" delay to catch an imminent segment completion:
                # - only if predicted mode is growth (to avoid frequent short polls)
                # - wait up to 1s (configurable via hls-smart-plan-grace), not more
                # - only if there are in-flight fetches, or a completion already signaled
                if mode == "growth":
                    try:
                        writer_ref = getattr(self.reader, "writer", None)
                        ev = getattr(writer_ref, "_seg_complete_event", None) if writer_ref else None
                        # Check if any futures are still in-flight
                        in_flight = False
                        active_count = 0
                        try:
                            futs = getattr(writer_ref, "_futures", None) if writer_ref else None
                            if futs and isinstance(futs, list):
                                active_count = sum(1 for f in futs if f is not None and not f.done())
                                in_flight = active_count > 0
                        except Exception:
                            in_flight = False

                        # Decide if we should grace-wait
                        if ev is not None and (in_flight or ev.is_set()):
                            # Dynamic grace:
                            # - base from plan_completion_grace_max (default 1.0s)
                            # - if EMA of fetch ratio is known, estimate time to finish the next seg: ema * seg_len
                            # - clamp overall grace to [0 .. 1.5s] to avoid long stalls
                            try:
                                ema = float(getattr(self, "_fetch_ratio_ema", 0.0) or 0.0)
                            except Exception:
                                ema = 0.0
                            grace_base = max(0.0, float(getattr(self, "plan_completion_grace_max", 1.0)))
                            est_finish = ema * float(seg_len) if ema > 0.0 else 0.0
                            grace = min(1.5, max(grace_base, est_finish))
                            try:
                                log.debug(f"{self.client_info} Smart growth: grace-wait {grace:.2f}s (inflight={active_count}, ema={ema:.2f})")
                            except Exception:
                                pass
                            if ev.is_set():
                                # We already have a completion signal; consume it without waiting
                                with contextlib.suppress(Exception):
                                    ev.clear()
                            elif grace > 0.0:
                                # Wait briefly for completion signal
                                with contextlib.suppress(Exception):
                                    ev.wait(grace)
                                    ev.clear()
                            # Recompute buffer after grace period
                            try:
                                buf_now2 = self._buffer_seconds_signed()
                            except Exception:
                                buf_now2 = 0.0
                            buf_now_print = 0.0 if buf_now2 < 0 else buf_now2
                            # Recompute fill (cap unchanged)
                            try:
                                fill_ratio = (buf_now_print / cap) if cap > 0 else 0.0
                            except Exception:
                                fill_ratio = 0.0
                            # Re-evaluate mode with updated buffer snapshot
                            if buf_now_print > cap + band and not is_startup:
                                mode = "slow"
                            elif (buf_now_print < seg_len or buf_now_print < max(0.0, cap - band)) and not is_startup:
                                mode = "growth"
                            else:
                                mode = "normal"
                            # Recompute elapsed after grace (for accurate wait calculation)
                            time_completed = now()
                            time_elapsed = max(0.0, (time_completed - self.playlist_reload_last).total_seconds())
                    except Exception:
                        pass

                # Buffer-based rule:
                planned_wait = float(seg_len)
                if mode == "growth":
                    # Speeding up: poll sooner when buffer is low.
                    # planned_wait scales with current fill of the live target buffer: seg_len * (buf/cap).
                    # This yields shorter waits for lower fill, and approaches seg_len as we near the target.
                    try:
                        fill_g = (buf_now_print / cap) if cap > 0 else 0.0
                    except Exception:
                        fill_g = 0.0
                    fill_g = max(0.0, min(1.0, float(fill_g)))
                    planned_wait = max(self.MIN_RELOAD_FLOOR, float(seg_len) * fill_g)
                elif mode == "slow":
                    # We slow down proportionally to filling:
                    # fill_ratio = buf/cap -> planned_wait = seg_len * fill_ratio
                    try:
                        fill_ratio = (buf_now_print / cap) if cap > 0 else 1.0
                    except Exception:
                        fill_ratio = 1.0
                    planned_wait = seg_len * max(1.0, float(fill_ratio))
                    # Upper limit — cap
                    if cap and cap > 0:
                        planned_wait = min(planned_wait, float(cap))
                    planned_wait = max(self.MIN_RELOAD_FLOOR, planned_wait)
                # Update planned reload time and remaining wait
                self.playlist_reload_time = float(planned_wait)
                # Re-evaluate remaining wait using potentially updated time_elapsed
                time_wait = max(0.0, self.playlist_reload_time - time_elapsed)
                # Growth-mode smoothing: ensure we don't poll too frequently even if remaining
                # time becomes < 1s due to elapsed processing time between cycles.
                if mode == "growth":
                    time_wait = max(self.MIN_RELOAD_FLOOR, time_wait)

                # ratio reflects buffer fill (buf/cap), not planned_wait/seg_len
                ratio_out = float(fill_ratio) if cap and cap > 0 else 1.0
                self._last_wait_ratio = ratio_out

                # Presentation for logging
                planned_wait = float(self.playlist_reload_time)
                real_wait = float(time_wait)
                try:
                    throttle_s = planned_wait - float(seg_len)
                except Exception:
                    throttle_s = 0.0
                throttle_part = f" thr={throttle_s:+.2f}s"
                log.debug(
                    f"{self.client_info} << Planning Reload [smart] in {planned_wait:.2f}s, real={real_wait:.3f}s: "
                    f"(seg={seg_len:.2f}s buf={buf_now_print:.1f}s/{cap:.1f}s){throttle_part} "
                    f"fill={fill_ratio:.2f} mode={mode})"
                )
            else:
                log.debug(
                    "%s << Planning Reload [%s] in %.3fs",
                    self.client_info,
                    self.playlist_reload_type,
                    float(time_wait),
                )

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
                        "%s >> Reloading Playlist [smart]: base=%.3fs changed=%s planned=%.3fs | waited=%.3fs",
                        self.client_info,
                        float(self._smart_base or 0.0),
                        str(self._smart_changed),
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
        self.hls_close_silen: bool = True
        # Closing guards
        self._close_lock = threading.Lock()
        self._close_thread = None

        super().__init__(stream, name=name)
        # Install "closing threads" noise filter once per session if requested
        try:
            if self.hls_close_silen and not getattr(self.session, "_hls_close_noise_filter", None):
                filt = _ClosingNoiseFilter()
                # Attach to multiple relevant loggers to be safe, including root ("")
                for lname in ("streamlink.stream", "streamlink.stream.segmented", "streamlink", ""):
                    logging.getLogger(lname).addFilter(filt)
                # Cache on session to avoid duplicate installs
                setattr(self.session, "_hls_close_noise_filter", filt)
        except Exception:
            pass

    def _close_sync(self):
        with self._close_lock:
            # Reuse attribute as a flag to ensure single execution
            if getattr(self, "_close_started", False):
                return
            self._close_started = True
        # Trigger fast abort only if the writer is actually running and there is something to cancel it with
        try:
            w = getattr(self, "writer", None)
            if w and hasattr(w, "is_fast_aborted") and not w.is_fast_aborted():
                has_exec = getattr(w, "executor", None) is not None
                has_active = False
                try:
                    futs = getattr(w, "_futures", None)
                    if isinstance(futs, list):
                        has_active = any(f is not None and not f.done() for f in futs)
                except Exception:
                    pass

                if has_exec or has_active:
                    w.fast_abort()
        except Exception:
            pass

        super().close()
        try:
            gc.collect()
        except Exception:
            pass

    def close(self):
        async_close = bool(self.session.options.get("hls-close-async"))
        if async_close:
            # Start only one closing thread
            try:
                t = getattr(self, "_close_thread", None)
            except Exception:
                t = None
            if t is not None:
                try:
                    if t.is_alive():
                        return
                except Exception:
                    pass
            t = threading.Thread(target=self._close_sync, name=f"hls-close-{id(self)}", daemon=True)
            self._close_thread = t
            t.start()
            return
        self._close_sync()

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
            TStream(
                session,
                url,
                multivariant=multivariant,
                force_restart=force_restart,
                name=None if idx == 0 else "audio",
                **kwargs,
            )
            for idx, url in enumerate(tracks)
        ]
        ffmpeg_options = ffmpeg_options or {}

        super().__init__(session, *substreams, format="mpegts", maps=maps, **ffmpeg_options)
        self.multivariant = multivariant if multivariant and multivariant.is_master else None

    def to_manifest_url(self):
        url = self.multivariant.uri if self.multivariant and self.multivariant.uri else None

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
        multivariant: M3U8 | None = None,
        name: str | None = None,
        force_restart: bool = False,
        start_offset: float = 0,
        **kwargs,
    ):
        """
        :param session: Streamlink session instance
        :param url: The URL of the HLS playlist
        :param multivariant: The parsed multivariant playlist
        :param name: Optional name suffix for the stream's worker and writer threads
        :param force_restart: Start from the beginning after reaching the playlist's end
        :param start_offset: Number of seconds to be skipped from the beginning
        :param kwargs: Additional keyword arguments passed to :meth:`requests.Session.request`
        """

        super().__init__(session, url, **kwargs)
        self.multivariant = multivariant if multivariant and multivariant.is_master else None
        self.name = name
        self.force_restart = force_restart
        self.start_offset = start_offset
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

    def to_manifest_url(self):
        url = self.multivariant.uri if self.multivariant and self.multivariant.uri else None

        if url is None:
            return super().to_manifest_url()

        args = self.args.copy()
        args.update(url=url)

        return self.session.http.prepare_new_request(**args).url

    def open(self):
        self.reader.open()
        return self.reader

    def close(self):
        try:
            if getattr(self, "reader", None) is not None:
                self.reader.close()
        finally:
            # Always drop the reference afterwards
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
                    **kwargs,
                )
            else:
                stream = cls(
                    session,
                    playlist.uri,
                    multivariant=multivariant,
                    force_restart=force_restart,
                    start_offset=start_offset,
                    **kwargs,
                )

            streams[stream_name] = stream

        return streams
