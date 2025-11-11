from __future__ import annotations

import warnings
from pathlib import Path
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, Any, ClassVar

import urllib3.util.connection as urllib3_util_connection
from requests.adapters import HTTPAdapter

from streamlink.exceptions import StreamlinkDeprecationWarning
from streamlink.options import Options
from streamlink.session.http import TLSNoDHAdapter
from streamlink.utils.url import update_scheme


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from streamlink.session import Streamlink


_session_file = str(Path(__file__).parent / "session.py")

_original_allowed_gai_family = urllib3_util_connection.allowed_gai_family  # type: ignore[attr-defined]


def _get_deprecation_stacklevel_offset():
    """Deal with stacklevels of both session.{g,s}et_option() and session.options.{g,s}et() calls"""
    from inspect import currentframe  # noqa: PLC0415

    frame = currentframe().f_back.f_back
    offset = 0
    while frame:
        if frame.f_code.co_filename == _session_file and frame.f_code.co_name in ("set_option", "get_option"):
            offset += 1
            break
        frame = frame.f_back

    return offset


class StreamlinkOptions(Options):
    """
    Streamlink's session options.
    """

    def __init__(self, session: Streamlink) -> None:
        super().__init__({
            "user-input-requester": None,
            "locale": None,
            "interface": None,
            "ipv4": False,
            "ipv6": False,
            "ringbuffer-size": 1024 * 1024 * 16,  # 16 MB
            "mux-subtitles": False,
            "stream-segment-attempts": 3,
            "stream-segment-threads": 1,
            "stream-segment-timeout": 10.0,
            "stream-timeout": 60.0,
            "hls-live-edge": 3,
            "hls-live-restart": False,
            "hls-start-offset": 0.0,
            "hls-playlist-reload-attempts": 3,
            "hls-playlist-reload-time": "segment", # segment, smart, targetduration
            "hls-segment-queue-threshold": 3,
            "hls-segment-stream-data": False,
            "hls-segment-ignore-names": [],
            "hls-segment-key-uri": None,
            "hls-audio-select": [],
            "hls-segment-conn-close": False,       # close segment connection
            "hls-close-async": True,
            "hls-map-cache-size": 2,               # Limit how many distinct MAPs we keep. Allow explicit 0/1/2
            "dash-manifest-reload-attempts": 3,
            "ffmpeg-use": True,
            "ffmpeg-ffmpeg": None,
            "ffmpeg-no-validation": True,
            "ffmpeg-verbose": False,
            "ffmpeg-verbose-path": None,
            "ffmpeg-loglevel": None,
            "ffmpeg-fout": None,
            "ffmpeg-video-transcode": None,
            "ffmpeg-audio-transcode": None,
            "ffmpeg-copyts": False,
            "ffmpeg-start-at-zero": False,
            "segments-queue": 6,
            "chunk-size": 8192,
            "vod-start": 3,                        # VOD Limit segments on startup
            "vod-process": 1,                      # VOD Limit segments in progress
            "vod-queue-step": 1,                   # VOD segments queue Step
            "client-info": "",
            "live-buffer-mult": 2.0,               # Live buffer target multiplier (in segments' mean seconds)
            "vod-buffer-mult": 3.0,                # VOD buffer target multiplier (in segments' mean seconds)
        })
        self.session = session

    # ---- utils

    @staticmethod
    def _parse_key_equals_value_string(delimiter: str, value: str) -> Iterator[tuple[str, str]]:
        for keyval in value.split(delimiter):
            try:
                key, val = keyval.split("=", 1)
                yield key.strip(), val.strip()
            except ValueError:
                continue

    @staticmethod
    def _deprecate_https_proxy(key: str) -> None:
        if key == "https-proxy":
            warnings.warn(
                "The `https-proxy` option has been deprecated in favor of a single `http-proxy` option",
                StreamlinkDeprecationWarning,
                stacklevel=4 + _get_deprecation_stacklevel_offset(),
            )

    # ---- getters

    def _get_http_proxy(self, key):
        self._deprecate_https_proxy(key)
        return self.session.http.proxies.get("https" if key == "https-proxy" else "http")

    def _get_http_attr(self, key):
        return getattr(self.session.http, self._OPTIONS_HTTP_ATTRS[key])

    # ---- setters

    def _set_interface(self, key, value):
        for adapter in self.session.http.adapters.values():
            if not isinstance(adapter, HTTPAdapter):
                continue
            if not value:
                adapter.poolmanager.connection_pool_kw.pop("source_address", None)
            else:
                # https://docs.python.org/3/library/socket.html#socket.create_connection
                adapter.poolmanager.connection_pool_kw.update(source_address=(value, 0))
        self.set_explicit(key, None if not value else value)

    def _set_ipv4_ipv6(self, key, value):
        self.set_explicit(key, value)
        if not value:
            urllib3_util_connection.allowed_gai_family = _original_allowed_gai_family  # type: ignore[attr-defined]
        elif key == "ipv4":
            self.set_explicit("ipv6", False)
            urllib3_util_connection.allowed_gai_family = lambda: AF_INET  # type: ignore[attr-defined]
        else:
            self.set_explicit("ipv4", False)
            urllib3_util_connection.allowed_gai_family = lambda: AF_INET6  # type: ignore[attr-defined]

    def _set_http_proxy(self, key, value):
        self.session.http.proxies["http"] \
            = self.session.http.proxies["https"] \
            = update_scheme("https://", value, force=False)  # fmt: skip
        self._deprecate_https_proxy(key)

    def _set_http_attr(self, key, value):
        setattr(self.session.http, self._OPTIONS_HTTP_ATTRS[key], value)

    def _set_http_disable_dh(self, key, value):
        self.set_explicit(key, value)
        if value:
            adapter = TLSNoDHAdapter()
        else:
            adapter = HTTPAdapter()

        self.session.http.mount("https://", adapter)

    @staticmethod
    def _factory_set_http_attr_key_equals_value(delimiter: str) -> Callable[[StreamlinkOptions, str, Any], None]:
        def inner(self: "StreamlinkOptions", key: str, value: Any) -> None:
            getattr(self.session.http, self._OPTIONS_HTTP_ATTRS[key]).update(
                value if isinstance(value, dict) else dict(self._parse_key_equals_value_string(delimiter, value)),
            )

        return inner

    @staticmethod
    def _factory_set_deprecated(name: str, mapper: Callable[[Any], Any]) -> Callable[[StreamlinkOptions, str, Any], None]:
        def inner(self: StreamlinkOptions, key: str, value: Any) -> None:
            self.set_explicit(name, mapper(value))
            warnings.warn(
                f"`{key}` has been deprecated in favor of the `{name}` option",
                StreamlinkDeprecationWarning,
                stacklevel=3 + _get_deprecation_stacklevel_offset(),
            )

        return inner


    # ----

    _OPTIONS_HTTP_ATTRS: ClassVar[Mapping[str, str]] = {
        "http-cookies": "cookies",
        "http-headers": "headers",
        "http-query-params": "params",
        "http-ssl-cert": "cert",
        "http-ssl-verify": "verify",
        "http-trust-env": "trust_env",
        "http-timeout": "timeout",
    }

    _MAP_GETTERS: ClassVar[Mapping[str, Callable[[StreamlinkOptions, str], Any]]] = {
        "http-proxy": _get_http_proxy,
        "https-proxy": _get_http_proxy,
        "http-cookies": _get_http_attr,
        "http-headers": _get_http_attr,
        "http-query-params": _get_http_attr,
        "http-ssl-cert": _get_http_attr,
        "http-ssl-verify": _get_http_attr,
        "http-trust-env": _get_http_attr,
        "http-timeout": _get_http_attr,
    }

    _MAP_SETTERS: ClassVar[Mapping[str, Callable[[StreamlinkOptions, str, Any], None]]] = {
        "interface": _set_interface,
        "ipv4": _set_ipv4_ipv6,
        "ipv6": _set_ipv4_ipv6,
        "http-proxy": _set_http_proxy,
        "https-proxy": _set_http_proxy,
        "http-cookies": _factory_set_http_attr_key_equals_value(";"),
        "http-headers": _factory_set_http_attr_key_equals_value(";"),
        "http-query-params": _factory_set_http_attr_key_equals_value("&"),
        "http-disable-dh": _set_http_disable_dh,
        "http-ssl-cert": _set_http_attr,
        "http-ssl-verify": _set_http_attr,
        "http-trust-env": _set_http_attr,
        "http-timeout": _set_http_attr,
    }
