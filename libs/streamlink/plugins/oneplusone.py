import logging
import re
from base64 import b64decode
from html.parser import HTMLParser
from time import time
from urllib.parse import urljoin, urlparse

from streamlink.exceptions import PluginError
from streamlink.plugin import Plugin, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.stream.hls import HLSStream
from streamlink.utils import parse_json
from streamlink.utils.times import fromlocaltimestamp


log = logging.getLogger(__name__)


class Online_Parser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag == 'iframe':
            attrs = dict(attrs)
            if 'src' in attrs and 'embed' in attrs['src']:
                self.iframe_url = attrs['src']


class Iframe_Parser(HTMLParser):
    js = False

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            attrs = dict(attrs)
            if 'type' in attrs and attrs['type'] == 'text/javascript':
                self.js = True

    def handle_data(self, data):
        if self.js and data.startswith('window.onload'):
            self.data = data


class OnePlusOneHLS(HLSStream):
    __shortname__ = "hls-oneplusone"

    def __init__(self, session, url, self_url=None, **args):
        super().__init__(session, url, None, **args)
        self._url = url

        first_parsed = urlparse(self._url)
        self._first_netloc = first_parsed.netloc
        self._first_path_chunklist = first_parsed.path.split("/")[-1]
        self.watch_timeout = int(first_parsed.path.split("/")[2]) - 15
        self.api = OnePlusOneAPI(session, self_url)

    def _next_watch_timeout(self):
        _next = fromlocaltimestamp(self.watch_timeout).isoformat(" ")
        log.debug(f"next watch_timeout at {_next}")

    def open(self):
        self._next_watch_timeout()
        return super().open()

    @property
    def url(self):
        if int(time()) >= self.watch_timeout:
            log.debug("Reloading HLS URL")
            _hls_url = self.api.get_hls_url()
            if not _hls_url:
                self.watch_timeout += 10
                return self._url
            parsed = urlparse(_hls_url)
            path_parts = parsed.path.split("/")
            path_parts[-1] = self._first_path_chunklist
            self.watch_timeout = int(path_parts[2]) - 15
            self._next_watch_timeout()

            self._url = parsed._replace(
                netloc=self._first_netloc,
                path="/".join([p for p in path_parts])
            ).geturl()
        return self._url


class OnePlusOneAPI:
    def __init__(self, session, url):
        self.session = session
        self.url = url
        self._re_data = re.compile(r"ovva-player\",\"([^\"]*)\"\)")
        self.ovva_data_schema = validate.Schema({
            "balancer": validate.url()
            }, validate.get("balancer"))
        self.ovva_redirect_schema = validate.Schema(validate.all(
            validate.transform(lambda x: x.split("=")),
            ['302', validate.url()],
            validate.get(1)
        ))

    def find_iframe(self, res):
        parser = Online_Parser()
        parser.feed(res.text)
        url = parser.iframe_url
        log.trace(f"find_iframe url: {url}")
        if url.startswith("/"):
            p = urlparse(self.url)
            if url.startswith("//"):
                return "{0}:{1}".format(p.scheme, url)
            return "{0}://{1}{2}".format(p.scheme, p.netloc, url)
        else:
            return url

    def get_data(self, res):
        parser = Iframe_Parser()
        parser.feed(res.text)
        if hasattr(parser, "data"):
            m = self._re_data.search(parser.data)
            if m:
                data = m.group(1)
                return data

    def get_hls_url(self):
        self.session.http.cookies.clear()
        res = self.session.http.get(self.url)
        iframe_url = self.find_iframe(res)
        if iframe_url:
            log.debug("Found iframe: {0}".format(iframe_url))
            res = self.session.http.get(
                iframe_url,
                headers={"Referer": self.url})
            data = self.get_data(res)
            if data:
                try:
                    ovva_url = parse_json(
                        b64decode(data).decode(),
                        schema=self.ovva_data_schema)
                    log.debug("Found ovva: {0}".format(ovva_url))

                    stream_url = self.session.http.get(
                        ovva_url,
                        schema=self.ovva_redirect_schema,
                        headers={"Referer": iframe_url})
                    log.debug("Found stream: {0}".format(stream_url))
                    return stream_url

                except PluginError as e:
                    log.error("Could not find stream URL: {0}".format(e))
        return


@pluginmatcher(re.compile(
    r"https?://1plus1\.video/(?:\w{2}/)?tvguide/[^/]+/online"
))
class OnePlusOne(Plugin):
    def _get_streams(self):
        self.api = OnePlusOneAPI(self.session, self.url)
        url_hls = self.api.get_hls_url()
        if not url_hls:
            return
        for q, s in HLSStream.parse_variant_playlist(self.session, url_hls).items():
            yield q, OnePlusOneHLS(self.session, s.url, self_url=self.url)


__plugin__ = OnePlusOne
