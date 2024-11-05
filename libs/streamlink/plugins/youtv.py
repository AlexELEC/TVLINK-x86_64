import logging
import re
from time import time
from base64 import b64decode
from urllib.parse import urlparse
from urllib.parse import parse_qs

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)

class YouTVHLS(HLSStream):
    __shortname__ = "hls-youtv"

    def __init__(self, session_, url, code_url=None, **args):
        super().__init__(session_, url, None, **args)
        self._url = url
        self.stats_url = code_url
        self.watch_timeout = int(time()) + 80
        self.headers = {'user-agent': 'youtv/3.23.13+8004 (Samsung MB2; Android; 6.0.1; Mobile; null; MHC19J.20170619.091635 test-keys; 1920x1008)',
                        'accept': '*/*'}

    @property
    def url(self):
        if int(time()) >= self.watch_timeout:
            log.debug("*** YouTV addon send stats URL ***")
            log.debug(f"*** {self.stats_url}")
            res = self.session.http.get(self.stats_url, headers=self.headers)
            self.watch_timeout = int(time()) + 80
        return self._url

@pluginmatcher(
    re.compile(r"https?://stream\.youtv\.com\.ua/"),
)
@pluginmatcher(
    re.compile(r"https?://(\w+)\.live\.tvstitch\.com/"),
)
class YouTV(Plugin):
    def _get_streams(self):
        variant_play = HLSStream.parse_variant_playlist(self.session, self.url).items()
        if 'live.tvstitch.com' in self.url:
            stat_url = parse_qs(urlparse(self.url).query)['m'][0]
            stat_url = b64decode(stat_url).decode('utf-8')
        else:
            stat_url = self.url
        code_url = stat_url.replace('/NzM=/master.m3u8', '/stats')
        if variant_play:
            for q, s in variant_play:
                yield q, YouTVHLS(self.session, s.url, code_url=code_url)
        else:
            yield "live", YouTVHLS(self.session, self.url, code_url=code_url)


__plugin__ = YouTV
