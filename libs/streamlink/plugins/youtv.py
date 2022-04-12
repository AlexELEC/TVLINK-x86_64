import logging
import re
from time import time

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)

class YouTVHLS(HLSStream):
    __shortname__ = "hls-youtv"

    def __init__(self, session_, url, self_url=None, **args):
        super().__init__(session_, url, None, **args)
        self._url = url
        self.stats_url = self_url.replace('/NzM=/master.m3u8', '/stats')
        self.watch_timeout = int(time()) + 80

    @property
    def url(self):
        if int(time()) >= self.watch_timeout:
            log.debug("***YouTV addon send stats...***")
            res = self.session.http.get(self.stats_url)
            self.watch_timeout = int(time()) + 80
        return self._url

@pluginmatcher(re.compile(
    r"https?://stream\.youtv\.com\.ua/"
))
class YouTV(Plugin):
    def _get_streams(self):
        log.debug(f"***YouTV addon use!***")
        variant_play = HLSStream.parse_variant_playlist(self.session, self.url).items()
        if variant_play:
            for q, s in variant_play:
                yield q, YouTVHLS(self.session, s.url, self_url=self.url)
        else:
            yield "live", YouTVHLS(self.session, self.url, self_url=self.url)


__plugin__ = YouTV
