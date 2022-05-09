import logging
import re

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.plugin.api import useragents
from streamlink.stream.hls import HLSStream

log = logging.getLogger(__name__)

@pluginmatcher(re.compile(
    r"http?://starnet-md\."
))
class StarNet(Plugin):
    _site_url = "http://starnet-md."
    _api_url = "http://token.stb.md/api/Flussonic/stream/{0}/metadata.json"

    def _get_streams(self):
        log.debug(f"***StarNet addon use!***")
        chName = self.url.replace(self._site_url, '').strip()
        catch = None
        if ':catch:' in chName:
            ID, sep, catch = chName.partition(':catch:')
        else:
            ID = chName
            
        res = self.session.http.get(self._api_url.format(ID), headers={"User-Agent": useragents.ANDROID})
        data = self.session.http.json(res)
        if data:
            videourl = data["variants"][0]["url"]
            if videourl:
                videourl = videourl.replace('/index', '/video').replace('/mono', '/video')
                if catch:
                    videourl = videourl.replace('.m3u8', catch)
                return HLSStream.parse_variant_playlist(self.session, videourl)

__plugin__ = StarNet
