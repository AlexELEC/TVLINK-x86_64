import re
from streamlink.plugin import Plugin, pluginmatcher
from streamlink.stream.hls import HLSStream

@pluginmatcher(
    re.compile(r"https?://(\w+)\.mediavitrina\.ru/"),
)
class Mediavitrina(Plugin):
    def _get_streams(self):
        hls_url = self.url.replace('edge01d', 'edge02r').replace('edge02d', 'edge02r')
        return HLSStream.parse_variant_playlist(self.session, hls_url)


__plugin__ = Mediavitrina
