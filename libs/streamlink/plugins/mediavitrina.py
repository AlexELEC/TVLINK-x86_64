import re
from streamlink.plugin import Plugin, pluginmatcher
from streamlink.stream.hls import HLSStream

@pluginmatcher(
    re.compile(r"https?://(\w+)\.mediavitrina\.ru/"),
)
class Mediavitrina(Plugin):
    def _get_streams(self):
        hls_url = self.url.replace('edge01d', 'edge02r').replace('edge02d', 'edge02r')
        hls_url = hls_url.replace('tracks-v3a1/mono.m3u8', 'index.m3u8')
        s = HLSStream.parse_variant_playlist(self.session, hls_url)
        if not s:
            yield "live", HLSStream(self.session, hls_url)
        elif len(s) == 1:
            yield "live", next(iter(s.values()))
        else:
            yield from s.items()


__plugin__ = Mediavitrina
