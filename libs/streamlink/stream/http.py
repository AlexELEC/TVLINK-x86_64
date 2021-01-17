from inspect import getfullargspec

import requests

from streamlink.exceptions import StreamError
from streamlink.stream.stream import Stream
from streamlink.stream.wrappers import StreamIOIterWrapper, StreamIOThreadWrapper


def normalize_key(keyval):
    key, val = keyval
    key = hasattr(key, "decode") and key.decode("utf8", "ignore") or key

    return key, val


def valid_args(args):
    argspec = getfullargspec(requests.Request.__init__)

    return dict(filter(lambda kv: kv[0] in argspec.args, args.items()))


class HTTPStream(Stream):
    """A HTTP stream using the requests library.

    *Attributes:*

    - :attr:`url`  The URL to the stream, prepared by requests.
    - :attr:`args` A :class:`dict` containing keyword arguments passed
      to :meth:`requests.request`, such as headers and cookies.

    """

    __shortname__ = "http"

    def __init__(self, session_, url, buffered=True, **args):
        Stream.__init__(self, session_)

        self.args = dict(url=url, **args)
        self.buffered = buffered
        self.fdclose = None

    def __repr__(self):
        return "<HTTPStream({0!r})>".format(self.url)

    def __json__(self):
        method = self.args.get("method", "GET")
        req = requests.Request(method=method, **valid_args(self.args))

        # prepare_request is only available in requests 2.0+
        if hasattr(self.session.http, "prepare_request"):
            req = self.session.http.prepare_request(req)
        else:
            req = req.prepare()

        headers = dict(map(normalize_key, req.headers.items()))

        return dict(type=type(self).shortname(), url=req.url,
                    method=req.method, headers=headers,
                    body=req.body)

    @property
    def url(self):
        method = self.args.get("method", "GET")
        return requests.Request(method=method,
                                **valid_args(self.args)).prepare().url

    def open(self):
        method = self.args.get("method", "GET")
        timeout = self.session.http.timeout
        chunk_size = self.session.get_option("chunk-size-ts")
        #print ('timeout:', timeout)
        #print ('chunk-size-ts:', chunk_size)
        res = self.session.http.request(method=method,
                                        stream=True,
                                        exception=StreamError,
                                        timeout=timeout,
                                        **self.args)

        #print ('res:', res)
        fd = StreamIOIterWrapper(res.iter_content(chunk_size))
        if self.buffered:
            fd = StreamIOThreadWrapper(self.session, fd, timeout=timeout, chunk_size=chunk_size)

        self.fdclose = fd

        return fd

    def close(self):
        if self.fdclose:
            self.fdclose.close()
            self.fdclose = None

    def to_url(self):
        return self.url
