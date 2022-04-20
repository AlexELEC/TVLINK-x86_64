import json
import re
import xml.etree.ElementTree as ET
import zlib
from collections import OrderedDict
from importlib.machinery import FileFinder, SOURCE_SUFFIXES, SourceFileLoader
from importlib.util import module_from_spec
from typing import Generic, Optional, OrderedDict as TOrderedDict, TypeVar
from urllib.parse import parse_qsl, urlparse

from streamlink.exceptions import PluginError
from streamlink.utils.formatter import Formatter
from streamlink.utils.named_pipe import NamedPipe
from streamlink.utils.url import absolute_url, prepend_www, update_qsd, update_scheme, url_concat, url_equal


_loader_details = [(SourceFileLoader, SOURCE_SUFFIXES)]


def load_module(name, path=None):
    finder = FileFinder(path, *_loader_details)
    spec = finder.find_spec(name)
    if not spec or not spec.loader:
        raise ImportError(f"no module named {name}")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_json(data, name="JSON", exception=PluginError, schema=None):
    """Wrapper around json.loads.

    Wraps errors in custom exception with a snippet of the data in the message.
    """
    try:
        json_data = json.loads(data)
    except ValueError as err:
        snippet = repr(data)
        if len(snippet) > 35:
            snippet = snippet[:35] + " ..."
        else:
            snippet = data

        raise exception("Unable to parse {0}: {1} ({2})".format(name, err, snippet))

    if schema:
        json_data = schema.validate(json_data, name=name, exception=exception)

    return json_data


def parse_xml(data, name="XML", ignore_ns=False, exception=PluginError, schema=None, invalid_char_entities=False):
    """Wrapper around ElementTree.fromstring with some extras.

    Provides these extra features:
     - Handles incorrectly encoded XML
     - Allows stripping namespace information
     - Wraps errors in custom exception with a snippet of the data in the message
    """
    if isinstance(data, str):
        data = bytearray(data, "utf8")

    if ignore_ns:
        data = re.sub(br"[\t ]xmlns=\"(.+?)\"", b"", data)

    if invalid_char_entities:
        data = re.sub(br'&(?!(?:#(?:[0-9]+|[Xx][0-9A-Fa-f]+)|[A-Za-z0-9]+);)', b'&amp;', data)

    try:
        tree = ET.fromstring(data)
    except Exception as err:
        snippet = repr(data)
        if len(snippet) > 35:
            snippet = snippet[:35] + " ..."

        raise exception("Unable to parse {0}: {1} ({2})".format(name, err, snippet))

    if schema:
        tree = schema.validate(tree, name=name, exception=exception)

    return tree


def parse_qsd(data, name="query string", exception=PluginError, schema=None, **params):
    """Parses a query string into a dict.

    Unlike parse_qs and parse_qsl, duplicate keys are not preserved in
    favor of a simpler return value.
    """

    value = dict(parse_qsl(data, **params))
    if schema:
        value = schema.validate(value, name=name, exception=exception)

    return value


def search_dict(data, key):
    """
    Search for a key in a nested dict, or list of nested dicts, and return the values.

    :param data: dict/list to search
    :param key: key to find
    :return: matches for key
    """
    if isinstance(data, dict):
        for dkey, value in data.items():
            if dkey == key:
                yield value
            yield from search_dict(value, key)
    elif isinstance(data, list):
        for value in data:
            yield from search_dict(value, key)


TCacheKey = TypeVar("TCacheKey")
TCacheValue = TypeVar("TCacheValue")


class LRUCache(Generic[TCacheKey, TCacheValue]):
    def __init__(self, num: int):
        self.cache: TOrderedDict[TCacheKey, TCacheValue] = OrderedDict()
        self.num = num

    def get(self, key: TCacheKey) -> Optional[TCacheValue]:
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def set(self, key: TCacheKey, value: TCacheValue) -> None:
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.num:
            self.cache.popitem(last=False)


__all__ = ["load_module", "update_scheme", "url_equal",
           "absolute_url", "parse_qsd", "parse_json",
           "parse_xml", "prepend_www", "NamedPipe",
           "LRUCache", "Formatter", "update_qsd", "url_concat"]
