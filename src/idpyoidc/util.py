import base64
import importlib
import json
import logging
import os
import re
import secrets
import sys
from typing import Union
from urllib.parse import parse_qs
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from cryptojwt.utils import importer
import yaml

logger = logging.getLogger(__name__)


def rndstr(size=16):
    """
    Returns a string of random url safe characters

    :param size: The length of the string
    :return: string
    """
    return secrets.token_urlsafe(size)


def instantiate(cls, **kwargs):
    if isinstance(cls, str):
        return importer(cls)(**kwargs)
    else:
        return cls(**kwargs)


#: Parameters whose values are secrets or bearer credentials; never logged.
SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "assertion",
        "authorization",
        "client_assertion",
        "client_secret",
        "code",
        "code_verifier",
        "d",
        "dpop",
        "id_token",
        "jws",
        "k",
        "oauth-client-attestation",
        "oauth-client-attestation-pop",
        "password",
        "pre-authorized_code",
        "refresh_token",
        "registration_access_token",
        "token",
        "tx_code",
    }
)
REDACTED = "<redacted>"
_KEYS_PATTERN = "|".join(re.escape(k) for k in sorted(SENSITIVE_KEYS, key=len, reverse=True))
# key=value (query strings, form bodies)
_KV_RE = re.compile(r"(?i)(?<![\w-])(" + _KEYS_PATTERN + r")=([^&\s'\",}]+)")
# "key": "value" or 'key': 'value' (JSON, dict reprs)
_QUOTED_RE = re.compile(
    r"(?i)([\"'])(" + _KEYS_PATTERN + r")\1(\s*:\s*)([\"'])(.*?)(?<!\\)\4"
)


def sanitize(value):
    """Returns ``value`` with secrets redacted, for logging.

    Dicts and Messages are copied with the values of :data:`SENSITIVE_KEYS`
    replaced; in strings, ``key=value`` and quoted ``"key": "value"`` pairs
    are redacted and line breaks escaped (no forged log lines).
    """
    if hasattr(value, "to_dict"):
        try:
            value = value.to_dict()
        except Exception:
            value = str(value)
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else sanitize(v)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(sanitize(v) for v in value)
    if isinstance(value, str):
        value = _KV_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
        value = _QUOTED_RE.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}{m.group(4)}{REDACTED}{m.group(4)}",
            value,
        )
        return value.replace("\r", "\\r").replace("\n", "\\n")
    return value


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding="utf-8") as file:
        config_dict = yaml.safe_load(file)
    return config_dict


def load_config_file(filename):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _cnf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _cnf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        sys.path.append(head)
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
    else:
        raise ValueError("Unknown file type")

    return _cnf


def split_uri(uri: str) -> [str, Union[dict, None]]:
    """Removes fragment and separates the query part from the rest."""
    p = urlsplit(uri)

    if p.fragment:
        p = p._replace(fragment="")

    if p.query:
        o = p._replace(query="")
        base = urlunsplit(o)
        return [base, parse_qs(p.query)]
    else:
        base = urlunsplit(p)
        return [base, None]


# Converters


class QPKey:
    def serialize(self, str):
        return quote_plus(str)

    def deserialize(self, str):
        return unquote_plus(str)


class JSON:
    def serialize(self, str):
        return json.dumps(str)

    def deserialize(self, str):
        return json.loads(str)


class PassThru:
    def serialize(self, str):
        return str

    def deserialize(self, str):
        return str


class Base64(object):
    @staticmethod
    def serialize(str):
        return base64.b64encode(str.encode("utf-8")).decode("utf-8")

    @staticmethod
    def deserialize(str):
        return base64.b64decode(str.encode("utf-8")).decode("utf-8")


def get_http_params(config):
    params = config.get("httpc_params", {})

    if "verify" not in params:
        _ver = config.get("verify")
        if _ver is None:
            _ver = config.get("verify_ssl", True)
        params["verify"] = _ver

    _cert = config.get("client_cert")
    _key = config.get("client_key")
    if _cert:
        if _key:
            params["cert"] = (_cert, _key)
        else:
            params["cert"] = _cert

    return params


def add_path(url, path):
    if url.endswith("/"):
        if path.startswith("/"):
            return "{}{}".format(url, path[1:])
        else:
            return "{}{}".format(url, path)
    else:
        if path.startswith("/"):
            return "{}{}".format(url, path)
        else:
            return "{}/{}".format(url, path)


def qualified_name(cls):
    """Does both classes and class instances

    :param cls: The item, class or class instance
    :return: fully qualified class name
    """

    try:
        return cls.__module__ + "." + cls.name
    except AttributeError:
        return cls.__module__ + "." + cls.__name__
