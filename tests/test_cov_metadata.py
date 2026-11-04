"""Coverage tests for idpyoidc.metadata and idpyoidc.converter."""
import pytest
from cryptojwt import KeyJar
from cryptojwt.jwe import SUPPORTED
from cryptojwt.jws.jws import SIGNER_ALGS
from cryptojwt.key_jar import build_keyjar

from idpyoidc import converter
from idpyoidc import metadata
from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message import SINGLE_OPTIONAL_STRING
from idpyoidc.message import SINGLE_REQUIRED_STRING
from idpyoidc.metadata import Metadata

KEYDEFS = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]
KEY_CONF = {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"}


class MD(Metadata):
    _supports = {
        "response_types": ["code"],
        "scope": None,
        "client_secret": None,
        "grant_types": lambda: ["authorization_code"],
    }

    def get_id(self, configuration):
        return configuration.get("client_id")

    def get_base_url(self, configuration, entity_id=""):
        return configuration.get("base_url", entity_id)


class RecordingMD(MD):
    """Records the hook calls so the load_conf flow can be verified."""

    def __init__(self, *args, **kwargs):
        MD.__init__(self, *args, **kwargs)
        self.calls = []

    def locals(self, info):
        self.calls.append(("locals", sorted(info.keys())))

    def verify_rules(self, supports):
        self.calls.append(("verify_rules", sorted(supports.keys())))
        return True

    def get_jwks(self, keyjar):
        return keyjar.export_jwks()


# ---------------------------------------------------------------- basics


def test_init_filters_prefer_on_supports():
    md = MD(prefer={"scope": ["openid"], "unknown": 1}, callback_path={"code": "cb"})
    assert md.prefer == {"scope": ["openid"]}
    assert md.callback_path == {"code": "cb"}
    assert md.use == {}
    assert md._local == {}


def test_init_non_dict_prefer():
    md = MD(prefer=["scope"])
    assert md.prefer == {}
    assert md.callback_path == {}


def test_usage_and_preference_accessors():
    md = MD()
    md.set_usage("scope", ["openid"])
    assert md.get_use() == {"scope": ["openid"]}
    assert md.get_usage("scope") == ["openid"]
    assert md.get_usage("missing", "dflt") == "dflt"

    md.set_preference("scope", ["email"])
    assert md.get_preference("scope") == ["email"]
    assert md.get_preference("x", 7) == 7
    assert md.prefers() == {"scope": ["email"]}
    md.remove_preference("scope")
    assert md.get_preference("scope") is None
    # removing something not there is a no-op
    md.remove_preference("scope")
    assert md.prefers() == {}


def test_local_get_set():
    md = MD()
    assert md.get("a") is None
    assert md.get("a", "dflt") == "dflt"
    md.set("a", 1)
    assert md.get("a") == 1


def test_supports_resolves_callables_and_supported():
    md = MD()
    sup = md.supports()
    assert sup["grant_types"] == ["authorization_code"]
    assert sup["response_types"] == ["code"]
    assert md.supported("scope")
    assert not md.supported("nope")


def test_trivial_hooks():
    md = Metadata()
    assert md.verify_rules({}) is True
    assert md.locals({}) is None
    assert md.add_extra_keys(KeyJar(), "x") is None
    assert md.get_jwks(KeyJar()) is None
    assert md.construct_uris("a", "b") is None
    with pytest.raises(NotImplementedError):
        md.get_base_url({})
    with pytest.raises(NotImplementedError):
        md.get_id({})


def test_dump_and_load_roundtrip():
    md = MD(prefer={"scope": ["openid"]}, callback_path={"code": "cb"})
    md.set_usage("scope", ["openid"])
    md.set("x", "y")
    dumped = metadata.metadata_dump(md, exclude_attributes=[])
    key = next(iter(dumped))
    assert key.endswith("test_cov_metadata.MD")
    assert dumped[key]["prefer"] == {"scope": ["openid"]}

    loaded = metadata.metadata_load(dumped)
    assert isinstance(loaded, MD)
    assert loaded.prefer == {"scope": ["openid"]}
    assert loaded.use == {"scope": ["openid"]}
    assert loaded.callback_path == {"code": "cb"}
    assert loaded.get("x") == "y"


# ---------------------------------------------------------------- redirect uris


def test_construct_redirect_uris_with_explicit_callbacks():
    md = MD()
    cbs = {"code": "https://rp/cb/code"}
    md.construct_redirect_uris("https://rp", "abc", callbacks=cbs)
    assert md.get_preference("callbacks") == cbs
    assert md.get_preference("redirect_uris") == ["https://rp/cb/code"]
    assert md.callback == cbs


@pytest.mark.xfail(
    strict=True,
    reason="BUG: src/idpyoidc/metadata.py:75 `'form_post' in self.supports` tests membership "
    "in a bound method (should be self._supports) -> TypeError, so _callback_uris always fails",
)
def test_callback_uris_derived_from_response_types():
    md = MD(callback_path={"code": "authz_cb"})
    md.construct_redirect_uris("https://rp", "abc")
    assert md.get_preference("redirect_uris") == ["https://rp/authz_cb/abc"]


def test_callback_uris_logic_with_supports_shadowed():
    """Exercise the remaining _callback_uris logic by shadowing the buggy
    method lookup with an iterable instance attribute."""
    md = MD(
        callback_path={"code": "c", "implicit": "i", "form_post": "f"},
    )
    md.set_usage("response_types", ["code", "id_token", "id_token token", "token"])
    md.supports = ["form_post"]
    md.construct_redirect_uris("https://rp", "h")
    assert md.callback == {
        "code": "https://rp/c/h",
        "implicit": "https://rp/i/h",
        "form_post": "https://rp/f/h",
    }
    assert md.get_preference("redirect_uris") == list(md.callback.values())


def test_callback_uris_empty_result_does_not_set_preferences():
    md = MD()
    md.set_usage("response_types", ["token"])
    md.supports = []
    md.construct_redirect_uris("https://rp", "h")
    assert md.callback == {}
    assert md.get_preference("redirect_uris") is None
    assert md.get_preference("callbacks") is None


# ---------------------------------------------------------------- keys


def test_keyjar_from_keys_conf_and_entity_copy():
    md = MD()
    kj, uri_path = md._keyjar(
        None, {"keys": KEY_CONF, "httpc_params": {"verify": False}}, entity_id="https://rp"
    )
    assert uri_path == "static/jwks.json"
    assert len(kj.get_issuer_keys("")) == 1
    assert len(kj.get_issuer_keys("https://rp")) == 1
    assert kj.httpc_params == {"verify": False}


def test_keyjar_from_key_conf():
    md = MD()
    kj, uri_path = md._keyjar(None, {"key_conf": {"key_defs": KEYDEFS}})
    assert uri_path is None
    assert len(kj.get_issuer_keys("")) == 1
    assert "https://rp" not in kj


def test_keyjar_from_jwks():
    src = build_keyjar(KEYDEFS)
    jwks = src.export_jwks()
    md = MD()
    kj, uri_path = md._keyjar(None, {"jwks": jwks, "key_conf": None}, entity_id="me")
    assert uri_path == ""
    assert len(kj.get_issuer_keys("")) == 1
    assert len(kj.get_issuer_keys("me")) == 1


def test_keyjar_empty():
    md = MD()
    kj, uri_path = md._keyjar(None, {}, entity_id="me")
    assert isinstance(kj, KeyJar)
    assert "" not in kj
    assert "me" not in kj
    assert uri_path == ""


@pytest.mark.parametrize(
    "conf,expected",
    [
        ({"keys": {"uri_path": "a"}}, "a"),
        ({"key_conf": {"uri_path": "b"}}, "b"),
        ({"key_conf": None}, ""),
        ({}, ""),
    ],
)
def test_keyjar_given_returns_same(conf, expected):
    md = MD()
    given = KeyJar()
    kj, uri_path = md._keyjar(given, conf)
    assert kj is given
    assert uri_path == expected


def test_handle_keys_explicit_jwks_uri():
    md = MD()
    res = md.handle_keys({"jwks_uri": "https://rp/jwks"})
    assert res["jwks_uri"] == "https://rp/jwks"
    assert res["jwks"] is None
    assert isinstance(res["keyjar"], KeyJar)


def test_handle_keys_uri_path_with_base_url_arg():
    md = MD()
    res = md.handle_keys({"keys": KEY_CONF}, base_url="https://rp/")
    assert res["jwks_uri"] == "https://rp/static/jwks.json"
    assert res["jwks"] is None


def test_handle_keys_uri_path_base_url_from_config():
    md = MD()
    res = md.handle_keys({"keys": KEY_CONF, "base_url": "https://base"})
    assert res["jwks_uri"] == "https://base/static/jwks.json"


def test_handle_keys_no_uri_uses_get_jwks():
    md = RecordingMD()
    res = md.handle_keys({"key_conf": {"key_defs": KEYDEFS}, "client_id": "cli"})
    assert res["jwks_uri"] is None
    assert len(res["jwks"]["keys"]) == 1
    # keys copied to the id returned by get_id
    assert "cli" in res["keyjar"]


def test_load_conf_flow():
    md = RecordingMD()
    supports = md.supports()
    conf = {
        "preference": {"scope": ["openid"], "not_supported": 1},
        "response_types": ["code"],
        "ignored": True,
        "key_conf": {"key_defs": KEYDEFS},
    }
    kj = md.load_conf(conf, supports)
    assert isinstance(kj, KeyJar)
    assert md.get_preference("scope") == ["openid"]
    assert md.get_preference("response_types") == ["code"]
    assert md.get_preference("not_supported") is None
    assert md.get_preference("ignored") is None
    assert len(md.get_preference("jwks")["keys"]) == 1
    assert md.get_preference("jwks_uri") is None
    assert [c[0] for c in md.calls] == ["locals", "verify_rules"]


def test_load_conf_with_keyjar_and_jwks_uri():
    md = MD()
    given = KeyJar()
    kj = md.load_conf({"jwks_uri": "https://x/jwks"}, md.supports(), keyjar=given)
    assert kj is given
    assert md.get_preference("jwks_uri") == "https://x/jwks"
    assert "jwks" not in md.prefer


# ---------------------------------------------------------------- algorithms


def test_cmp():
    assert metadata.cmp(1, 2) == -1
    assert metadata.cmp(2, 1) == 1
    assert metadata.cmp(2, 2) == 0


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("none", "RS256", 1),
        ("RS256", "none", -1),
        ("RS256", "RS512", -1),
        ("RS512", "RS256", 1),
        ("RS256", "RS256", 0),
        ("ES256", "RS256", 1),
        ("RS256", "ES256", -1),
        ("HS256", "PS256", 1),
    ],
)
def test_alg_cmp(a, b, expected):
    assert metadata.alg_cmp(a, b) == expected


def test_get_signing_algs_sorted_without_none():
    algs = metadata.get_signing_algs()
    assert "none" not in algs
    assert set(algs) == {a for a in SIGNER_ALGS if a != "none"}
    prefixes = [metadata.SIGNING_ALGORITHM_SORT_ORDER.index(a[:2]) for a in algs]
    assert prefixes == sorted(prefixes)
    assert algs[0].startswith("RS")


def test_encryption_algs_and_encs():
    assert metadata.get_encryption_algs() == SUPPORTED["alg"]
    assert metadata.get_encryption_encs() == SUPPORTED["enc"]


@pytest.mark.parametrize(
    "spec,values,expected",
    [
        (([str],), ["a", "b"], ["a", "b"]),
        (([str],), "a", ["a"]),
        ((str,), ["a", "b"], "a"),
        ((str,), "a", "a"),
    ],
)
def test_array_or_singleton(spec, values, expected):
    assert metadata.array_or_singleton(spec, values) == expected


@pytest.mark.parametrize(
    "a,b,expected",
    [
        (["a", "b"], ["a"], True),
        (["a"], ["a", "b"], False),
        ("a", ["a", "b"], True),
        ("c", ["a", "b"], False),
        ("a", "a", True),
        ("a", "b", False),
    ],
)
def test_is_subset(a, b, expected):
    assert metadata.is_subset(a, b) is expected


def test_is_subset_list_vs_scalar_returns_none():
    # Falls through every branch: documents current (implicit None) behaviour.
    assert metadata.is_subset(["a"], "a") is None


# ---------------------------------------------------------------- converter


class Sample(Message):
    c_param = {
        "name": SINGLE_REQUIRED_STRING,
        "nick": SINGLE_OPTIONAL_STRING,
        "tags": OPTIONAL_LIST_OF_STRINGS,
        "count": (int, True, None, None, False),
        "extra": (dict, False, None, None, False),
        "flag": (bool, False, None, None, False),
        "ids": ([int], True, None, None, False),
    }
    c_default = {"nick": "bob"}


@pytest.mark.parametrize(
    "typ,expected",
    [(str, "str"), (int, "int"), (dict, "dict"), (any, "any"), (bool, "bool"), (Message, "Message")],
)
def test_get_type(typ, expected):
    assert converter.get_type(typ) == expected


def test_convert():
    res = converter.convert(Sample)
    assert res == [
        "class Sample(BaseModel):",
        "    count: int",
        "    extra: Optional[dict]",
        "    flag: Optional[bool]",
        "    ids: List[int]",
        "    name: str",
        "    nick: Optional[str] = 'bob'",
        "    tags: Optional[List[str]]",
    ]
