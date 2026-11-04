"""Coverage tests for idpyoidc.claims, idpyoidc.node, idpyoidc.context,
idpyoidc.combo, idpyoidc.server.claims.oauth2 and
idpyoidc.client.claims.oauth2resource."""
import pytest
from cryptojwt import KeyJar
from cryptojwt.key_jar import build_keyjar

from idpyoidc import claims
from idpyoidc import node
from idpyoidc.client.claims import oauth2resource
from idpyoidc.combo import Combo
from idpyoidc.context import OidcContext
from idpyoidc.context import add_issuer
from idpyoidc.node import ClientUnit
from idpyoidc.node import Collection
from idpyoidc.node import Node
from idpyoidc.node import Unit
from idpyoidc.node import create_keyjar
from idpyoidc.node import make_keyjar
from idpyoidc.node import topmost_unit
from idpyoidc.server.claims import oauth2 as server_oauth2

KEYDEFS = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]
KEY_CONF = {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"}


def _jwks():
    return build_keyjar(KEYDEFS).export_jwks()


# =================================================================== claims


class C(claims.Claims):
    _supports = {
        "response_types": ["code"],
        "scope": None,
        "form_post": None,
        "grant_types": lambda: ["authorization_code"],
    }

    def get_id(self, configuration):
        return configuration.get("client_id")

    def get_base_url(self, configuration, entity_id=""):
        return configuration.get("base_url", entity_id)


class CNoFormPost(C):
    _supports = {"response_types": ["code", "id_token"]}


class CRecording(C):
    def __init__(self, *args, **kwargs):
        C.__init__(self, *args, **kwargs)
        self.calls = []

    def locals(self, info):
        self.calls.append("locals")

    def verify_rules(self, supports):
        self.calls.append("verify_rules")
        return True


class CExtraKeys(C):
    """add_extra_keys provides a key jar when none was produced."""

    def __init__(self, *args, **kwargs):
        C.__init__(self, *args, **kwargs)
        self.extra = build_keyjar(KEYDEFS)

    def _keyjar(self, keyjar=None, conf=None, entity_id=""):
        return None, ""

    def add_extra_keys(self, keyjar, id):
        return self.extra

    def get_jwks(self, keyjar):
        return {"keys": [], "from": keyjar}


def test_claims_init_and_accessors():
    c = C(prefer={"scope": ["openid"], "bogus": 1}, callback_path={"code": "cb"})
    assert c.prefer == {"scope": ["openid"]}
    assert C(prefer="x").prefer == {}
    c.set_usage("scope", ["email"])
    assert c.get_use() == {"scope": ["email"]}
    assert c.get_usage("scope") == ["email"]
    assert c.get_usage("nope", 1) == 1
    c.set_preference("a", 1)
    assert c.get_preference("a") == 1
    c.remove_preference("a")
    c.remove_preference("a")
    assert c.get_preference("a", "d") == "d"
    assert c.prefers() == {"scope": ["openid"]}
    c.set("x", 2)
    assert c.get("x") == 2
    assert c.get("y", 3) == 3
    assert c.supports()["grant_types"] == ["authorization_code"]
    assert c.supported("scope") and not c.supported("zzz")
    assert c.construct_uris() is None


def test_claims_base_hooks():
    c = claims.Claims()
    with pytest.raises(NotImplementedError):
        c.get_id({})
    with pytest.raises(NotImplementedError):
        c.get_base_url({})
    assert c.add_extra_keys(None, "") is None
    kj = build_keyjar(KEYDEFS)
    assert len(c.get_jwks(kj)["keys"]) == 1
    assert c.verify_rules({}) is True
    assert c.locals({}) is None


def test_get_claim_order():
    c = C()
    assert c.get_claim("scope", "dflt") == "dflt"
    c.set_preference("scope", ["p"])
    assert c.get_claim("scope") == ["p"]
    c.set_usage("scope", ["u"])
    assert c.get_claim("scope") == ["u"]


def test_claims_dump_load():
    c = C(prefer={"scope": ["openid"]})
    c.set_usage("response_types", ["code"])
    d = claims.claims_dump(c, [])
    loaded = claims.claims_load(d)
    assert isinstance(loaded, C)
    assert loaded.prefer == {"scope": ["openid"]}
    assert loaded.use == {"response_types": ["code"]}


def test_construct_redirect_uris_derived():
    c = C(callback_path={"code": "c", "implicit": "i", "form_post": "f"})
    c.set_usage("response_types", ["code", "id_token", "id_token token"])
    c.construct_redirect_uris("https://rp", "hx")
    # "id_token token" is not treated as implicit in claims.py
    assert c.callback == {
        "code": "https://rp/c/hx",
        "implicit": "https://rp/i/hx",
        "form_post": "https://rp/f/hx",
    }
    assert c.get_preference("callbacks") == c.callback
    assert c.get_preference("redirect_uris") == list(c.callback.values())


def test_construct_redirect_uris_defaults_and_explicit():
    c = CNoFormPost(callback_path={"code": "c", "implicit": "i"})
    c.construct_redirect_uris("https://rp", "1")
    assert c.callback == {"code": "https://rp/c/1", "implicit": "https://rp/i/1"}

    c2 = C()
    c2.construct_redirect_uris("https://rp", "1", callbacks={"x": "https://x"})
    assert c2.get_preference("redirect_uris") == ["https://x"]


def test_construct_redirect_uris_nothing():
    c = CNoFormPost()
    c.set_usage("response_types", ["token"])
    c.construct_redirect_uris("https://rp", "1")
    assert c.callback == {}
    assert c.get_preference("redirect_uris") is None


def test_claims_keyjar_variants():
    c = C()
    kj, p = c._keyjar(None, {"keys": KEY_CONF, "httpc_params": {"timeout": 3}}, entity_id="me")
    assert p == "static/jwks.json"
    assert "me" in kj and "" in kj
    assert kj.httpc_params == {"timeout": 3}

    kj, p = c._keyjar(None, {"key_conf": {"key_defs": KEYDEFS, "uri_path": "k"}})
    assert p == "k" and "" in kj

    kj, p = c._keyjar(None, {"jwks": _jwks(), "key_conf": None}, entity_id="me")
    assert p == "" and "me" in kj

    kj, p = c._keyjar(None, {})
    assert "" not in kj

    given = KeyJar()
    assert c._keyjar(given, {"keys": {"uri_path": "a"}}) == (given, "a")
    assert c._keyjar(given, {"key_conf": {"uri_path": "b"}}) == (given, "b")
    assert c._keyjar(given, {"key_conf": {}}) == (given, "")


def test_claims_handle_keys_branches():
    c = C()
    r = c.handle_keys({"jwks_uri": "https://j"})
    assert r["jwks_uri"] == "https://j" and r["jwks"] is None

    r = c.handle_keys({"keys": KEY_CONF, "base_url": "https://b"})
    assert r["jwks_uri"] == "https://b/static/jwks.json"

    r = c.handle_keys({"keys": KEY_CONF}, entity_id="https://e/")
    assert r["jwks_uri"] == "https://e/static/jwks.json"

    r = c.handle_keys({"key_conf": {"key_defs": KEYDEFS}, "client_id": "cid"})
    assert r["jwks_uri"] is None
    assert len(r["jwks"]["keys"]) == 1
    assert "cid" in r["keyjar"]


def test_claims_handle_keys_extra_keyjar_used_when_none():
    c = CExtraKeys()
    r = c.handle_keys({})
    assert r["keyjar"] is c.extra
    assert r["jwks"]["from"] is c.extra


def test_claims_load_conf():
    c = CRecording()
    conf = {
        "preference": {"scope": ["openid"], "nope": 1},
        "capabilities": {"response_types": ["code"]},
        "grant_types": ["implicit"],
        "other": 1,
        "jwks_uri": "https://j",
    }
    kj = c.load_conf(conf, c.supports())
    assert isinstance(kj, KeyJar)
    assert c.get_preference("scope") == ["openid"]
    assert c.get_preference("response_types") == ["code"]
    assert c.get_preference("grant_types") == ["implicit"]
    assert c.get_preference("nope") is None
    assert c.get_preference("other") is None
    assert c.get_preference("jwks_uri") == "https://j"
    assert "jwks" not in c.prefer
    assert c.calls == ["locals", "verify_rules"]


def test_claims_load_conf_keeps_given_keyjar():
    c = C()
    given = build_keyjar(KEYDEFS)
    assert c.load_conf({}, c.supports(), keyjar=given) is given
    assert len(c.get_preference("jwks")["keys"]) == 1


# ===================================================================== node


def test_create_keyjar_given():
    kj = KeyJar()
    assert create_keyjar(kj) is kj


def test_create_keyjar_key_conf_with_id():
    kj = create_keyjar(key_conf=KEY_CONF, id="me")
    assert "" in kj and "me" in kj


def test_create_keyjar_conf_variants():
    kj = create_keyjar(conf={"keys": KEY_CONF})
    assert "" in kj
    kj = create_keyjar(conf={"key_conf": {"key_defs": KEYDEFS}})
    assert "" in kj
    kj = create_keyjar(conf={"jwks": _jwks()}, id="x")
    assert "" in kj and "x" in kj
    kj = create_keyjar(conf={"foo": 1}, id="x")
    assert isinstance(kj, KeyJar) and "x" not in kj


def test_create_keyjar_nothing():
    assert create_keyjar() is None


def test_make_keyjar_false():
    assert make_keyjar(False, {}) is None


def test_make_keyjar_from_config_keyjar():
    given = build_keyjar(KEYDEFS)
    assert make_keyjar(None, {"keyjar": given}) is given


def test_make_keyjar_jwks_and_client_secret():
    import json

    jwks = json.dumps(_jwks())
    kj = make_keyjar(None, {"jwks": jwks, "client_secret": "0123456789abcdef0123456789abcdef"}, client_id="cid")
    # jwks imported under client_id, symmetric keys added under cid and ""
    assert len(kj.get_issuer_keys("cid")) == 2
    assert len(kj.get_issuer_keys("")) == 1


def test_make_keyjar_key_conf_with_issuer():
    kj = make_keyjar(None, {}, key_conf={"key_defs": KEYDEFS}, issuer_id="https://op")
    assert "https://op" in kj and "" in kj


def test_make_keyjar_from_config_keys():
    kj = make_keyjar(None, {"keys": {"key_defs": KEYDEFS}}, client_id="cid")
    # no client_secret -> only asymmetric keys copied to cid
    assert len(kj.get_issuer_keys("cid")) == 1


def test_make_keyjar_secret_only():
    kj = make_keyjar(None, {"client_secret": "0123456789abcdef0123456789abcdef"}, client_id="cid")
    assert len(kj.get_issuer_keys("cid")) == 1
    assert len(kj.get_issuer_keys("")) == 1


def test_make_keyjar_empty():
    kj = make_keyjar(None, {})
    assert isinstance(kj, KeyJar)
    assert len(kj) == 0
    kj = make_keyjar(None, {}, client_id="cid")
    assert len(kj) == 0


def test_node_basic():
    n = Node()
    n.foo = "bar"
    assert n.get_attribute("foo") == "bar"
    assert n.get_attribute("missing") is None
    n.set_attribute("none_attr", None)
    assert n.get_attribute("none_attr") is None
    assert n.unit_get("unit") is n
    assert n.unit_get("attribute", "foo") == "bar"
    assert n.unit_get("nonexistent") is None


def test_node_upstream():
    parent = Node()
    parent.foo = "parent"
    parent.bar = "pbar"
    child = Node(upstream_get=parent.unit_get)
    child.bar = None
    assert child.get_attribute("foo") == "parent"
    assert child.get_attribute("bar") == "pbar"


def test_unit_init_defaults():
    u = Unit()
    assert u.upstream_get is None
    assert u.httpc is None
    assert u.httpc_params == {}
    assert isinstance(u.keyjar, KeyJar)


def test_unit_keyjar_gets_httpc():
    sentinel = object()
    u = Unit(httpc=sentinel, httpc_params={"verify": False}, key_conf={"key_defs": KEYDEFS})
    assert u.keyjar.httpc is sentinel
    assert u.keyjar.httpc_params == {"verify": False}

    u2 = Unit(config={"httpc_params": {"timeout": 5}, "key_conf": {"key_defs": KEYDEFS}})
    assert u2.httpc_params == {"timeout": 5}
    assert u2.keyjar.httpc_params == {"timeout": 5}


def test_unit_keyjar_false():
    u = Unit(keyjar=False)
    assert u.keyjar is None


class _Ctx:
    pass


def test_unit_get_attribute_chain():
    top = Unit()
    top.top_attr = "T"
    u = Unit(upstream_get=top.unit_get)
    u.own = "O"
    u.context = _Ctx()
    u.context.ctx_attr = "C"
    assert u.get_attribute("own") == "O"
    assert u.get_attribute("ctx_attr") == "C"
    assert u.get_attribute("top_attr") == "T"
    assert u.unit_get("unit") is u
    assert u.unit_get("nope") is None
    u.set_attribute("own", "O2")
    assert u.own == "O2"


def test_unit_get_attribute_no_upstream():
    u = Unit()
    u.context = _Ctx()
    u.context.empty = ""
    assert u.get_attribute("empty") == ""
    assert u.get_attribute("missing") is None


def test_topmost_unit():
    top = Unit()
    mid = Unit(upstream_get=top.unit_get)
    bottom = Unit(upstream_get=mid.unit_get)
    assert topmost_unit(bottom) is top
    assert topmost_unit(top) is top
    assert topmost_unit(object()) is not None

    class NoUnit:
        upstream_get = staticmethod(lambda what, *a: None)

    nu = NoUnit()
    assert topmost_unit(nu) is nu


def test_client_unit():
    cu = ClientUnit(config={"client_id": "cid", "client_secret": "0123456789abcdef0123456789abcdef", "entity_id": "eid"})
    assert cu.entity_id == "eid"
    assert cu.client_id == "cid"
    assert cu.context is None
    assert len(cu.keyjar.get_issuer_keys("cid")) == 1

    cu2 = ClientUnit(entity_id="e2")
    assert cu2.client_id == "e2"
    assert cu2.entity_id == "e2"


def test_client_unit_context_attribute():
    parent = Unit()
    parent.context = _Ctx()
    parent.get_context_attribute = lambda attr, *a: f"up:{attr}"
    ctx = _Ctx()
    ctx.a = "val"
    ctx.b = None
    cu = ClientUnit(upstream_get=parent.unit_get, context=ctx)
    assert cu.get_context_attribute("a") == "val"
    assert cu.get_context_attribute("b") == "up:b"

    cu2 = ClientUnit(context=ctx)
    assert cu2.get_context_attribute("b") is None


class _Func:
    def __init__(self, upstream_get=None, value=None):
        self.upstream_get = upstream_get
        self.value = value


def test_collection_functions_and_attributes():
    col = Collection(
        config={"entity_id": "https://col"},
        functions={
            "f1": {"class": _Func, "kwargs": {"value": 1}},
            "f2": {"class": _Func, "kwargs": {"value": 2}},
        },
        claims={"x": 1},
    )
    assert col.entity_id == "https://col"
    assert col.claims == {"x": 1}
    assert col.f1.value == 1 and col.f2.value == 2
    # functions get the collection's unit_get as upstream
    assert col.f1.upstream_get("unit") is col
    assert col.get_attribute("entity_id") == "https://col"
    assert col.get_attribute("missing") is None
    assert col.get_context_attribute("anything") is None


def test_collection_string_class_and_upstream():
    parent = Unit()
    parent.shared = "S"
    parent.get_context_attribute = lambda attr, *a: f"pc:{attr}"
    col = Collection(
        upstream_get=parent.unit_get,
        entity_id="e",
        functions={"f": {"class": "idpyoidc.node.Node", "kwargs": {}}},
    )
    assert isinstance(col.f, Node)
    assert col.claims == {}
    assert col.get_attribute("shared") == "S"
    assert col.get_context_attribute("z") == "pc:z"
    col.context = _Ctx()
    col.context.z = "local"
    assert col.get_context_attribute("z") == "local"
    col.context.z = None
    assert col.get_context_attribute("z") == "pc:z"


# ================================================================== context


def test_add_issuer():
    conf = {
        "abstract_storage_cls": "some.Class",
        "jwks": {"label": "x"},
    }
    res = add_issuer(conf, "https://op.example.com/a b")
    assert res["abstract_storage_cls"] == "some.Class"
    assert res["jwks"] == {"label": "x", "issuer": "https%3A%2F%2Fop.example.com%2Fa+b"}
    # original untouched (shallow copy per value)
    assert "issuer" not in conf["jwks"]


@pytest.mark.parametrize(
    "config,entity_id,expected",
    [
        (None, "explicit", "explicit"),
        ({"client_id": "cid", "issuer": "iss"}, "", "cid"),
        ({"issuer": "iss", "entity_id": "eid"}, "", "iss"),
        ({"entity_id": "eid"}, "", "eid"),
        ({"other": 1}, "", None),
        (None, "", ""),
        ({}, "", ""),
    ],
)
def test_oidc_context_entity_id(config, entity_id, expected):
    assert OidcContext(config=config, entity_id=entity_id).entity_id == expected


def test_oidc_context_dump_load():
    c = OidcContext(entity_id="https://e")
    d = c.dump()
    assert d == {"entity_id": "https://e"}
    assert OidcContext().load(d).entity_id == "https://e"


# ==================================================================== combo


class _Part:
    def __init__(self, upstream_get=None, entity_id="", httpc=None, **kwargs):
        self.upstream_get = upstream_get
        self.entity_id = entity_id
        self.httpc = httpc
        self.kwargs = kwargs


def test_combo_basic():
    httpc = object()
    conf = {
        "entity_id": "https://combo",
        "a": {"class": _Part, "kwargs": {"foo": 1}},
        "b": {"class": "idpyoidc.node.Collection", "kwargs": {}},
        "plain": {"no": "class"},
        "scalar": 1,
    }
    combo = Combo(config=conf, httpc=httpc)
    assert combo.entity_id == "https://combo"
    assert combo.name == "root"
    assert sorted(combo.get_entity_types()) == ["a", "b"]
    assert sorted(combo.keys()) == ["a", "b"]
    assert dict(combo.items())["a"] is combo["a"]
    assert combo["a"].entity_id == "https://combo"
    assert combo["a"].httpc is httpc
    assert combo["a"].kwargs == {"foo": 1}
    assert combo["a"].upstream_get("unit") is combo
    assert isinstance(combo["b"], Collection)
    assert combo["b"].entity_id == "https://combo"
    assert combo["missing"] is None
    combo["c"] = "x"
    assert combo["c"] == "x"
    assert combo.httpc_params == {}


def test_combo_entity_id_arg_overrides():
    combo = Combo(config={"entity_id": "conf"}, entity_id="arg")
    assert combo.entity_id == "arg"
    assert combo.get_entity_types() == []


def test_combo_httpc_params_propagation():
    hp = {"verify": False}
    conf = {
        "httpc_params": hp,
        "with_config": {"class": _Part, "kwargs": {"config": {"x": 1}}},
        "with_config_hp": {
            "class": _Part,
            "kwargs": {"config": {"httpc_params": {"verify": True}}},
        },
        "no_config": {"class": _Part, "kwargs": {}},
        "no_config_hp": {"class": _Part, "kwargs": {"httpc_params": {"timeout": 1}}},
    }
    combo = Combo(config=conf, entity_id="https://e")
    assert combo.httpc_params == hp
    assert combo["with_config"].kwargs["config"]["httpc_params"] == hp
    assert combo["with_config_hp"].kwargs["config"]["httpc_params"] == {"verify": True}
    assert combo["no_config"].kwargs["httpc_params"] == hp
    assert combo["no_config_hp"].kwargs["httpc_params"] == {"timeout": 1}


def test_combo_spec_without_kwargs_gets_no_params_via_temp_dict():
    # spec without "kwargs": _add_httpc_params writes into a throw-away dict
    conf = {"httpc_params": {"v": 1}, "p": {"class": _Part}}
    combo = Combo(config=conf)
    assert "httpc_params" not in combo["p"].kwargs


def test_combo_explicit_httpc_params():
    conf = {"p": {"class": _Part, "kwargs": {"config": {}}}}
    combo = Combo(config=conf, httpc_params={"h": 1})
    assert combo["p"].kwargs["config"]["httpc_params"] == {"h": 1}
    assert combo._get_httpc_params({"httpc_params": 3}) == 3


# ========================================================= server oauth2 claims


def test_server_oauth2_claims_provider_info():
    c = server_oauth2.Claims(prefer={"scopes_supported": ["read"], "bad": 1})
    assert c.prefer == {"scopes_supported": ["read"]}
    assert c.register2preferred["scope"] == "scopes_supported"
    supports = {
        "response_types_supported": ["code"],
        "grant_types_supported": [],
        "issuer": "https://op",
        "not_in_message": "x",
    }
    info = c.provider_info(supports)
    assert info == {
        "scopes_supported": ["read"],
        "response_types_supported": ["code"],
        "issuer": "https://op",
    }


def test_server_oauth2_claims_preference_wins():
    c = server_oauth2.Claims()
    c.set_preference("response_types_supported", ["token"])
    info = c.provider_info({"response_types_supported": ["code"]})
    assert info["response_types_supported"] == ["token"]
    assert c.callback_uris == ["redirect_uris"]


# ================================================= client oauth2resource claims


def test_oauth2resource_registration_request_defaults():
    c = oauth2resource.Claims()
    # only non-empty supported defaults survive; none of them overlap the request
    assert c.create_registration_request() == {}


def test_oauth2resource_registration_request():
    c = oauth2resource.Claims(
        prefer={
            "resource": ["https://rs", "https://other"],
            "authorization_servers": "https://as",
            "scopes_supported": ["read", "write"],
            "organization_name": "Org",
            "bearer_methods_supported": [],
            "not_supported": "x",
        }
    )
    assert "not_supported" not in c.prefer
    c.set_preference("jwks_uri", "https://rs/jwks")
    req = c.create_registration_request()
    assert req == {
        "resource": "https://rs",
        "authorization_servers": ["https://as"],
        "scopes_supported": ["read", "write"],
        "organization_name": "Org",
        "jwks_uri": "https://rs/jwks",
    }


def test_oauth2resource_uses_supports_when_not_preferred(monkeypatch):
    monkeypatch.setitem(oauth2resource.Claims._supports, "resource_tos_uri", "https://tos")
    c = oauth2resource.Claims()
    assert c.create_registration_request() == {"resource_tos_uri": "https://tos"}


def test_unit_get_attribute_without_context_goes_upstream():
    top = Unit()
    top.only_top = "T"
    u = Unit(upstream_get=top.unit_get)
    assert getattr(u, "context", None) is None
    assert u.get_attribute("only_top") == "T"
    assert u.get_attribute("nowhere") is None
