"""Coverage tests for idpyoidc.client.oauth2.add_on.identity_assurance.

The add-on imports ``match_verified_claims`` and ``verification_per_claim`` from
``idpyoidc.message.oidc.identity_assurance`` but those functions do not exist there,
so the module cannot be imported as is. The tests below inject stand-ins for the two
helpers so the remaining add-on logic can be exercised.
"""
import importlib
import sys

import pytest
from cryptojwt.key_jar import init_key_jar

from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.client.entity import Entity
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import identity_assurance as ia_msg

MODNAME = "idpyoidc.client.oauth2.add_on.identity_assurance"
KEYSPEC = [{"type": "RSA", "use": ["sig"]}, {"type": "EC", "crv": "P-256", "use": ["sig"]}]


@pytest.mark.xfail(
    strict=True,
    raises=ImportError,
    reason="BUG: client/oauth2/add_on/identity_assurance.py:6-7 imports "
    "match_verified_claims/verification_per_claim which do not exist in "
    "message/oidc/identity_assurance.py",
)
def test_module_imports(monkeypatch):
    monkeypatch.delitem(sys.modules, MODNAME, raising=False)
    importlib.import_module(MODNAME)


@pytest.fixture
def calls():
    return {"match": [], "per_claim": []}


@pytest.fixture
def addon(monkeypatch, calls):
    """Import the add-on with stand-ins for the missing helpers."""

    def match_verified_claims(vc, request):
        calls["match"].append((vc, request))
        return [
            {"verification": {"trust_framework": vc["verification"]["trust_framework"]},
             "claims": dict(vc["claims"])},
            {"verification": False, "claims": {"ignored": "x"}},
        ]

    def verification_per_claim(verified_response):
        calls["per_claim"].append(verified_response)
        return {"per_claim": verified_response}

    monkeypatch.setattr(ia_msg, "match_verified_claims", match_verified_claims, raising=False)
    monkeypatch.setattr(ia_msg, "verification_per_claim", verification_per_claim, raising=False)
    monkeypatch.delitem(sys.modules, MODNAME, raising=False)
    mod = importlib.import_module(MODNAME)
    yield mod
    sys.modules.pop(MODNAME, None)


RESPONSE = {
    "sub": "248289761001",
    "email": "jane@example.com",
    "_claim_names": {"verified_claims": "src1"},
    "_claim_sources": {"src1": {"JWT": "xxx"}},
    "verified_claims": {"verification": {"trust_framework": "x"}},
}

VERIFIED = [
    {"verification": {"trust_framework": "de_aml"}, "claims": {"given_name": "Max"}},
    {"verification": False, "claims": {"family_name": "Meier"}},
]


class TestFormatResponse:
    def test_claims(self, addon):
        res = addon.format_response("claims", RESPONSE, VERIFIED)
        assert res == {"sub": "248289761001", "email": "jane@example.com", "given_name": "Max"}

    def test_per_verification(self, addon):
        res = addon.format_response("per_verification", RESPONSE, VERIFIED)
        assert res == {
            "": {"sub": "248289761001", "email": "jane@example.com"},
            '{"trust_framework": "de_aml"}': {"given_name": "Max"},
        }

    def test_per_claim(self, addon, calls):
        verified = {}
        res = addon.format_response("per_claim", RESPONSE, verified)
        assert verified[""] == {"sub": "248289761001", "email": "jane@example.com"}
        assert calls["per_claim"] == [verified]
        assert res == {"per_claim": verified}


def _entity():
    config = {
        "client_id": "client_id",
        "client_secret": "a longesh password",
        "redirect_uris": ["https://example.com/cli/authz_cb"],
        "issuer": "https://server.otherop.com",
        "base_url": "https://example.com/cli/",
    }
    return Entity(
        config=config, services=DEFAULT_OIDC_SERVICES, keyjar=init_key_jar(key_defs=KEYSPEC)
    )


class TestAddSupport:
    @pytest.fixture(autouse=True)
    def setup(self, addon):
        self.addon = addon
        self.entity = _entity()
        self.service = self.entity.get_service("userinfo")
        self.context = self.entity.get_context()

    def test_add_support_defaults(self):
        before = len(self.service.post_parse_process)
        self.addon.add_support(
            self.entity.get_services(),
            trust_frameworks_supported=["de_aml"],
            evidence_supported=["document"],
        )
        conf = self.context.add_on["identity_assurance"]
        assert conf == {
            "verified_claims_supported": True,
            "trust_frameworks_supported": ["de_aml"],
            "evidence_supported": ["document"],
            "id_documents_supported": None,
            "id_documents_verification_methods_supported": None,
            "claims_in_verified_claims_supported": None,
            "verified_claims_request": None,
            "response_format": "claims",
        }
        assert len(self.service.post_parse_process) == before + 1
        assert self.service.post_parse_process[-1] is self.addon.identity_assurance_process

    def test_add_support_all_args(self):
        self.addon.add_support(
            self.entity.get_services(),
            trust_frameworks_supported=["eidas"],
            evidence_supported=["document", "electronic_record"],
            id_documents_supported=["idcard"],
            id_documents_verification_methods_supported=["pipp"],
            claims_in_verified_claims_supported=["given_name"],
            verified_claims_request={"claims": {"given_name": None}},
            response_format="per_verification",
        )
        conf = self.context.add_on["identity_assurance"]
        assert conf["id_documents_supported"] == ["idcard"]
        assert conf["claims_in_verified_claims_supported"] == ["given_name"]
        assert conf["response_format"] == "per_verification"

    def _store_auth_request(self, claims=None):
        _cstate = self.context.cstate
        state = _cstate.create_state(iss="issuer")
        req = AuthorizationRequest(redirect_uri="https://example.com/cli/authz_cb", state=state)
        if claims is not None:
            req["claims"] = claims
        _cstate.update(state, req)
        return state

    def test_process_without_claims_request(self):
        state = self._store_auth_request()
        resp = {"sub": "a"}
        assert self.addon.identity_assurance_process(resp, self.context, state) is resp

    def test_process_without_userinfo_claims(self):
        state = self._store_auth_request({"id_token": {"email": None}})
        resp = {"sub": "a"}
        assert self.addon.identity_assurance_process(resp, self.context, state) is resp

    def test_process_with_verified_claims(self, calls):
        self.addon.add_support(
            self.entity.get_services(),
            trust_frameworks_supported=["de_aml"],
            evidence_supported=["document"],
            response_format="claims",
        )
        request_vc = {
            "verification": {"trust_framework": None},
            "claims": {"given_name": None},
        }
        state = self._store_auth_request({"userinfo": {"verified_claims": request_vc}})
        resp = {
            "sub": "a",
            "verified_claims": {
                "verification": {"trust_framework": "de_aml"},
                "claims": {"given_name": "Max"},
            },
        }
        res = self.addon.identity_assurance_process(resp, self.context, state)
        assert res == {"sub": "a", "given_name": "Max"}
        vc, req = calls["match"][0]
        assert isinstance(vc, ia_msg.VerifiedClaims)
        assert req["verification"] == {"trust_framework": None}
