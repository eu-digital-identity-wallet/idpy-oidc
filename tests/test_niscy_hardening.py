"""Regression tests for the niscy-eudiw hardening of the fork."""

from types import SimpleNamespace

import pytest

from idpyoidc.message.oauth2 import AuthorizationErrorResponse
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.oauth2.add_on import pkce


class _Endpoint:
    def __init__(self, context):
        self.post_parse_request = []
        self._context = context

    def upstream_get(self, what, *args):
        return self._context


def _context(essential=True, methods=("S256",), client=None):
    context = SimpleNamespace(
        cdb={"client": client or {}},
        add_on={},
        set_preference=lambda *args: None,
    )
    endpoints = {"authorization": _Endpoint(context), "token": _Endpoint(context)}
    pkce.add_support(endpoints, code_challenge_methods=list(methods), essential=essential)
    return context


def _request(**extra):
    return AuthorizationRequest(
        client_id="client", response_type="code", redirect_uri="https://w.example/cb", **extra
    )


def _is_error(result):
    return isinstance(result, AuthorizationErrorResponse)


class TestPkce:
    def test_missing_code_challenge_is_rejected(self):
        assert _is_error(pkce.post_authn_parse(_request(), "client", _context()))

    def test_plain_method_is_rejected(self):
        request = _request(code_challenge="abc", code_challenge_method="plain")
        assert _is_error(pkce.post_authn_parse(request, "client", _context()))

    def test_missing_method_defaults_to_plain_and_is_rejected(self):
        request = _request(code_challenge="abc")
        assert _is_error(pkce.post_authn_parse(request, "client", _context()))

    def test_s256_is_accepted(self):
        request = _request(code_challenge="abc", code_challenge_method="S256")
        assert not _is_error(pkce.post_authn_parse(request, "client", _context()))

    def test_client_setting_cannot_relax_pkce(self):
        context = _context(client={"pkce_essential": False})
        assert _is_error(pkce.post_authn_parse(_request(), "client", context))

    def test_client_setting_can_require_pkce(self):
        context = _context(essential=False, client={"pkce_essential": True})
        assert _is_error(pkce.post_authn_parse(_request(), "client", context))

    def test_internal_pre_authorized_request_skips_pkce(self):
        result = pkce.post_authn_parse(_request(), "client", _context(), pre_authorized_code=True)
        assert not _is_error(result)

    def test_method_list_limits_supported_methods(self):
        context = _context(methods=["S256"])
        assert list(context.add_on["pkce"]["code_challenge_methods"]) == ["S256"]

    def test_unknown_method_is_refused_at_start_up(self):
        with pytest.raises(ValueError):
            _context(methods=["S256", "nope"])

    def test_misspelt_option_is_refused_at_start_up(self):
        context = SimpleNamespace(cdb={}, add_on={}, set_preference=lambda *args: None)
        endpoints = {"authorization": _Endpoint(context), "token": _Endpoint(context)}
        with pytest.raises(ValueError):
            pkce.add_support(endpoints, code_challenge_method="S256", essential=True)


class TestSanitize:
    """``sanitize`` returned its input: codes, verifiers, tokens and client
    secrets were written to the logs."""

    def test_dict_values_are_redacted(self):
        from idpyoidc.util import sanitize

        out = sanitize({"code": "c", "client_id": "w", "inner": {"client_secret": "s", "n": 1}})
        assert out == {"code": "<redacted>", "client_id": "w", "inner": {"client_secret": "<redacted>", "n": 1}}

    def test_message_is_redacted(self):
        from idpyoidc.message.oauth2 import AccessTokenRequest
        from idpyoidc.util import sanitize

        out = sanitize(AccessTokenRequest(code="c", code_verifier="v", grant_type="authorization_code"))
        assert out["code"] == out["code_verifier"] == "<redacted>"
        assert out["grant_type"] == "authorization_code"

    @pytest.mark.parametrize(
        "text",
        [
            "code=secret-code&state=s",
            "{'code': 'secret-code', 'state': 's'}",
            '{"access_token": "secret-code", "token_type": "DPoP"}',
        ],
    )
    def test_strings_are_redacted(self, text):
        from idpyoidc.util import sanitize

        assert "secret-code" not in sanitize(text)

    def test_line_breaks_are_escaped(self):
        from idpyoidc.util import sanitize

        assert "\n" not in sanitize("a\nb") and "\r" not in sanitize("a\rb")

    def test_other_values_are_kept(self):
        from idpyoidc.util import sanitize

        assert sanitize("response_type=code&client_id=w") == "response_type=code&client_id=w"


class TestTokenClientStatus:
    """The access token's client_status came from the shared client database
    entry, which another wallet instance with the same client_id may have
    overwritten in the meantime."""

    def _token(self, cdb):
        from idpyoidc.server.token.jwt_token import JWTToken

        token = JWTToken.__new__(JWTToken)
        token.cdb = cdb
        token.upstream_get = lambda *args: None
        return token

    def test_status_of_the_verified_attestation_wins(self):
        from idpyoidc.server.client_authn import VERIFIED_CLIENT_STATUS

        token = self._token({"w": {"client_status": {"status": "other-instance"}}})
        marker = VERIFIED_CLIENT_STATUS.set({"status": "this-request"})
        try:
            payload = token.load_custom_claims({"client_id": "w"})
        finally:
            VERIFIED_CLIENT_STATUS.reset(marker)
        assert payload["client_status"] == {"status": "this-request"}

    def test_falls_back_to_the_client_entry_without_an_attestation(self):
        token = self._token({"w": {"client_status": {"status": "stored"}}})
        assert token.load_custom_claims({"client_id": "w"})["client_status"] == {"status": "stored"}

    def test_client_authentication_resets_the_status(self):
        from idpyoidc.server.client_authn import VERIFIED_CLIENT_STATUS, verify_client

        VERIFIED_CLIENT_STATUS.set({"status": "stale"})
        try:
            verify_client(request={}, http_info={"headers": {}}, endpoint=None)
        except Exception:
            pass
        assert VERIFIED_CLIENT_STATUS.get() is None


class TestPublicClientWithDpop:
    """A public client sending a DPoP proof (RFC 9449) was not recognised as
    public, so wallet attestation could not be made optional with DPoP on."""

    def _usable(self, headers):
        from idpyoidc.server.client_authn import PublicAuthn

        return PublicAuthn(None).is_usable(request={"client_id": "w"}, http_info={"headers": headers})

    def test_dpop_proof_does_not_exclude_public(self):
        assert self._usable({"DPoP": "proof"})

    def test_wallet_attestation_headers_exclude_public(self):
        assert not self._usable({"OAuth-Client-Attestation": "a", "OAuth-Client-Attestation-PoP": "b"})

    def test_authorization_header_excludes_public(self):
        assert not self._usable({"Authorization": "Basic x"})


class TestJarEncryptionSettings:
    """Unsupported request object encryption was silently ignored (the
    AttributeError was created, not raised)."""

    class _Service:
        def __init__(self):
            self.post_construct = []

        def upstream_get(self, what):
            from types import SimpleNamespace

            return SimpleNamespace(add_on={})

    @pytest.mark.parametrize(
        "alg, enc",
        [("not-an-alg", "A128GCM"), ("ECDH-ES", "not-an-enc")],
    )
    def test_unsupported_encryption_is_refused(self, alg, enc):
        from idpyoidc.client.oauth2.add_on import jar

        with pytest.raises(AttributeError):
            jar.add_support({"authorization": self._Service()}, request_object_encryption_alg=alg,
                            request_object_encryption_enc=enc)

    def test_supported_encryption_is_kept(self):
        from idpyoidc.client.oauth2.add_on import jar

        service = self._Service()
        context = service.upstream_get("context")
        service.upstream_get = lambda what: context
        jar.add_support({"authorization": service}, request_object_encryption_alg="ECDH-ES",
                        request_object_encryption_enc="A128GCM")
        assert context.add_on["jar"]["request_object_encryption_alg"] == "ECDH-ES"


class TestCurrentIssuer:
    """An application serving several issuers sets CURRENT_ISSUER per request."""

    def test_falls_back_to_the_configured_issuer(self):
        from idpyoidc.server.util import current_issuer

        assert current_issuer(SimpleNamespace(issuer="https://as.example")) == "https://as.example"

    def test_current_issuer_wins(self):
        from idpyoidc.server.util import CURRENT_ISSUER, current_issuer

        marker = CURRENT_ISSUER.set("https://as.example/fe")
        try:
            assert current_issuer(SimpleNamespace(issuer="https://as.example")) == "https://as.example/fe"
        finally:
            CURRENT_ISSUER.reset(marker)

    def test_endpoint_url_under_the_current_issuer(self):
        from idpyoidc.server.util import CURRENT_ISSUER, endpoint_url

        endpoint = SimpleNamespace(endpoint_path="token", full_path="https://as.example/token")
        assert endpoint_url(endpoint) == "https://as.example/token"
        marker = CURRENT_ISSUER.set("https://as.example/fe")
        try:
            assert endpoint_url(endpoint) == "https://as.example/fe/token"
        finally:
            CURRENT_ISSUER.reset(marker)
