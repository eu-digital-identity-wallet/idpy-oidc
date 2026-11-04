"""Exact OAuth error codes of the authorization and pushed authorization endpoints.

RFC 6749 section 4.1.2.1 (authorization errors), RFC 7636 section 4.4.1 (PKCE),
RFC 9126 sections 2.1, 2.3 and 4 (PAR) and RFC 9101 section 7 (request_uri).
The server is the one of test_rfc_error_conformance (set up like the AS).

When the client or its redirect URI can not be trusted the server must not
redirect (RFC 6749 section 4.1.2.1): the library then raises a client
authentication error or returns an error that carries no redirect target.
"""

import pytest

from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import UnAuthorizedClientScope

from .test_rfc_error_conformance import CODE_CHALLENGE
from .test_rfc_error_conformance import REDIRECT_URI
from .test_rfc_error_conformance import assert_error
from .test_rfc_error_conformance import make_server

AUTHZ_ARGS = {
    "client_id": "client_1",
    "redirect_uri": REDIRECT_URI,
    "scope": "openid eu.europa.ec.eudi.pid.1",
    "state": "STATE",
    "response_type": "code",
    "code_challenge": CODE_CHALLENGE,
    "code_challenge_method": "S256",
}


def args(**overrides):
    _args = {**AUTHZ_ARGS, **overrides}
    return {k: v for k, v in _args.items() if v is not None}


def assert_not_redirected(response):
    """The error is for the user agent, not for a redirect URI."""
    for key in ("return_uri", "redirect_uri", "redirect_location"):
        assert key not in response


class TestAuthorizationEndpoint:
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.server = make_server()
        self.context = self.server.context
        self.endpoint = self.server.get_endpoint("authorization")

    def test_valid_request(self):
        _req = self.endpoint.parse_request(args())
        assert "error" not in _req

    # --- errors that must not be redirected -------------------------------

    def test_unknown_client_is_not_redirected(self):
        with pytest.raises(ClientAuthenticationError):
            self.endpoint.parse_request(args(client_id="unknown"))

    def test_unregistered_redirect_uri_is_not_redirected(self):
        _resp = self.endpoint.parse_request(args(redirect_uri="https://evil.example.com/cb"))
        assert_error(_resp, "invalid_request")
        assert_not_redirected(_resp)

    @pytest.mark.parametrize(
        "redirect_uri",
        [f"{REDIRECT_URI}#fragment", f"{REDIRECT_URI}?extra=1", "https://example.com/cb/other"],
    )
    def test_redirect_uri_mismatch_is_not_redirected(self, redirect_uri):
        # RFC 6749 section 3.1.2: no fragment; registered URIs are matched exactly
        _resp = self.endpoint.parse_request(args(redirect_uri=redirect_uri))
        assert_error(_resp, "invalid_request")
        assert_not_redirected(_resp)

    def test_missing_client_id_is_not_redirected(self):
        _resp = self.endpoint.parse_request(args(client_id=None))
        assert_error(_resp, "invalid_request")
        assert_not_redirected(_resp)

    # --- errors about the request ----------------------------------------

    def test_missing_response_type_is_invalid_request(self):
        assert_error(self.endpoint.parse_request(args(response_type=None)), "invalid_request")

    def test_unsupported_response_type(self):
        # Neither the server nor anyone supports it: unsupported_response_type.
        _resp = self.endpoint.parse_request(args(response_type="foo"))
        assert_error(_resp, "unsupported_response_type")
        assert _resp["state"] == "STATE"

    def test_response_type_not_registered_for_client_is_unauthorized_client(self):
        # The server supports it, this client may not use it: unauthorized_client.
        self.context.provider_info["response_types_supported"] = ["code", "id_token"]
        _resp = self.endpoint.parse_request(args(response_type="id_token", nonce="n"))
        assert_error(_resp, "unauthorized_client")

    def test_missing_code_challenge_is_invalid_request(self):
        # RFC 7636 section 4.4.1
        _resp = self.endpoint.parse_request(args(code_challenge=None, code_challenge_method=None))
        assert_error(_resp, "invalid_request")

    def test_unsupported_code_challenge_method_is_invalid_request(self):
        # RFC 7636 section 4.4.1: "transform algorithm not supported"
        _resp = self.endpoint.parse_request(args(code_challenge_method="plain"))
        assert_error(_resp, "invalid_request")

    @pytest.mark.xfail(
        strict=True,
        raises=UnAuthorizedClientScope,
        reason="RFC 6749 section 4.1.2.1: an unknown scope (deny_unknown_scopes) should be "
        "an invalid_scope error response; the endpoint raises UnAuthorizedClientScope and "
        "leaves the mapping to the caller (the AS answers invalid_request)",
    )
    def test_unknown_scope_is_invalid_scope(self):
        self.context.cdb["client_1"]["deny_unknown_scopes"] = True
        _req = self.endpoint.parse_request(args(scope="openid unknown_scope"))
        _resp = self.endpoint.process_request(_req)
        assert_error(_resp, "invalid_scope")

    def test_unsupported_acr_is_access_denied(self):
        # No authentication method for the required ACR: access_denied, sent
        # to the client (not an exception).
        _req = self.endpoint.parse_request(args())
        _resp = self.endpoint.process_request(_req, acr="urn:example:unknown-acr")
        assert _resp["error"] == "access_denied"
        assert _resp["return_uri"] == REDIRECT_URI

    def test_failure_after_authentication_is_server_error(self, monkeypatch):
        _req = self.endpoint.parse_request(args())

        def broken(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(self.endpoint, "post_authentication", broken)
        _resp = self.endpoint.authz_part2(_req, "session_id")
        assert_error(_resp["response_args"], "server_error")
        assert _resp["response_args"]["state"] == "STATE"


class TestPushedAuthorization:
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.server = make_server()
        self.context = self.server.context
        self.par_endpoint = self.server.get_endpoint("pushed_authorization")
        self.endpoint = self.server.get_endpoint("authorization")

    def _push(self, **overrides):
        _args = args(**{"client_secret": "client_1-secret", **overrides})
        return self.par_endpoint.parse_request(_args, http_info={"headers": {}})

    def _request_uri(self):
        _req = self._push()
        return self.par_endpoint.process_request(_req)["http_response"]["request_uri"]

    def test_valid_push_and_use(self):
        _uri = self._request_uri()
        _req = self.endpoint.parse_request(args(request_uri=_uri))
        assert "error" not in _req
        assert _req["code_challenge"] == CODE_CHALLENGE

    def test_failed_client_authentication(self):
        # RFC 9126 section 2.3: invalid_client (401), raised for the caller to map
        with pytest.raises(ClientAuthenticationError):
            self._push(client_secret="wrong")

    def test_missing_response_type_is_invalid_request(self):
        assert_error(self._push(response_type=None), "invalid_request")

    def test_unregistered_redirect_uri_is_invalid_request(self):
        # RFC 9126 section 2.3: invalid_request for a bad redirection URI
        _resp = self._push(redirect_uri="https://evil.example.com/cb")
        assert_error(_resp, "invalid_request")
        assert_not_redirected(_resp)

    def test_missing_code_challenge_is_invalid_request(self):
        assert_error(self._push(code_challenge=None, code_challenge_method=None), "invalid_request")

    def test_request_uri_in_pushed_request_is_invalid_request(self):
        # RFC 9126 section 2.1: request_uri MUST NOT be provided
        assert_error(self._push(request_uri="urn:uuid:anything"), "invalid_request")

    def test_pushed_request_uri_cannot_be_pushed_again(self):
        _uri = self._request_uri()
        assert_error(self._push(request_uri=_uri), "invalid_request")
        # ... and was not used up by that attempt
        assert "error" not in self.endpoint.parse_request(args(request_uri=_uri))

    # --- request_uri at the authorization endpoint ------------------------

    def test_unknown_request_uri_is_invalid_request_uri(self):
        _resp = self.endpoint.parse_request(args(request_uri="urn:uuid:unknown"))
        assert_error(_resp, "invalid_request_uri")
        assert_not_redirected(_resp)

    def test_reused_request_uri_is_invalid_request_uri(self):
        # RFC 9126 sections 4 and 7.3: one-time use
        _uri = self._request_uri()
        assert "error" not in self.endpoint.parse_request(args(request_uri=_uri))
        assert_error(self.endpoint.parse_request(args(request_uri=_uri)), "invalid_request_uri")

    def test_expired_request_uri_is_invalid_request_uri(self):
        # RFC 9126 section 4: "An expired request_uri MUST be rejected as invalid."
        self.par_endpoint.ttl = -1
        _uri = self._request_uri()
        assert_error(self.endpoint.parse_request(args(request_uri=_uri)), "invalid_request_uri")

    def test_minimal_request_with_request_uri(self):
        _uri = self._request_uri()
        _req = self.endpoint.parse_request({"client_id": "client_1", "request_uri": _uri})
        assert not (isinstance(_req, ResponseMessage) and "error" in _req)
        assert _req["code_challenge"] == CODE_CHALLENGE
