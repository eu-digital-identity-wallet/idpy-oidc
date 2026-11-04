import uuid
from typing import Optional
from typing import Union

from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.time_util import utc_time_sans_frac


class PushedAuthorization(Authorization):
    request_cls = oauth2.PushedAuthorizationRequest
    response_cls = oauth2.Message
    endpoint_name = "pushed_authorization_request_endpoint"
    request_placement = "body"
    request_format = "urlencoded"
    response_placement = "body"
    response_format = "json"
    name = "pushed_authorization"
    endpoint_type = "oauth2"
    # RFC 9126 section 2.1: request_uri is refused here (_no_request_uri)
    resolves_pushed_requests = False

    def __init__(self, upstream_get, **kwargs):
        Authorization.__init__(self, upstream_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.insert(0, self._no_request_uri)
        self.post_parse_request.append(self._post_parse_request)
        self.ttl = kwargs.get("ttl", 3600)
        # request_uri -> time after which it is expired (RFC 9126 section 2.2)
        self._expires_at = {}

    def _no_request_uri(self, request, client_id, context, **kwargs):
        # RFC 9126 section 2.1: request_uri MUST NOT be provided here.
        if "request_uri" in request:
            return self.authentication_error_response(
                request,
                error="invalid_request",
                error_description="request_uri is not allowed in a pushed authorization request",
            )
        return request

    def is_expired(self, request_uri: str) -> bool:
        """An expired request_uri MUST be rejected (RFC 9126 section 4)."""
        _exp = self._expires_at.pop(request_uri, None)
        self.purge_expired()
        return _exp is not None and _exp < utc_time_sans_frac()

    def purge_expired(self) -> int:
        """Forgets pushed requests that expired without being redeemed.

        :return: The number of requests removed.
        """
        _now = utc_time_sans_frac()
        _par_db = self.upstream_get("context").par_db
        # list() snapshots the items so requests may be pushed meanwhile.
        _expired = [u for u, exp in list(self._expires_at.items()) if exp < _now]
        for _uri in _expired:
            self._expires_at.pop(_uri, None)
            _par_db.pop(_uri, None)
        return len(_expired)

    def process_request(self, request: Optional[Union[Message, str]] = None, **kwargs):
        """
        Store the request and return a URI.

        :param request:
        """
        # create URN

        if isinstance(request, str):
            _request = AuthorizationRequest().from_urlencoded(request)
        else:
            _request = AuthorizationRequest(**request)

        _request.verify(keyjar=self.upstream_get("attribute", "keyjar"))

        _urn = "urn:uuid:{}".format(uuid.uuid4())
        # Store the parsed and verified request
        self.upstream_get("context").par_db[_urn] = _request
        self._expires_at[_urn] = utc_time_sans_frac() + self.ttl

        return {
            "http_response": {"request_uri": _urn, "expires_in": self.ttl},
            "return_uri": _request["redirect_uri"],
        }
