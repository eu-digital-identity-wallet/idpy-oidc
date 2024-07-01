from typing import Optional
from typing import Union
import uuid

from idpyoidc.message import Message
from idpyoidc.message import oauth2
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.server.oauth2.authorization import Authorization
from idpyoidc.server.util import verify_client_attestation, verify_pop_attestation


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

    def __init__(self, upstream_get, **kwargs):
        Authorization.__init__(self, upstream_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._post_parse_request)
        self.ttl = kwargs.get("ttl", 3600)

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

        if (
            "client_assertion_type" in _request
            and _request["client_assertion_type"]
            == "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
        ):
            if "client_assertion" not in _request:
                return self.error_cls(
                    error="invalid_client_assertion", error_description="Missing client_assertion"
                )
            separated_attestation = _request["client_assertion"].split("~")
            print("\n separated: ", separated_attestation)
            if len(separated_attestation) != 2:
                return self.error_cls(
                    error="invalid_client_assertion", error_description="Missing an attestation"
                )
            print("\n----Separated---\n", separated_attestation)
            attestationClient = separated_attestation[0]
            attestationPop = separated_attestation[1]
            public_key = verify_client_attestation(attestationClient, _request["client_id"])
            verify_pop_attestation(attestationPop, public_key, _request["client_id"])

        return {
            "http_response": {"request_uri": _urn, "expires_in": self.ttl},
            "return_uri": _request["redirect_uri"],
        }
