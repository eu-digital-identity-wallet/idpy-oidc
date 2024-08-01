import json
import logging

import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from idpyoidc.util import importer

from .exception import OidcEndpointError

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [("Pragma", "no-cache"), ("Cache-Control", "no-store")]


def build_endpoints(conf, upstream_get, issuer):
    """
    conf typically contains::

        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },

    This function uses class and kwargs to instantiate a class instance with kwargs.

    :param conf:
    :param upstream_get: Callback function
    :param issuer:
    :return:
    """

    if issuer.endswith("/"):
        _url = issuer[:-1]
    else:
        _url = issuer

    endpoint = {}
    for name, spec in conf.items():
        kwargs = spec.get("kwargs", {})

        # class can be a string (class path) or a class reference
        if isinstance(spec["class"], str):
            _instance = importer(spec["class"])(upstream_get=upstream_get, **kwargs)
        else:
            _instance = spec["class"](upstream_get=upstream_get, **kwargs)

        _path = spec.get("path", "")

        if _path:
            _instance.endpoint_path = _path
            _instance.full_path = "{}/{}".format(_url, _path)

        endpoint[_instance.name] = _instance

    return endpoint


class JSONDictDB(object):
    def __init__(self, filename):
        with open(filename, "r") as f:
            self._db = json.load(f)

    def __getitem__(self, item):
        return self._db[item]

    def __contains__(self, item):
        return item in self._db


def lv_pack(*args):
    """
    Serializes using length:value format

    :param args: values
    :return: string
    """
    s = []
    for a in args:
        s.append("{}:{}".format(len(a), a))
    return "".join(s)


def lv_unpack(txt):
    """
    Deserializes a string of the length:value format

    :param txt: The input string
    :return: a list og values
    """
    txt = txt.strip()
    res = []
    while txt:
        l, v = txt.split(":", 1)
        res.append(v[: int(l)])
        txt = v[int(l) :]
    return res


def get_http_params(config):
    _verify_ssl = config.get("verify")
    if _verify_ssl is None:
        _verify_ssl = config.get("verify_ssl")

    if _verify_ssl in [True, False]:
        params = {"verify": _verify_ssl}
    else:
        params = {}

    _cert = config.get("client_cert")
    _key = config.get("client_key")
    if _cert:
        if _key:
            params["cert"] = (_cert, _key)
        else:
            params["cert"] = _cert
    elif _key:
        raise ValueError("Key without cert is no good")

    return params


def allow_refresh_token(context):
    # Are there a refresh_token handler
    refresh_token_handler = context.session_manager.token_handler.handler.get("refresh_token")
    if refresh_token_handler is None:
        return False

    # Is refresh_token grant type supported
    _token_supported = False
    _supported = context.get_preference("grant_types_supported")
    if _supported:
        if "refresh_token" in _supported:
            # self.allow_refresh = kwargs.get("allow_refresh", True)
            _token_supported = True

    if refresh_token_handler and _token_supported:
        return True
    elif refresh_token_handler:
        logger.warning("Refresh Token handler available but grant type not supported")
    elif _token_supported:
        logger.error(
            "refresh_token grant type to be supported but no refresh_token handler available"
        )
        raise OidcEndpointError('Grant type "refresh_token" lacks support')

    return False


def execute(spec, **kwargs):
    extra_args = spec.get("kwargs", {})
    kwargs.update(extra_args)

    _class = spec.get("class")
    if _class:
        # class can be a string (class path) or a class reference
        if isinstance(_class, str):
            return importer(_class)(**kwargs)
        else:
            return _class(**kwargs)
    else:
        _function = spec.get("func")
        if _function:
            if isinstance(_function, str):
                _func = importer(_function)
            else:
                _func = _function
            return _func(**kwargs)
        else:
            return kwargs


def verify_client_attestation(attestationClient, client_id):
    try:
        decoded_payload = jwt.decode(
            attestationClient,
            options={"verify_exp": True, "verify_nbf": True, "verify_signature": False},
        )
        # Manually verify the subject
        if "iss" not in decoded_payload:
            raise jwt.InvalidTokenError("Missing iss claim")

        if "sub" not in decoded_payload or decoded_payload["sub"] != client_id:
            raise jwt.InvalidTokenError("Invalid subject")
        # Verify the cnf claim

        if "exp" not in decoded_payload:
            raise jwt.InvalidTokenError("Missing exp claim")

        if "cnf" not in decoded_payload:
            raise jwt.InvalidTokenError("Missing cnf claim")

        if "jwk" not in decoded_payload["cnf"]:
            raise jwt.InvalidTokenError("Missing jwk")

        jwk_claim = decoded_payload["cnf"]["jwk"]

        # Verify jwk
        required_fields = ["kty"]

        if "kty" not in jwk_claim:
            raise jwt.InvalidTokenError(f"Missing required jwk field: kty")

        if "RSA" not in jwk_claim["kty"] and "EC" not in jwk_claim["kty"]:
            raise jwt.InvalidTokenError("Key must be asymmetric")

        # Additional checks based on key type
        if jwk_claim["kty"] == "RSA":
            if "n" not in jwk_claim or "e" not in jwk_claim:
                raise jwt.InvalidTokenError("RSA key must have 'n' and 'e' fields")

            n = jwt.utils.base64url_decode(jwk_claim["n"])
            e = jwt.utils.base64url_decode(jwk_claim["e"])
            public_numbers = rsa.RSAPublicNumbers(
                int.from_bytes(e, byteorder="big"), int.from_bytes(n, byteorder="big")
            )
            public_key = public_numbers.public_key(default_backend())

        if jwk_claim["kty"] == "EC":
            if "crv" not in jwk_claim or "x" not in jwk_claim or "x" not in jwk_claim:
                raise jwt.InvalidTokenError("EC key must have 'crv' and 'x' and 'y' fields")
            x = jwt.utils.base64url_decode(jwk_claim["x"])
            y = jwt.utils.base64url_decode(jwk_claim["y"])

            # Load the EC public key
            public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, byteorder="big"),
                int.from_bytes(y, byteorder="big"),
                ec.SECP256R1(),
            )
            public_key = public_numbers.public_key()

        if "iat" in decoded_payload:
            # Check if "iat" is not unreasonably far in the past
            max_allowed_iat_delta = 3600  # Allow a maximum difference of 1 hour
            iat_delta = int(time.time()) - decoded_payload["iat"]
            if iat_delta > max_allowed_iat_delta:
                raise jwt.InvalidTokenError("'iat' claim value is unreasonably far in the past")

        if not public_key:
            raise jwt.InvalidTokenError("Invalid public key")

        print("Client Attestation JWT is valid. Payload:")
        print(decoded_payload)

        return public_key
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError("Invalid JWT:", e)


def verify_pop_attestation(attestationPop, public_key, client_id):
    # Verify the JWT
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_length = public_key.curve.key_size
        algo = "ES" + str(key_length)

    if isinstance(public_key, rsa.RSAPublicKey):
        key_length = public_key.curve.key_size
        algo = "RS" + str(key_length)
    try:
        decoded_payload = jwt.decode(
            attestationPop,
            public_key,
            algorithms=[algo],
            options={
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_signature": True,
            },
            audience="https://issuer.eudiw.dev/",
            issuer=client_id,
        )
        # Check if "jti" is present in the decoded payload
        if "jti" not in decoded_payload:
            raise jwt.InvalidTokenError("Missing 'jti' claim")
        # Check if "iat" is present in the decoded payload
        if "iat" in decoded_payload:
            # Check if "iat" is not unreasonably far in the past
            max_allowed_iat_delta = 3600  # Allow a maximum difference of 1 hour
            iat_delta = int(time.time()) - decoded_payload["iat"]
            if iat_delta > max_allowed_iat_delta:
                raise jwt.InvalidTokenError("'iat' claim value is unreasonably far in the past")

        print("Attestation PoP JWT is valid. Payload:")
        print(decoded_payload)
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError("Invalid JWT:", e)
