# Change Log

## 0.1.0

### Changed
- Updated implementation to align with EUDI TS3 v1.5 specification.

## 0.1.1

### Changed
- Wallet attestation (`wallet_attestation`) client authentication verifies the WIA signature with the `x5c` leaf certificate in every case. With `trust_validator_url` only the certificate chain was sent to the validator: a WIA signed by any key with a genuine wallet provider chain was accepted.
- Without a trust validator, the `x5c` chain must contain, or be issued by, a certificate in `trusted_attesters_path`; certificate validity dates are checked. The algorithm is checked before the signature.
- The WIA `sub` must match the request `client_id`. The check could be skipped by any client sending `redirect_uri=preauth`; only the server can now skip it (`skip_client_id_check`, for its internal pre-authorized code call).
- The PoP `aud` must be this server (issuer or endpoint URL), its `iss` must be the WIA `sub`, and a PoP `jti` is accepted once.
- The WIA `iat` is required (maximum age) and `client_status.exp` is checked.
- Client registration from a WIA is merged into the existing client entry instead of replacing it (redirect URIs of other in-flight flows were lost).
- DPoP add-on: the proof algorithm must be in `dpop_signing_alg_values_supported` (default `ES256`); symmetric or private `jwk`s are rejected; the proof `iat` must be within 5 minutes.
- Removed the legacy `client_assertion` attestation check in pushed authorization (`verify_client_attestation` / `verify_pop_attestation`), which decoded the attestation without verifying its signature.

### Fixed
- Local `trusted_attesters_path` verification always failed (NameError after the signature check).
- Malformed attestations, a missing `x5c` or `client_id`, or missing `http_info` raised errors that became 500s instead of authentication errors.
- `token_args` (DPoP) raised `KeyError` for clients without a DPoP key; the token endpoint `kwargs` lookup raised `KeyError` when the endpoint had none.
- Removed `print` calls that wrote client attestations, tokens, request headers and the authentication JWS to stdout; the raw WIA and PoP are no longer logged.

## 0.2.0

### Added
- `PushedAuthorization.purge_expired()` removes pushed requests that expired unredeemed.
- Token endpoint `kwargs`: `pop_allowed_aud` (extra wallet attestation PoP `aud` values) and `status_validation_context` (default `WalletOrKeyStorageStatus`, was `PIDStatus`).
- `tests/test_niscy_hardening.py`, and about 800 unit tests (`tests/test_cov_*.py`) for modules with little coverage: 74% -> 88%.
- Bugs found by those tests are pinned as `xfail(strict=True)` tests whose reason starts with `BUG:`.
- `idpyoidc.server.util.CURRENT_ISSUER`: an application serving several issuers (e.g. one per URL path) sets the request's issuer; the authorization response `iss` (RFC 9207), access, refresh and ID token `iss`, introspection `iss`, PoP and client assertion `aud`, and the DPoP `allowed_htu` / `par_allowed_htu` follow it.

### Changed
- `EudiwIssuer` hand-off JWTs expire (`token_lifetime`, default 1800 s) and must be signed by this server.
- The access token's `client_status` comes from the wallet attestation of the current request, not the shared client entry.
- `BearerHeader` takes the client id from the token, not the request.
- `PublicAuthn` accepts requests with a DPoP proof (RFC 9449).
- PKCE add-on: `code_challenge_methods` takes a list, the misspelt `code_challenge_method` is refused, and PAR requests are checked too.
- Client cookie MAC is HMAC-SHA256 (was SHA1; older cookies are refused); generated client secrets use HMAC-SHA256.
- CI: `tests.yml` (Python 3.12/3.13) replaces `python-app.yml`; Gitleaks, Dependency-Check and SonarCloud added.
- `tests/conftest.py` marks upstream tests broken by intentional fork changes as strict xfails.
- Removed the unused `private/` modules, and test-generated keys (`private/*.json`) and request objects (`requests/`) from the repository root.

### Fixed
- DPoP add-on (RFC 9449): proofs are fully checked (signature, `typ`, `htm`, `htu` against `allowed_htu`, `iat`, base64url `ath`, single-use `jti`); errors are `invalid_dpop_proof`; refreshes need the same key; `/introspection` returns `cnf.jkt`.
- DPoP add-on (RFC 9449 section 10): a proof with a pushed request binds it as `dpop_jkt`, and its code is only redeemed with that key.
- Concurrent token requests with one authorization code could each get an access token; a code is redeemed under a per-code lock.
- `util.sanitize` returned its input unchanged; codes, tokens and secrets are now redacted from logs.
- OAuth error codes follow RFC 6749 and RFC 9126 at the token and authorization endpoints.
- Pushed authorization requests (RFC 9126): `request_uri` expires after `ttl`, unknown or used ones are `invalid_request_uri`, and the authorization endpoint resolves them in `parse_request`.
- Wallet attestation signatures were refused when the JWS `kid` differed from the key's.
- SonarCloud findings: a `TypeError` from catching a list of exceptions, an unraised JAR error, a backtracking regex, `utcnow()`.
- The `refresh_token` handler read the keyjar from a misspelt attribute.
