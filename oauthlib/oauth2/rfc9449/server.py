"""
oauthlib.oauth2.rfc9449.server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Server-side `RFC 9449`_ (DPoP) building blocks.

- :class:`DPoPReplayCache` / :class:`InMemoryDPoPReplayCache`: proof ``jti``
  replay protection.
- :class:`DPoPProofValidator`: parses and validates a DPoP proof JWT
  (signature, ``htm``/``htu`` binding, ``iat`` window, optional nonce,
  optional ``ath`` and ``jti`` replay) and returns the public key
  thumbprint used for the token's ``cnf`` claim.
- :class:`DPoPProtectedToken`: a drop-in token handler wrapping
  :class:`~oauthlib.oauth2.rfc6749.tokens.BearerToken`, issuing
  ``token_type=DPoP`` tokens with a ``cnf`` binding and validating DPoP
  proofs on protected resources.
- :func:`enable_dpop`: wire DPoP into an existing pre-configured server
  without touching its Bearer flows.

JWT/cryptography libraries are optional dependencies and are imported lazily.

.. _`RFC 9449`: https://www.rfc-editor.org/rfc/rfc9449
"""
import logging
import threading
import time

from ..rfc6749.errors import InvalidRequestError, InvalidTokenError
from ..rfc6749.tokens import BearerToken
from . import errors as dpop_errors
from .client import (
    DEFAULT_ACCEPTED_ALGORITHMS, access_token_hash, jwk_thumbprint,
    normalize_htu,
)

log = logging.getLogger(__name__)


class DPoPReplayCache:
    """Abstract replay cache. Subclasses back this with a real datastore."""

    def add_if_absent(self, jti, expires_at):
        """Atomically remember *jti* until *expires_at*.

        :returns: ``True`` if the jti was previously unknown (the proof is
            not a replay), ``False`` if it was already seen.
        """
        raise NotImplementedError('Subclasses must implement this method.')


class InMemoryDPoPReplayCache(DPoPReplayCache):
    """Thread-safe in-memory ``jti`` cache with TTL eviction.

    Suitable for single-process deployments and tests. Distributed
    deployments should provide their own :class:`DPoPReplayCache` (e.g.
    backed by Redis with the same TTL).
    """

    def __init__(self, ttl=600, max_entries=100000):
        self._ttl = ttl
        self._max_entries = max_entries
        self._seen = {}
        self._lock = threading.Lock()

    def add_if_absent(self, jti, expires_at=None):
        now = time.time()
        if expires_at is None:
            expires_at = now + self._ttl
        with self._lock:
            self._prune(now)
            if jti in self._seen:
                return False
            if len(self._seen) >= self._max_entries:
                # Bound memory: drop the oldest entry rather than growing
                # without limit under a flood of unique proofs.
                oldest = min(self._seen, key=self._seen.get)
                del self._seen[oldest]
            self._seen[jti] = expires_at
            return True

    def _prune(self, now):
        expired = [jti for jti, exp in self._seen.items() if exp <= now]
        for jti in expired:
            del self._seen[jti]

    def clear(self):
        with self._lock:
            self._seen.clear()


class DPoPProofValidator:
    """Validate DPoP proof JWTs per RFC 9449 Sections 4 and 7.

    The validator is deliberately independent of any particular grant type so
    it can be shared by the token endpoint and the resource endpoint. Every
    failure raises a distinct exception from
    :mod:`oauthlib.oauth2.rfc9449.errors`; underlying JWT parsing errors are
    never swallowed but wrapped with exception chaining.

    :param accepted_algorithms: JWS algorithms accepted in the proof header.
    :param iat_ttl: Maximum age of a proof's ``iat``, in seconds.
    :param iat_future_skew: How far in the future ``iat`` may be, in seconds.
    :param replay_cache: :class:`DPoPReplayCache` implementation.
    :param nonce_validator: Optional callable ``(nonce, request) -> bool``.
        If provided, proofs without a nonce or with an invalid nonce raise
        :class:`UseDPoPNonceError`. The nonce value to return is taken from
        :attr:`expected_nonce` or, if that callable is set, from
        ``nonce_provider(request)``.
    :param expected_nonce: Static nonce value advertised to clients. Pair
        with a simple equality-checking *nonce_validator*.
    :param nonce_provider: Optional callable ``(request) -> nonce`` used to
        populate the ``DPoP-Nonce`` response header.
    :param require_proof: When True, a token request without a DPoP header
        raises :class:`MissingDPoPProofError`; when False (default) DPoP is
        optional and plain Bearer requests pass through untouched.
    :param jwt_decode: Injectable decode function for tests; defaults to
        ``jwt.decode`` from PyJWT.
    """

    def __init__(self, accepted_algorithms=None, iat_ttl=60,
                 iat_future_skew=30, replay_cache=None, nonce_validator=None,
                 expected_nonce=None, nonce_provider=None,
                 require_proof=False, jwt_decode=None):
        self.accepted_algorithms = tuple(
            accepted_algorithms or DEFAULT_ACCEPTED_ALGORITHMS)
        self.iat_ttl = iat_ttl
        self.iat_future_skew = iat_future_skew
        self.replay_cache = replay_cache or InMemoryDPoPReplayCache()
        self.nonce_validator = nonce_validator
        self.expected_nonce = expected_nonce
        self.nonce_provider = nonce_provider
        self.require_proof = require_proof
        self._jwt_decode = jwt_decode
        self._jwt_module = None

    @property
    def jwt(self):
        if self._jwt_module is None:
            import jwt  # noqa: PLC0415

            self._jwt_module = jwt
        return self._jwt_module

    def _decode(self, *args, **kwargs):
        if self._jwt_decode is not None:
            return self._jwt_decode(*args, **kwargs)
        return self.jwt.decode(*args, **kwargs)

    def _new_nonce(self, request):
        if self.nonce_provider is not None:
            return self.nonce_provider(request)
        return self.expected_nonce

    def extract_proof(self, request):
        """Return the raw DPoP proof header or ``None``.

        A missing header is ``None`` (the caller decides whether DPoP is
        required); a malformed header (multiple header fields or non-string
        content) is an invalid proof.
        """
        header_value = request.headers.get('DPoP')
        if not header_value:
            return None
        if not isinstance(header_value, str):
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP header must be a single JWT string.',
                request=request)
        # A proof is a compact JWT with exactly two dots and no surrounding
        # whitespace/comma. Multiple DPoP header fields are invalid.
        parts = header_value.split('.')
        if len(parts) != 3 or not all(parts) or ',' in header_value \
                or header_value != header_value.strip():
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP header is not a single compact JWT.',
                request=request)
        return header_value

    def validate_token_request_proof(self, request):
        """Validate the proof on a token endpoint request.

        Sets ``request.dpop_jwk`` (public JWK), ``request.dpop_jkt`` (RFC
        7638 thumbprint) and ``request.dpop_claims`` on success. Raises a
        :class:`DPoPError` subclass on any failure. Returns ``False`` when
        no proof was present and DPoP is optional.
        """
        proof = self.extract_proof(request)
        if proof is None:
            if self.require_proof:
                raise dpop_errors.MissingDPoPProofError(request=request)
            return False

        claims, jwk = self._parse_and_verify(proof, request)
        self._validate_binding(claims, request)
        self._validate_iat(claims, request)
        self._validate_nonce(claims, request, resource=False)
        # Replay is checked last, once the proof is otherwise sound, so a
        # flood of garbage proofs never pollutes the replay cache.
        self._check_replay(claims, request,
                           error_cls=dpop_errors.DPoPReplayError)

        request.dpop_jwk = jwk
        request.dpop_jkt = jwk_thumbprint(jwk)
        request.dpop_claims = claims
        return True

    def validate_resource_request_proof(self, request, access_token):
        """Validate the proof accompanying a DPoP-bound access token.

        In addition to the token-endpoint checks this enforces the ``ath``
        hash claim binding the proof to the presented access token. All
        failures are HTTP 401 resource errors.
        """
        proof = self.extract_proof(request)
        if proof is None:
            raise dpop_errors.InvalidDPoPTokenError(
                description='Missing DPoP proof for DPoP-bound access token.',
                request=request)
        try:
            claims, jwk = self._parse_and_verify(proof, request)
            self._validate_binding(claims, request)
            self._validate_iat(claims, request)
            self._validate_nonce(claims, request, resource=True)
        except dpop_errors.UseDPoPNonceError:
            raise dpop_errors.UseDPoPNonceResourceError(
                nonce=self._new_nonce(request), request=request)
        except dpop_errors.DPoPError as error:
            # Re-raise as the resource-side 401 variant while retaining the
            # original error (and its own __cause__) instead of swallowing it.
            raise dpop_errors.InvalidDPoPTokenError(
                description=error.description,
                request=request) from error

        expected_ath = access_token_hash(access_token)
        if not claims.get('ath') or claims['ath'] != expected_ath:
            raise dpop_errors.InvalidDPoPTokenError(
                description='DPoP proof "ath" does not match the access token.',
                request=request)

        try:
            self._check_replay(
                claims, request,
                error_cls=dpop_errors.InvalidDPoPTokenError)
        except dpop_errors.DPoPError as error:
            raise dpop_errors.InvalidDPoPTokenError(
                description=error.description,
                request=request) from error

        request.dpop_jwk = jwk
        request.dpop_jkt = jwk_thumbprint(jwk)
        request.dpop_claims = claims
        return request.dpop_jkt

    def _parse_and_verify(self, proof, request):
        jwt = self.jwt
        try:
            header = jwt.get_unverified_header(proof)
        except jwt.exceptions.PyJWTError as e:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof is not a parseable JWT.',
                request=request) from e

        if header.get('typ') != 'DPoP':
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "typ" header must be "DPoP".',
                request=request)

        algorithm = header.get('alg')
        if algorithm not in self.accepted_algorithms:
            raise dpop_errors.InvalidDPoPProofError(
                description='Unsupported DPoP proof algorithm: %r' % algorithm,
                request=request)

        jwk = header.get('jwk')
        if not isinstance(jwk, dict) or 'd' in jwk:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof must carry a public JWK in the '
                            '"jwk" header.', request=request)
        if jwk.get('kty') not in ('EC', 'RSA'):
            raise dpop_errors.InvalidDPoPProofError(
                description='Unsupported DPoP key type: %r' % jwk.get('kty'),
                request=request)
        if algorithm.startswith('ES'):
            expected_crv = {'ES256': 'P-256', 'ES384': 'P-384',
                            'ES512': 'P-521'}[algorithm]
            if jwk.get('kty') != 'EC' or jwk.get('crv') != expected_crv:
                raise dpop_errors.InvalidDPoPProofError(
                    description='DPoP JWK does not match algorithm %s.'
                                % algorithm, request=request)
        elif jwk.get('kty') != 'RSA':
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP JWK does not match algorithm %s.'
                            % algorithm, request=request)

        try:
            verification_key = jwt.PyJWK(jwk, algorithm=algorithm).key
        except jwt.exceptions.PyJWTError as e:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof JWK could not be loaded.',
                request=request) from e

        required_claims = ['jti', 'htm', 'htu', 'iat']
        try:
            claims = self._decode(
                proof, verification_key,
                algorithms=[algorithm],
                options={'require': required_claims,
                         'verify_aud': False, 'verify_iss': False},
                leeway=self.iat_future_skew,
            )
        except jwt.exceptions.MissingRequiredClaimError as e:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof is missing required claim: %s' % e,
                request=request) from e
        except jwt.exceptions.PyJWTError as e:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof signature or JWT is invalid: %s' % e,
                request=request) from e

        for name in ('jti', 'htm', 'htu'):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise dpop_errors.InvalidDPoPProofError(
                    description='DPoP proof "%s" claim must be a non-empty '
                                'string.' % name, request=request)
        if not isinstance(claims.get('iat'), int) or isinstance(
                claims.get('iat'), bool):
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "iat" claim must be an integer.',
                request=request)

        return claims, jwk

    def _validate_binding(self, claims, request):
        if claims['htm'] != request.http_method.upper():
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "htm" does not match the request '
                            'method.', request=request)
        if claims['htu'] != normalize_htu(request.uri):
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "htu" does not match the request URL.',
                request=request)

    def _validate_iat(self, claims, request):
        now = int(time.time())
        iat = claims['iat']
        if iat > now + self.iat_future_skew:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "iat" is too far in the future.',
                request=request)
        if iat < now - self.iat_ttl:
            raise dpop_errors.InvalidDPoPProofError(
                description='DPoP proof "iat" is too old.',
                request=request)

    def _validate_nonce(self, claims, request, resource):
        if self.nonce_validator is None:
            return
        nonce = claims.get('nonce')
        if nonce is None or not self.nonce_validator(nonce, request):
            if resource:
                raise dpop_errors.UseDPoPNonceResourceError(
                    nonce=self._new_nonce(request), request=request)
            raise dpop_errors.UseDPoPNonceError(
                nonce=self._new_nonce(request), request=request)

    def _check_replay(self, claims, request, error_cls):
        expires_at = claims['iat'] + self.iat_ttl
        if not self.replay_cache.add_if_absent(claims['jti'], expires_at):
            log.debug('DPoP replay detected for jti %r.', claims['jti'])
            raise error_cls(request=request)


def _get_dpop_proof_from_request(request):
    """Return the raw DPoP header of a protected-resource request or None."""
    header = request.headers.get('Authorization', '')
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == 'dpop':
        return parts[1]
    return request.access_token


class DPoPProtectedToken:
    """Token handler issuing RFC 9449 DPoP-bound access tokens.

    Wraps a regular :class:`BearerToken`: proof validation and the ``cnf``
    binding are added on top, while the underlying token generation, expiry
    and refresh-token behaviour is unchanged. Requests without a DPoP proof
    still produce ordinary Bearer tokens unless the validator is configured
    with ``require_proof=True``.
    """

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None,
                 proof_validator=None):
        self.bearer = BearerToken(
            request_validator, token_generator=token_generator,
            expires_in=expires_in,
            refresh_token_generator=refresh_token_generator)
        self.request_validator = self.bearer.request_validator
        self.proof_validator = proof_validator or DPoPProofValidator()

    @property
    def replay_cache(self):
        return self.proof_validator.replay_cache

    def create_token(self, request, refresh_token=False, **kwargs):
        # When wired in through enable_dpop() the grant's post_token custom
        # validator has already validated the proof and set dpop_jkt, so the
        # proof is not validated a second time (which would falsely trip the
        # single-use jti replay cache). When this handler is used directly
        # without that hook, validate here so standalone use stays correct.
        if not getattr(request, 'dpop_jkt', None):
            self.proof_validator.validate_token_request_proof(request)

        token = self.bearer.create_token(
            request, refresh_token=refresh_token, **kwargs)

        if getattr(request, 'dpop_jkt', None):
            token['token_type'] = 'DPoP'
            token['cnf'] = {'jkt': request.dpop_jkt}
        return token

    def estimate_type(self, request):
        scheme = request.headers.get('Authorization', '').split(' ')[0].lower()
        if scheme == 'dpop':
            # Higher than BearerToken's 9 so a DPoP Authorization header is
            # never dispatched to the plain Bearer handler.
            return 10
        # A non-DPoP request reaching this handler (e.g. a body-parameter
        # token) must lose to the dedicated Bearer handler; validate_request
        # still branches to the bearer path as a defensive measure.
        if scheme == 'bearer':
            return 8
        if request.access_token is not None:
            return 4
        return 0

    def validate_request(self, request):
        scheme = request.headers.get(
            'Authorization', '').split(' ')[0].lower()
        if scheme != 'dpop':
            # Plain Bearer traffic (header or body token) keeps the exact
            # RFC 6750 validation path, guaranteeing zero regression on a
            # DPoP-enabled server.
            return self.bearer.validate_request(request)

        access_token = _get_dpop_proof_from_request(request)
        if not access_token:
            raise InvalidRequestError(
                description='Missing access token.', request=request)

        thumbprint = self.proof_validator.validate_resource_request_proof(
            request, access_token)

        # Mirrors BearerToken.validate_request: return the validator's
        # verdict instead of raising, so ResourceEndpoint's boolean contract
        # is unchanged. Proof failures above still raise the DPoP errors.
        return self.request_validator.validate_dpop_token(
            access_token, thumbprint, request.scopes, request)


def enable_dpop(server, *, proof_validator=None, require_proof=False,
                replay_cache=None):
    """Enable DPoP on a pre-configured oauthlib server in place.

    Replaces the server's Bearer token handler with a
    :class:`DPoPProtectedToken` and registers a ``post_token`` custom
    validator on every grant type so DPoP errors are raised inside the
    grants' try/except blocks and serialised as ordinary JSON token-endpoint
    errors. Plain Bearer requests keep working unchanged.

    :param server: A server such as
        :class:`~oauthlib.oauth2.rfc6749.endpoints.pre_configured.Server`.
    :param proof_validator: An existing :class:`DPoPProofValidator`; a new one
        is created otherwise.
    :param require_proof: When True, token requests without a DPoP proof are
        rejected with :class:`MissingDPoPProofError`.
    :param replay_cache: Custom :class:`DPoPReplayCache`, forwarded to a new
        default validator.
    :returns: The created (or supplied) proof validator.
    """
    if proof_validator is None:
        proof_validator = DPoPProofValidator(
            require_proof=require_proof, replay_cache=replay_cache)
    elif require_proof:
        proof_validator.require_proof = True

    dpop_token = DPoPProtectedToken(
        request_validator=server.bearer.request_validator,
        token_generator=server.bearer.token_generator,
        expires_in=server.bearer.expires_in,
        refresh_token_generator=server.bearer.refresh_token_generator,
        proof_validator=proof_validator)
    server.bearer = dpop_token

    # The token endpoint dispatches through this mapping; point every grant
    # at the DPoP-aware handler while keeping the endpoint defaults intact.
    server._default_token_type = dpop_token
    if hasattr(server, '_tokens'):
        # Keep the ordinary Bearer token type as a separate entry so the
        # resource endpoint still identifies and validates plain Bearer
        # requests through the RFC 6750 path; the DPoP entry handles
        # DPoP-scheme requests with proof validation.
        plain_bearer = dpop_token.bearer
        token_types = server._tokens
        token_types.clear()
        token_types['Bearer'] = plain_bearer
        token_types['DPoP'] = dpop_token
        server._default_token = 'DPoP'

    def validate_dpop(request):
        proof_validator.validate_token_request_proof(request)

    for grant in server.grant_types.values():
        grant.custom_validators.post_token.append(validate_dpop)

    return proof_validator
