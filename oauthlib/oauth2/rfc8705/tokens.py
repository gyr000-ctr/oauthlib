"""
oauthlib.oauth2.rfc8705.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certificate-bound access tokens as defined by RFC 8705 section 3.

When a client authenticates with a mutual-TLS certificate, the issued
access token carries a confirmation member (``cnf``) holding the
``x5t#S256`` SHA-256 thumbprint of that certificate. A resource server
then only accepts the token when it is presented on a TLS connection
whose client certificate has the same thumbprint.

The binding is added to the token dictionary as ``token['cnf']`` so it
is persisted alongside the opaque token by ``save_bearer_token`` and so
JWT-style generators can embed it as a JWT ``cnf`` claim.
"""
import logging

from ..rfc6749.errors import ServerError
from ..rfc6749.tokens import BearerToken
from .errors import (
    InvalidTokenCertificateBindingError,
    MismatchingCertificateThumbprintError,
    UntrustedClientCertificateError,
)
from .mtls import (
    calculate_x5t_s256,
    certificate_chain_verified,
    get_client_certificate,
    thumbprints_equal,
)

log = logging.getLogger(__name__)


class CertificateBoundBearerToken(BearerToken):
    """Bearer token that embeds the client certificate ``x5t#S256``.

    Drop-in replacement for :class:`~oauthlib.oauth2.BearerToken`: when
    the validated request carries a client certificate (the normal case
    on an mTLS endpoint), the issued token gets a ``cnf`` confirmation
    member::

        {
            "access_token": "...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "cnf": {"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"}
        }

    Requests without a client certificate still produce ordinary,
    unbound tokens, so the same token handler can serve both the regular
    and the mTLS endpoint aliases.
    """

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None,
                 require_certificate=False):
        super().__init__(request_validator, token_generator, expires_in,
                         refresh_token_generator)
        # When True, issuing a token without a presented certificate is a
        # server-side configuration error rather than silently producing
        # an unbound token.
        self.require_certificate = require_certificate

    def create_token(self, request, refresh_token=False, **kwargs):
        token = super().create_token(request,
                                     refresh_token=refresh_token, **kwargs)
        thumbprint = getattr(request, 'client_cert_thumbprint', None)
        certificate = get_client_certificate(request) if not thumbprint else None

        if not thumbprint and certificate is not None:
            thumbprint = calculate_x5t_s256(certificate)
            request.client_cert_thumbprint = thumbprint

        if thumbprint:
            token['cnf'] = {'x5t#S256': thumbprint}
            log.debug('Binding access token to certificate thumbprint %s.',
                      thumbprint)
        elif self.require_certificate:
            raise ServerError(
                'Cannot issue a certificate-bound token: no client '
                'certificate was presented.')
        return token

    def validate_request(self, request):
        """Validate the bearer token and, when bound, its TLS binding.

        The regular :meth:`validate_bearer_token` validator call runs
        first and is expected to populate the token's claims on the
        request (at minimum ``request.token_claims`` or a ``cnf`` claim
        returned by the validator). When the token record contains a
        ``cnf.x5t#S256`` value the client certificate presented on the
        current TLS connection must match it.
        """
        valid = super().validate_request(request)
        if not valid:
            return False

        binding = self._extract_binding(request)
        if not binding:
            return True

        certificate = get_client_certificate(request)
        if certificate is None:
            log.debug('Rejecting bound token without client certificate.')
            raise InvalidTokenCertificateBindingError(request=request)
        if not certificate_chain_verified(request):
            raise UntrustedClientCertificateError(request=request)

        actual = calculate_x5t_s256(certificate)
        if not thumbprints_equal(actual, binding):
            log.debug('Rejecting token: cnf x5t#S256 %s != presented %s.',
                      binding, actual)
            raise MismatchingCertificateThumbprintError(request=request)
        return True

    def _extract_binding(self, request):
        """Locate the expected x5t#S256 value stored with the token.

        Integrations can expose the persisted confirmation claim in any
        of three places:

        - ``request.token_claims['cnf']['x5t#S256']`` (preferred),
        - ``request.cnf['x5t#S256']``,
        - a validator method
          ``get_token_certificate_binding(token, request)``.
        """
        claims = getattr(request, 'token_claims', None)
        if claims and isinstance(claims, dict):
            cnf = claims.get('cnf') or {}
            if cnf.get('x5t#S256'):
                return cnf['x5t#S256']

        cnf = getattr(request, 'cnf', None)
        if cnf and isinstance(cnf, dict) and cnf.get('x5t#S256'):
            return cnf['x5t#S256']

        validator = getattr(self, 'request_validator', None)
        getter = getattr(validator,
                         'get_token_certificate_binding', None)
        if callable(getter):
            token = getattr(request, 'token', None)
            binding = getter(token, request)
            if binding:
                return binding
        return None
