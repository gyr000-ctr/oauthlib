"""
oauthlib.oauth2.rfc8705.errors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error classes for OAuth 2.0 Mutual-TLS Client Authentication and
Certificate-Bound Access Tokens (`RFC 8705`_).

Every failure mode defined by the mTLS validation flow gets its own
error class instead of being collapsed into a generic ``invalid_client``
401 response, so that operators can tell apart transport-level problems
(missing or untrusted certificate), registration problems (no
certificate registered for the client) and data mismatches (subject or
thumbprint).

.. _`RFC 8705`: https://www.rfc-editor.org/rfc/rfc8705
"""
from ..rfc6749.errors import FatalClientError, InvalidTokenError


class MtlsError(FatalClientError):
    """Base class for all RFC 8705 mutual-TLS errors."""

    error = 'invalid_client'
    status_code = 401


class MissingClientCertificateError(MtlsError):
    """No client certificate was presented on the TLS connection.

    RFC 8705 section 2.1.2: if the client did not provide a certificate,
    or the certificate was not sufficient for authentication, the server
    returns an ``invalid_client`` error.
    """

    error = 'invalid_client'
    status_code = 401
    description = 'No client certificate was presented for mTLS authentication.'


class UntrustedClientCertificateError(MtlsError):
    """The presented certificate failed chain or trust verification.

    This is kept separate from subject mismatches: a chain/trust failure
    means the certificate itself cannot be trusted at all, whereas a
    subject mismatch means a trusted certificate does not belong to the
    authenticating client.
    """

    error = 'invalid_client'
    status_code = 401
    description = (
        'Client certificate chain verification failed: the certificate '
        'is not signed by a trusted certificate authority.'
    )


class InvalidClientCertificateError(MtlsError):
    """The presented certificate is malformed or otherwise unusable."""

    error = 'invalid_client'
    status_code = 400
    description = 'The presented client certificate is invalid or malformed.'


class MissingClientCertificateRegistrationError(MtlsError):
    """The client has no certificate registration data to compare against.

    Raised when neither a registered subject DN/SAN nor a registered
    certificate thumbprint is available for the identified client.
    """

    error = 'invalid_client'
    status_code = 400
    description = (
        'No certificate subject DN, SAN or thumbprint is registered for '
        'this client; mTLS authentication cannot be performed.'
    )


class MismatchingCertificateSubjectError(MtlsError):
    """The certificate subject DN / SAN does not match the registration."""

    error = 'invalid_client'
    status_code = 401
    description = (
        'Client certificate subject distinguished name or SAN does not '
        'match the registered certificate information.'
    )


class MismatchingCertificateThumbprintError(MtlsError):
    """The certificate ``x5t#S256`` thumbprint does not match.

    Used in two places:

    - Section 2.1.1 self-authentication, when the presented
      certificate's thumbprint differs from the registered thumbprint.
    - Section 3, when a certificate-bound token is presented on a
      resource request whose TLS certificate does not match the
      ``cnf.x5t#S256`` claim carried by the token.
    """

    error = 'invalid_token'
    status_code = 401
    description = (
        'Client certificate thumbprint (x5t#S256) does not match the '
        'registered or token-bound certificate.'
    )


class InvalidTokenCertificateBindingError(InvalidTokenError):
    """A certificate-bound token was presented without a client certificate.

    RFC 8705 section 3.2: when access to a protected resource requires a
    certificate-bound access token and the request does not carry a
    certificate, the resource server rejects the request.
    """

    error = 'invalid_token'
    status_code = 401
    description = (
        'The access token is certificate-bound but no client certificate '
        'was presented with the request.'
    )


# Re-exported for callers that handle generic invalid_client/invalid_token.
__all__ = [
    'InvalidClientCertificateError',
    'InvalidTokenCertificateBindingError',
    'MismatchingCertificateSubjectError',
    'MismatchingCertificateThumbprintError',
    'MissingClientCertificateError',
    'MissingClientCertificateRegistrationError',
    'MtlsError',
    'UntrustedClientCertificateError',
]
