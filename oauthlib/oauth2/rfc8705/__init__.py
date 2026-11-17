"""
oauthlib.oauth2.rfc8705
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of OAuth 2.0 Mutual-TLS Client
Authentication and Certificate-Bound Access Tokens (`RFC 8705`_).

It provides two complementary mechanisms:

1. Mutual-TLS client authentication at the token, introspection and
   revocation endpoints, where the certificate presented during the
   TLS handshake is compared against the client's registration data
   (subject DN and/or Subject Alternative Name).

2. Certificate-bound access tokens, which carry an ``x5t#S256``
   confirmation member holding the SHA-256 thumbprint of the client
   certificate. Resource servers then verify that the TLS certificate
   presented alongside a token matches that thumbprint.

Only the Python standard library is used.

.. _`RFC 8705`: https://www.rfc-editor.org/rfc/rfc8705
"""
from .errors import (
    InvalidClientCertificateError,
    InvalidTokenCertificateBindingError,
    MismatchingCertificateSubjectError,
    MismatchingCertificateThumbprintError,
    MissingClientCertificateError,
    MissingClientCertificateRegistrationError,
    MtlsError,
    UntrustedClientCertificateError,
)
from .mtls import (
    CLIENT_CERT_ATTR,
    CLIENT_CERT_HEADERS,
    MTLS_ENDPOINT_ALIASES,
    MtlsEndpointMixin,
    build_mtls_metadata_aliases,
    calculate_x5t_s256,
    get_client_certificate,
)
from .tokens import CertificateBoundBearerToken

__all__ = [
    "CLIENT_CERT_ATTR",
    "CLIENT_CERT_HEADERS",
    "MTLS_ENDPOINT_ALIASES",
    "CertificateBoundBearerToken",
    "InvalidClientCertificateError",
    "InvalidTokenCertificateBindingError",
    "MismatchingCertificateSubjectError",
    "MismatchingCertificateThumbprintError",
    "MissingClientCertificateError",
    "MissingClientCertificateRegistrationError",
    "MtlsEndpointMixin",
    "MtlsError",
    "UntrustedClientCertificateError",
    "build_mtls_metadata_aliases",
    "calculate_x5t_s256",
    "get_client_certificate",
]
