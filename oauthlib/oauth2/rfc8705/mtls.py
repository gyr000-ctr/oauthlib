"""
oauthlib.oauth2.rfc8705.mtls
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Core logic for OAuth 2.0 Mutual-TLS Client Authentication (`RFC 8705`_,
section 2) and certificate-bound access token verification (section 3).

The transport layer (a reverse proxy such as nginx, or a TLS-terminating
web framework) is responsible for the TLS handshake, including requesting
and validating the client certificate. It passes the parsed certificate
to the OAuth layer, by convention as ``request.client_cert``; other
attribute names and header names can be configured through
:data:`CLIENT_CERT_ATTR`.

A certificate may be represented as:

- a :class:`cryptography.x509.Certificate` (if the optional
  ``cryptography`` package is installed),
- an :class:`ssl.SSLSocket`-like object exposing ``getpeercert()`` and
  ``getpeercert(binary_form=True)``,
- raw PEM/DER bytes,
- the dict returned by ``SSLSocket.getpeercert()``.

Only the Python standard library is required.

.. _`RFC 8705`: https://www.rfc-editor.org/rfc/rfc8705
"""
import base64
import hashlib
import ipaddress
import logging

from ..rfc6749.errors import InvalidClientError, ServerError
from . import _crypto
from .errors import (
    InvalidClientCertificateError,
    InvalidTokenCertificateBindingError,
    MismatchingCertificateSubjectError,
    MismatchingCertificateThumbprintError,
    MissingClientCertificateError,
    MissingClientCertificateRegistrationError,
    UntrustedClientCertificateError,
)

log = logging.getLogger(__name__)

#: Attribute names checked, in order, on a request to locate the
#: client certificate. Framework integrations may extend this list.
CLIENT_CERT_ATTR = ('client_cert', 'peer_cert', 'ssl_object')

#: Header names (case-insensitive) checked when no request attribute holds
#: a certificate. Proxies commonly forward the verified peer certificate
#: in one of these. Only consult headers when the proxy is trusted.
CLIENT_CERT_HEADERS = (
    'X-SSL-CERT',
    'X-Client-Cert',
    'X-Client-Certificate',
    'X-Tls-Client-Cert',
    'X-Forwarded-Tls-Client-Cert',
)

#: Header used by deployments to signal that the peer certificate chain
#: was verified by the TLS terminator (e.g. nginx ``$ssl_client_verify``).
CLIENT_VERIFY_HEADER = 'X-SSL-Client-Verify'

#: The ``mtls_endpoint_aliases`` metadata parameter (RFC 8705 section 6)
#: mirrors one regular endpoint claim per alias entry.
MTLS_ENDPOINT_ALIASES = (
    'token_endpoint',
    'revocation_endpoint',
    'introspection_endpoint',
    'device_authorization_endpoint',
    'registration_endpoint',
    'authorization_endpoint',
)


def calculate_x5t_s256(certificate):
    """Calculate the ``x5t#S256`` confirmation value of a certificate.

    The value is defined by RFC 8705 section 3.1 as the base64url-encoded
    SHA-256 hash of the DER encoding of the certificate, without padding.

    :param certificate: A cryptography ``Certificate``, an object exposing
        ``getpeercert(binary_form=True)`` (an :class:`ssl.SSLSocket`),
        or raw DER/PEM bytes.
    :rtype: str
    """
    der = certificate_der(certificate)
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def get_client_certificate(request):
    """Extract the client certificate from a request.

    Looks at the attributes listed in :data:`CLIENT_CERT_ATTR` and then
    at the forwarding headers in :data:`CLIENT_CERT_HEADERS`. Returns
    ``None`` when no certificate is present.

    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    """
    for attr in CLIENT_CERT_ATTR:
        cert = getattr(request, attr, None)
        # A truthiness check keeps dynamic-attribute objects (mocks,
        # generic namespaces) from being mistaken for a certificate.
        if cert:
            return cert

    headers = getattr(request, 'headers', None) or {}
    for header in CLIENT_CERT_HEADERS:
        value = headers.get(header)
        if value:
            return header_to_pem(value)
    return None


def certificate_chain_verified(request):
    """Return whether the TLS layer reports a verified client certificate.

    When the request carries an explicit verification header (for example
    nginx's ``X-SSL-Client-Verify: SUCCESS``) its value is honored. When
    no header is present the integration itself is responsible for chain
    validation (typical when the WSGI/ASGI server terminates mTLS), so
    ``True`` is returned.
    """
    headers = getattr(request, 'headers', None) or {}
    verify = headers.get(CLIENT_VERIFY_HEADER)
    if verify is not None:
        return verify.strip().upper() == 'SUCCESS'
    return True


def header_to_pem(value):
    """Convert a header-carried certificate back to PEM bytes."""
    if isinstance(value, bytes):
        value = value.decode('ascii', errors='ignore')
    value = value.strip()
    if 'BEGIN CERTIFICATE' in value:
        return value.encode('ascii')
    # URL-decoded header values may contain spaces instead of newlines.
    return (
        '-----BEGIN CERTIFICATE-----\n'
        + value.replace(' ', '\n')
        + '\n-----END CERTIFICATE-----\n'
    ).encode('ascii')


def certificate_der(certificate):
    """Return the DER encoding of a certificate in any supported form."""
    # cryptography x509.Certificate
    public_bytes = getattr(certificate, 'public_bytes', None)
    if callable(public_bytes):
        return _crypto.certificate_public_der(certificate)

    # ssl.SSLSocket-like object
    getpeercert = getattr(certificate, 'getpeercert', None)
    if callable(getpeercert):
        der = getpeercert(binary_form=True)
        if der:
            return der
        raise InvalidClientCertificateError(
            description='The TLS peer provided no binary certificate; '
                        'the TLS context may not have requested one.')

    if isinstance(certificate, bytes):
        if certificate.lstrip().startswith(b'-----BEGIN'):
            return pem_to_der(certificate)
        # Raw DER cannot be sanity-checked without an ASN.1 parser; the
        # caller (load_certificate) validates the content when needed.
        return certificate

    if isinstance(certificate, str):
        if 'BEGIN CERTIFICATE' in certificate:
            return pem_to_der(certificate.encode('ascii'))
        raise InvalidClientCertificateError(
            description='Unsupported string certificate representation; '
                        'expected PEM-encoded client certificate.')

    raise InvalidClientCertificateError(
        description='Unsupported client certificate type %r.'
                    % type(certificate).__name__)

def pem_to_der(pem):
    """Strip the PEM envelope and decode the base64 body."""
    lines = [line.strip() for line in pem.decode('ascii').splitlines()
             if line and 'BEGIN CERTIFICATE' not in line
             and 'END CERTIFICATE' not in line]
    try:
        return base64.b64decode(''.join(lines), validate=True)
    except Exception as e:
        raise InvalidClientCertificateError(
            description='Client certificate is not valid base64 PEM.') from e


class ParsedCertificate:
    """Framework-neutral view of the certificate fields needed by RFC 8705.

    :ivar subject_dn: dict of RDN attribute -> value, e.g.
        ``{'CN': 'client.example', 'O': 'Example Org'}``.
    :ivar sans: list of ``(type_name, value)`` tuples, e.g.
        ``[('DNS', 'client.example'), ('IP Address', '203.0.113.7')]``.
    """

    def __init__(self, subject_dn, sans):
        self.subject_dn = subject_dn
        self.sans = sans

    @classmethod
    def from_ssl_dict(cls, peercert):
        """Build from the dict returned by ``SSLSocket.getpeercert()``."""
        subject = {}
        for rdn in peercert.get('subject', ()):
            for key, value in rdn:
                subject.setdefault(key, value)
        sans = list(peercert.get('subjectAltName', ()))
        return cls(subject, sans)

    @classmethod
    def from_cryptography(cls, cert):
        """Build from a ``cryptography.x509.Certificate``."""
        subject, sans = _crypto.parse_certificate_attributes(cert)
        return cls(subject, sans)


def load_certificate(certificate):
    """Parse any supported certificate representation.

    :rtype: ParsedCertificate
    :raises InvalidClientCertificateError: if parsing fails.
    """
    if isinstance(certificate, ParsedCertificate):
        return certificate

    if isinstance(certificate, dict):
        return ParsedCertificate.from_ssl_dict(certificate)

    getpeercert = getattr(certificate, 'getpeercert', None)
    if callable(getpeercert):
        parsed = getpeercert()
        if parsed:
            return ParsedCertificate.from_ssl_dict(parsed)
        raise InvalidClientCertificateError(
            description='The TLS peer provided no usable certificate.')

    if isinstance(certificate, (bytes, str)):
        if not _crypto.cryptography_available():
            raise InvalidClientCertificateError(
                description='Parsing PEM/DER certificates requires the '
                            'optional "cryptography" package.')
        try:
            if isinstance(certificate, str):
                cert = _crypto.load_pem_certificate(
                    certificate.encode('ascii'))
            elif certificate.lstrip().startswith(b'-----BEGIN'):
                cert = _crypto.load_pem_certificate(certificate)
            else:
                cert = _crypto.load_der_certificate(certificate)
        except (ValueError, TypeError) as e:
            raise InvalidClientCertificateError(
                description='Could not parse the client certificate.') from e
        return ParsedCertificate.from_cryptography(cert)

    # A cryptography Certificate object (or compatible).
    if getattr(certificate, 'subject', None) is not None:
        return ParsedCertificate.from_cryptography(certificate)

    raise InvalidClientCertificateError(
        description='Unsupported client certificate type %r.'
                    % type(certificate).__name__)


def normalize_dn(value):
    """Normalize a distinguished name for comparison.

    Accepts either a dict of RDN attributes (``{'CN': '...', 'O': '...'}``)
    or an RFC 4514 string (``"CN=...,O=..."``). Returns a dict of
    upper-cased attribute names with inner whitespace collapsed, which is
    sufficient for the byte-level comparison required by RFC 8705 once
    both sides use the same string preparation.
    """
    if not value:
        return {}
    items = value.items() if isinstance(value, dict) \
        else parse_dn_string(value)
    normalized = {}
    for key, val in items:
        key = key.strip().upper()
        val = ' '.join(str(val).split()).strip()
        normalized.setdefault(key, val)
    return normalized


def parse_dn_string(dn):
    """Parse a subset of RFC 4514 DN strings into ``(attr, value)`` pairs."""
    pairs = []
    # RFC 4514 lists RDNs most-significant-last.
    for segment in reversed(dn.split(',')):
        if not segment.strip() or '=' not in segment:
            continue
        key, value = segment.split('=', 1)
        pairs.append((key.strip(), value.strip()))
    return pairs


def san_name_matches(presented, registered):
    """Compare a SAN entry, handling IP addresses and DNS names."""
    ptype, pvalue = presented
    rtype, rvalue = registered
    if ptype != rtype:
        return False
    if ptype == 'IP Address':
        try:
            return ipaddress.ip_address(pvalue) == \
                ipaddress.ip_address(rvalue)
        except ValueError:
            return pvalue == rvalue
    return pvalue.strip().lower() == rvalue.strip().lower()


class MtlsEndpointMixin:
    """RFC 8705 mutual-TLS authentication for OAuth endpoints.

    Endpoints mix this in and call :meth:`authenticate_mtls_client`
    instead of, or in addition to, the regular client authentication.
    All certificate handling and error differentiation lives here so the
    token, introspection and revocation endpoints share one semantics.
    """

    def get_client_certificate(self, request):
        """Hook allowing integrations to override certificate extraction."""
        return get_client_certificate(request)

    def authenticate_mtls_client(self, request, client=None):
        """Authenticate ``request`` using its mutual-TLS certificate.

        Implements RFC 8705 sections 2.1 and 2.2. On success the validated
        client object is set on ``request.client`` and the certificate
        thumbprint is stored on ``request.client_cert_thumbprint`` so the
        token layer can bind the issued token.

        Each failure raises a distinct error class:

        - :class:`MissingClientCertificateError` - no certificate,
        - :class:`UntrustedClientCertificateError` - chain verification
          failed,
        - :class:`InvalidClientCertificateError` - unparseable certificate,
        - :class:`MissingClientCertificateRegistrationError` - the client
          has no registered DN/SAN/thumbprint to compare against,
        - :class:`MismatchingCertificateSubjectError` - DN/SAN mismatch,
        - :class:`MismatchingCertificateThumbprintError` - thumbprint
          mismatch.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param client: Optional already-identified client object. When
            omitted the validator is asked to identify the client.
        """
        certificate = self.get_client_certificate(request)
        if certificate is None:
            log.debug('mTLS authentication failed: no certificate on %r.',
                      request)
            raise MissingClientCertificateError(request=request)

        if not certificate_chain_verified(request):
            log.debug('mTLS authentication failed: untrusted chain on %r.',
                      request)
            raise UntrustedClientCertificateError(request=request)

        parsed = load_certificate(certificate)
        # A parsed ssl getpeercert() dict does not carry the DER bytes;
        # thumbprint-based binding is simply unavailable in that case and
        # subject DN/SAN comparison remains fully supported.
        try:
            thumbprint = calculate_x5t_s256(certificate)
        except InvalidClientCertificateError:
            if isinstance(certificate, dict):
                thumbprint = None
            else:
                raise
        request.client_cert_thumbprint = thumbprint

        client = client or self._identify_client(request)
        request.client = client

        registration = self._get_certificate_registration(request, client)
        if not registration:
            log.debug('mTLS authentication failed: no registration for '
                      'client %r.', request.client_id)
            raise MissingClientCertificateRegistrationError(request=request)

        registered_thumbprint = registration.get('thumbprint') \
            or registration.get('x5t#S256')
        if registered_thumbprint:
            if not thumbprint or not thumbprints_equal(
                    thumbprint, registered_thumbprint):
                log.debug('mTLS authentication failed: thumbprint mismatch '
                          'for client %r.', request.client_id)
                raise MismatchingCertificateThumbprintError(request=request)
            self._set_client_id(request, client)
            return client

        # Subject DN / SAN path (RFC 8705 section 2.2).
        registered_dn = registration.get('subject_dn') \
            or registration.get('dn')
        registered_sans = registration.get('san') \
            or registration.get('subject_alt_names')
        self._compare_subject(parsed, registered_dn, registered_sans,
                              request)
        self._set_client_id(request, client)
        return client

    def verify_token_binding(self, request, token_claims):
        """Verify the certificate binding of a presented access token.

        RFC 8705 section 3.2. ``token_claims`` is the claim set associated
        with the presented token; its ``cnf`` member may contain an
        ``x5t#S256`` value. When present, the certificate on the TLS
        connection must exist and hash to the same thumbprint.

        :raises InvalidTokenCertificateBindingError: no certificate was
            presented for a bound token.
        :raises UntrustedClientCertificateError: the presented certificate
            failed chain verification.
        :raises MismatchingCertificateThumbprintError: the presented
            certificate does not match the token binding.
        """
        binding = (token_claims or {}).get('cnf') or {}
        expected = binding.get('x5t#S256')
        if not expected:
            # Token is not certificate-bound; nothing to verify here.
            return True

        certificate = self.get_client_certificate(request)
        if certificate is None:
            log.debug('Bound token presented without a certificate on %r.',
                      request)
            raise InvalidTokenCertificateBindingError(request=request)
        if not certificate_chain_verified(request):
            raise UntrustedClientCertificateError(request=request)

        actual = calculate_x5t_s256(certificate)
        if not thumbprints_equal(actual, expected):
            log.debug('Token binding mismatch: expected %s got %s.',
                      expected, actual)
            raise MismatchingCertificateThumbprintError(request=request)
        return True

    # -- internal helpers -------------------------------------------------

    def _identify_client(self, request):
        validator = self.request_validator
        identify = getattr(validator,
                           'get_client_from_client_certificate', None)
        client = identify(request) if callable(identify) else \
            validator.authenticate_client_id(request.client_id, request)
        if not client:
            # Keep the standard invalid_client semantics for an unknown
            # client rather than inventing a new error code.
            raise InvalidClientError(request=request)
        return client

    def _get_certificate_registration(self, request, client):
        validator = self.request_validator
        getter = getattr(validator,
                         'get_client_certificate_registration', None)
        if not callable(getter):
            return None
        client_id = request.client_id or getattr(client, 'client_id', None)
        registration = getter(client_id, request)
        if not registration:
            return None
        if not isinstance(registration, dict):
            # Allow validators returning a bare thumbprint string.
            return {'thumbprint': registration}
        return registration

    def _compare_subject(self, parsed, registered_dn, registered_sans,
                         request):
        dn_ok = True
        if registered_dn:
            dn_ok = normalize_dn(parsed.subject_dn) == \
                normalize_dn(registered_dn)

        san_ok = True
        if registered_sans:
            expected = [tuple(entry) if isinstance(entry, (list, tuple))
                        else ('DNS', entry)
                        for entry in registered_sans]
            san_ok = any(san_name_matches(presented, registered)
                         for presented in parsed.sans
                         for registered in expected)

        if not dn_ok or not san_ok:
            log.debug('Certificate subject mismatch (dn_ok=%r, san_ok=%r).',
                      dn_ok, san_ok)
            raise MismatchingCertificateSubjectError(request=request)

    @staticmethod
    def _set_client_id(request, client):
        client_id = getattr(client, 'client_id', None)
        if not request.client_id:
            request.client_id = client_id
        elif client_id and request.client_id != client_id:
            raise ServerError(
                'Discrepancy found between client identifier')


def thumbprints_equal(actual, expected):
    """Compare two base64url thumbprints tolerantly (case, padding)."""
    actual = actual.strip().rstrip('=')
    expected = expected.strip().rstrip('=')
    return actual.lower() == expected.lower()


def build_mtls_metadata_aliases(alias_urls, base_claims):
    """Populate the ``mtls_endpoint_aliases`` metadata claim.

    RFC 8705 section 6 / RFC 8414: the authorization server metadata
    document advertises mTLS-specific endpoint URLs under
    ``mtls_endpoint_aliases``. Every alias mirrors the corresponding
    regular endpoint claim and carries auth-method lists including
    ``tls_client_auth``.

    :param alias_urls: mapping of regular endpoint claim name to the mTLS
        alias URL, e.g. ``{'token_endpoint': 'https://mtls.example/token'}``.
    :param base_claims: full metadata claim set, used to preserve any
        explicitly provided alias configuration and copy auth-method lists.
    """
    aliases = dict(base_claims.get('mtls_endpoint_aliases') or {})
    for claim, alias_url in alias_urls.items():
        if alias_url and claim in MTLS_ENDPOINT_ALIASES and claim not in aliases:
            aliases[claim] = alias_url

    method_claims = {
        'token_endpoint': 'token_endpoint_auth_methods_supported',
        'revocation_endpoint':
            'revocation_endpoint_auth_methods_supported',
        'introspection_endpoint':
            'introspection_endpoint_auth_methods_supported',
    }
    for endpoint, methods_claim in method_claims.items():
        if endpoint not in aliases:
            continue
        methods = list(base_claims.get(methods_claim,
                                       ['client_secret_basic',
                                        'client_secret_post']))
        if 'tls_client_auth' not in methods:
            methods.append('tls_client_auth')
        aliases.setdefault(methods_claim, methods)
    return aliases
