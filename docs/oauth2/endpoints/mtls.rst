Mutual-TLS (RFC 8705)
=====================

OAuthLib implements `RFC 8705`_ — OAuth 2.0 Mutual-TLS Client Authentication
and Certificate-Bound Access Tokens. It provides two complementary
mechanisms:

1. **Mutual-TLS client authentication** (section 2): the client
   authenticates at the token, introspection and revocation endpoints
   with an X.509 certificate presented during the TLS handshake, instead
   of (or in addition to) a ``client_secret``.
2. **Certificate-bound access tokens** (section 3): the issued token
   carries a confirmation member ``cnf`` with an ``x5t#S256`` value —
   the base64url-encoded SHA-256 hash of the client certificate. A
   protected resource only accepts the token when it is presented on a
   TLS connection whose client certificate has the same thumbprint.

The implementation lives in :mod:`oauthlib.oauth2.rfc8705` and uses only
the Python standard library for its own logic; parsing PEM/DER
certificates uses the optional ``cryptography`` package when available.

.. _`RFC 8705`: https://www.rfc-editor.org/rfc/rfc8705

How the certificate reaches the library
---------------------------------------

The TLS handshake — including requesting the client certificate and
validating its chain — is performed by your web framework or the TLS
terminator (e.g. nginx) in front of the application. OAuthLib never opens
a socket itself. Once the handshake is done, the parsed certificate is
attached to the request, by convention as ``request.client_cert``.

Accepted certificate representations are:

- a ``cryptography.x509.Certificate`` object,
- an :class:`ssl.SSLSocket`-like object exposing ``getpeercert()`` and
  ``getpeercert(binary_form=True)``,
- raw PEM or DER bytes,
- the dict returned by :meth:`ssl.SSLSocket.getpeercert`.

A trusted proxy may instead forward the certificate in a header
(``X-SSL-CERT``, ``X-Client-Cert``, ``X-Tls-Client-Cert`` and variants);
the optional header list is defined in
``oauthlib.oauth2.rfc8705.mtls.CLIENT_CERT_HEADERS``. Chain verification
status can be signalled with an ``X-SSL-Client-Verify: SUCCESS`` header
(the nginx ``$ssl_client_verify`` convention).

Enabling mTLS on a server
-------------------------

The pre-configured servers accept two keyword arguments that are
propagated to every grant and to the introspection and revocation
endpoints:

- ``mtls_enabled``: a request presenting a client certificate is
  authenticated against the client's registered certificate information.
  Requests without a certificate keep using the unchanged HTTP Basic /
  POST-body secret paths.
- ``require_mtls``: every client-authenticated request must present a
  certificate; otherwise a distinct error is returned.

.. code-block:: python

    from oauthlib.oauth2 import BackendApplicationServer

    server = BackendApplicationServer(
        validator,
        mtls_enabled=True,
        # require_mtls=True,  # uncomment for a strict mTLS-only alias
    )

The same flags are available directly on ``TokenEndpoint``,
``IntrospectEndpoint`` and ``RevocationEndpoint``, and on the individual
grant classes.

Validator hooks
---------------

Two optional ``RequestValidator`` methods drive the authentication path.

``get_client_certificate_registration(client_id, request)``
    Return the certificate information registered for the client, as a
    dict with any combination of:

    - ``thumbprint`` (or ``x5t#S256``): the expected base64url SHA-256
      thumbprint, compared directly (section 2.1.1);
    - ``subject_dn`` (or ``dn``): a dict such as
      ``{'CN': 'client.example', 'O': 'Example'}`` or an RFC 4514
      string;
    - ``san`` (or ``subject_alt_names``): a list of
      ``(type, value)`` tuples (``('DNS', ...)``,
      ``('IP Address', ...)``, ``('email', ...)``, ``('URI', ...)``) or
      bare DNS-name strings.

    A bare string is treated as a registered thumbprint. Returning
    ``None`` raises a dedicated "missing registration" error.

``get_client_from_client_certificate(request)``
    Optional. Identify the client from the certificate alone when no
    ``client_id`` form parameter was supplied.

For protected-resource validation of a bound token, implement
``get_token_certificate_binding(token, request)`` or expose the stored
binding as ``request.token_claims['cnf']`` / ``request.cnf`` inside
``validate_bearer_token``.

Distinct error classes
----------------------

Each failure mode has its own exception in
:mod:`oauthlib.oauth2.rfc8705.errors` rather than being collapsed into a
generic 401:

``MissingClientCertificateError``
    No client certificate was presented.

``UntrustedClientCertificateError``
    The certificate chain / trust verification failed.

``InvalidClientCertificateError``
    The certificate is malformed or could not be parsed.

``MissingClientCertificateRegistrationError``
    The client has no registered certificate DN, SAN or thumbprint.

``MismatchingCertificateSubjectError``
    The certificate subject DN or SAN does not match the registration.

``MismatchingCertificateThumbprintError``
    The ``x5t#S256`` thumbprint does not match, either during client
    authentication or token-binding verification.

``InvalidTokenCertificateBindingError``
    A certificate-bound token was presented without any client
    certificate.

Chain verification failure and subject mismatch are deliberately
different classes so an operator can tell an untrusted certificate apart
from a trusted certificate that simply does not belong to the
authenticating client.

Certificate-bound tokens
------------------------

Use :class:`~oauthlib.oauth2.rfc8705.CertificateBoundBearerToken` as a
drop-in replacement for ``BearerToken``. When the request carries a
client certificate, the issued token includes a ``cnf`` member::

    {
        "access_token": "...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "cnf": {"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"}
    }

The same ``cnf`` dict is handed to ``save_bearer_token`` so it can be
persisted alongside the opaque token, or embedded as a JWT claim by a
signed-token generator. On a protected-resource request, the handler
recomputes the presented certificate's thumbprint and compares it to the
stored binding, raising ``InvalidTokenCertificateBindingError`` or
``MismatchingCertificateThumbprintError`` on failure.

Discovery metadata
------------------

When mTLS is enabled, the ``MetadataEndpoint`` automatically adds
``tls_client_auth`` to the ``token_endpoint_auth_methods_supported``,
``revocation_endpoint_auth_methods_supported`` and
``introspection_endpoint_auth_methods_supported`` lists.

The mTLS endpoint aliases (RFC 8705 section 6) are advertised through the
``mtls_endpoint_aliases`` metadata claim. Supply it in the metadata
claims and it is validated and enriched with per-alias auth-method
lists::

    claims = {
        "issuer": "https://as.example",
        "token_endpoint": "https://as.example/token",
        "mtls_endpoint_aliases": {
            "token_endpoint": "https://mtls.as.example/token",
            "revocation_endpoint": "https://mtls.as.example/revoke",
            "introspection_endpoint":
                "https://mtls.as.example/introspect",
        },
    }

The helper
:func:`~oauthlib.oauth2.rfc8705.mtls.build_mtls_metadata_aliases` builds
the alias object from regular endpoint URLs.

Backwards compatibility
-----------------------

When ``mtls_enabled`` is ``False`` (the default), no certificate is
inspected and the HTTP Basic and POST-body client authentication paths
behave exactly as in RFC 6749. Existing deployments and tests are
unaffected; mTLS is strictly opt-in.
