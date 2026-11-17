"""
oauthlib.oauth2.rfc9449.client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Client-side `RFC 9449`_ (DPoP) primitives: key generation, JWK handling,
RFC 7638 thumbprints and DPoP proof JWT creation.

A DPoP proof is a JWT signed with the client's asymmetric key. Its JOSE header
carries the public key as a ``jwk`` and its payload binds the proof to the
HTTP method (``htm``) and URL (``htu``) of the request it accompanies, plus
``iat`` and a unique ``jti``.

JWT/cryptography libraries are optional dependencies of oauthlib; they are
imported lazily so that importing this module never adds a runtime dependency
to deployments that do not use DPoP.

.. _`RFC 9449`: https://www.rfc-editor.org/rfc/rfc9449
"""
import base64
import hashlib
import json
import time
import uuid

from oauthlib.common import check_http_header_value

#: JWS algorithms allowed for DPoP proofs by RFC 9449 Section 4.1.
DPOP_ALGORITHMS = ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                   'PS256', 'PS384', 'PS512')

#: Algorithms accepted by the server-side validator by default. Asymmetric
#: ECDSA is the MTI DPoP algorithm family; RSA is still accepted.
DEFAULT_ACCEPTED_ALGORITHMS = ('ES256', 'ES384', 'ES512', 'PS256', 'RS256')

_EC_CURVE_NAMES = {
    'secp256r1': 'P-256',
    'secp384r1': 'P-384',
    'secp521r1': 'P-521',
}
_EC_CURVE_LENGTHS = {
    'P-256': 32,
    'P-384': 48,
    'P-521': 66,
}


def base64url_encode(data):
    """Base64url-encode bytes without padding, as used by JWT/JWK/RFC 7638."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def jwk_thumbprint(jwk):
    """Compute the RFC 7638 JWK thumbprint of a public JWK.

    The thumbprint is the base64url-encoded SHA-256 hash of the canonical
    JSON object containing only the required members of the JWK, with
    lexicographically sorted member names and no whitespace. This is the
    value placed in an access token's ``cnf.jkt`` claim.

    :param jwk: Public JWK dict (e.g. an EC key with ``kty``/``crv``/``x``/
        ``y`` or an RSA key with ``kty``/``n``/``e``).
    :raises ValueError: if the key type is unsupported.
    """
    if jwk.get('kty') == 'EC':
        members = {k: jwk[k] for k in ('crv', 'kty', 'x', 'y')}
    elif jwk.get('kty') == 'RSA':
        members = {k: jwk[k] for k in ('e', 'kty', 'n')}
    else:
        raise ValueError('Unsupported JWK key type: %r' % jwk.get('kty'))
    canonical = json.dumps(members, sort_keys=True, separators=(',', ':'))
    return base64url_encode(hashlib.sha256(canonical.encode('ascii')).digest())


def generate_dpop_key(algorithm='ES256'):
    """Generate a DPoP private key suitable for ``algorithm``.

    :param algorithm: One of :data:`DPOP_ALGORITHMS`.
    :returns: A tuple ``(private_key, public_jwk)`` where ``private_key`` is a
        cryptography key object accepted by :func:`create_dpop_proof` and
        ``public_jwk`` is the serialised public JWK dict to embed in the
        ``jwk`` proof header.
    """
    if algorithm not in DPOP_ALGORITHMS:
        raise ValueError('Unsupported DPoP algorithm: %s' % algorithm)

    if algorithm.startswith('ES'):
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

        curve = {
            'ES256': ec.SECP256R1(),
            'ES384': ec.SECP384R1(),
            'ES512': ec.SECP521R1(),
        }[algorithm]
        private_key = ec.generate_private_key(curve)
    else:
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
    return private_key, public_jwk_from_private_key(private_key)


def public_jwk_from_private_key(private_key):
    """Serialise the public part of a private key (object or JWK dict)."""
    if isinstance(private_key, dict):
        if 'd' not in private_key:
            raise ValueError('A private JWK dict must contain the "d" member')
        return {k: v for k, v in private_key.items() if k != 'd'}

    from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: PLC0415

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        numbers = private_key.public_key().public_numbers()
        length = (private_key.curve.key_size + 7) // 8
        return {
            'kty': 'EC',
            'crv': _EC_CURVE_NAMES[private_key.curve.name],
            'x': base64url_encode(numbers.x.to_bytes(length, 'big')),
            'y': base64url_encode(numbers.y.to_bytes(length, 'big')),
        }
    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.public_key().public_numbers()
        size = (numbers.n.bit_length() + 7) // 8
        return {
            'kty': 'RSA',
            'n': base64url_encode(numbers.n.to_bytes(size, 'big')),
            'e': base64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')),
        }
    raise TypeError('Unsupported private key type: %r' % type(private_key))


def _cryptography_private_key(private_key):
    """Return a cryptography private key object, loading a JWK dict if given."""
    if not isinstance(private_key, dict):
        return private_key

    from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: PLC0415

    def _b64u_decode(value):
        padding = '=' * (-len(value) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(value + padding), 'big')

    if private_key['kty'] == 'EC':
        curve = {v: k for k, v in _EC_CURVE_NAMES.items()}[private_key['crv']]
        curve_obj = {
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(),
            'secp521r1': ec.SECP521R1(),
        }[curve]
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=_b64u_decode(private_key['x']),
            y=_b64u_decode(private_key['y']),
            curve=curve_obj,
        )
        return ec.EllipticCurvePrivateNumbers(
            private_value=_b64u_decode(private_key['d']),
            public_numbers=public_numbers,
        ).private_key()
    if private_key['kty'] == 'RSA':
        public_numbers = rsa.RSAPublicNumbers(
            e=_b64u_decode(private_key['e']),
            n=_b64u_decode(private_key['n']),
        )
        return rsa.RSAPrivateNumbers(
            p=_b64u_decode(private_key['p']),
            q=_b64u_decode(private_key['q']),
            d=_b64u_decode(private_key['d']),
            dmp1=_b64u_decode(private_key['dp']),
            dmq1=_b64u_decode(private_key['dq']),
            iqmp=_b64u_decode(private_key['qi']),
            public_numbers=public_numbers,
        ).private_key()
    raise ValueError('Unsupported JWK key type: %r' % private_key.get('kty'))


def normalize_htu(uri):
    """Normalise an ``htu`` URL per RFC 9449 Section 4.3.

    The comparison URL uses the https (or http) scheme and HTTP origin, with
    no query or fragment component and the default port for the scheme
    omitted. The host is compared case-insensitively.
    """
    from urllib.parse import urlparse, urlunparse  # noqa: PLC0415

    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower()
    port = parsed.port
    netloc = ('%s:%d' % (host, port)
              if port and not (
                  (scheme == 'https' and port == 443)
                  or (scheme == 'http' and port == 80))
              else host)
    path = parsed.path or '/'
    return urlunparse((scheme, netloc, path, '', '', ''))


def access_token_hash(access_token):
    """Compute the ``ath`` claim value for an access token (RFC 9449 4.2)."""
    return base64url_encode(
        hashlib.sha256(access_token.encode('utf-8')).digest())


def create_dpop_proof(private_key, http_method, uri, *, algorithm='ES256',
                      nonce=None, access_token=None, jti=None,
                      issued_at=None, additional_claims=None):
    """Create a signed DPoP proof JWT.

    :param private_key: A cryptography private key object (as returned by
        :func:`generate_dpop_key`) or a private JWK dict.
    :param http_method: HTTP method the proof is bound to, e.g. ``"POST"``.
    :param uri: Full request URL the proof is bound to; it is normalised per
        :func:`normalize_htu` before being placed in the ``htu`` claim.
    :param algorithm: JWS algorithm, one of :data:`DPOP_ALGORITHMS`.
    :param nonce: Optional server-provided DPoP nonce to include.
    :param access_token: When given (proof accompanying a DPoP-bound access
        token at a protected resource), the ``ath`` hash claim is added.
    :param jti: Optional explicit JWT id; a random UUID4 hex string otherwise.
    :param issued_at: Optional explicit ``iat`` (epoch seconds); ``time.time``
        otherwise.
    :param additional_claims: Optional dict of extra payload claims.
    :returns: The compact-serialised proof JWT as an ASCII string.
    """
    import jwt  # noqa: PLC0415

    if algorithm not in DPOP_ALGORITHMS:
        raise ValueError('Unsupported DPoP algorithm: %s' % algorithm)

    public_jwk = public_jwk_from_private_key(private_key)
    _assert_algorithm_matches_jwk(algorithm, public_jwk)

    payload = {
        'jti': jti or uuid.uuid4().hex,
        'htm': http_method.upper(),
        'htu': normalize_htu(uri),
        'iat': int(issued_at if issued_at is not None else time.time()),
    }
    if nonce is not None:
        payload['nonce'] = nonce
    if access_token is not None:
        payload['ath'] = access_token_hash(access_token)
    if additional_claims:
        payload.update(additional_claims)

    # All values end up in an HTTP header field value; make sure they are
    # safe to put there (jti/nonce are attacker-influenceable on retry).
    check_http_header_value('DPoP jti', payload['jti'])
    if nonce is not None:
        check_http_header_value('DPoP nonce', nonce)

    headers = {'typ': 'DPoP', 'jwk': public_jwk}
    signing_key = _cryptography_private_key(private_key)
    return jwt.encode(payload, signing_key, algorithm=algorithm,
                      headers=headers)


def _assert_algorithm_matches_jwk(algorithm, jwk):
    if algorithm.startswith('ES') and jwk.get('kty') != 'EC':
        raise ValueError('Algorithm %s requires an EC key' % algorithm)
    if algorithm[:2] in ('RS', 'PS') and jwk.get('kty') != 'RSA':
        raise ValueError('Algorithm %s requires an RSA key' % algorithm)
    if algorithm.startswith('ES'):
        expected_crv = {'ES256': 'P-256', 'ES384': 'P-384',
                        'ES512': 'P-521'}[algorithm]
        if jwk.get('crv') != expected_crv:
            raise ValueError('Algorithm %s requires a %s curve'
                             % (algorithm, expected_crv))
