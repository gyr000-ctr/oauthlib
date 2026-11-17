"""In-memory test certificate fixtures for the RFC 8705 test-suite.

Certificates are generated once per session with the ``cryptography``
package (a test-time dependency only; the library itself does not require
it). Keeping generation here, instead of shipping PEM files, avoids
expiry problems and makes every distinguished name / SAN explicit.
"""
import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from oauthlib.oauth2.rfc8705 import calculate_x5t_s256


def _make_cert(cn, sans=None, issuer=None, issuer_key=None, key=None):
    """Build a (cert, key) pair; self-signed unless an issuer is given."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    issuer = issuer or _make_name(cn)
    issuer_key = issuer_key or key
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    names = [x509.DNSName(s) for s in (sans or [cn])]
    # One fixture mixes a DNS name and an IP address.
    if cn == 'mixed.example':
        names.append(x509.IPAddress(ipaddress.ip_address('203.0.113.7')))
    cert = (
        x509.CertificateBuilder()
        .subject_name(_make_name(cn))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _make_name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Org'),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


@pytest.fixture(scope='session')
def ca():
    cert, key = _make_cert('Example Test CA')
    return cert, key


@pytest.fixture(scope='session')
def client_cert(ca):
    """Client certificate signed by the test CA."""
    ca_cert, ca_key = ca
    cert, key = _make_cert(
        'client.example',
        sans=['client.example', 'alias.example'],
        issuer=ca_cert.subject,
        issuer_key=ca_key,
    )
    return cert, key


@pytest.fixture(scope='session')
def other_cert(ca):
    """A different CA-signed client certificate."""
    ca_cert, ca_key = ca
    cert, key = _make_cert(
        'other.example',
        issuer=ca_cert.subject,
        issuer_key=ca_key,
    )
    return cert, key


@pytest.fixture(scope='session')
def mixed_cert(ca):
    """Certificate carrying both a DNS SAN and an IP SAN."""
    ca_cert, ca_key = ca
    cert, key = _make_cert(
        'mixed.example',
        sans=['mixed.example'],
        issuer=ca_cert.subject,
        issuer_key=ca_key,
    )
    return cert, key


@pytest.fixture(scope='session')
def cert_pem(client_cert):
    cert, _ = client_cert
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope='session')
def cert_der(client_cert):
    cert, _ = client_cert
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope='session')
def other_cert_pem(other_cert):
    cert, _ = other_cert
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope='session')
def client_thumbprint(client_cert):
    cert, _ = client_cert
    return calculate_x5t_s256(cert)


@pytest.fixture(scope='session')
def other_thumbprint(other_cert):
    cert, _ = other_cert
    return calculate_x5t_s256(cert)
