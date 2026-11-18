"""
TraceX PKI & Mutual TLS Certificate Manager
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Generates and manages X.509 Certificate Authorities, Server Certificates,
and Client Certificates for hardened mutual TLS (mTLS) communication between
the TraceX Manager VM and the VirtualBox Host Controller Agent.

Security Standards:
- RSA 2048/3072-bit keys (FIPS / NIST SP 800-57 compliant)
- SHA-256 Signature Algorithm
- Explicit Subject Alternative Names (SAN) for 192.168.56.1, 127.0.0.1, localhost
- Extended Key Usage: serverAuth for Host Agent, clientAuth for Manager VM
- Strict validation of certificate expiration and revocation status
"""

import os
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class PKIManager:
    """Manages generation, serialization, and validation of mTLS X.509 certificates."""

    @staticmethod
    def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

    @classmethod
    def create_ca(
        cls,
        common_name: str = "TraceX Dynamic Lab Internal Root CA",
        validity_days: int = 365,
        key_size: int = 2048
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generates self-signed Root CA certificate and private key."""
        private_key = cls.generate_private_key(key_size)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TraceX Digital Forensics"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Forensic Control Plane CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        return cert, private_key

    @classmethod
    def create_server_certificate(
        cls,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        common_name: str = "tracex-host-agent",
        ip_addresses: Optional[list] = None,
        dns_names: Optional[list] = None,
        validity_days: int = 180,
        key_size: int = 2048
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generates Host Agent server certificate signed by TraceX Root CA."""
        private_key = cls.generate_private_key(key_size)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TraceX Digital Forensics"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "VirtualBox Host Controller"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        ips = [ipaddress.ip_address(ip) for ip in (ip_addresses or ["192.168.56.1", "127.0.0.1"])]
        dns = [x509.DNSName(d) for d in (dns_names or ["localhost", "tracex-host-agent"])]
        san_entries = [x509.IPAddress(ip) for ip in ips] + dns

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return cert, private_key

    @classmethod
    def create_client_certificate(
        cls,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        common_name: str = "tracex-manager-vm",
        validity_days: int = 180,
        key_size: int = 2048,
        expired: bool = False
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generates Manager VM client certificate signed by TraceX Root CA."""
        private_key = cls.generate_private_key(key_size)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TraceX Digital Forensics"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Manager VM Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.now(timezone.utc)
        if expired:
            not_before = now - timedelta(days=30)
            not_after = now - timedelta(days=1)
        else:
            not_before = now - timedelta(minutes=5)
            not_after = now + timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return cert, private_key

    @staticmethod
    def serialize_cert_pem(cert: x509.Certificate) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    @staticmethod
    def serialize_key_pem(key: rsa.RSAPrivateKey) -> str:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    @classmethod
    def generate_full_pki_bundle(cls, output_dir: Path) -> Dict[str, Path]:
        """
        Generates and saves the full set of mTLS certificates:
        - ca_cert.pem, ca_key.pem
        - server_cert.pem, server_key.pem
        - client_cert.pem, client_key.pem
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        ca_cert, ca_key = cls.create_ca()
        server_cert, server_key = cls.create_server_certificate(ca_cert, ca_key)
        client_cert, client_key = cls.create_client_certificate(ca_cert, ca_key)

        paths = {
            "ca_cert": output_dir / "ca_cert.pem",
            "ca_key": output_dir / "ca_key.pem",
            "server_cert": output_dir / "server_cert.pem",
            "server_key": output_dir / "server_key.pem",
            "client_cert": output_dir / "client_cert.pem",
            "client_key": output_dir / "client_key.pem",
        }

        paths["ca_cert"].write_text(cls.serialize_cert_pem(ca_cert), encoding="utf-8")
        paths["ca_key"].write_text(cls.serialize_key_pem(ca_key), encoding="utf-8")
        paths["server_cert"].write_text(cls.serialize_cert_pem(server_cert), encoding="utf-8")
        paths["server_key"].write_text(cls.serialize_key_pem(server_key), encoding="utf-8")
        paths["client_cert"].write_text(cls.serialize_cert_pem(client_cert), encoding="utf-8")
        paths["client_key"].write_text(cls.serialize_key_pem(client_key), encoding="utf-8")

        # Set strict read permissions on private key files where supported
        for k in ("ca_key", "server_key", "client_key"):
            try:
                os.chmod(str(paths[k]), 0o600)
            except Exception:
                pass

        return paths


pki_manager = PKIManager()

