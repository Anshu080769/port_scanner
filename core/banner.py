"""
Service Banner Grabbing and Regex Version Parsing Module.

Provides:
- Active & passive socket banner acquisition
- TLS/SSL handshake negotiation for secure services
- Regular expression signature matching for product and version identification
- HTTP header inspection (Server, X-Powered-By, Title)
"""

import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class ServiceInfo:
    """Detailed fingerprint for a detected service."""
    port: int
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: str = ""
    protocol: str = "tcp"
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "service_name": self.service_name,
            "product": self.product or "Unknown",
            "version": self.version or "",
            "banner": self.banner,
            "protocol": self.protocol,
            "metadata": self.metadata,
        }


# Signature patterns for regex extraction of products and versions
SIGNATURE_PATTERNS = [
    # SSH
    {
        "service": "ssh",
        "pattern": re.compile(r"SSH-([\d.]+)-OpenSSH_([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "OpenSSH",
        "version_group": 2,
    },
    {
        "service": "ssh",
        "pattern": re.compile(r"SSH-([\d.]+)-dropbear_([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "Dropbear SSH",
        "version_group": 2,
    },
    {
        "service": "ssh",
        "pattern": re.compile(r"SSH-([\d.]+)-([^\r\n\s]+)", re.IGNORECASE),
        "product": "SSH",
        "version_group": 2,
    },
    # FTP
    {
        "service": "ftp",
        "pattern": re.compile(r"\(vsFTPd\s+([0-9a-zA-Z._-]+)\)", re.IGNORECASE),
        "product": "vsftpd",
        "version_group": 1,
    },
    {
        "service": "ftp",
        "pattern": re.compile(r"ProFTPD\s+([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "ProFTPD",
        "version_group": 1,
    },
    {
        "service": "ftp",
        "pattern": re.compile(r"Pure-FTPd", re.IGNORECASE),
        "product": "Pure-FTPd",
        "version_group": None,
    },
    {
        "service": "ftp",
        "pattern": re.compile(r"FileZilla Server (?:version )?([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "FileZilla Server",
        "version_group": 1,
    },
    {
        "service": "ftp",
        "pattern": re.compile(r"Microsoft FTP Service", re.IGNORECASE),
        "product": "Microsoft FTP Service",
        "version_group": None,
    },
    # SMTP
    {
        "service": "smtp",
        "pattern": re.compile(r"220.*ESMTP Postfix(?: \(([^)\r\n]+)\))?", re.IGNORECASE),
        "product": "Postfix ESMTP",
        "version_group": 1,
    },
    {
        "service": "smtp",
        "pattern": re.compile(r"220.*ESMTP Exim\s+([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "Exim ESMTP",
        "version_group": 1,
    },
    {
        "service": "smtp",
        "pattern": re.compile(r"220.*Sendmail\s+([0-9a-zA-Z._-]+)", re.IGNORECASE),
        "product": "Sendmail",
        "version_group": 1,
    },
    # HTTP Server Headers
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*Apache(?:/([0-9a-zA-Z._-]+))?(?:\s*\(([^)\r\n]+)\))?", re.IGNORECASE),
        "product": "Apache HTTP Server",
        "version_group": 1,
    },
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*nginx(?:/([0-9a-zA-Z._-]+))?", re.IGNORECASE),
        "product": "nginx",
        "version_group": 1,
    },
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*Microsoft-IIS/([0-9.]+)", re.IGNORECASE),
        "product": "Microsoft IIS",
        "version_group": 1,
    },
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*Werkzeug/([0-9.]+)\s+Python/([0-9.]+)", re.IGNORECASE),
        "product": "Werkzeug (Python)",
        "version_group": 1,
    },
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*lighttpd(?:/([0-9a-zA-Z._-]+))?", re.IGNORECASE),
        "product": "lighttpd",
        "version_group": 1,
    },
    {
        "service": "http",
        "pattern": re.compile(r"Server:\s*Caddy", re.IGNORECASE),
        "product": "Caddy",
        "version_group": None,
    },
    # Redis
    {
        "service": "redis",
        "pattern": re.compile(r"redis_version:([0-9.]+)", re.IGNORECASE),
        "product": "Redis Key-Value Store",
        "version_group": 1,
    },
    # MySQL / MariaDB
    {
        "service": "mysql",
        "pattern": re.compile(r"([0-9]+\.[0-9]+\.[0-9]+-[0-9a-zA-Z._-]+-MariaDB)", re.IGNORECASE),
        "product": "MariaDB",
        "version_group": 1,
    },
    {
        "service": "mysql",
        "pattern": re.compile(r"([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9._-]*mysql)", re.IGNORECASE),
        "product": "MySQL",
        "version_group": 1,
    },
]


def clean_banner_text(raw_bytes: bytes) -> str:
    """
    Decodes binary socket payloads, filtering out control/binary sequences
    while preserving readable ASCII/UTF-8 strings.
    """
    if not raw_bytes:
        return ""

    # Decode with replacement
    text = raw_bytes.decode("utf-8", errors="replace")

    # Replace non-printable characters (except standard whitespaces)
    cleaned = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in text)

    # Normalize line breaks and trim excessive whitespace
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    return " | ".join(lines[:5])  # Cap at first 5 lines for concise reporting


class BannerGrabber:
    """
    Executes service banner grabbing probes and identifies software versions.
    """

    def __init__(self, target_ip: str, timeout: float = 1.5):
        self.target_ip = target_ip
        self.timeout = timeout

    def grab_banner(self, port: int, service_hint: str = "unknown") -> ServiceInfo:
        """
        Attempts to retrieve the service banner and identify software version.
        Uses passive listening first, then active probing (HTTP/SSL/Generic).
        """
        raw_data = b""
        protocol = "tcp"
        extra_meta: Dict[str, str] = {}

        is_ssl_port = port in (443, 8443, 9443, 465, 993, 995, 636) or "https" in service_hint.lower()
        is_http_port = is_ssl_port or port in (80, 8080, 8000, 8888, 3000, 5000, 9000, 8081) or "http" in service_hint.lower()

        # Step 1: Probe based on service type
        if is_ssl_port:
            raw_data, extra_meta = self._probe_tls(port)
            protocol = "tls/tcp"
        elif is_http_port:
            raw_data, extra_meta = self._probe_http(port)
        elif port == 6379 or "redis" in service_hint.lower():
            raw_data = self._probe_redis(port)
        else:
            # Generic TCP: Passive wait first, fallback to active probe
            raw_data = self._probe_generic(port)

        # Step 2: Clean the banner text
        banner_text = clean_banner_text(raw_data)

        # Step 3: Parse software product and version using regular expressions
        product, version = self._parse_version(banner_text, raw_data, service_hint)

        return ServiceInfo(
            port=port,
            service_name=service_hint,
            product=product,
            version=version,
            banner=banner_text,
            protocol=protocol,
            metadata=extra_meta,
        )

    def _probe_generic(self, port: int) -> bytes:
        """Passive connect and read; if no greeting, send generic probe."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        data = b""

        try:
            sock.connect((self.target_ip, port))
            # 1. Passive receive (e.g. SSH, FTP, SMTP send immediate banner)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                pass

            # 2. If nothing received, send an active probe
            if not data:
                try:
                    sock.sendall(b"\r\n\r\n")
                    data = sock.recv(1024)
                except socket.timeout:
                    pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return data

    def _probe_http(self, port: int) -> Tuple[bytes, Dict[str, str]]:
        """Sends HTTP request and parses headers and page title."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        meta: Dict[str, str] = {}
        data = b""

        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (SecurityAuditor/1.0)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")

        try:
            sock.connect((self.target_ip, port))
            sock.sendall(req)
            data = sock.recv(4096)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Extract headers and title if present
        text = data.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().lower()
                if k_clean in ("server", "x-powered-by", "x-aspnet-version"):
                    meta[k.strip()] = v.strip()

        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if title_match:
            meta["Title"] = title_match.group(1).strip()[:80]

        return data, meta

    def _probe_tls(self, port: int) -> Tuple[bytes, Dict[str, str]]:
        """Wraps connection with TLS (ignoring untrusted certs for lab testing)."""
        meta: Dict[str, str] = {}
        data = b""

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)

        try:
            raw_sock.connect((self.target_ip, port))
            with context.wrap_socket(raw_sock, server_hostname=self.target_ip) as tls_sock:
                # Capture certificate info
                try:
                    cert = tls_sock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        meta["SSL_Common_Name"] = subject.get("commonName", "")
                except Exception:
                    pass

                # Send HTTPS request
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (SecurityAuditor/1.0)\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8")

                tls_sock.sendall(req)
                data = tls_sock.recv(4096)

        except Exception:
            pass

        # Extract HTTP headers if present
        text = data.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().lower()
                if k_clean in ("server", "x-powered-by"):
                    meta[k.strip()] = v.strip()

        return data, meta

    def _probe_redis(self, port: int) -> bytes:
        """Sends Redis INFO command."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        data = b""

        try:
            sock.connect((self.target_ip, port))
            sock.sendall(b"INFO\r\n")
            data = sock.recv(2048)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return data

    def _parse_version(
        self,
        banner_text: str,
        raw_bytes: bytes,
        service_hint: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Matches regular expression signatures against banner text to determine product and version.
        """
        combined_text = banner_text + " " + raw_bytes.decode("utf-8", errors="ignore")

        # Check signature patterns
        for sig in SIGNATURE_PATTERNS:
            match = sig["pattern"].search(combined_text)
            if match:
                product = sig["product"]
                version = None
                vg = sig["version_group"]
                if vg is not None and vg <= len(match.groups()):
                    version = match.group(vg)
                return product, version

        # MySQL binary handshake heuristic
        if len(raw_bytes) > 5 and b"mysql" in raw_bytes.lower():
            # MySQL protocol 10 puts null-terminated version string starting around byte 5
            m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9._-]*)", raw_bytes.decode("latin1", errors="ignore"))
            if m:
                return "MySQL", m.group(1)

        return None, None
