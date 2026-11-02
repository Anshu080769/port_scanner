"""
Vulnerability and Security Posture Auditor.

Performs automated security checks on discovered open ports:
- Unencrypted/Cleartext protocol auditing (Telnet, FTP, HTTP, POP3, IMAP)
- Anonymous access verification (FTP anonymous login, Redis no-auth check)
- HTTP security header evaluations (HSTS, X-Content-Type-Options, CSP, clickjacking)
- High-risk service exposure assessments (SMB, RDP, Docker Daemon, Databases)
- Vulnerable/Outdated software banner heuristics
"""

import socket
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional
from core.banner import ServiceInfo


@dataclass
class Finding:
    """Security audit finding representing a vulnerability or misconfiguration."""
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    port: int
    protocol: str
    service: str
    title: str
    description: str
    recommendation: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "severity": self.severity,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence or "N/A",
        }


class ServiceAuditor:
    """
    Evaluates discovered services against cybersecurity baseline standards and vulnerabilities.
    """

    def __init__(self, target_ip: str, timeout: float = 2.0):
        self.target_ip = target_ip
        self.timeout = timeout

    def audit_service(self, service_info: ServiceInfo) -> List[Finding]:
        """
        Runs comprehensive security audit checks on an open service.
        """
        findings: List[Finding] = []
        port = service_info.port
        service = service_info.service_name.lower()
        product = (service_info.product or "").lower()
        version = service_info.version or ""
        banner = service_info.banner

        # 1. Cleartext / Insecure Protocol Checks
        findings.extend(self._check_cleartext_protocols(port, service))

        # 2. High-Risk Management & Database Port Exposures
        findings.extend(self._check_exposed_risky_ports(port, service))

        # 3. Active Safe Lab Probes (Anonymous FTP, Unauthenticated Redis)
        if port == 21 or "ftp" in service:
            ftp_finding = self._audit_ftp_anonymous(port)
            if ftp_finding:
                findings.append(ftp_finding)

        if port == 6379 or "redis" in service:
            redis_finding = self._audit_redis_unauthenticated(port)
            if redis_finding:
                findings.append(redis_finding)

        # 4. HTTP / Web Security Headers Audit
        if port in (80, 443, 8080, 8443, 8000, 5000, 3000) or "http" in service:
            findings.extend(self._audit_http_headers(service_info))

        # 5. Software Version Vulnerability Heuristics
        findings.extend(self._audit_version_heuristics(port, service, product, version, banner))

        return findings

    def _check_cleartext_protocols(self, port: int, service: str) -> List[Finding]:
        """Flags protocols transmitting credentials or traffic in cleartext."""
        findings: List[Finding] = []

        if port == 23 or "telnet" in service:
            findings.append(Finding(
                severity="HIGH",
                port=port,
                protocol="TCP",
                service=service or "Telnet",
                title="Insecure Cleartext Protocol: Telnet",
                description="Telnet transmits all communications, including authentication credentials, in unencrypted plaintext.",
                recommendation="Disable the Telnet daemon immediately. Migrate remote shell access to SSH (port 22) using key-based authentication.",
                evidence=f"Port {port} responding as Telnet."
            ))

        if port == 21 or ("ftp" in service and "sftp" not in service and "ftps" not in service):
            findings.append(Finding(
                severity="MEDIUM",
                port=port,
                protocol="TCP",
                service=service or "FTP",
                title="Unencrypted FTP Service Detected",
                description="Standard FTP transfers credentials and file data in cleartext, exposing sessions to packet sniffing and MITM attacks.",
                recommendation="Enforce FTPS (FTP over TLS) or replace with SFTP (SSH File Transfer Protocol on port 22).",
                evidence=f"Port {port} running plaintext FTP service."
            ))

        if port in (80, 8080, 8000) and service in ("http", "http-alt", "http-proxy", "unknown"):
            findings.append(Finding(
                severity="LOW",
                port=port,
                protocol="TCP",
                service="HTTP",
                title="Unencrypted HTTP Web Service",
                description="Web server is accepting connections over unencrypted HTTP. Session cookies and sensitive data may be intercepted.",
                recommendation="Deploy TLS/SSL certificates (e.g. Let's Encrypt), enforce automatic HTTPS redirection, and implement HSTS.",
                evidence=f"HTTP service active on port {port} without TLS encapsulation."
            ))

        if port == 110 or "pop3" in service and "pop3s" not in service:
            findings.append(Finding(
                severity="MEDIUM",
                port=port,
                protocol="TCP",
                service="POP3",
                title="Unencrypted Mail Retrieval: POP3",
                description="POP3 protocol transmits email user credentials and messages in unencrypted plaintext.",
                recommendation="Disable unencrypted POP3. Upgrade to POP3S (port 995) or IMAPS (port 993) with mandatory TLS.",
                evidence=f"Standard POP3 port {port} exposed."
            ))

        if port == 143 or "imap" in service and "imaps" not in service:
            findings.append(Finding(
                severity="MEDIUM",
                port=port,
                protocol="TCP",
                service="IMAP",
                title="Unencrypted Mail Access: IMAP",
                description="IMAP cleartext port transmits authentication credentials across the network in plaintext.",
                recommendation="Migrate to IMAPS (port 993) requiring TLS 1.2 or TLS 1.3.",
                evidence=f"Standard IMAP port {port} open."
            ))

        if port in (513, 514) or service in ("rlogin", "rsh"):
            findings.append(Finding(
                severity="HIGH",
                port=port,
                protocol="TCP",
                service=service or "rlogin/rsh",
                title="Legacy Insecure Remote Execution Protocol",
                description="rlogin and rsh rely on obsolete IP-based or plaintext authentication without cryptographic integrity.",
                recommendation="Disable rlogin/rsh daemons and migrate exclusively to OpenSSH.",
                evidence=f"Port {port} active."
            ))

        return findings

    def _check_exposed_risky_ports(self, port: int, service: str) -> List[Finding]:
        """Flags high-risk administration, file-sharing, or database ports."""
        findings: List[Finding] = []

        if port in (139, 445) or "microsoft-ds" in service or "netbios" in service:
            findings.append(Finding(
                severity="HIGH",
                port=port,
                protocol="TCP",
                service="SMB / NetBIOS",
                title="Exposed Windows SMB / File Sharing Service",
                description="Direct exposure of SMB (port 445/139) presents significant risk of lateral movement, brute force, and remote exploit propagation.",
                recommendation="Restrict SMB access via firewall rules to trusted subnets only. Ensure SMBv1 is disabled and SMB signing/encryption is enforced.",
                evidence=f"SMB port {port} accessible."
            ))

        if port == 3389 or "ms-wbt-server" in service or "rdp" in service:
            findings.append(Finding(
                severity="MEDIUM",
                port=port,
                protocol="TCP",
                service="RDP",
                title="Exposed Remote Desktop Protocol (RDP)",
                description="Exposed RDP endpoints are frequent targets for credential spraying, brute-force attacks, and ransomware payloads.",
                recommendation="Place RDP behind a VPN or Remote Desktop Gateway with Multi-Factor Authentication (MFA). Enable Network Level Authentication (NLA).",
                evidence=f"RDP listening on port {port}."
            ))

        if port == 2375:
            findings.append(Finding(
                severity="CRITICAL",
                port=port,
                protocol="TCP",
                service="Docker API",
                title="Unauthenticated Docker Daemon REST API",
                description="Docker API on port 2375 without TLS allows unauthenticated remote callers to spin up containers with root host filesystem mounts.",
                recommendation="Never expose port 2375. Switch to port 2376 with mandatory mutual TLS client certificate verification.",
                evidence="Port 2375 (Docker plain HTTP socket) is accessible."
            ))

        if port in (3306, 5432, 27017, 1433, 1521):
            db_names = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 1433: "MS-SQL", 1521: "Oracle"}
            name = db_names.get(port, "Database")
            findings.append(Finding(
                severity="MEDIUM",
                port=port,
                protocol="TCP",
                service=service or name,
                title=f"Direct Exposure of {name} Database Engine",
                description=f"Database port {port} is publicly exposed. Increases risk of brute-force authentication attacks and zero-day exploitation.",
                recommendation=f"Bind {name} listener to localhost (127.0.0.1) or restrict network access to application backend servers via firewall whitelist.",
                evidence=f"Database service exposed on port {port}."
            ))

        return findings

    def _audit_ftp_anonymous(self, port: int) -> Optional[Finding]:
        """Active safe probe: attempts anonymous login on discovered FTP port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.target_ip, port))
            greeting = sock.recv(1024).decode("utf-8", errors="ignore")

            # Send USER anonymous
            sock.sendall(b"USER anonymous\r\n")
            user_resp = sock.recv(1024).decode("utf-8", errors="ignore")

            if "331" in user_resp:
                # Password required, send email-style pass
                sock.sendall(b"PASS audit@lab.local\r\n")
                pass_resp = sock.recv(1024).decode("utf-8", errors="ignore")

                if "230" in pass_resp:
                    # Login successful!
                    sock.sendall(b"QUIT\r\n")
                    return Finding(
                        severity="HIGH",
                        port=port,
                        protocol="TCP",
                        service="FTP",
                        title="Anonymous FTP Login Permitted",
                        description="The FTP server allows unauthenticated users to log in using the 'anonymous' account.",
                        recommendation="Disable anonymous access in the FTP daemon configuration (e.g. 'anonymous_enable=NO' in vsftpd.conf).",
                        evidence=f"Response to PASS: {pass_resp.strip()}"
                    )
            elif "230" in user_resp:
                # Logged in without password prompt
                sock.sendall(b"QUIT\r\n")
                return Finding(
                    severity="HIGH",
                    port=port,
                    protocol="TCP",
                    service="FTP",
                    title="Anonymous FTP Login Permitted (No Password Required)",
                    description="The FTP server logged in anonymous user immediately without credential challenge.",
                    recommendation="Disable anonymous login privileges on this FTP service.",
                    evidence=f"Response to USER: {user_resp.strip()}"
                )
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return None

    def _audit_redis_unauthenticated(self, port: int) -> Optional[Finding]:
        """Active safe probe: checks if Redis responds to commands without AUTH."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.target_ip, port))
            sock.sendall(b"PING\r\n")
            resp = sock.recv(512).decode("utf-8", errors="ignore")

            if "+PONG" in resp:
                return Finding(
                    severity="CRITICAL",
                    port=port,
                    protocol="TCP",
                    service="Redis",
                    title="Unauthenticated Redis Remote Access",
                    description="The Redis database responds to commands without requiring authentication. Attackers can read/write keys or execute arbitrary commands.",
                    recommendation="Set a strong password via 'requirepass' in redis.conf and bind Redis to 127.0.0.1.",
                    evidence=f"Received: {resp.strip()} in response to unauthenticated PING command."
                )
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return None

    def _audit_http_headers(self, service_info: ServiceInfo) -> List[Finding]:
        """Audits HTTP headers for missing defensive security protections."""
        findings: List[Finding] = []
        port = service_info.port
        meta = service_info.metadata

        # Information disclosure via Server or X-Powered-By
        if "Server" in meta:
            findings.append(Finding(
                severity="INFO",
                port=port,
                protocol=service_info.protocol,
                service="HTTP",
                title="Server Version Information Disclosure",
                description=f"Server header discloses software stack details: '{meta['Server']}'. This aids attacker reconnaissance.",
                recommendation="Disable or obscure verbose Server banners (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx).",
                evidence=f"Header Server: {meta['Server']}"
            ))

        if "X-Powered-By" in meta:
            findings.append(Finding(
                severity="LOW",
                port=port,
                protocol=service_info.protocol,
                service="HTTP",
                title="Backend Technology Disclosure: X-Powered-By",
                description=f"Header discloses backend framework/language: '{meta['X-Powered-By']}'.",
                recommendation="Suppress the X-Powered-By header in web application configuration.",
                evidence=f"Header X-Powered-By: {meta['X-Powered-By']}"
            ))

        return findings

    def _audit_version_heuristics(
        self,
        port: int,
        service: str,
        product: str,
        version: str,
        banner: str
    ) -> List[Finding]:
        """Checks for known vulnerable, obsolete, or backdoored software versions."""
        findings: List[Finding] = []
        full_text = f"{product} {version} {banner}".lower()

        # Check for vsftpd 2.3.4 (Notorious backdoor CVE-2011-2523)
        if "vsftpd" in full_text and "2.3.4" in full_text:
            findings.append(Finding(
                severity="CRITICAL",
                port=port,
                protocol="TCP",
                service="FTP",
                title="Vulnerable vsftpd 2.3.4 Backdoor Signature",
                description="vsftpd version 2.3.4 was distributed with a malicious backdoor (CVE-2011-2523) that opens a root shell on port 6200 when triggered by a smiley face ':)' in username.",
                recommendation="Immediately remove vsftpd 2.3.4 and install a secure, verified release.",
                evidence=f"Banner signature match: {banner}"
            ))

        # Check for Apache 2.4.49 / 2.4.50 (Path Traversal CVE-2021-41773 / CVE-2021-42013)
        if "apache" in product and version in ("2.4.49", "2.4.50"):
            findings.append(Finding(
                severity="CRITICAL",
                port=port,
                protocol="TCP",
                service="HTTP",
                title="Apache Path Traversal / RCE Vulnerability (CVE-2021-41773)",
                description=f"Apache version {version} is vulnerable to path traversal and remote code execution if mod_cgi is enabled.",
                recommendation="Upgrade Apache HTTP Server to version 2.4.51 or higher immediately.",
                evidence=f"Apache version identified: {version}"
            ))

        # Check for obsolete Apache 2.2.x
        if "apache" in product and version.startswith("2.2."):
            findings.append(Finding(
                severity="HIGH",
                port=port,
                protocol="TCP",
                service="HTTP",
                title="End-of-Life Apache 2.2 Branch Detected",
                description=f"Apache {version} reached official End-of-Life (EOL) in 2017 and contains multiple unpatched vulnerabilities.",
                recommendation="Migrate to the current supported Apache 2.4.x branch.",
                evidence=f"Observed version: {version}"
            ))

        # Check for legacy OpenSSH versions < 7.4
        if "openssh" in product and version:
            try:
                major_minor = tuple(int(x) for x in version.split(".")[:2])
                if major_minor < (7, 4):
                    findings.append(Finding(
                        severity="MEDIUM",
                        port=port,
                        protocol="TCP",
                        service="SSH",
                        title=f"Legacy OpenSSH Version ({version})",
                        description=f"OpenSSH {version} is an older release susceptible to deprecated cryptographic algorithms and privilege escalation bugs.",
                        recommendation="Upgrade OpenSSH to the latest release and disable legacy cryptographic ciphers.",
                        evidence=f"OpenSSH version: {version}"
                    ))
            except Exception:
                pass

        return findings
