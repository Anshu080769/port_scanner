"""
Comprehensive Automated Test Suite for VulnAudit.

Tests:
1. Target validation & DNS resolution
2. Port string parser (ranges, lists, aliases, errors)
3. Banner regex parsing signatures
4. Security auditor vulnerability detection & risk calculation
5. JSON and CSV report export formats
6. Live socket integration test with an ephemeral mock service
"""

import json
import os
import socket
import threading
import time
import unittest

from utils.validator import validate_target, parse_ports, validate_output_format, TOP_20_PORTS, TOP_100_PORTS
from utils.reporter import export_json_report, export_csv_report, calculate_risk_summary
from core.scanner import PortScanner, ScanResult, lookup_service_name
from core.banner import BannerGrabber, ServiceInfo, clean_banner_text
from core.auditor import ServiceAuditor, Finding


class TestValidator(unittest.TestCase):
    """Unit tests for IP validation and port string parsing."""

    def test_ip_target_resolution(self):
        ip, host = validate_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    def test_target_strips_url_prefixes(self):
        ip, host = validate_target("http://127.0.0.1:8080/path")
        self.assertEqual(ip, "127.0.0.1")

    def test_invalid_target_raises_error(self):
        with self.assertRaises(ValueError):
            validate_target("999.999.999.999")
        with self.assertRaises(ValueError):
            validate_target("")

    def test_single_port_parse(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_port_range_parse(self):
        self.assertEqual(parse_ports("20-25"), [20, 21, 22, 23, 24, 25])

    def test_comma_list_parse(self):
        self.assertEqual(parse_ports("80, 443, 22"), [22, 80, 443])

    def test_mixed_port_spec(self):
        self.assertEqual(parse_ports("80, 21-23, 443"), [21, 22, 23, 80, 443])

    def test_aliases(self):
        self.assertEqual(parse_ports("common"), sorted(TOP_20_PORTS))
        self.assertEqual(parse_ports("top100"), sorted(TOP_100_PORTS))
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_invalid_ports_raise_error(self):
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("65536")
        with self.assertRaises(ValueError):
            parse_ports("100-50")
        with self.assertRaises(ValueError):
            parse_ports("invalid_port")


class TestBannerParsing(unittest.TestCase):
    """Unit tests for banner cleaning and regex version extraction."""

    def setUp(self):
        self.grabber = BannerGrabber("127.0.0.1")

    def test_openssh_regex(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        prod, ver = self.grabber._parse_version(banner, banner.encode(), "ssh")
        self.assertEqual(prod, "OpenSSH")
        self.assertEqual(ver, "8.9p1")

    def test_vsftpd_regex(self):
        banner = "220 (vsFTPd 2.3.4)"
        prod, ver = self.grabber._parse_version(banner, banner.encode(), "ftp")
        self.assertEqual(prod, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_apache_regex(self):
        banner = "Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1"
        prod, ver = self.grabber._parse_version(banner, banner.encode(), "http")
        self.assertEqual(prod, "Apache HTTP Server")
        self.assertEqual(ver, "2.4.49")

    def test_nginx_regex(self):
        banner = "Server: nginx/1.22.1"
        prod, ver = self.grabber._parse_version(banner, banner.encode(), "http")
        self.assertEqual(prod, "nginx")
        self.assertEqual(ver, "1.22.1")

    def test_clean_banner_text(self):
        raw = b"220 Welcome to Lab FTP\r\n\x00\x01Second line\r\n"
        cleaned = clean_banner_text(raw)
        self.assertIn("220 Welcome to Lab FTP", cleaned)
        self.assertIn("Second line", cleaned)


class TestAuditor(unittest.TestCase):
    """Unit tests for security vulnerability checks."""

    def setUp(self):
        self.auditor = ServiceAuditor("127.0.0.1")

    def test_telnet_unencrypted_flag(self):
        s_info = ServiceInfo(port=23, service_name="telnet")
        findings = self.auditor.audit_service(s_info)
        severities = [f.severity for f in findings]
        self.assertIn("HIGH", severities)
        self.assertTrue(any("Telnet" in f.title for f in findings))

    def test_ftp_unencrypted_flag(self):
        s_info = ServiceInfo(port=21, service_name="ftp")
        findings = self.auditor.audit_service(s_info)
        self.assertTrue(any("Unencrypted FTP" in f.title for f in findings))

    def test_vsftpd_backdoor_heuristic(self):
        s_info = ServiceInfo(
            port=21,
            service_name="ftp",
            product="vsftpd",
            version="2.3.4",
            banner="220 (vsFTPd 2.3.4)"
        )
        findings = self.auditor.audit_service(s_info)
        self.assertTrue(any(f.severity == "CRITICAL" and "Backdoor" in f.title for f in findings))

    def test_apache_cve_heuristic(self):
        s_info = ServiceInfo(
            port=80,
            service_name="http",
            product="Apache HTTP Server",
            version="2.4.49",
            banner="Server: Apache/2.4.49"
        )
        findings = self.auditor.audit_service(s_info)
        self.assertTrue(any(f.severity == "CRITICAL" and "CVE-2021-41773" in f.title for f in findings))

    def test_smb_exposure_flag(self):
        s_info = ServiceInfo(port=445, service_name="microsoft-ds")
        findings = self.auditor.audit_service(s_info)
        self.assertTrue(any(f.severity == "HIGH" and "SMB" in f.title for f in findings))


class TestReporter(unittest.TestCase):
    """Unit tests for JSON and CSV exports."""

    def test_json_and_csv_export(self):
        results = [
            ScanResult(port=80, status="OPEN", service="http", latency_ms=1.5, banner="Server: test"),
            ScanResult(port=22, status="CLOSED", service="ssh"),
        ]
        findings = [
            Finding(
                severity="LOW",
                port=80,
                protocol="TCP",
                service="HTTP",
                title="Unencrypted HTTP",
                description="Test desc",
                recommendation="Test rec"
            )
        ]

        json_path = os.path.join("outputs", "test_report.json")
        csv_path = os.path.join("outputs", "test_report.csv")

        json_out = export_json_report("127.0.0.1", "localhost", results, findings, 0.5, 2, json_path)
        csv_out = export_csv_report("127.0.0.1", "localhost", results, findings, csv_path)

        self.assertTrue(os.path.exists(json_out))
        self.assertTrue(os.path.exists(csv_out))

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["scan_metadata"]["target_ip"], "127.0.0.1")
            self.assertEqual(len(data["open_ports"]), 1)
            self.assertEqual(len(data["audit_findings"]), 1)

        # Cleanup test files
        os.remove(json_out)
        os.remove(csv_out)


class TestLiveScanIntegration(unittest.TestCase):
    """Spins up a mock TCP server to test scanner connect, latency, and banner capture."""

    def test_mock_tcp_service_scan(self):
        # 1. Bind to an ephemeral port
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_port = server_sock.getsockname()[1]
        server_sock.listen(5)

        running = [True]

        # 2. Worker thread that accepts connections and sends banner
        def mock_server_worker():
            server_sock.settimeout(2.0)
            while running[0]:
                try:
                    conn, _ = server_sock.accept()
                    conn.sendall(b"SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n")
                    time.sleep(0.05)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break

        th = threading.Thread(target=mock_server_worker, daemon=True)
        th.start()

        try:
            # 3. Scan the mock port
            scanner = PortScanner("127.0.0.1", timeout=1.0, max_workers=5)
            res = scanner.scan_port(server_port)

            self.assertEqual(res.status, "OPEN")
            self.assertIsNotNone(res.latency_ms)

            # 4. Banner grab
            grabber = BannerGrabber("127.0.0.1", timeout=1.0)
            s_info = grabber.grab_banner(server_port, service_hint="ssh")
            self.assertIn("OpenSSH", s_info.banner)
            self.assertEqual(s_info.product, "OpenSSH")
            self.assertEqual(s_info.version, "9.3p1")
        finally:
            running[0] = False
            try:
                server_sock.close()
            except Exception:
                pass
            th.join(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
