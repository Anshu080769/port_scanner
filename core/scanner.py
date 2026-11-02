"""
High-Performance Multithreaded TCP Port Scanner.

Implements TCP connect scanning with:
- Configurable worker thread pools (ThreadPoolExecutor)
- Strict, millisecond-resolution connection timeouts
- RTT latency measurement
- Accurate port state classification (OPEN, CLOSED, FILTERED)
- Graceful signal/cancellation handling
"""

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


# Fallback service mappings for modern ports not present in default OS services files
KNOWN_SERVICES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    513: "rlogin",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2121: "ftp-alt",
    2222: "ssh-alt",
    2375: "docker-plain",
    2376: "docker-tls",
    3000: "node-http",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "flask-dev",
    5432: "postgresql",
    5672: "rabbitmq",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "portainer/sonar",
    9090: "prometheus",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


def lookup_service_name(port: int, proto: str = "tcp") -> str:
    """
    Resolves standard service name for a given port number.
    Tries OS socket service catalog first, then falls back to built-in knowledge base.
    """
    try:
        return socket.getservbyport(port, proto)
    except (OSError, socket.error):
        return KNOWN_SERVICES.get(port, "unknown")


@dataclass
class ScanResult:
    """Represents the scan results for an individual TCP port."""
    port: int
    status: str  # "OPEN", "CLOSED", or "FILTERED"
    service: str
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    service_details: Optional[Dict] = None
    audit_findings: List = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.status == "OPEN"


class PortScanner:
    """
    Multithreaded TCP connect port scanner.
    """

    def __init__(
        self,
        target_ip: str,
        timeout: float = 1.0,
        max_workers: int = 50,
        verbose: bool = False
    ):
        """
        Initializes the PortScanner.

        Args:
            target_ip: Target IPv4 or IPv6 address.
            timeout: Connection timeout in seconds.
            max_workers: Maximum number of concurrent scanning threads.
            verbose: If True, tracks closed/filtered ports in detailed results.
        """
        self.target_ip = target_ip
        self.timeout = max(0.1, float(timeout))
        self.max_workers = max(1, min(max_workers, 500))
        self.verbose = verbose
        self._is_cancelled = False

    def scan_port(self, port: int) -> ScanResult:
        """
        Performs a full TCP three-way handshake attempt against a single target port.
        Accurately differentiates between OPEN, CLOSED, and FILTERED states.

        Args:
            port: Destination TCP port number.

        Returns:
            ScanResult object detailing the port state and latency.
        """
        service_name = lookup_service_name(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        start_time = time.perf_counter()
        status = "FILTERED"
        latency: Optional[float] = None

        try:
            err = sock.connect_ex((self.target_ip, port))
            elapsed = (time.perf_counter() - start_time) * 1000.0

            if err == 0:
                status = "OPEN"
                latency = round(elapsed, 2)
            elif err in (errno.ECONNREFUSED, 10061):  # 10061 is WSAECONNREFUSED on Windows
                status = "CLOSED"
            elif err in (errno.ETIMEDOUT, 10060):   # 10060 is WSAETIMEDOUT on Windows
                status = "FILTERED"
            elif err in (errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051):
                status = "FILTERED"
            else:
                # Other socket error codes typically signify firewall drops/resets
                status = "FILTERED"

        except socket.timeout:
            status = "FILTERED"
        except (ConnectionRefusedError, socket.error):
            status = "CLOSED"
        except OSError:
            status = "FILTERED"
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return ScanResult(
            port=port,
            status=status,
            service=service_name,
            latency_ms=latency
        )

    def scan_ports(
        self,
        ports: List[int],
        progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scans a collection of ports concurrently using ThreadPoolExecutor.

        Args:
            ports: List of target port numbers.
            progress_callback: Optional callback invoked as each port completes:
                               callback(completed_count, total_count, scan_result)

        Returns:
            List of ScanResult objects for all open ports (or all ports if verbose=True),
            sorted by port number.
        """
        total_ports = len(ports)
        completed_count = 0
        results: List[ScanResult] = []
        self._is_cancelled = False

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port
                for port in ports
            }

            try:
                for future in as_completed(future_to_port):
                    if self._is_cancelled:
                        break

                    try:
                        res = future.result()
                    except Exception as e:
                        # Fallback for unexpected worker exceptions
                        p = future_to_port[future]
                        res = ScanResult(
                            port=p,
                            status="FILTERED",
                            service=lookup_service_name(p)
                        )

                    completed_count += 1

                    if res.is_open or self.verbose:
                        results.append(res)

                    if progress_callback:
                        progress_callback(completed_count, total_ports, res)

            except KeyboardInterrupt:
                self._is_cancelled = True
                # Cancel pending futures in the executor
                for f in future_to_port:
                    f.cancel()
                raise

        # Sort findings ascending by port number
        results.sort(key=lambda r: r.port)
        return results
