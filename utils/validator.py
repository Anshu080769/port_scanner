"""
Input Validation and Target Resolution Module.

Provides robust validation and normalization for:
- Target IP addresses and hostnames (DNS resolution)
- Port specifications (ranges, comma-delimited lists, aliases)
- Export formats
"""

import ipaddress
import re
import socket
from typing import List, Tuple, Set


# Common high-value ports frequently audited in penetration testing & lab assessments
TOP_20_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCbind
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # Microsoft-DS / SMB
    993,   # IMAPS
    995,   # POP3S
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP-Proxy / Alt-HTTP
]

TOP_100_PORTS = sorted(list(set(TOP_20_PORTS + [
    7, 9, 13, 19, 26, 37, 79, 88, 102, 106, 113, 119, 137, 138, 144, 161, 162,
    179, 199, 389, 427, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636,
    873, 902, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 2000,
    2049, 2121, 2222, 2601, 2604, 3000, 3128, 3306, 4000, 4899, 5000, 5060,
    5222, 5432, 5666, 6000, 6379, 6667, 7000, 7070, 8000, 8008, 8081, 8443,
    8888, 9000, 9090, 9100, 9200, 9418, 9999, 10000, 27017, 50000
])))

COMMON_PORTS = TOP_100_PORTS


def normalize_target_input(raw_target: str) -> str:
    """
    Cleans up user input by stripping accidental protocol schemes (http/https),
    trailing slashes, port suffixes, and whitespace.
    """
    target = raw_target.strip()
    # Strip URL schemes if user typed e.g. "http://192.168.1.1" or "https://lab.local/"
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    # Strip paths if user typed e.g. "192.168.1.1/index.html"
    target = target.split("/")[0]
    # Strip port if user typed e.g. "127.0.0.1:8080"
    if ":" in target and not target.count(":") > 1:  # Not IPv6
        target = target.split(":")[0]
    return target.strip()


def validate_target(raw_target: str) -> Tuple[str, str]:
    """
    Validates a target IP address or hostname.
    Resolves hostnames to their corresponding IPv4 address.

    Args:
        raw_target: User-provided IP address or hostname.

    Returns:
        Tuple of (resolved_ip, hostname_or_alias)

    Raises:
        ValueError: If target is empty, malformed, or cannot be resolved.
    """
    clean_target = normalize_target_input(raw_target)

    if not clean_target:
        raise ValueError("Target specification cannot be empty.")

    # 1. Check if it is a valid IPv4 address
    try:
        ip_obj = ipaddress.IPv4Address(clean_target)
        # Attempt reverse DNS lookup for convenience, but fallback to IP if slow/fails
        try:
            hostname = socket.gethostbyaddr(str(ip_obj))[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = str(ip_obj)
        return str(ip_obj), hostname
    except ipaddress.AddressValueError:
        pass

    # 2. Check if it is a valid IPv6 address
    try:
        ip6_obj = ipaddress.IPv6Address(clean_target)
        return str(ip6_obj), str(ip6_obj)
    except ipaddress.AddressValueError:
        pass

    # 3. Target is assumed to be a domain/hostname; perform DNS resolution
    try:
        resolved_ip = socket.gethostbyname(clean_target)
        return resolved_ip, clean_target
    except socket.gaierror as e:
        raise ValueError(
            f"Failed to resolve hostname '{clean_target}': {e}. "
            "Please verify the domain name or check your DNS configuration."
        ) from e
    except Exception as e:
        raise ValueError(f"Invalid target '{clean_target}': {str(e)}") from e


def parse_ports(port_spec: str) -> List[int]:
    """
    Parses complex port range specifications into a sorted list of unique port integers.

    Supported formats:
        - Single port: "80"
        - Comma-delimited list: "21,22,80,443"
        - Range: "1-1024" or "8000-8080"
        - Mixed: "21-25,80,443,8000-8080"
        - Aliases:
            - "common" or "top" or "top20": 20 standard ports
            - "top100": Top 100 most frequent ports
            - "all": Full port space (1-65535)

    Args:
        port_spec: String specifying ports to scan.

    Returns:
        Sorted list of integer ports.

    Raises:
        ValueError: If port syntax is invalid or port numbers fall outside [1, 65535].
    """
    if not port_spec or not port_spec.strip():
        raise ValueError("Port specification cannot be empty. E.g., '1-1024', '21,22,80', or 'common'.")

    spec = port_spec.strip().lower()

    ports: Set[int] = set()
    segments = [seg.strip() for seg in spec.split(",") if seg.strip()]

    if not segments:
        raise ValueError(f"Invalid port expression: '{port_spec}'")

    for seg in segments:
        # Check if individual segment is an alias
        if seg in ("common", "top", "top20"):
            ports.update(TOP_20_PORTS)
        elif seg in ("top100", "top-100"):
            ports.update(TOP_100_PORTS)
        elif seg in ("all", "full", "1-65535"):
            ports.update(range(1, 65536))
        elif "-" in seg:
            # Handle range: e.g. "80-90"
            parts = seg.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid range segment '{seg}'. Expected format 'START-END' (e.g. '1-1024').")
            try:
                start_port = int(parts[0].strip())
                end_port = int(parts[1].strip())
            except ValueError:
                raise ValueError(f"Port range '{seg}' must contain valid integers.")

            if start_port > end_port:
                raise ValueError(f"Invalid range '{seg}': start port ({start_port}) cannot be greater than end port ({end_port}).")

            if start_port < 1 or end_port > 65535:
                raise ValueError(f"Port range '{seg}' is outside valid TCP port boundaries (1-65535).")

            ports.update(range(start_port, end_port + 1))
        else:
            # Handle single port: e.g. "80"
            try:
                port = int(seg)
            except ValueError:
                raise ValueError(f"Invalid port value '{seg}'. Expected an integer between 1 and 65535 or a recognized alias.")

            if port < 1 or port > 65535:
                raise ValueError(f"Port {port} is outside valid TCP port boundaries (1-65535).")

            ports.add(port)

    result = sorted(list(ports))
    if not result:
        raise ValueError(f"No valid ports parsed from '{port_spec}'.")

    return result


def validate_output_format(fmt: str) -> str:
    """
    Validates and normalizes report export format.
    Accepts: 'json', 'csv', 'both'.
    """
    cleaned = fmt.strip().lower()
    valid_formats = {"json", "csv", "both"}
    if cleaned not in valid_formats:
        raise ValueError(f"Unsupported export format '{fmt}'. Choose from: {', '.join(valid_formats)}.")
    return cleaned
