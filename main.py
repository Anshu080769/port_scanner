#!/usr/bin/env python3
"""
Network Port Scanner and Service Auditor
========================================

A production-grade, modular, multithreaded TCP port scanner and service vulnerability auditor
specifically engineered for authorized lab environments and ethical penetration testing.

Features:
- Concurrent ThreadPoolExecutor engine with microsecond timeouts
- Intelligent TCP connect scanning & socket error classification
- Passive & active banner grabbing with regex version extraction
- Automated security posture auditor (unencrypted protocols, anonymous logins, missing headers)
- Colorized CLI outputs with risk analysis and JSON/CSV reporting
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
except ImportError:
    # Minimal fallback if colorama is unavailable
    class _EmptyStyle:
        def __getattr__(self, name):
            return ""
    Fore = Back = Style = _EmptyStyle()

from core.scanner import PortScanner, ScanResult
from core.banner import BannerGrabber, ServiceInfo
from core.auditor import ServiceAuditor, Finding
from utils.validator import validate_target, parse_ports, validate_output_format
from utils.reporter import (
    export_json_report,
    export_csv_report,
    calculate_risk_summary,
)


TOOL_NAME = "VULNAUDIT // PORT SCANNER & SERVICE AUDITOR"
VERSION = "1.0.0 (Lab Edition)"

ASCII_BANNER = rf"""{Fore.CYAN}
  ____             _     ____                                  
 |  _ \ ___  _ __ | |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |_) / _ \| '__|| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | |   | |_   ___) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/|_|    \__| |____/ \___\__,_|_| |_|_| |_|\___|_|   
{Fore.YELLOW}          [+] Service Auditor & Vulnerability Scanner [+]
{Style.RESET_ALL}"""

DISCLAIMER_TEXT = rf"""{Fore.RED}{Style.BRIGHT}========================================================================================
[!] LEGAL & ETHICAL DISCLAIMER:
    This tool is designed STRICTLY for authorized security auditing, defensive assessments,
    and penetration testing in controlled, authorized laboratory environments.
    Scanning, auditing, or probing networks without prior explicit written permission
    from the target system owner is illegal under federal and international law (e.g. CFAA).
    The developers assume no liability for misuse, unauthorized actions, or damage.
========================================================================================{Style.RESET_ALL}"""


def print_banner():
    """Prints the application banner and mandatory ethical disclaimer."""
    print(ASCII_BANNER)
    print(DISCLAIMER_TEXT)
    print()


def print_session_info(
    target_ip: str,
    target_host: str,
    ports_count: int,
    threads: int,
    timeout: float,
    audit_enabled: bool
):
    """Prints formatted summary of the active scan configuration."""
    print(f"{Fore.GREEN}{Style.BRIGHT}[*] AUDIT SESSION CONFIGURATION:{Style.RESET_ALL}")
    print(f"    Target IP Address : {Fore.CYAN}{target_ip}{Style.RESET_ALL}")
    print(f"    Resolved Hostname : {Fore.CYAN}{target_host}{Style.RESET_ALL}")
    print(f"    Ports to Inspect  : {Fore.YELLOW}{ports_count} ports{Style.RESET_ALL}")
    print(f"    Concurrent Threads: {Fore.YELLOW}{threads}{Style.RESET_ALL}")
    print(f"    Socket Timeout    : {Fore.YELLOW}{timeout}s{Style.RESET_ALL}")
    audit_str = f"{Fore.GREEN}ENABLED (Deep Audit){Style.RESET_ALL}" if audit_enabled else f"{Fore.RED}DISABLED{Style.RESET_ALL}"
    print(f"    Service Auditor   : {audit_str}")
    print("-" * 88)


def get_severity_badge(severity: str) -> str:
    """Returns colorized severity badge for terminal output."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} CRITICAL {Style.RESET_ALL}"
    elif sev == "HIGH":
        return f"{Fore.RED}{Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
    elif sev == "MEDIUM":
        return f"{Fore.YELLOW}{Style.BRIGHT}[MEDIUM]  {Style.RESET_ALL}"
    elif sev == "LOW":
        return f"{Fore.CYAN}[LOW]     {Style.RESET_ALL}"
    else:
        return f"{Fore.BLUE}[INFO]    {Style.RESET_ALL}"


def display_results_table(results: List[ScanResult]):
    """Renders formatted ASCII table of open ports and fingerprinted services."""
    open_results = [r for r in results if r.is_open]

    if not open_results:
        print(f"\n{Fore.YELLOW}[!] No open ports identified within the specified scope.{Style.RESET_ALL}\n")
        return

    print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] DISCOVERED OPEN PORTS & SERVICES ({len(open_results)} open):{Style.RESET_ALL}")
    header = f"{'PORT':<10} {'STATE':<8} {'SERVICE':<16} {'PRODUCT / VERSION':<28} {'LATENCY':<10}"
    print(f"{Fore.WHITE}{Style.BRIGHT}{header}{Style.RESET_ALL}")
    print("-" * 88)

    for r in open_results:
        details = r.service_details or {}
        prod = details.get("product", "Unknown")
        ver = details.get("version", "")
        if ver and ver != "Unknown":
            prod_ver = f"{prod} {ver}"
        else:
            prod_ver = prod

        # Truncate if too long for column
        if len(prod_ver) > 26:
            prod_ver = prod_ver[:23] + "..."

        lat_str = f"{r.latency_ms}ms" if r.latency_ms is not None else "N/A"
        port_proto = f"{r.port}/tcp"

        print(
            f"{Fore.CYAN}{port_proto:<10}{Style.RESET_ALL} "
            f"{Fore.GREEN}{r.status:<8}{Style.RESET_ALL} "
            f"{Fore.YELLOW}{r.service:<16}{Style.RESET_ALL} "
            f"{Fore.WHITE}{prod_ver:<28}{Style.RESET_ALL} "
            f"{Fore.MAGENTA}{lat_str:<10}{Style.RESET_ALL}"
        )
        if r.banner and len(r.banner) > 0:
            clean_b = r.banner[:75] + ("..." if len(r.banner) > 75 else "")
            print(f"   {Fore.LIGHTBLACK_EX}|-- Banner: {clean_b}{Style.RESET_ALL}")

    print("-" * 88)


def display_findings_table(findings: List[Finding]):
    """Renders formatted security vulnerabilities and misconfigurations."""
    if not findings:
        print(f"\n{Fore.GREEN}[+] Security Auditor completed: 0 baseline vulnerabilities detected.{Style.RESET_ALL}\n")
        return

    print(f"\n{Fore.RED}{Style.BRIGHT}[!] SECURITY AUDIT FINDINGS & VULNERABILITIES ({len(findings)} issues):{Style.RESET_ALL}")
    print("=" * 88)

    # Sort findings by severity order
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.upper(), 99))

    for idx, f in enumerate(sorted_findings, 1):
        badge = get_severity_badge(f.severity)
        print(f"{badge} {Fore.WHITE}{Style.BRIGHT}#{idx}: {f.title} (Port {f.port}/{f.protocol}){Style.RESET_ALL}")
        print(f"    {Fore.LIGHTWHITE_EX}Description   :{Style.RESET_ALL} {f.description}")
        if f.evidence and f.evidence != "N/A":
            print(f"    {Fore.LIGHTYELLOW_EX}Evidence      :{Style.RESET_ALL} {f.evidence}")
        print(f"    {Fore.LIGHTGREEN_EX}Recommendation:{Style.RESET_ALL} {f.recommendation}")
        print("-" * 88)


def display_risk_summary(findings: List[Finding]):
    """Prints executive risk score tally."""
    counts = calculate_risk_summary(findings)
    print(f"\n{Fore.WHITE}{Style.BRIGHT}[*] AUDIT EXECUTIVE RISK SUMMARY:{Style.RESET_ALL}")
    print(
        f"    {Back.RED}{Fore.WHITE} CRITICAL: {counts['CRITICAL']} {Style.RESET_ALL}  "
        f"{Fore.RED}[HIGH: {counts['HIGH']}]{Style.RESET_ALL}  "
        f"{Fore.YELLOW}[MEDIUM: {counts['MEDIUM']}]{Style.RESET_ALL}  "
        f"{Fore.CYAN}[LOW: {counts['LOW']}]{Style.RESET_ALL}  "
        f"{Fore.BLUE}[INFO: {counts['INFO']}]{Style.RESET_ALL}"
    )
    print("=" * 88)


def print_command_reference():
    """
    Renders a comprehensive, colorized reference guide displaying all supported
    command-line flags, port expressions, usage examples, and companion tools.
    """
    print_banner()

    print(f"{Fore.GREEN}{Style.BRIGHT}========================================================================================{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}                         COMMAND-LINE REFERENCE & USAGE GUIDE                           {Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}========================================================================================{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}{Style.BRIGHT}USAGE SYNTAX:{Style.RESET_ALL}")
    print(f"    python main.py -t <TARGET> [OPTIONS]")
    print(f"    python main.py help\n")

    print(f"{Fore.YELLOW}{Style.BRIGHT}SUPPORTED COMMAND-LINE FLAGS:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}-t, --target <TARGET>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Target IPv4 address or hostname to audit (REQUIRED).{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}-t 127.0.0.1  |  -t 192.168.1.50  |  -t lab.internal{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-p, --ports <SPECIFICATION>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Ports to audit. Accepts single ports, ranges, comma-separated lists,{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}mixed expressions, or predefined aliases (Default: '1-1024').{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}-p 80  |  -p 1-1024  |  -p 21,22,80,443  |  -p common  |  -p top100{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-T, --threads <NUMBER>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Number of concurrent worker scanning threads (1 to 500). (Default: 50).{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}-T 100{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}--timeout <SECONDS>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Socket connection timeout in seconds (Default: 1.0).{Style.RESET_ALL}")
    print(f"        Use lower values (0.3-0.5s) on fast LANs, higher (1.5-2.0s) on latent links.{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}--timeout 0.5{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}--no-audit{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Disables deep vulnerability checks, anonymous login probes, and security{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}evaluations. Executes pure port discovery & latency measurement only.{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}--no-audit{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-o, --output <FILEPATH>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Custom output file path for the audit report.{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}-o outputs/lab_audit.json  |  -o report.csv{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-f, --format <FORMAT>{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Export file format: 'json', 'csv', or 'both' (Default: 'json').{Style.RESET_ALL}")
    print(f"        Reports are automatically saved in the 'outputs/' folder if -o is omitted.{Style.RESET_ALL}")
    print(f"        Example: {Fore.LIGHTBLACK_EX}-f csv  |  -f both{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-v, --verbose{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Enables verbose terminal logging, detailing closed/filtered ports{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}and internal socket debug traces.{Style.RESET_ALL}\n")

    print(f"  {Fore.CYAN}-h, --help, help{Style.RESET_ALL}")
    print(f"        {Fore.WHITE}Displays this comprehensive command reference guide and exits.{Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}{Style.BRIGHT}----------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}PORT EXPRESSION CHEAT-SHEET:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Single Port       :{Style.RESET_ALL} {Fore.CYAN}-p 80{Style.RESET_ALL}                  (Scans port 80)")
    print(f"  {Fore.WHITE}Port Range        :{Style.RESET_ALL} {Fore.CYAN}-p 1-1024{Style.RESET_ALL}              (Scans ports 1 through 1024)")
    print(f"  {Fore.WHITE}Comma List        :{Style.RESET_ALL} {Fore.CYAN}-p 21,22,80,443{Style.RESET_ALL}        (Scans specific ports)")
    print(f"  {Fore.WHITE}Mixed Range & List:{Style.RESET_ALL} {Fore.CYAN}-p 21-25,80,8000-8080{Style.RESET_ALL}  (Combines ranges & individual ports)")
    print(f"  {Fore.WHITE}Alias 'common'    :{Style.RESET_ALL} {Fore.CYAN}-p common{Style.RESET_ALL}              (Scans top 20 frequent attack ports)")
    print(f"  {Fore.WHITE}Alias 'top100'    :{Style.RESET_ALL} {Fore.CYAN}-p top100{Style.RESET_ALL}              (Scans top 100 penetration testing ports)")
    print(f"  {Fore.WHITE}Alias 'all'       :{Style.RESET_ALL} {Fore.CYAN}-p all{Style.RESET_ALL}                 (Full 16-bit space: 1-65535)")
    print(f"{Fore.GREEN}{Style.BRIGHT}----------------------------------------------------------------------------------------{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}{Style.BRIGHT}PRACTICAL USAGE EXAMPLES:{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTBLACK_EX}# 1. Quick baseline audit of localhost ports 1-1024:{Style.RESET_ALL}")
    print(f"  python main.py -t 127.0.0.1\n")

    print(f"  {Fore.LIGHTBLACK_EX}# 2. Fast scan of top 100 ports using 100 concurrent threads:{Style.RESET_ALL}")
    print(f"  python main.py -t 192.168.1.50 -p top100 -T 100\n")

    print(f"  {Fore.LIGHTBLACK_EX}# 3. Deep security audit exporting BOTH JSON and CSV reports:{Style.RESET_ALL}")
    print(f"  python main.py -t 192.168.1.20 -p 1-1024 -f both\n")

    print(f"  {Fore.LIGHTBLACK_EX}# 4. Custom output path for auditing specific web and database services:{Style.RESET_ALL}")
    print(f"  python main.py -t lab.internal -p 21,22,80,443,3306,8080 -o outputs/client_audit.json\n")

    print(f"  {Fore.LIGHTBLACK_EX}# 5. High-speed full TCP port discovery (skipping vulnerability auditor):{Style.RESET_ALL}")
    print(f"  python main.py -t 10.0.0.1 -p all -T 250 --no-audit\n")

    print(f"{Fore.GREEN}{Style.BRIGHT}----------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}COMPANION LAB TOOLS:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}python lab_target_demo.py{Style.RESET_ALL}             Run local mock FTP, HTTP, and Redis services")
    print(f"  {Fore.WHITE}python -m unittest test_scanner.py{Style.RESET_ALL}    Execute automated 21-test verification suite")
    print(f"{Fore.GREEN}{Style.BRIGHT}========================================================================================{Style.RESET_ALL}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    """Configures the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="vulnaudit",
        description="Production-Grade Network Port Scanner & Service Auditor for Authorized Lab Environments.",
        epilog="Type 'python main.py help' or 'python main.py -h' to see the full command reference.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )

    # Help flag
    parser.add_argument(
        "-h", "--help", "-help", "--reference", "-r",
        action="store_true",
        dest="show_help",
        help="Show comprehensive command reference guide and exit."
    )

    # Target specification
    parser.add_argument(
        "-t", "--target",
        dest="target",
        default=None,
        help="Target IP address or hostname to audit (e.g., '192.168.1.50' or 'lab.local')"
    )

    # Ports specification
    parser.add_argument(
        "-p", "--ports",
        dest="ports",
        default="1-1024",
        help="Port specification: ranges ('1-1024'), comma list ('21,22,80,443'), mixed, or aliases ('common', 'top100', 'all'). Default: '1-1024'."
    )

    # Performance & Concurrency
    parser.add_argument(
        "-T", "--threads",
        dest="threads",
        type=int,
        default=50,
        help="Number of concurrent scanning worker threads (1-500). Default: 50."
    )

    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=1.0,
        help="Socket connection timeout in seconds. Default: 1.0."
    )

    # Auditor toggle
    parser.add_argument(
        "--no-audit",
        dest="audit",
        action="store_false",
        default=True,
        help="Disable deep vulnerability checks and service posture auditing."
    )

    # Reporting
    parser.add_argument(
        "-o", "--output",
        dest="output",
        default=None,
        help="Custom file path for export (e.g., 'outputs/scan.json' or 'audit.csv')."
    )

    parser.add_argument(
        "-f", "--format",
        dest="format",
        choices=["json", "csv", "both"],
        default="json",
        help="Output report format ('json', 'csv', 'both'). Default: 'json'."
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output (displays closed/filtered ports and debug traces)."
    )

    return parser


def main():
    """Main execution workflow."""
    # Fast intercept for help flags: 'help', '-h', '--help', '-help', '--reference', '-r'
    help_triggers = {"-h", "--help", "-help", "help", "--reference", "-r", "?"}
    raw_args = [arg.strip().lower() for arg in sys.argv[1:]]

    if len(sys.argv) == 1 or any(arg in help_triggers for arg in raw_args):
        print_command_reference()
        sys.exit(0)

    parser = build_arg_parser()
    args = parser.parse_args()

    if getattr(args, "show_help", False) or not args.target:
        print_command_reference()
        sys.exit(0)

    print_banner()

    # Step 1: Validate Target
    try:
        target_ip, target_host = validate_target(args.target)
    except ValueError as e:
        print(f"{Fore.RED}[!] Target Validation Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Step 2: Parse Port Specification
    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError as e:
        print(f"{Fore.RED}[!] Port Parsing Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Print Session Parameters
    print_session_info(
        target_ip=target_ip,
        target_host=target_host,
        ports_count=len(ports_to_scan),
        threads=args.threads,
        timeout=args.timeout,
        audit_enabled=args.audit
    )

    # Initialize Scanner
    scanner = PortScanner(
        target_ip=target_ip,
        timeout=args.timeout,
        max_workers=args.threads,
        verbose=args.verbose
    )

    start_time = time.time()
    open_ports_found: List[ScanResult] = []

    # Real-time progress callback
    def progress_callback(completed: int, total: int, res: ScanResult):
        if res.is_open:
            lat = f"{res.latency_ms}ms" if res.latency_ms is not None else ""
            print(
                f"  {Fore.GREEN}[+] OPEN PORT DETECTED: {Fore.CYAN}{res.port}/tcp{Style.RESET_ALL} "
                f"({res.service}) {Fore.MAGENTA}{lat}{Style.RESET_ALL}"
            )
        elif args.verbose:
            print(f"  {Fore.LIGHTBLACK_EX}[.] Port {res.port}/tcp: {res.status}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[*] Initiating multithreaded TCP connect scan...{Style.RESET_ALL}")

    try:
        scan_results = scanner.scan_ports(ports_to_scan, progress_callback=progress_callback)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user (Ctrl+C). Terminating workers...{Style.RESET_ALL}")
        sys.exit(130)

    elapsed_time = time.time() - start_time
    open_results = [r for r in scan_results if r.is_open]

    print(f"\n{Fore.CYAN}[*] Port scan finished in {elapsed_time:.2f} seconds. Discovered {len(open_results)} open ports.{Style.RESET_ALL}")

    # Step 3: Banner Grabbing & Service Fingerprinting
    banner_grabber = BannerGrabber(target_ip=target_ip, timeout=args.timeout)
    if open_results:
        print(f"{Fore.GREEN}[*] Performing banner grabbing and service fingerprinting...{Style.RESET_ALL}")
        for res in open_results:
            try:
                s_info: ServiceInfo = banner_grabber.grab_banner(res.port, service_hint=res.service)
                res.banner = s_info.banner
                res.service_details = s_info.to_dict()
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.LIGHTBLACK_EX}[!] Banner probe error on port {res.port}: {e}{Style.RESET_ALL}")

    # Display Port Scan Summary Table
    display_results_table(scan_results)

    # Step 4: Security Posture & Vulnerability Auditing
    all_findings: List[Finding] = []
    if args.audit and open_results:
        print(f"\n{Fore.GREEN}[*] Executing security auditor & vulnerability checks...{Style.RESET_ALL}")
        auditor = ServiceAuditor(target_ip=target_ip, timeout=args.timeout)

        for res in open_results:
            s_dict = res.service_details or {}
            s_info = ServiceInfo(
                port=res.port,
                service_name=res.service,
                product=s_dict.get("product"),
                version=s_dict.get("version"),
                banner=res.banner or "",
                protocol=s_dict.get("protocol", "tcp"),
                metadata=s_dict.get("metadata", {})
            )
            findings = auditor.audit_service(s_info)
            res.audit_findings = findings
            all_findings.extend(findings)

        display_findings_table(all_findings)
        display_risk_summary(all_findings)

    # Step 5: Report Export (JSON / CSV)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target_name = target_ip.replace(":", "_").replace(".", "_")

    # Determine export format and file paths
    formats_to_export = []
    if args.output:
        # User specified exact output path
        out_ext = os.path.splitext(args.output)[1].lower()
        if out_ext == ".json":
            formats_to_export.append(("json", args.output))
        elif out_ext == ".csv":
            formats_to_export.append(("csv", args.output))
        else:
            # Format flag dictates
            if args.format == "csv":
                formats_to_export.append(("csv", args.output))
            elif args.format == "both":
                formats_to_export.append(("json", f"{args.output}.json"))
                formats_to_export.append(("csv", f"{args.output}.csv"))
            else:
                formats_to_export.append(("json", args.output))
    else:
        # Default to outputs/ directory
        base_dir = "outputs"
        if args.format in ("json", "both"):
            formats_to_export.append(("json", os.path.join(base_dir, f"audit_{clean_target_name}_{timestamp_str}.json")))
        if args.format in ("csv", "both"):
            formats_to_export.append(("csv", os.path.join(base_dir, f"audit_{clean_target_name}_{timestamp_str}.csv")))

    # Perform exports
    for fmt, path in formats_to_export:
        try:
            if fmt == "json":
                saved_path = export_json_report(
                    target_ip=target_ip,
                    target_host=target_host,
                    results=scan_results,
                    findings=all_findings,
                    duration=elapsed_time,
                    total_ports_scanned=len(ports_to_scan),
                    output_path=path
                )
                print(f"{Fore.GREEN}[+] JSON audit report saved to: {Fore.CYAN}{saved_path}{Style.RESET_ALL}")
            elif fmt == "csv":
                saved_path = export_csv_report(
                    target_ip=target_ip,
                    target_host=target_host,
                    results=scan_results,
                    findings=all_findings,
                    output_path=path
                )
                print(f"{Fore.GREEN}[+] CSV audit report saved to:  {Fore.CYAN}{saved_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to export {fmt.upper()} report to {path}: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[OK] Audit complete. Stay safe and ethical!{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
