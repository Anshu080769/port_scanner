"""
Report Generation and Export Module.

Generates structured JSON and CSV audit reports.
Automatically creates destination directories and formats timestamps.
"""

import csv
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
from core.scanner import ScanResult
from core.auditor import Finding


def calculate_risk_summary(findings: List[Finding]) -> Dict[str, int]:
    """Tallies count of findings by severity rating."""
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = 1
    return counts


def export_json_report(
    target_ip: str,
    target_host: str,
    results: List[ScanResult],
    findings: List[Finding],
    duration: float,
    total_ports_scanned: int,
    output_path: str
) -> str:
    """
    Exports comprehensive audit results to a JSON file.

    Returns:
        Absolute path to the created JSON report file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    risk_counts = calculate_risk_summary(findings)

    open_ports_data = []
    for r in results:
        if r.is_open:
            s_details = r.service_details or {}
            open_ports_data.append({
                "port": r.port,
                "status": r.status,
                "service": r.service,
                "latency_ms": r.latency_ms,
                "product": s_details.get("product", "Unknown"),
                "version": s_details.get("version", "Unknown"),
                "banner": r.banner or "",
                "metadata": s_details.get("metadata", {}),
            })

    report_payload = {
        "scan_metadata": {
            "tool": "Network Port Scanner & Service Auditor",
            "version": "1.0.0",
            "target_ip": target_ip,
            "target_host": target_host,
            "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(duration, 3),
            "total_ports_scanned": total_ports_scanned,
            "open_ports_discovered": len(open_ports_data),
            "total_findings_count": len(findings),
            "risk_summary": risk_counts,
        },
        "open_ports": open_ports_data,
        "audit_findings": [f.to_dict() for f in findings],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=4)

    return os.path.abspath(output_path)


def export_csv_report(
    target_ip: str,
    target_host: str,
    results: List[ScanResult],
    findings: List[Finding],
    output_path: str
) -> str:
    """
    Exports audit results to a structured CSV file suitable for SIEM, Excel, or reporting.

    Returns:
        Absolute path to the created CSV report file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    fieldnames = [
        "Target_IP",
        "Target_Hostname",
        "Port",
        "Status",
        "Service",
        "Product",
        "Version",
        "Latency_ms",
        "Banner",
        "Finding_Severity",
        "Finding_Title",
        "Finding_Description",
        "Finding_Recommendation",
        "Finding_Evidence",
    ]

    # Map findings by port for easy correlation
    findings_by_port: Dict[int, List[Finding]] = {}
    for f in findings:
        findings_by_port.setdefault(f.port, []).append(f)

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            if not r.is_open:
                continue

            s_details = r.service_details or {}
            port_findings = findings_by_port.get(r.port, [])

            if port_findings:
                for f in port_findings:
                    writer.writerow({
                        "Target_IP": target_ip,
                        "Target_Hostname": target_host,
                        "Port": r.port,
                        "Status": r.status,
                        "Service": r.service,
                        "Product": s_details.get("product", "Unknown"),
                        "Version": s_details.get("version", "Unknown"),
                        "Latency_ms": r.latency_ms if r.latency_ms is not None else "",
                        "Banner": r.banner or "",
                        "Finding_Severity": f.severity,
                        "Finding_Title": f.title,
                        "Finding_Description": f.description,
                        "Finding_Recommendation": f.recommendation,
                        "Finding_Evidence": f.evidence or "",
                    })
            else:
                writer.writerow({
                    "Target_IP": target_ip,
                    "Target_Hostname": target_host,
                    "Port": r.port,
                    "Status": r.status,
                    "Service": r.service,
                    "Product": s_details.get("product", "Unknown"),
                    "Version": s_details.get("version", "Unknown"),
                    "Latency_ms": r.latency_ms if r.latency_ms is not None else "",
                    "Banner": r.banner or "",
                    "Finding_Severity": "None",
                    "Finding_Title": "No vulnerabilities identified",
                    "Finding_Description": "",
                    "Finding_Recommendation": "",
                    "Finding_Evidence": "",
                })

    return os.path.abspath(output_path)
