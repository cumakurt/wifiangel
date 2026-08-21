"""HTML report generation."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Optional

from wifi.playbook import recommend_assessment


def generate_security_report(
    log_dir: Path,
    timestamp: str,
    networks: Optional[dict[str, dict]] = None,
) -> Path:
    report_file = log_dir / f"report_{timestamp}.html"

    main_logs = _read_lines(log_dir / "main.log")
    attack_logs = _read_lines(log_dir / "attacks.log")
    network_logs = _read_lines(log_dir / "networks.log")
    client_logs = _read_lines(log_dir / "clients.log")
    playbook_section = _playbook_section(networks)

    html_content = f"""<html>
<head>
    <title>WiFiAngel Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>WiFiAngel Security Analysis Report</h1>
    <p>Report generated on: {escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>

    {playbook_section}
    {_section("Attack Summary", ("Timestamp", "Attack Type", "Details"), attack_logs)}
    {_section("Network Activity", ("Timestamp", "Network", "Activity"), network_logs)}
    {_section("Client Connections", ("Timestamp", "Client", "Activity"), client_logs)}
    {_section("System Events", ("Timestamp", "Level", "Message"), main_logs)}
</body>
</html>
"""

    report_file.write_text(html_content, encoding="utf-8")
    return report_file


def _read_lines(path: Path, *, max_lines: int = 500, max_bytes: int = 256 * 1024) -> list[str]:
    if not path.exists():
        return []
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[-max_bytes:]
    lines = data.decode("utf-8", errors="replace").splitlines()
    if len(lines) > max_lines:
        return lines[-max_lines:]
    return lines


def _section(title: str, headers: tuple[str, str, str], lines: list[str]) -> str:
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    rows = "".join(_log_row(line) for line in lines)
    return f"""<div class="section">
    <h2>{escape(title)}</h2>
    <table>
        <tr>{header_html}</tr>
        {rows}
    </table>
</div>"""


def _log_row(line: str) -> str:
    parts = line.split(" - ", 2)
    if len(parts) == 1:
        cells = ("", "", parts[0])
    elif len(parts) == 2:
        cells = (parts[0], parts[1], "")
    else:
        cells = (parts[0], parts[1], parts[2])

    return "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in cells) + "</tr>"


def _playbook_section(networks: Optional[dict[str, dict[str, Any]]]) -> str:
    if not networks:
        return ""
    rows = []
    for bssid, network in networks.items():
        playbook = recommend_assessment(network)
        ssid = str(network.get("ssid") or "")
        cipher = str(network.get("cipher") or "")
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{escape(cell)}</td>"
                for cell in (
                    ssid,
                    str(bssid),
                    playbook.akm_label,
                    "yes" if playbook.skip_deauth else "no",
                    playbook.capture_mode,
                    playbook.menu_label,
                    playbook.reason,
                    cipher,
                )
            )
            + "</tr>"
        )
    headers = ("SSID", "BSSID", "AKM", "Skip deauth", "Capture", "Next module", "Reason", "Scan cipher")
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    return f"""<div class="section">
    <h2>Assessment playbook</h2>
    <table>
        <tr>{header_html}</tr>
        {''.join(rows)}
    </table>
</div>"""
