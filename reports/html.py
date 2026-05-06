"""HTML report generation."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path


def generate_security_report(log_dir: Path, timestamp: str) -> Path:
    report_file = log_dir / f"report_{timestamp}.html"

    main_logs = _read_lines(log_dir / "main.log")
    attack_logs = _read_lines(log_dir / "attacks.log")
    network_logs = _read_lines(log_dir / "networks.log")
    client_logs = _read_lines(log_dir / "clients.log")

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

    {_section("Attack Summary", ("Timestamp", "Attack Type", "Details"), attack_logs)}
    {_section("Network Activity", ("Timestamp", "Network", "Activity"), network_logs)}
    {_section("Client Connections", ("Timestamp", "Client", "Activity"), client_logs)}
    {_section("System Events", ("Timestamp", "Level", "Message"), main_logs)}
</body>
</html>
"""

    report_file.write_text(html_content, encoding="utf-8")
    return report_file


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


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
