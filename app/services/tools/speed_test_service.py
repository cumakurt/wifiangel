"""Network speed test service."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time

from rich import box
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from adapters.system_tools import (
    DOWNLOAD_TEST_BYTES,
    UPLOAD_TEST_BYTES,
    build_speed_recommendations,
    bytes_to_mbytes_per_second,
    curl_download_command,
    curl_upload_command,
    download_speed_rating,
    estimate_upload_mbytes_per_second,
    fallback_upload_mbytes_per_second,
    mbytes_to_mbits,
    parse_ping_stats,
    ping_command,
    speed_gauge_blocks,
    upload_speed_rating,
)
from app.ui import BORDER_STYLE


def run_speed_test(app) -> None:
    """Tests network connection speed using available methods."""
    app.console.clear()
    app.create_header()

    title = Panel(
        "[bold cyan]Network Speed Test[/bold cyan]",
        border_style=BORDER_STYLE,
        box=box.MINIMAL,
        expand=False,
    )
    app.console.print(title)
    app.console.print("[yellow]Testing your internet connection speed...[/yellow]")
    app.console.print("\n[bold blue]Step 1:[/bold blue] Checking Internet Connection...")

    try:
        test_connection = app.command_runner.run(
            ping_command(count=1, timeout_seconds=2),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if test_connection.returncode != 0:
            app.console.print("[error]No internet connection detected.[/]")
            app.console.print("[yellow]Please check your network connection and try again.[/]")
            return

        app.console.print("[success]Internet connection detected.[/]")
        app.console.print("\n[bold blue]Step 2:[/bold blue] Starting Speed Test...")
        app.console.print("[yellow]This may take up to 30 seconds. Please wait...[/yellow]")

        download_speed = 0.0
        upload_speed = 0.0

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold green]{task.percentage:.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            download_task = progress.add_task("[cyan]Testing Download Speed...", total=100)
            upload_task = progress.add_task("[magenta]Testing Upload Speed...", total=100, visible=False)

            start_time = time.time()
            download_result = app.command_runner.run(
                curl_download_command(DOWNLOAD_TEST_BYTES),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=45,
            )
            download_time = time.time() - start_time
            if download_result.ok:
                download_speed = bytes_to_mbytes_per_second(DOWNLOAD_TEST_BYTES, download_time)
            else:
                app.logger.warning(f"Download test failed: {download_result.stderr}")

            for i in range(100):
                progress.update(download_task, completed=i + 1)
                time.sleep(0.02)

            progress.update(upload_task, visible=True)
            upload_start_time = time.time()
            test_file = None

            try:
                with tempfile.NamedTemporaryFile(
                    prefix="speedtest_",
                    suffix=".dat",
                    dir="/tmp",
                    delete=False,
                ) as upload_file:
                    upload_file.write(os.urandom(UPLOAD_TEST_BYTES))
                    test_file = upload_file.name

                for i in range(30):
                    progress.update(upload_task, completed=i)
                    time.sleep(0.02)

                result = app.command_runner.run(
                    curl_upload_command(test_file),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                )

                for i in range(30, 70):
                    progress.update(upload_task, completed=i)
                    time.sleep(0.02)

                upload_time = time.time() - upload_start_time
                if result.ok:
                    upload_speed = estimate_upload_mbytes_per_second(
                        UPLOAD_TEST_BYTES,
                        upload_time,
                    )
                else:
                    app.logger.warning("Upload test failed")
                    upload_speed = fallback_upload_mbytes_per_second(download_speed)
            except Exception as exc:
                app.logger.warning(f"Upload test error: {exc}")
                upload_speed = fallback_upload_mbytes_per_second(download_speed)
            finally:
                if test_file:
                    try:
                        os.remove(test_file)
                    except OSError:
                        pass

            for i in range(70, 101):
                progress.update(upload_task, completed=i)
                time.sleep(0.01)

        ping_result = app.command_runner.run(
            ping_command(count=5, quiet=True),
            capture_output=True,
            text=True,
        )
        ping_stats = parse_ping_stats(ping_result.stdout if ping_result.ok else "")

        app.console.print("\n[success]Speed test completed.[/]")
        result_table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL,
            border_style=BORDER_STYLE,
            title="[bold blue]Network Speed Test Results[/]",
        )
        result_table.add_column("Test", style="cyan", justify="center")
        result_table.add_column("Result", style="green", justify="center")
        result_table.add_column("Details", style="yellow", justify="center")

        download_mbps = mbytes_to_mbits(download_speed)
        result_table.add_row("Download", f"{download_mbps:.2f} Mbps", f"({download_speed:.2f} MB/s)")
        upload_mbps = mbytes_to_mbits(upload_speed)
        result_table.add_row("Upload", f"{upload_mbps:.2f} Mbps", f"({upload_speed:.2f} MB/s)")
        if ping_stats:
            result_table.add_row("Ping", f"{ping_stats.average_ms:.2f} ms", f"min/avg/max = {ping_stats.raw} ms")
        else:
            result_table.add_row("Ping", "N/A", "Could not measure ping")
        app.console.print(result_table)

        app.console.print("\n[bold cyan]Speed Gauges:[/]")
        download_blocks = speed_gauge_blocks(download_mbps, 100)
        download_gauge = f"Download: [green]{'#' * download_blocks}{'.' * (10 - download_blocks)}[/] {download_mbps:.2f} Mbps"
        app.console.print(f"{download_gauge} - {download_speed_rating(download_mbps)}")
        upload_blocks = speed_gauge_blocks(upload_mbps, 50)
        upload_gauge = f"Upload:   [blue]{'#' * upload_blocks}{'.' * (10 - upload_blocks)}[/] {upload_mbps:.2f} Mbps"
        app.console.print(f"{upload_gauge} - {upload_speed_rating(upload_mbps)}")

        recommendations = build_speed_recommendations(
            download_mbps,
            upload_mbps,
            ping_stats.average_ms if ping_stats else None,
        )
        if recommendations:
            app.console.print("\n[bold red]Recommendations:[/]")
            for rec in recommendations:
                app.console.print(f"[yellow]- {rec}[/]")
        else:
            app.console.print("\n[success]Your internet connection is performing well.[/]")
    except Exception as exc:
        app.console.print(f"[bold red]Error during speed test: {str(exc)}[/]")
