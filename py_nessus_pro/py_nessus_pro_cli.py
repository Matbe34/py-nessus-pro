import typer
from typing import Optional
from typing_extensions import Annotated
import os
import sys
from loguru import logger

from py_nessus_pro.py_nessus_pro import PyNessusPro

app = typer.Typer()

def configure_logger(log_level: str):
    """Configure logger with specified log level"""
    if log_level in ["debug", "info", "success", "warning", "warn", "error", "critical"]:
        logger.remove()
        logger.add(sys.stderr, level=log_level.upper())
        return True
    else:
        logger.info("Invalid log level. log_level must be one of the following: [debug, info, success, warning, warn, error, critical]")
        logger.error("Invalid log level, using default (warning)")
        logger.remove()
        logger.add(sys.stderr, level="WARNING")
        return False

def nessus_login(server_ip: str, username: str, verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output")):
    if server_ip and username:
        """Ask for nessus password"""
        password = typer.prompt("Password", hide_input=True)
        """Create a Nessus object"""
        log_level = "debug" if verbose else "warning"
        configure_logger(log_level)
        nessus = PyNessusPro(server_ip, username, password, log_level=log_level)
        return nessus
    else:
        typer.echo("[!] No server ip or username provided", color=typer.colors.RED)
        exit(1)

@app.command()
def list_scans(
    server_ip: Annotated[str, typer.Option(..., "--server-ip", "-s", help="Nessus server ip")],
    username: Annotated[str, typer.Option(..., "--username", "-u", help="Nessus username")],
    name: Optional[str] = typer.Option("", "--name", "-n", help="Name of the scan to download reports from"),
    verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Lists all scans on nessus server or list scans containing a string in the name"""
    nessus = nessus_login(server_ip, username, verbose)
    """List scans"""
    if name:
        typer.echo(nessus.get_status_by_name(name))
    else:
        typer.echo(nessus.list_scans())

@app.command()
def download_reports(
    server_ip: Annotated[str, typer.Option(..., "--server-ip", "-s", help="Nessus server ip")],
    username: Annotated[str, typer.Option(..., "--username", "-u", help="Nessus username")],
    name: Optional[str] = typer.Option("", "--name", "-n", help="Name of the scan to download reports from"),
    verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    path: Optional[str] = typer.Option(".", "--path", "-p", help="Path to save reports"),
):
    """Download reports from nessus server"""
    nessus = nessus_login(server_ip, username, verbose)
    """Download reports"""
    if os.path.exists(path):
        typer.echo(nessus.get_reports_by_name(name = name, path = path), color=typer.colors.GREEN)
    else:
        typer.echo(f"[!] Path {path} does not exist", color=typer.colors.RED)

@app.command()
def launch_scan(
    server_ip: Annotated[str, typer.Option(..., "--server-ip", "-s", help="Nessus server ip")],
    username: Annotated[str, typer.Option(..., "--username", "-u", help="Nessus username")],
    name: Optional[str] = typer.Option("PyNessus AutoScan", "--name", "-n", help="Name of the scan to be launched"),
    verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    targets: Optional[str] = typer.Option(None, "--targets", "-t", help="Targets to scan"),
    folder: Optional[str] = typer.Option("My Scans", "--folder", "-f", help="Folder to save scan in"),
    create_folder: Optional[bool] = typer.Option(True, "--create-folder", "-c", help="Create folder if it does not exist"),
    policy: Optional[str] = typer.Option(None, "--policy", "-p", help="Policy to use for the scan"),
    launch_now: Optional[bool] = typer.Option(True, "--launch-now", "-l", help="Launch scan now"),
):
    """Launch a scan on nessus server"""
    nessus = nessus_login(server_ip, username, verbose)
    """Launch scan"""
    if targets:
        scan_id = nessus.new_scan(name = name, targets = targets, folder = folder, create_folder = create_folder)
        if policy:
            nessus.set_scan_policy(scan_id = scan_id, policy = policy)
        nessus.set_scan_launch_now(scan_id = scan_id, launch_now = launch_now)
        nessus.post_scan(scan_id = scan_id)
    else:
        typer.echo("[!] No targets provided", color=typer.colors.RED)

@app.command()
def upload_policy(
    server_ip: Annotated[str, typer.Option(..., "--server-ip", "-s", help="Nessus server ip")],
    username: Annotated[str, typer.Option(..., "--username", "-u", help="Nessus username")],
    policy_file: Annotated[str, typer.Option(..., "--file", "-f", help="Path to the policy file to upload")],
    verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Upload a policy to nessus server"""
    nessus = nessus_login(server_ip, username, verbose)
    if policy_file:
        if os.path.exists(policy_file):
            typer.echo(f"Uploading policy file {policy_file}")
            nessus.import_policy(policy_file)
            typer.echo(f"Policy file {policy_file} uploaded", color=typer.colors.GREEN)
        else:
            typer.echo(f"[!] Policy file {policy_file} does not exist", color=typer.colors.RED)

@app.command()
def get_scan_status(
    server_ip: Annotated[str, typer.Option(..., "--server-ip", "-s", help="Nessus server ip")],
    username: Annotated[str, typer.Option(..., "--username", "-u", help="Nessus username")],
    name: Optional[str] = typer.Option("PyNessus AutoScan", "--name", "-n", help="Name of the scan/s to get status from"),
    verbose: Optional[bool] = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Get scan status by name"""
    nessus = nessus_login(server_ip, username, verbose)
    typer.echo(nessus.get_status_by_name(name))

if __name__ == "__main__":
    app()