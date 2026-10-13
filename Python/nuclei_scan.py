#!/usr/bin/env python3
"""
Run ProjectDiscovery's `nuclei` in automatic-scan mode (``-as``) to enrich URLs
and report out-of-band interactions to a self-hosted Interactsh server.

Nuclei is no longer part of the batch pipeline (Python/scan.py). It now runs
on-demand, per URL, from the dashboard: the user clicks the nuclei icon next to a
URL and the web server calls :func:`scan_url` for that single target.

Automatic-scan mode (``-as``) lets nuclei fingerprint the target itself and pick
the matching templates — so there is no hand-maintained technology→template map
anymore; nuclei autodetects "anything" that applies.

Both the CLI and :func:`scan_url` apply ``config/nuclei-config.yaml`` (per-VPS
settings) and the Interactsh server from ``config/interactsh.config``.

Usage:
  # single URL (what the dashboard does under the hood)
  python3 Python/nuclei_scan.py -u https://example.com -o findings.json
  # a list of URLs
  python3 Python/nuclei_scan.py -l urls.txt -o findings.json
  # scan and ingest into Elasticsearch in one go
  python3 Python/nuclei_scan.py -u https://example.com -o findings.json --import
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# How long a single automatic scan may run before we give up (seconds).
DEFAULT_TIMEOUT = 600


def find_nuclei(repo_root: Path, exit_on_missing: bool = True) -> Optional[Path]:
    """Locate the nuclei binary (repo root, bin/, or PATH).

    With ``exit_on_missing`` the process exits (CLI behaviour); otherwise returns
    ``None`` so a caller embedding this module (the web server) can handle it.
    """
    for candidate in (repo_root / 'nuclei', repo_root / 'bin' / 'nuclei'):
        if candidate.exists():
            return candidate
    on_path = shutil.which('nuclei')
    if on_path:
        return Path(on_path)
    logger.error("nuclei binary not found at ./nuclei, ./bin/nuclei, or on PATH")
    if exit_on_missing:
        sys.exit(2)
    return None


def read_interactsh(config_path: Path) -> dict:
    """Parse interactsh.config -> dict with server_url / server_ip."""
    values = {}
    if not config_path.exists():
        logger.warning(f"interactsh.config not found at {config_path}; "
                       "running without an Interactsh server")
        return values
    for raw in config_path.read_text().splitlines():
        line = raw.split('#', 1)[0].strip()
        if '=' in line:
            key, _, val = line.partition('=')
            values[key.strip()] = val.strip()
    return values


def base_nuclei_cmd(nuclei: Path, repo_root: Path, interactsh: dict, output_file: Path) -> list:
    """Build the common nuclei argument list (autodetect + config + interactsh + JSON out).

    ``-as`` (``-automatic-scan``) makes nuclei fingerprint the target and select
    the templates that apply, instead of being handed a fixed tag/template set.
    """
    cmd = [str(nuclei), '-as', '-disable-update-check', '-j', '-o', str(output_file)]
    nuclei_cfg = repo_root / 'config' / 'nuclei-config.yaml'
    if nuclei_cfg.exists():
        cmd += ['-config', str(nuclei_cfg)]
    server_url = interactsh.get('server_url')
    if server_url:
        if not server_url.startswith(('http://', 'https://')):
            server_url = f"https://{server_url}"
        cmd += ['-interactsh-server', server_url]
    return cmd


def run_cmd(cmd, timeout: Optional[int] = None) -> int:
    """Run a nuclei command, streaming errors. Returns the exit code."""
    logger.info(f"Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error(f"nuclei timed out after {timeout}s")
        return 124
    if proc.stdout:
        logger.info(proc.stdout)
    if proc.returncode != 0 and proc.stderr:
        logger.error(proc.stderr)
    return proc.returncode


def parse_findings(output_file: Path) -> List[dict]:
    """Read nuclei's ``-j`` output (NDJSON) into a list of finding dicts."""
    findings: List[dict] = []
    if not output_file.exists():
        return findings
    for line in output_file.read_text(errors='replace').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if isinstance(rec, dict):
                findings.append(rec)
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping malformed nuclei output line: {e}")
    return findings


def run_auto(nuclei: Path, repo_root: Path, interactsh: dict, *,
             url: Optional[str] = None, input_file: Optional[Path] = None,
             output_file: Path, timeout: Optional[int] = None) -> int:
    """Run ``nuclei -as`` against a single URL or a list file. Returns exit code."""
    cmd = base_nuclei_cmd(nuclei, repo_root, interactsh, output_file)
    if url:
        cmd += ['-u', url]
    else:
        cmd += ['-l', str(input_file)]
    # Always create the output file so "ran, no findings" is distinguishable.
    output_file.write_text('')
    return run_cmd(cmd, timeout=timeout)


def scan_url(url: str, repo_root: Optional[Path] = None,
             timeout: int = DEFAULT_TIMEOUT) -> List[dict]:
    """Run an automatic (``-as``) nuclei scan against a single URL.

    This is the entry point the web server calls when the user clicks the nuclei
    icon next to a URL. Returns the parsed findings (possibly empty). Raises
    :class:`RuntimeError` if the nuclei binary cannot be found.
    """
    repo_root = repo_root or Path(__file__).resolve().parents[1]
    nuclei = find_nuclei(repo_root, exit_on_missing=False)
    if nuclei is None:
        raise RuntimeError("nuclei binary not found (looked in ./nuclei, ./bin/nuclei, PATH)")
    interactsh = read_interactsh(repo_root / 'config' / 'interactsh.config')
    tmp_out = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                          prefix='nuclei-as-')
    tmp_out.close()
    out_path = Path(tmp_out.name)
    try:
        run_auto(nuclei, repo_root, interactsh, url=url, output_file=out_path, timeout=timeout)
        return parse_findings(out_path)
    finally:
        out_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="Run nuclei automatic-scan (-as) enrichment over a URL or list")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='A single URL to scan')
    group.add_argument('-l', '--list', help='File of URLs to scan (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output JSON findings file')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Per-run timeout in seconds (default {DEFAULT_TIMEOUT})')
    parser.add_argument('--import', dest='do_import', action='store_true',
                        help='Import findings into Elasticsearch after scanning')
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    nuclei = find_nuclei(repo_root)
    interactsh = read_interactsh(repo_root / 'config' / 'interactsh.config')
    output_file = Path(args.output)

    if args.list:
        input_file = Path(args.list).expanduser().resolve()
        if not input_file.is_file():
            logger.error(f"Input file not found: {input_file}")
            sys.exit(2)
        run_auto(nuclei, repo_root, interactsh, input_file=input_file,
                 output_file=output_file, timeout=args.timeout)
    else:
        run_auto(nuclei, repo_root, interactsh, url=args.url,
                 output_file=output_file, timeout=args.timeout)

    if args.do_import:
        if output_file.exists() and output_file.stat().st_size > 0:
            logger.info("Importing nuclei findings into Elasticsearch...")
            import_script = repo_root / 'Python' / 'import_nuclei.py'
            subprocess.run([sys.executable, str(import_script), '-f', str(output_file)], check=False)
        else:
            logger.info(f"No nuclei findings to import ({output_file.name} missing or empty); "
                        "skipping import")


if __name__ == '__main__':
    main()
