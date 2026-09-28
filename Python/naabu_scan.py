#!/usr/bin/env python3
"""
Wrapper to run ProjectDiscovery's `naabu` port scanner over the hosts derived
from a URL/host list, using the ports defined in ports.conf.

The scan is run according to the project's rules:
  -nmap-cli 'nmap -sC -sV'  run nmap default scripts + service/version detection
                            on the discovered ports (requires nmap on PATH)
  -retries 4          retry unanswered probes 4 times
  -timeout 1200       per-probe timeout (milliseconds)
  -scan-all-ips       scan every resolved IP for a host
  -j -o <file>        write results as JSON

Input hosts:
  naabu expects hosts / IPs / CIDRs, not full URLs. This wrapper reads the input
  file, strips any scheme/path so `https://example.com/login` becomes
  `example.com`, de-duplicates, and feeds the result to naabu.

Usage:
  python3 Python/naabu_scan.py -l urls.txt -o ports.json
  python3 Python/naabu_scan.py -host example.com -o ports.json
  python3 Python/naabu_scan.py -l urls.txt -o ports.json --import
"""

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def parse_ports_conf(path: Path) -> str:
    """Parse ports.conf into a comma-separated naabu port list.

    Supports one port (or range) per line and comma-separated lists, with '#'
    comments (inline or full-line) and blank lines ignored.
    """
    ports = []
    for raw in path.read_text().splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        for token in line.split(','):
            token = token.strip()
            if token:
                ports.append(token)
    if not ports:
        raise ValueError(f"No ports defined in {path}")
    return ','.join(ports)


def normalize_host(entry: str) -> str:
    """Reduce a URL or host entry to a bare host/IP naabu can scan."""
    entry = entry.strip()
    if not entry:
        return ''
    if '://' in entry:
        parsed = urlparse(entry)
        return parsed.hostname or ''
    # host[:port]/path form without a scheme
    entry = entry.split('/', 1)[0]
    # keep IPv6 in brackets intact; strip a trailing :port for host:port form
    if entry.count(':') == 1:
        entry = entry.split(':', 1)[0]
    return entry


def build_host_file(input_file: Path, dest: Path) -> Path:
    """Write a de-duplicated host file (derived from a URL/host list) to ``dest``.

    The file is written next to the scan output (not a temp file that is deleted
    afterwards) so the exact ``-list`` input naabu received stays on disk for
    inspection.
    """
    seen = set()
    hosts = []
    for line in input_file.read_text().splitlines():
        host = normalize_host(line)
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    if not hosts:
        raise ValueError(f"No hosts found in {input_file}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text('\n'.join(hosts) + '\n')
    logger.info(f"Prepared {len(hosts)} unique hosts -> {dest}")
    return dest


def find_naabu(repo_root: Path) -> Path:
    """Locate the naabu binary (repo root, bin/, or PATH)."""
    for candidate in (repo_root / 'naabu', repo_root / 'bin' / 'naabu'):
        if candidate.exists():
            return candidate
    on_path = shutil.which('naabu')
    if on_path:
        return Path(on_path)
    logger.error("naabu binary not found at ./naabu, ./bin/naabu, or on PATH")
    sys.exit(2)


def run_naabu(naabu: Path, host_file: Path, ports: str, output_file: Path):
    """Run naabu with the project's standard switches."""
    cmd = [
        str(naabu),
        '-list', str(host_file),
        '-port', ports,
        '-nmap-cli', 'nmap -sC -sV',
        '-retries', '4',
        '-timeout', '1200',
        '-scan-all-ips',
        '-j',
        '-o', str(output_file),
    ]
    logger.info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if result.stdout:
            logger.info(result.stdout)
        logger.info(f"Scan completed. Output saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        logger.error(f"naabu failed with exit code {e.returncode}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Run naabu over hosts from a URL/host list")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', help='File of URLs/hosts (one per line)')
    group.add_argument('-host', '--host', dest='host', help='Single host/IP/CIDR to scan')
    parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    parser.add_argument('-c', '--ports-conf', help='Path to ports.conf (default: config/ports.conf)')
    parser.add_argument('--import', dest='do_import', action='store_true',
                        help='Import results into Elasticsearch after scanning')
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    ports_conf = Path(args.ports_conf) if args.ports_conf else repo_root / 'config' / 'ports.conf'
    if not ports_conf.exists():
        logger.error(f"ports.conf not found at {ports_conf}")
        sys.exit(2)
    ports = parse_ports_conf(ports_conf)
    logger.info(f"Scanning ports: {ports}")

    naabu = find_naabu(repo_root)
    if shutil.which('nmap') is None:
        logger.warning("nmap not found on PATH; naabu's -nmap-cli service/version "
                       "detection needs nmap installed to produce results.")
    output_file = Path(args.output)
    hosts_file = output_file.parent / f"{output_file.stem}-hosts.txt"

    try:
        if args.list:
            input_file = Path(args.list).expanduser().resolve()
            if not input_file.is_file():
                logger.error(f"Input file not found: {input_file}")
                sys.exit(2)
            build_host_file(input_file, hosts_file)
        else:
            host = normalize_host(args.host)
            if not host:
                logger.error(f"No valid host derived from: {args.host}")
                sys.exit(2)
            hosts_file.parent.mkdir(parents=True, exist_ok=True)
            hosts_file.write_text(host + '\n')
            logger.info(f"Prepared 1 host -> {hosts_file}")
        run_naabu(naabu, hosts_file, ports, output_file)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)

    if args.do_import:
        if output_file.exists() and output_file.stat().st_size > 0:
            logger.info("Importing naabu results into Elasticsearch...")
            import_script = repo_root / 'Python' / 'import_naabu.py'
            subprocess.run([sys.executable, str(import_script), '-f', str(output_file)], check=False)
        else:
            logger.info(f"No naabu results to import ({output_file.name} missing or empty); "
                        "skipping import")


if __name__ == '__main__':
    main()
