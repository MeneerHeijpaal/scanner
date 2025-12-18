#!/usr/bin/env python3
"""Simple wrapper to run the bundled `httpx` binary for a file of URLs or a single URL.

Usage:
  - File of URLs: python3 scanner.py -f /path/to/list.txt [-o results.json]
  - Single URL:      python3 scanner.py -u https://example.com [-o test.json]

This script expects the `httpx` binary to be present at the repository root (`./httpx`).
It will call it like:
  ./httpx -config <config.yaml for httpx> -l <INPUTFILE> -j -o <OUTPUT>
or
  ./httpx -config <config.yaml for httpx> -u <URL> -j -o <OUTPUT>

The script resolves paths relative to its location so it works when launched from VS Code.
"""

import argparse
import logging
import shutil
import subprocess
from pathlib import Path
import sys
from urllib.parse import urlparse
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def run_httpx_for_file(httpx_path: Path, config_path: Path, input_file: Path, output_file: Path):
	"""Run httpx scanner with a file containing URLs."""
	cmd = [str(httpx_path), '-config', str(config_path), '-l', str(input_file), '-j', '-o', str(output_file)]
	logger.info(f'Running: {" ".join(cmd)}')
	try:
		result = subprocess.run(cmd, check=True, capture_output=True, text=True)
		if result.stdout:
			logger.info(result.stdout)
		logger.info(f'Scan completed successfully. Output saved to: {output_file}')
	except subprocess.CalledProcessError as e:
		logger.error(f'httpx command failed with exit code {e.returncode}')
		if e.stderr:
			logger.error(f'Error output: {e.stderr}')
		raise


def run_httpx_for_url(httpx_path: Path, config_path: Path, url: str, output_file: Path):
	"""Run httpx scanner with a single URL."""
	cmd = [str(httpx_path), '-config', str(config_path), '-u', url, '-j', '-o', str(output_file)]
	logger.info(f'Running: {" ".join(cmd)}')
	try:
		result = subprocess.run(cmd, check=True, capture_output=True, text=True)
		if result.stdout:
			logger.info(result.stdout)
		logger.info(f'Scan completed successfully. Output saved to: {output_file}')
	except subprocess.CalledProcessError as e:
		logger.error(f'httpx command failed with exit code {e.returncode}')
		if e.stderr:
			logger.error(f'Error output: {e.stderr}')
		raise


def main():
	parser = argparse.ArgumentParser(description='Run bundled httpx for a file of URLs or a single URL')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-f', '--file', help='Path to file with URLs (one per line)')
	group.add_argument('-u', '--url', help='Single URL to scan')
	parser.add_argument('-o', '--output', help='Output JSON filename (optional)')
	args = parser.parse_args()

	# Determine repo root (two levels up from this file: .../Scanner/Python/scanner.py)
	this_file = Path(__file__).resolve()
	repo_root = this_file.parents[1]

	# Check for httpx binary
	httpx_path = repo_root / 'httpx'
	if not httpx_path.exists():
		# Try bin/httpx as alternative location
		httpx_path = repo_root / 'bin' / 'httpx'
		if not httpx_path.exists():
			logger.error(f'httpx binary not found at {repo_root}/httpx or {repo_root}/bin/httpx')
			sys.exit(2)

	# Ensure executable permissions
	if not shutil.which(str(httpx_path)):
		try:
			httpx_path.chmod(httpx_path.stat().st_mode | 0o111)
			logger.info(f'Made httpx executable: {httpx_path}')
		except Exception as e:
			logger.warning(f'Could not set executable bit on httpx: {e}')

	config_path = repo_root / 'httpx-config.yaml'
	if not config_path.exists():
		logger.error(f'config.yaml not found at {config_path}')
		sys.exit(2)

	try:
		if args.file:
			input_file = Path(args.file).expanduser().resolve()
			if not input_file.exists():
				logger.error(f'Input file not found: {input_file}')
				sys.exit(2)
			if not input_file.is_file():
				logger.error(f'Path is not a file: {input_file}')
				sys.exit(2)

			# Default output: inputfile + .json (replace extension)
			if args.output:
				output_file = Path(args.output)
			else:
				output_file = input_file.with_suffix('.json')
				logger.info(f'No output filename specified. Using: {output_file}')

			run_httpx_for_file(httpx_path, config_path, input_file, output_file)

		else:
			# Single URL
			url = args.url

			# Basic URL validation
			if not url.startswith(('http://', 'https://')):
				logger.warning(f'URL does not start with http:// or https://: {url}')
				logger.info('httpx will attempt to auto-detect the protocol')

			if args.output:
				output_file = Path(args.output)
			else:
				# Derive a filename from the hostname of the supplied URL
				try:
					parsed = urlparse(url)
					hostname = parsed.hostname or parsed.netloc or 'unknown'
					# Sanitize hostname to be filesystem-safe
					safe = re.sub(r'[^A-Za-z0-9.-]', '_', hostname)
					output_file = repo_root / f"{safe}.json"
					logger.info(f'No output filename specified. Using: {output_file}')
				except Exception as e:
					logger.warning(f'Could not parse URL for filename: {e}')
					output_file = repo_root / 'scan_output.json'
					logger.info(f'Using default output: {output_file}')

			run_httpx_for_url(httpx_path, config_path, url, output_file)

	except subprocess.CalledProcessError as e:
		logger.error(f'httpx scan failed with exit code {e.returncode}')
		sys.exit(e.returncode)
	except KeyboardInterrupt:
		logger.info('Scan interrupted by user')
		sys.exit(130)
	except Exception as e:
		logger.error(f'Unexpected error: {e}')
		sys.exit(1)


if __name__ == '__main__':
	main()
