#!/usr/bin/env python3
"""
Scanner pipeline orchestrator.

Runs the full recon pipeline over a list of targets in one command:

    httpx  (probe)   -> import into Elasticsearch  (scanner_records)
    naabu  (ports)   -> import into Elasticsearch  (scanner_ports)
    nuclei (enrich)  -> import into Elasticsearch  (scanner_findings)

Each stage is delegated to the existing per-tool scripts (scanner.py,
naabu_scan.py, nuclei_scan.py and their import_*.py counterparts), so this is
purely orchestration — the tools remain usable on their own.

Interactsh interactions are collected continuously by Python/interactsh_stream.py
and are intentionally not part of this batch pipeline.

Usage:
    python3 Python/scan.py -l urls.txt
    python3 Python/scan.py -u https://example.com
    python3 Python/scan.py -l urls.txt -o run1/ --skip-naabu
    python3 Python/scan.py -l urls.txt --nuclei-mode workflow
    python3 Python/scan.py -l urls.txt --no-import        # scan only, no ingestion
"""

import argparse
import logging
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("pipeline")

REPO = Path(__file__).resolve().parents[1]
PY = REPO / "Python"


def run_step(name, cmd):
    """Run a pipeline step; return True on success, False on failure."""
    logger.info("=" * 64)
    logger.info(f"▶ {name}")
    logger.info(f"  {' '.join(str(c) for c in cmd)}")
    rc = subprocess.run(cmd).returncode
    if rc == 0:
        logger.info(f"✓ {name} completed")
        return True
    logger.error(f"✗ {name} failed (exit {rc})")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Run the full httpx -> naabu -> nuclei pipeline and ingest into Elasticsearch")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-l", "--list", help="File of target URLs/hosts (one per line)")
    src.add_argument("-u", "--url", help="A single target URL/host")
    parser.add_argument("-o", "--outdir", help="Directory for scan output (default: scan-<timestamp>/)")
    parser.add_argument("--skip-httpx", action="store_true", help="Skip the httpx stage")
    parser.add_argument("--skip-naabu", action="store_true", help="Skip the naabu stage")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip the nuclei stage")
    parser.add_argument("--nuclei-mode", choices=["tech-aware", "workflow"], default="tech-aware",
                        help="tech-aware reads httpx-detected tech from Elasticsearch (default); "
                             "workflow runs the tech-conditional workflow over the target list")
    parser.add_argument("--no-import", action="store_true",
                        help="Run the scans but do not ingest results into Elasticsearch")
    args = parser.parse_args()

    # Resolve the target list (single URL -> a temp one-line file used by all stages).
    tmp_targets = None
    if args.list:
        targets = Path(args.list).expanduser().resolve()
        if not targets.is_file():
            logger.error(f"Target list not found: {targets}")
            sys.exit(2)
    else:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, prefix="scan-target-")
        tmp.write(args.url.strip() + "\n")
        tmp.close()
        targets = Path(tmp.name)
        tmp_targets = targets

    outdir = Path(args.outdir) if args.outdir else REPO / f"scan-{datetime.now():%Y%m%d-%H%M%S}"
    outdir.mkdir(parents=True, exist_ok=True)
    httpx_out = outdir / "httpx.json"
    ports_out = outdir / "ports.json"
    findings_out = outdir / "findings.json"

    do_import = not args.no_import
    results = []

    try:
        # 1) httpx
        if not args.skip_httpx:
            if run_step("httpx scan", [sys.executable, str(PY / "scanner.py"),
                                       "-f", str(targets), "-o", str(httpx_out)]):
                results.append(("httpx scan", True))
                if do_import:
                    results.append(("httpx import", run_step("httpx import",
                        [sys.executable, str(PY / "import_httpx.py"), "-f", str(httpx_out)])))
            else:
                results.append(("httpx scan", False))

        # 2) naabu
        if not args.skip_naabu:
            if run_step("naabu scan", [sys.executable, str(PY / "naabu_scan.py"),
                                       "-l", str(targets), "-o", str(ports_out)]):
                results.append(("naabu scan", True))
                if do_import:
                    results.append(("naabu import", run_step("naabu import",
                        [sys.executable, str(PY / "import_naabu.py"), "-f", str(ports_out)])))
            else:
                results.append(("naabu scan", False))

        # 3) nuclei
        if not args.skip_nuclei:
            if args.nuclei_mode == "tech-aware":
                nuclei_cmd = [sys.executable, str(PY / "nuclei_scan.py"),
                              "--from-elasticsearch", "-o", str(findings_out)]
            else:
                nuclei_cmd = [sys.executable, str(PY / "nuclei_scan.py"),
                              "-l", str(targets), "-o", str(findings_out)]
            if run_step(f"nuclei scan ({args.nuclei_mode})", nuclei_cmd):
                results.append(("nuclei scan", True))
                if do_import:
                    results.append(("nuclei import", run_step("nuclei import",
                        [sys.executable, str(PY / "import_nuclei.py"), "-f", str(findings_out)])))
            else:
                results.append(("nuclei scan", False))
    finally:
        if tmp_targets and tmp_targets.exists():
            try:
                tmp_targets.unlink()
            except OSError:
                pass

    # Summary
    logger.info("=" * 64)
    logger.info(f"Pipeline finished. Output in: {outdir}")
    for name, ok in results:
        logger.info(f"  {'✓' if ok else '✗'} {name}")
    failed = [n for n, ok in results if not ok]
    if failed:
        logger.warning(f"{len(failed)} step(s) failed: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
