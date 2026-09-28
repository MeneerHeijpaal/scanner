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
    results = []  # list of (name, status) where status is "ok" | "fail" | "skip"

    def run_stage(name, scan_cmd, importer, out_file):
        """Run a scan step, then import its output if it produced any."""
        if not run_step(f"{name} scan", scan_cmd):
            results.append((f"{name} scan", "fail"))
            return
        results.append((f"{name} scan", "ok"))
        if not do_import:
            return
        # A stage that finds nothing may not write an output file at all — that
        # is not an error, so skip the import cleanly instead of failing on a
        # missing file.
        if not out_file.exists() or out_file.stat().st_size == 0:
            logger.info(f"↷ {name}: no results to import ({out_file.name} missing or empty); skipping")
            results.append((f"{name} import", "skip"))
            return
        ok = run_step(f"{name} import",
                      [sys.executable, str(importer), "-f", str(out_file)])
        results.append((f"{name} import", "ok" if ok else "fail"))

    try:
        if not args.skip_httpx:
            run_stage("httpx",
                      [sys.executable, str(PY / "scanner.py"), "-f", str(targets), "-o", str(httpx_out)],
                      PY / "import_httpx.py", httpx_out)

        if not args.skip_naabu:
            run_stage("naabu",
                      [sys.executable, str(PY / "naabu_scan.py"), "-l", str(targets), "-o", str(ports_out)],
                      PY / "import_naabu.py", ports_out)

        if not args.skip_nuclei:
            if args.nuclei_mode == "tech-aware":
                nuclei_cmd = [sys.executable, str(PY / "nuclei_scan.py"),
                              "--from-elasticsearch", "-o", str(findings_out)]
            else:
                nuclei_cmd = [sys.executable, str(PY / "nuclei_scan.py"),
                              "-l", str(targets), "-o", str(findings_out)]
            logger.info(f"nuclei mode: {args.nuclei_mode}")
            run_stage("nuclei", nuclei_cmd, PY / "import_nuclei.py", findings_out)
    finally:
        if tmp_targets and tmp_targets.exists():
            try:
                tmp_targets.unlink()
            except OSError:
                pass

    # Summary
    symbol = {"ok": "✓", "fail": "✗", "skip": "↷"}
    logger.info("=" * 64)
    logger.info(f"Pipeline finished. Output in: {outdir}")
    for name, status in results:
        logger.info(f"  {symbol.get(status, '?')} {name}")
    failed = [n for n, s in results if s == "fail"]
    if failed:
        logger.warning(f"{len(failed)} step(s) failed: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
