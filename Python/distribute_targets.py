#!/usr/bin/env python3
"""
Split a target list into N shards to distribute a scan across multiple VPSes.

Each worker (provisioned by the Terraform module in terraform/) scans one shard.
This tool splits an input file of URLs/hosts round-robin into ``--workers``
shards and, optionally, copies each shard to the corresponding worker over SSH.

Usage:
  # Just write shard files (targets.shard1.txt ... targetsN.txt)
  python3 Python/distribute_targets.py -f targets.txt --workers 3

  # Write shards and scp them to the workers (IPs from terraform output)
  python3 Python/distribute_targets.py -f targets.txt --workers 3 \
      --hosts 203.0.113.10,203.0.113.11,203.0.113.12 \
      --remote-path /opt/scanner/targets.txt
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def read_targets(path: Path):
    """Return de-duplicated, non-empty target lines preserving order."""
    seen = set()
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def shard(targets, workers):
    """Round-robin split targets into ``workers`` lists."""
    buckets = [[] for _ in range(workers)]
    for i, target in enumerate(targets):
        buckets[i % workers].append(target)
    return buckets


def main():
    parser = argparse.ArgumentParser(description="Shard a target list across workers")
    parser.add_argument('-f', '--file', required=True, help='Input target file (URLs/hosts)')
    parser.add_argument('--workers', type=int, required=True, help='Number of workers/shards')
    parser.add_argument('--out-prefix', default=None,
                        help='Output prefix (default: derived from input filename)')
    parser.add_argument('--hosts', help='Comma-separated worker IPs/hosts to scp shards to')
    parser.add_argument('--ssh-user', default='root', help='SSH user for scp (default root)')
    parser.add_argument('--remote-path', default='/opt/scanner/targets.txt',
                        help='Destination path on each worker')
    args = parser.parse_args()

    if args.workers < 1:
        logger.error("--workers must be >= 1")
        sys.exit(1)

    input_file = Path(args.file)
    if not input_file.is_file():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    targets = read_targets(input_file)
    if not targets:
        logger.error("No targets found in input file")
        sys.exit(1)

    buckets = shard(targets, args.workers)
    prefix = args.out_prefix or input_file.with_suffix('').name

    shard_files = []
    for idx, bucket in enumerate(buckets, 1):
        shard_path = input_file.parent / f"{prefix}.shard{idx}.txt"
        shard_path.write_text('\n'.join(bucket) + ('\n' if bucket else ''))
        shard_files.append(shard_path)
        logger.info(f"Wrote {len(bucket)} targets to {shard_path}")

    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(',') if h.strip()]
        if len(hosts) != args.workers:
            logger.error(f"--hosts has {len(hosts)} entries but --workers is {args.workers}")
            sys.exit(1)
        for host, shard_path in zip(hosts, shard_files):
            dest = f"{args.ssh_user}@{host}:{args.remote_path}"
            logger.info(f"Copying {shard_path} -> {dest}")
            rc = subprocess.run(['scp', str(shard_path), dest]).returncode
            if rc != 0:
                logger.error(f"scp to {host} failed (exit {rc})")


if __name__ == '__main__':
    main()
