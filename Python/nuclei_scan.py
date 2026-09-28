#!/usr/bin/env python3
"""
Run ProjectDiscovery's `nuclei` to enrich URLs, applying templates only to the
URLs that matter, and reporting out-of-band interactions to a self-hosted
Interactsh server.

Two modes:

  1. Workflow mode (default): run the native nuclei workflow
     ``nuclei-workflows/tech-conditional-workflow.yaml``. Each technology's
     templates only run against a URL once a detection template matches it
     (WordPress -> wordpress templates; FrontPage -> CVE-2000-0114).

  2. Tech-aware mode (--from-elasticsearch): read the technologies httpx already
     detected (stored in Elasticsearch) and run nuclei per URL group with just
     the matching template tags/paths. This guarantees "only WordPress templates
     on WordPress URLs" using real detection data and avoids wasted requests.

Both modes apply nuclei-config.yaml (per-VPS settings) and the Interactsh server
from interactsh.config.

Usage:
  python3 Python/nuclei_scan.py -l urls.txt -o findings.json
  python3 Python/nuclei_scan.py --from-elasticsearch -o findings.json
  python3 Python/nuclei_scan.py -l urls.txt -o findings.json --import
"""

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Map a detected technology (lower-cased substring) to nuclei template tags.
TECH_TO_TAGS = {
    'wordpress': ['wordpress'],
    'joomla': ['joomla'],
    'drupal': ['drupal'],
    'magento': ['magento'],
    'apache': ['apache'],
    'nginx': ['nginx'],
    'tomcat': ['tomcat'],
    'iis': ['iis'],
    'php': ['php'],
    'jira': ['jira'],
    'confluence': ['confluence'],
    'gitlab': ['gitlab'],
    'jenkins': ['jenkins'],
    'grafana': ['grafana'],
    'phpmyadmin': ['phpmyadmin'],
}

# Map a detected technology to explicit template paths (resolved by nuclei
# against its templates directory). Use for one-off, technology-specific CVEs.
TECH_TO_TEMPLATES = {
    'frontpage': ['http/cves/2000/CVE-2000-0114.yaml'],
    'microsoft frontpage': ['http/cves/2000/CVE-2000-0114.yaml'],
}


def find_nuclei(repo_root: Path) -> Path:
    """Locate the nuclei binary (repo root, bin/, or PATH)."""
    for candidate in (repo_root / 'nuclei', repo_root / 'bin' / 'nuclei'):
        if candidate.exists():
            return candidate
    on_path = shutil.which('nuclei')
    if on_path:
        return Path(on_path)
    logger.error("nuclei binary not found at ./nuclei, ./bin/nuclei, or on PATH")
    sys.exit(2)


def read_interactsh(config_path: Path):
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


def base_nuclei_cmd(nuclei: Path, repo_root: Path, interactsh: dict, output_file: Path):
    """Build the common nuclei argument list (config + interactsh + JSON out)."""
    cmd = [str(nuclei), '-disable-update-check', '-j', '-o', str(output_file)]
    nuclei_cfg = repo_root / 'config' / 'nuclei-config.yaml'
    if nuclei_cfg.exists():
        cmd += ['-config', str(nuclei_cfg)]
    server_url = interactsh.get('server_url')
    if server_url:
        if not server_url.startswith(('http://', 'https://')):
            server_url = f"https://{server_url}"
        cmd += ['-interactsh-server', server_url]
    return cmd


def run_cmd(cmd):
    """Run a nuclei command, streaming errors. Returns the exit code."""
    logger.info(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        logger.info(proc.stdout)
    if proc.returncode != 0 and proc.stderr:
        logger.error(proc.stderr)
    return proc.returncode


def run_workflow(nuclei, repo_root, interactsh, input_file, output_file):
    """Mode 1: run the tech-conditional nuclei workflow over a URL list."""
    workflow = repo_root / 'nuclei-workflows' / 'tech-conditional-workflow.yaml'
    if not workflow.exists():
        logger.error(f"Workflow not found at {workflow}")
        sys.exit(2)
    cmd = base_nuclei_cmd(nuclei, repo_root, interactsh, output_file)
    cmd += ['-l', str(input_file), '-w', str(workflow)]
    return run_cmd(cmd)


def tags_for_tech(tech_list):
    """Return (tags set, template paths set) for a URL's detected technologies."""
    tags = set()
    templates = set()
    for tech in tech_list or []:
        t = str(tech).lower()
        for needle, mapped in TECH_TO_TAGS.items():
            if needle in t:
                tags.update(mapped)
        for needle, mapped in TECH_TO_TEMPLATES.items():
            if needle in t:
                templates.update(mapped)
    return tags, templates


def run_tech_aware(nuclei, repo_root, interactsh, output_file, config):
    """Mode 2: read detected tech from Elasticsearch and scan per tech group."""
    sys.path.insert(0, str(repo_root / 'Server'))
    from elasticsearch_manager import ElasticsearchManager

    config.setdefault('elasticsearch', {})['enabled'] = True
    store = ElasticsearchManager(config)
    if not store.is_connected:
        logger.error("Cannot reach Elasticsearch for tech-aware scanning")
        sys.exit(1)

    # Group URLs by their (tags, templates) signature so each nuclei run is
    # scoped to exactly the templates that matter for that group.
    groups = {}
    query = {"bool": {"filter": [{"exists": {"field": "tech"}}]}}
    for doc in store.scan(query, source=['url', 'tech']):
        url = doc.get('url')
        if not url:
            continue
        tags, templates = tags_for_tech(doc.get('tech'))
        if not tags and not templates:
            continue
        key = (frozenset(tags), frozenset(templates))
        groups.setdefault(key, []).append(url)

    if not groups:
        logger.warning("No URLs with a mapped technology found in Elasticsearch")
        return 0

    logger.info(f"Prepared {len(groups)} technology group(s) for scanning")
    final = Path(output_file)
    final.write_text('')  # start empty; append each group's results

    rc = 0
    for (tags, templates), urls in groups.items():
        tmp_urls = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                               prefix='nuclei-urls-')
        tmp_urls.write('\n'.join(urls))
        tmp_urls.close()
        tmp_out = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                              prefix='nuclei-out-')
        tmp_out.close()

        cmd = base_nuclei_cmd(nuclei, repo_root, interactsh, Path(tmp_out.name))
        cmd += ['-l', tmp_urls.name]
        if tags:
            cmd += ['-tags', ','.join(sorted(tags))]
        for tpl in sorted(templates):
            cmd += ['-t', tpl]

        logger.info(f"Group: {len(urls)} URL(s), tags={sorted(tags)}, "
                    f"templates={sorted(templates)}")
        rc |= run_cmd(cmd)

        # Append this group's findings to the combined output.
        out_text = Path(tmp_out.name).read_text()
        if out_text:
            with open(final, 'a') as f:
                f.write(out_text if out_text.endswith('\n') else out_text + '\n')
        Path(tmp_urls.name).unlink(missing_ok=True)
        Path(tmp_out.name).unlink(missing_ok=True)

    logger.info(f"Tech-aware scan completed. Combined output: {final}")
    return rc


def main():
    parser = argparse.ArgumentParser(description="Run nuclei enrichment (workflow or tech-aware)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', help='File of URLs to scan (workflow mode)')
    group.add_argument('--from-elasticsearch', action='store_true',
                       help='Scan URLs grouped by tech detected in Elasticsearch')
    parser.add_argument('-o', '--output', required=True, help='Output JSON findings file')
    parser.add_argument('--import', dest='do_import', action='store_true',
                        help='Import findings into Elasticsearch after scanning')
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    nuclei = find_nuclei(repo_root)
    interactsh = read_interactsh(repo_root / 'config' / 'interactsh.config')
    output_file = Path(args.output)

    if args.from_elasticsearch:
        import yaml
        config_file = repo_root / 'config' / 'server-config.yaml'
        config = yaml.safe_load(config_file.read_text()) if config_file.exists() else {}
        run_tech_aware(nuclei, repo_root, interactsh, output_file, config)
    else:
        input_file = Path(args.list).expanduser().resolve()
        if not input_file.is_file():
            logger.error(f"Input file not found: {input_file}")
            sys.exit(2)
        run_workflow(nuclei, repo_root, interactsh, input_file, output_file)

    if args.do_import:
        logger.info("Importing nuclei findings into Elasticsearch...")
        import_script = repo_root / 'Python' / 'import_nuclei.py'
        subprocess.run([sys.executable, str(import_script), '-f', str(output_file)], check=False)


if __name__ == '__main__':
    main()
