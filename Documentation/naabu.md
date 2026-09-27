# naabu

[naabu](https://github.com/projectdiscovery/naabu) is the port scanner. It takes
hosts and reports open ports, with service discovery and version detection when
enabled. In the scanner it complements httpx: httpx tells you what is served over
HTTP, naabu tells you which other ports are open on the same hosts.

## Files

| File | Purpose |
|------|---------|
| `ports.conf` | The ports naabu scans (editable). |
| `Python/naabu_scan.py` | Wrapper that derives hosts from a URL list and runs naabu. |
| `Python/import_naabu.py` | Imports naabu JSON output into Elasticsearch. |
| `bin/naabu` | The naabu binary (downloaded by the user; gitignored). |

## ports.conf

Defines the ports to scan. One port (or range) per line, or comma-separated;
`#` comments and blank lines are ignored. The default set:

```
21, 22, 23, 25, 110, 143, 445, 993, 995, 2222
```

Edit this file to change what gets scanned — the wrapper reads it at runtime.

## Running a scan

```bash
# Derive hosts from a URL/host list and scan the ports in ports.conf
python3 Python/naabu_scan.py -l urls.txt -o ports.json

# Single host/IP/CIDR
python3 Python/naabu_scan.py -host example.com -o ports.json

# Scan and import into Elasticsearch in one step
python3 Python/naabu_scan.py -l urls.txt -o ports.json --import
```

`naabu_scan.py` normalises input first: `https://example.com/login` becomes
`example.com`, entries are de-duplicated, and the bare host list is handed to
naabu. It then runs naabu with the project's standard switches:

```
naabu -list <hosts> -port <ports.conf> \
      -sD \                 # service discovery
      -sV \                 # service version detection
      -sV-timeout 8 \       # service-version timeout (seconds)
      -retries 4 \          # retry unanswered probes 4 times
      -timeout 1200 \       # per-probe timeout (milliseconds)
      -scan-all-ips \       # scan every resolved IP of a host
      -j -o <output>        # JSON output
```

> naabu's SYN scanning needs `libpcap` and root/`CAP_NET_RAW`. The Terraform
> workers install `libpcap-dev` and run as root; locally you may need `sudo`.

## Importing results

```bash
python3 Python/import_naabu.py -f ports.json
```

Port records are indexed into a dedicated index (`elasticsearch.ports_index`,
default `scanner_ports`), separate from the httpx records. Each document is keyed
by `host:ip:port`, so re-scanning updates entries in place. Mapped fields include
`host`, `ip` (ip type), `port`, `protocol`, `service`, `version`, and
`timestamp`; other naabu fields are captured dynamically.

See [architecture.md](architecture.md) for how the indices relate.
