# Interactsh

[Interactsh](https://github.com/projectdiscovery/interactsh) is an
out-of-band (OOB) interaction server. Many vulnerability classes are *blind* —
the target does not return the result in the HTTP response but instead makes an
outbound DNS/HTTP/SMTP callback (blind SSRF, blind command injection, blind
XXE, some SQLi). nuclei asks the target to call back to an Interactsh server; if
a callback arrives, the vulnerability is confirmed.

This project uses a **self-hosted** Interactsh server so callbacks stay under
your control.

## Files

| File | Purpose |
|------|---------|
| `config/interactsh.config` | The server URL and IP used by the nuclei runner. |

## interactsh.config

```
server_url = example.com
server_ip  = 127.0.0.1
```

- `server_url` — the Interactsh server hostname. `Python/nuclei_scan.py` reads
  this and passes it to nuclei as `-interactsh-server https://<server_url>`.
- `server_ip` — the server's IP address, for DNS / `/etc/hosts` pinning and for
  running the self-hosted `interactsh-server` / `interactsh-client`.

Edit this file to point at a different server; the nuclei runner picks it up on
the next run.

## How it fits in

1. `nuclei_scan.py` reads `interactsh.config` and starts nuclei with
   `-interactsh-server https://example.com`.
2. nuclei registers with that server and injects unique callback URLs into its
   probes.
3. If a target performs an OOB interaction, the server records it and nuclei
   correlates it back to the finding.
4. The finding is written to the JSON output and imported into the
   `scanner_findings` index like any other.

## Running your own Interactsh server

On the host behind `example.com` / `127.0.0.1`:

```bash
interactsh-server -domain example.com -ip 127.0.0.1
```

DNS for `example.com` must delegate to that server so callbacks resolve. See the
[Interactsh self-hosting guide](https://github.com/projectdiscovery/interactsh#interactsh-server)
for the required NS/A records and wildcard setup.

See [architecture.md](architecture.md) for the end-to-end flow.
