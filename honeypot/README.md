# BrovanaRange HTTP Honeypot

This is a low-interaction HTTP decoy intended to receive opportunistic scans and login attempts. It is a standalone service: it has no route to the application, database, Docker socket, or lab networks.

## Run and monitor

Start it with the rest of the stack:

```bash
docker compose up -d --build honeypot
docker compose logs -f honeypot
```

It listens on host port `8081` by default. To make it reachable from the Internet, place only that port behind a dedicated DNS name and firewall rule; do not reuse the primary application hostname or expose Docker management ports.

Events are emitted as JSON to Docker logs. They include the source IP, method, target path, query string, user agent, and request metadata. Request bodies are not retained.

## Admin dashboard integration

The backend ingests recent honeypot container logs into the Admin dashboard at `/admin/honeypot/events`. Events are deduplicated, classified by severity, and optionally enriched with VirusTotal IP reputation data.

Set these values in `.env` to enable reputation checks:

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
VIRUSTOTAL_MALICIOUS_THRESHOLD=1
VIRUSTOTAL_CACHE_HOURS=24
HONEYPOT_CONTAINER_NAME=brovanarange-honeypot
```

Without a VirusTotal API key, the dashboard still shows honeypot hits but marks reputation enrichment as disabled.

## Safety boundaries

- The service runs on its own internal Docker network.
- It has a read-only filesystem, no Linux capabilities, `no-new-privileges`, and strict CPU, memory, and process limits.
- It does not proxy requests, execute payloads, retain credentials, or use forwarded client-IP headers.
