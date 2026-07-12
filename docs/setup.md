# Setup Guide

Full install and configuration guide for running BrovanaRange locally.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker + Docker Compose | Required — everything runs containerized |
| Git | To clone the repo |
| 4GB+ free RAM | Lab containers, IDS stack, and DB all run concurrently |
| Linux host (recommended) | gVisor (`runsc`) sandboxing works best on Linux; Windows/macOS work via Docker Desktop but with reduced isolation guarantees |

## 1. Clone the repository

```bash
git clone https://github.com/Aymwvn/BrovanaRange.git
cd BrovanaRange
```

## 2. Configure environment variables

Copy the example env file and fill in real values:

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```env
# Database
POSTGRES_USER=brovana
POSTGRES_PASSWORD=<generate a strong password>
POSTGRES_DB=brovanarange

# Backend
JWT_SECRET=<generate a long random string — backend refuses to boot on a weak one>
ADMIN_EMAIL=<your admin login email>
ADMIN_PASSWORD=<your admin login password>

# CORS
ALLOWED_ORIGINS=https://localhost
```

To generate a strong JWT secret:

```bash
# Linux/macOS
openssl rand -hex 32

# Windows PowerShell
-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 48 | % {[char]$_})
```

**Never commit your real `.env` file.** It's already covered by `.gitignore`, but double-check with `git status` before your first commit if you're setting this up fresh.

## 3. Build and start the stack

```bash
docker-compose up --build
```

First run will take a few minutes — it's building the frontend, backend, and pulling Suricata/Zeek images.

Once running, check that all containers are healthy:

```bash
docker-compose ps
```

You should see the frontend, backend, database, Suricata, and Zeek containers all in an `Up`/`healthy` state.

## 4. Access the platform

- **Web UI**: `https://localhost` (self-signed cert — your browser will warn you, that's expected locally; click through "Advanced → Proceed")
- **Admin login**: use the `ADMIN_EMAIL` / `ADMIN_PASSWORD` you set in `.env`

## 5. Verify IDS is working

Check that Suricata and Zeek are actually capturing traffic:

```bash
docker-compose logs suricata --tail=50
docker-compose logs zeek --tail=50
```

Start a lab from the dashboard, then check the Suricata EVE log for activity:

```bash
docker exec -it <suricata-container-name> tail -f /var/log/suricata/eve.json
```

## Common Issues

**Containers fail to start / port conflicts**
Something else is likely using port 80, 443, or 5432. Stop the conflicting service or change the port mapping in `docker-compose.yml`.

**Backend fails to boot with a JWT secret error**
Your `JWT_SECRET` in `.env` is too short or weak. Generate a new one with the command above.

**Lab containers won't spawn**
Check the Docker socket proxy container is running (`docker-compose ps`) and that your user has permission to run Docker commands (`docker ps` should work without `sudo` on Linux).

**gVisor (runsc) not available**
gVisor sandboxing is optional and Linux-only. On Windows/macOS or hosts without `runsc` installed, labs will fall back to standard `runc` — check `scripts/check-runsc.sh` to verify availability on your host.

**Self-signed cert warnings**
Expected for local development. For a real deployment, replace with a trusted cert (see the "Future Security Improvements" section in `docs/SECURITY.md`).

## Stopping the stack

```bash
docker-compose down
```

To also remove volumes (wipes the database):

```bash
docker-compose down -v
```
