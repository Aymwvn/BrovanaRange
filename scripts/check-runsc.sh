#!/usr/bin/env sh
set -eu

echo "[1/3] Docker runtimes"
docker info | sed -n '/Runtimes:/,/Default Runtime:/p'

echo "[2/3] runsc smoke test"
docker run --rm --runtime=runsc alpine:latest uname -a

echo "[3/3] RedRange lab runtime env"
grep -E '^(LAB_CONTAINER_RUNTIME|ALLOW_UNSANDBOXED_LABS)=' .env.example
