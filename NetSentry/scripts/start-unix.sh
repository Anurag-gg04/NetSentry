#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v java >/dev/null 2>&1 || { echo 'Java 17+ was not found on PATH.' >&2; exit 1; }
command -v mvn >/dev/null 2>&1 || { echo 'Maven 3.9+ was not found on PATH.' >&2; exit 1; }
if [[ ! -f target/netsentry.jar ]]; then mvn clean package; fi
exec java -jar target/netsentry.jar web
