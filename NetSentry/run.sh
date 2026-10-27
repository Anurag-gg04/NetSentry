#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -f target/netsentry.jar ]]; then mvn clean package; fi
exec java -jar target/netsentry.jar web
