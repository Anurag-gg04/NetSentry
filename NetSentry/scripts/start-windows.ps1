$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command java -ErrorAction SilentlyContinue)) { throw 'Java 17+ was not found on PATH.' }
if (-not (Get-Command mvn -ErrorAction SilentlyContinue)) { throw 'Maven 3.9+ was not found on PATH. Build with Maven, then rerun this script.' }
if (-not (Test-Path 'target/netsentry.jar')) { mvn clean package }
java -jar target/netsentry.jar web
