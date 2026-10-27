# NetSentry

**A small, local tool for reviewing saved network-flow data and spotting suspicious patterns.**

Give NetSentry a CSV or JSON file of network flow records. It checks the data, runs a set of detection rules, and shows you the results in a browser dashboard or right in your terminal.

It's built with plain Java 17+ and the JDK's built-in HTTP server, with a dashboard in plain HTML, CSS, and JavaScript. There's no Spring Boot, database, Node.js, or separate frontend server to set up. Maven handles the build and tests.

> **Please read this first.** NetSentry is for defensive analysis of traffic you're allowed to review. It does **not** capture live packets, scan networks, or block anything, and it can't prove an attack happened. Treat every alert as a lead to investigate, not a verdict.

---

## Quick start

You need **Java 17+** (Java 21 works too) and **Maven 3.9+**. The first build needs internet access to download dependencies, unless they're already cached.

From the `NetSentry` project folder:

```bash
mvn clean test package
java -jar target/netsentry.jar web
```

Then open [http://localhost:8080](http://localhost:8080). Press `Ctrl+C` to stop the server.

That's it. The same commands work on Windows PowerShell, Linux, and macOS.

**A few handy variations:**

- **Different port:** `java -jar target/netsentry.jar web --port 8081`
- **Start scripts:** `scripts\start-windows.ps1` (Windows) or `bash scripts/start-unix.sh` (Linux/macOS)
- **No command at all:** `java -jar target/netsentry.jar` starts the dashboard on port 8080

Want to try it without your own data? Open the dashboard, go to **Traffic analysis**, and run one of the bundled samples.

> **Security note:** The server listens on `127.0.0.1` only and has no sign-in or user access control. Keep it as a local development or demo tool.

---

## What you get

- **Five detection rules:** port scans, connection bursts, repeated failed connections, traffic spikes, and host sweeps
- **Careful input checking:** CSV and JSON parsing, timestamp/IP/port validation, clear row-level error messages, and limits of 10 MiB per file and 500,000 records
- **A browser dashboard:** overview metrics, traffic trend, alert search and filters, host summaries, alert correlations, incident cases, rule settings, and report downloads
- **An incident desk:** turn an alert into a case, assign it to an analyst, add notes, and track it as *Open*, *Investigating*, *Resolved*, or *False Positive*
- **Saved run history:** keeps a summary of each completed analysis, without saving your original traffic data
- **A command-line interface:** analyze files, validate input, inspect rules, benchmark, evaluate detections against labelled hosts, and manage history
- **Reports and tests:** JSON and CSV output, plus JUnit 5 tests that use local synthetic data

---

## Using the command line

Run these from the project root after building the JAR.

**Analyze a file and print a JSON report:**

```bash
java -jar target/netsentry.jar analyze --input samples/port-scan.csv
```

**Save just the alerts as a CSV:**

```bash
java -jar target/netsentry.jar analyze --input samples/port-scan.csv --format csv --output reports/port-scan-alerts.csv
```

**Check a file without running detection** (exits with code `2` if any rows are rejected):

```bash
java -jar target/netsentry.jar validate --input samples/mixed.csv
```

**See the active rules or the version:**

```bash
java -jar target/netsentry.jar rules
java -jar target/netsentry.jar version
```

**Run the synthetic benchmark.** Results depend on your machine and JVM, so don't read them as a general performance claim:

```bash
java -jar target/netsentry.jar benchmark --sizes 10000,100000
```

**Compare alerts against labelled hosts:**

```bash
java -jar target/netsentry.jar evaluate --input samples/mixed.csv --labels samples/mixed-ground-truth.csv
```

**Manage saved history:**

```bash
java -jar target/netsentry.jar history list
java -jar target/netsentry.jar history show <analysis-id>
java -jar target/netsentry.jar history export <analysis-id> --output reports/history-entry.json
java -jar target/netsentry.jar history delete <analysis-id>
```

**Need a reminder of any command?**

```bash
java -jar target/netsentry.jar help
```

---

## Sample files

The `samples/` folder holds synthetic data only. None of it comes from live network captures, and the IP addresses are from documentation or private ranges.

| File | What it demonstrates |
|---|---|
| `normal.csv` | Ordinary traffic spread across several time buckets |
| `port-scan.csv` | One source contacting many ports on one destination |
| `connection-burst.csv` | A high number of flows from a single source |
| `failed-connections.csv` | Repeated records marked `FAILED` |
| `traffic-spike.csv` | One busy time bucket among quieter ones |
| `host-sweep.csv` | One source contacting many different destination hosts |
| `mixed.csv` | Normal and suspicious-looking patterns together |
| `malformed.csv` | Valid rows mixed with invalid ones |
| `normal.json` | An example of JSON input |
| `mixed-ground-truth.csv` | Source-host labels for the `evaluate` command |

The dashboard and the CLI share the same parsing and detection engine, so you'll get the same results from either.

---

## Preparing your own data

### CSV

Your file needs a header row. Column names are case-insensitive.

- **Required:** `timestamp`, `srcIp`, `dstIp`, `dstPort`
- **Optional:** `srcPort`, `protocol`, `packets`, `bytes`, `connectionStatus`

If you leave out packet or byte counts, they default to zero. A missing protocol or status becomes `UNKNOWN`.

```csv
timestamp,srcIp,dstIp,srcPort,dstPort,protocol,packets,bytes,connectionStatus
2026-10-27T10:00:00Z,10.0.0.1,192.0.2.10,51515,443,TCP,4,1800,SUCCESS
```

### JSON

Use either a plain array of records or an object with a `records` array:

```json
{
  "records": [
    {
      "timestamp": "2026-10-27T10:00:00Z",
      "srcIp": "10.0.0.1",
      "dstIp": "192.0.2.10",
      "srcPort": 51515,
      "dstPort": 443,
      "protocol": "TCP",
      "packets": 4,
      "bytes": 1800,
      "connectionStatus": "SUCCESS"
    }
  ]
}
```

### The rules for each field

- **Timestamps** must be ISO-8601 and include a timezone
- **Ports** must be whole numbers from `0` to `65535`
- **Packet and byte counts** must be non-negative whole numbers
- **Protocols:** `TCP`, `UDP`, `ICMP`, or `UNKNOWN`
- **Connection statuses:** `SUCCESS`, `FAILED`, or `UNKNOWN`

### What happens when something is wrong

If a single record is invalid, NetSentry rejects that row and keeps going where it can. Two problems are bigger and stop parsing entirely: a missing required CSV column, or an invalid JSON document.

---

## How detection works

Every threshold and timing lives in `config/rules.json`. The dashboard shows these settings but can't edit them. To change something, edit the file and restart NetSentry.

| Rule | What it looks for | Default threshold |
|---|---|---:|
| **Port scan** | Many distinct destination ports contacted by one source, against one destination, within a time window | 10 ports in 60 seconds |
| **Connection burst** | Many flow records from one source within a time window | 30 records in 60 seconds |
| **Repeated failed connections** | `FAILED` records between a source and destination | 8 failures in 120 seconds |
| **Traffic spike** | A time bucket's flow count compared with the median of the other observed buckets | 20 records and 2× baseline (60-second buckets) |
| **Host sweep** | Many distinct destination IPs contacted by one source within a time window | 12 hosts in 60 seconds |

A few things worth knowing:

- Source IPs listed in `allowlist` are skipped by all rules.
- Duplicate alerts (same rule, endpoints, and time bucket) are collapsed into one, keeping the alert with the highest observed metric.
- Severity (`HIGH`, `MEDIUM`, or `LOW`) is a label you configure. It is **not** a probability score.
- The default thresholds are starting points tuned for the included synthetic data, not universal settings.

### Why an alert isn't proof of anything

Plenty of harmless things look suspicious in flow data. A scan may be approved inventory work. A burst may be a load test. Failed connections may come from a service outage. A spike may follow a normal deployment. Before deciding what an alert means, check your firewall, endpoint, authentication, and application logs.

---

## Dashboard tour

| Page | What you can do there |
|---|---|
| **Overview** | See record counts, alert totals, the traffic trend, and recent alerts |
| **Traffic analysis** | Upload a CSV/JSON file or run a bundled sample |
| **Alerts explorer** | Search by IP, filter by severity or rule, and read the evidence and recommended checks |
| **Host intelligence** | Summarize the source and destination hosts in the current alert list (this is not a full network inventory) |
| **Alert correlations** | See alerts grouped by source when at least two different rules fire within a rolling 10-minute window. These are leads, not confirmed attacks |
| **Incident desk** | Create, assign, and update cases built from alerts |
| **Detection rules** | Review thresholds, severity settings, and the source allowlist |
| **Reports** | Download the latest JSON report or the alert-only CSV |

---

## REST API

The API runs in the same Java process as the dashboard, at `http://localhost:8080` by default.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check and version |
| `GET` | `/api/stats` | Latest analysis metrics and traffic trend |
| `GET` | `/api/alerts` | Alerts, with optional `severity`, `rule`, and `ip` filters |
| `GET` | `/api/rules` | Current rule configuration |
| `GET` | `/api/samples` | Names and descriptions of bundled samples |
| `POST` | `/api/analyze?filename=flows.csv` | Analyze CSV/JSON bytes sent in the request body |
| `POST` | `/api/analyze/sample` | Analyze a bundled sample, e.g. `{"sample":"port-scan.csv"}` |
| `GET` | `/api/correlations` | Correlations for the latest analysis |
| `GET` | `/api/reports/latest` | Latest JSON report |
| `GET` | `/api/reports/latest.csv` | Latest alert-only CSV |
| `GET` | `/api/history` | Saved analysis summaries |
| `GET` | `/api/history/{id}` | One saved analysis summary |
| `DELETE` | `/api/history/{id}` | Delete a saved summary |
| `GET` | `/api/incidents` | Saved incident cases |
| `POST` | `/api/incidents` | Create a case from an alert in the latest analysis |
| `PUT` | `/api/incidents/{id}` | Update status, assignee, or notes |
| `DELETE` | `/api/incidents/{id}` | Delete a case |

Every successful API analysis also saves a summary to your local history. The latest full report stays in memory only, so it disappears when the server stops. For request and response details, see the [API reference](docs/api.md).

---

## Where your data is saved

By default, NetSentry stores saved data **outside** the project folder:

- **Analysis summaries:** `~/.netsentry/history`
- **Incident cases:** `~/.netsentry/incidents`

Only summaries and case metadata are saved. Your uploaded traffic files and original flow records are never copied there.

To store data somewhere else, set the `netsentry.dataDir` JVM property:

```bash
java -Dnetsentry.dataDir=/path/to/netsentry-data -jar target/netsentry.jar web
```

---

## Checking detection quality

The `evaluate` command compares NetSentry's predictions with your own labels. Provide a CSV with the columns `srcIp,label`, where each label is either `SUSPICIOUS` or `NORMAL`.

A host counts as "predicted suspicious" if it's the source of at least one alert. NetSentry then reports precision, recall, F1, and accuracy.

Keep in mind that these numbers apply only to the labelled hosts, the input file you chose, and your current rule settings. They are not a universal accuracy score.

---

## Building and testing

Run the unit tests:

```bash
mvn test
```

Build the executable JAR:

```bash
mvn clean test package
```

The tests cover parsing and validation, detection thresholds and time windows, configuration checks, correlation behavior, history, incident cases, report output, and API responses. For the checks completed on this copy of the project, see [BUILD_VERIFICATION.md](BUILD_VERIFICATION.md).

---

## Project layout

```text
NetSentry/
├── config/                 # Runtime rule configuration
├── docs/                   # API, architecture, and detection notes
├── reports/                # Example reports and output location
├── samples/                # Sample CSV/JSON files for the CLI
├── scripts/                # Start scripts for Windows and Unix-like systems
├── src/main/java/          # CLI, API, parser, rules, reports, and services
├── src/main/resources/     # Packaged configuration, samples, and dashboard
├── src/test/java/          # JUnit tests
└── pom.xml                 # Maven build
```

---

## Troubleshooting

| Problem | What to try |
|---|---|
| `mvn` isn't recognized | Install Maven 3.9+ and make sure it's on your `PATH` |
| Port 8080 is already in use | Start with `web --port 8081` and open `http://localhost:8081` |
| A sample won't load | Rebuild with `mvn clean test package` and confirm `src/main/resources/samples/` exists |
| Some rows were rejected | Check the validation messages for missing fields, invalid IPs or ports, timestamps without a timezone, and unsupported protocol or status values |
| No alerts appear | Look at `config/rules.json`. The default thresholds suit the synthetic samples and may be too high for your data |
| The report vanished after a restart | The latest API report lives in memory only. Use the CLI `--output` option to save a report to disk |