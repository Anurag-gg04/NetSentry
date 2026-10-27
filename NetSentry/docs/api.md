# API reference

The API is served by the same process as the dashboard. The default base URL is `http://localhost:8080`. Responses are JSON unless an endpoint returns a CSV download or an empty response. Errors use an object with `status`, `code`, and `message` fields.

## Analysis and reports

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/api/health` | Returns the service status, version, and current timestamp. |
| `GET` | `/api/stats` | Returns metrics and the traffic trend for the latest analysis. Before the first analysis, returns `status: "empty"`. |
| `GET` | `/api/alerts` | Returns latest alerts. Optional query parameters: `severity`, `rule` (substring), and `ip` (substring). |
| `GET` | `/api/rules` | Returns the active rule settings and allowlist. |
| `GET` | `/api/samples` | Lists the bundled sample files and their descriptions. |
| `POST` | `/api/analyze?filename=flows.csv` | Reads CSV or JSON from the raw request body. The filename extension selects the parser. |
| `POST` | `/api/analyze/sample` | Accepts JSON such as `{"sample":"port-scan.csv"}`. Only names returned by `/api/samples` are accepted. |
| `GET` | `/api/reports/latest` | Returns the latest full report, or `404` before an analysis. |
| `GET` | `/api/reports/latest.csv` | Downloads the alert rows as CSV, or `404` before an analysis. |
| `GET` | `/api/correlations` | Returns correlation groups calculated from the latest alerts. |

An upload is limited to 10 MiB and 500,000 flow records. A valid request can still contain rejected rows; those rows are listed in the analysis result.

## Analysis history

- `GET /api/history` lists saved summaries, newest first.
- `GET /api/history/{id}` reads one summary.
- `DELETE /api/history/{id}` deletes one summary.

Completed analyses are saved automatically as individual JSON files in `~/.netsentry/history` by default. Set `-Dnetsentry.dataDir=/path/to/data` to change the data root. A history record contains run metadata, counts, duration, and severity totals—not the original traffic records.

## Incident cases

- `GET /api/incidents` lists saved cases.
- `POST /api/incidents` creates a case from an alert in the latest analysis. Example body: `{"alertId":"<alert-id>","title":"Optional title"}`.
- `PUT /api/incidents/{id}` updates fields. Example body: `{"status":"INVESTIGATING","assignedTo":"Analyst A","notes":"Reviewed the firewall logs."}`.
- `DELETE /api/incidents/{id}` removes a case.

The allowed statuses are `OPEN`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`. Case JSON files are stored in `~/.netsentry/incidents` by default, or in the `incidents` folder under the configured data root.

## Alert correlations

Correlation groups are recalculated from alerts in the latest analysis. NetSentry groups by source IP and a rolling 10-minute window, and only returns a group when at least two different detection rules are represented. Results include the related rule names, alert IDs, severity, first/last timestamps, and a suggested investigation step. A correlation is not a separate saved incident and is not proof of malicious activity.

## Detection evaluation

Run the CLI command:

```bash
java -jar target/netsentry.jar evaluate --input samples/mixed.csv --labels samples/mixed-ground-truth.csv
```

The label file must be a CSV with `srcIp,label` columns. Labels are `SUSPICIOUS` or `NORMAL`. A source host is predicted suspicious if any alert names it as the source. Unlabelled hosts are not included in the metric calculations.

## Local-only design

The server binds to `127.0.0.1` by default and does not require an account. It accepts bundled sample names rather than arbitrary filesystem paths. The latest full report is stored in process memory and is cleared when the server stops. This is a single-user demo API, not a hardened multi-user service.
