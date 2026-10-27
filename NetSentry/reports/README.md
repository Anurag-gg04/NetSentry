# Example reports

The files in this directory show the output formats produced by NetSentry:

- `port-scan-sample-report.json` is a full report for the synthetic `samples/port-scan.csv` dataset.
- `port-scan-sample-alerts.csv` contains the alert rows from that report.

These are examples, not live results. Run a fresh analysis to generate current timestamps and alert IDs:

```bash
java -jar target/netsentry.jar analyze --input samples/port-scan.csv --output reports/port-scan-report.json
java -jar target/netsentry.jar analyze --input samples/port-scan.csv --format csv --output reports/port-scan-alerts.csv
```
