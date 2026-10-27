# Detection rules

Rules are enabled and tuned in `config/rules.json`. A rule reports patterns in flow records; it cannot determine intent by itself. Thresholds that work for the bundled samples may be too high or too low for a real environment.

## Port scan

For each source/destination pair, NetSentry sorts the records by time and uses a sliding window to count distinct destination ports. An alert is raised when the number of unique ports reaches the configured threshold.

**Default:** 10 unique ports in 60 seconds. Sorting dominates the work, so the time complexity is `O(n log n)` and auxiliary space is `O(n)`.

## Connection burst

Records are grouped by source IP. A sliding time window tracks the largest number of flow records seen from that source. A busy client or load test can look like a burst.

**Default:** 30 records in 60 seconds. Time complexity is `O(n log n)`; auxiliary space is `O(n)`.

## Repeated failed connections

Only records with `connectionStatus` set to `FAILED` count toward this rule. They are grouped by source and destination, then counted inside a sliding window. `SUCCESS` and `UNKNOWN` records do not increase the count.

**Default:** 8 failures in 120 seconds. Time complexity is `O(n log n)`; auxiliary space is `O(n)`.

## Traffic spike

Records are grouped into epoch-aligned buckets. Each observed bucket is compared with the median count of the other observed, non-empty buckets. A candidate must meet both the absolute threshold and the configured baseline multiplier. Empty intervals between far-apart timestamps are not generated.

**Default:** at least 20 records and 2 times the baseline in 60-second buckets. With `n` records and `b` observed buckets, time complexity is `O(n + b log b)` and space complexity is `O(n + b)`.

## Host sweep

For each source IP, NetSentry tracks the distinct destination IPs contacted within a sliding window. This may point to host discovery, but inventory scanners and monitoring tools can produce the same pattern.

**Default:** 12 different destination hosts in 60 seconds. Time complexity is `O(n log n)`; auxiliary space is `O(n)`.

## Allowlist and deduplication

Source addresses listed in `allowlist` are excluded from detection. Deduplication uses the rule name, source IP, destination IP, and configured time bucket as its key. If several alerts share that key, the one with the highest observed metric is kept.

Severity is a configured label (`HIGH`, `MEDIUM`, or `LOW`), not a likelihood that an attack occurred. Check related firewall, endpoint, authentication, and application logs before responding to a finding.
