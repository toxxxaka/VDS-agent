# Resource budget for optional collectors

| Component | Default | Bound | Release measurement required |
| --- | --- | --- | --- |
| Minute metric collector | enabled | one local sample/minute | CPU duration and SQLite growth |
| 5-minute/hourly rollups | enabled | two current buckets/sample | SQLite write latency |
| Flight Recorder | disabled | 512 KiB RAM, 5-minute window, 5-second cadence | CPU and RSS with feature enabled |
| Adaptive baseline | disabled | local SQLite reads only | query time on 30-day history |
| Notification outbox | disabled | 128 KiB/message, eight attempts | queue drain under network outage |

No optional feature becomes a release default until these measurements are
captured on a representative small VPS and documented in the release gate.
