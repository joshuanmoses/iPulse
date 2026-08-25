# iPulse Event Catalog

This file is generated from the event catalog in `internal/events/catalog_defs.go`.
Regenerate with `ipulse events catalog --markdown > docs/event-catalog.md`.

Every iPulse event has a stable numeric ID rendered as `IPULSE-<id>` and a stable
machine name. Once published, an ID never changes meaning.

## Severity levels

| Level | Log label | Syslog | Meaning |
|---|---|---|---|
| DEBUG | `DEBUG` | 7 | Routine measurement detail; off by default. |
| INFO | `INFO` | 6 | Normal significant activity, such as a completed speed test. |
| NOTICE | `NOTICE` | 5 | A noteworthy state change that is not a fault. |
| WARNING | `WARN` | 4 | Degradation or a suspicious observation worth review. |
| ERROR | `ERROR` | 3 | A real failure: outage, confirmed loss of a layer. |
| CRITICAL | `CRIT` | 2 | Local failure that stops monitoring, or a recovered panic. |

## Reserved ID ranges

| Range | Category |
|---|---|
| 1000-1999 | CONNECTIVITY |
| 2000-2999 | PERFORMANCE |
| 3000-3999 | AVAILABILITY |
| 4000-4999 | TRAFFIC |
| 5000-5999 | SECURITY |
| 6000-6999 | DNS_ROUTING |
| 7000-7999 | INTERFACE |
| 8000-8999 | SERVICE |
| 9000-9999 | INTERNAL |

## Events

### CONNECTIVITY (1000-1999)

#### IPULSE-1001 SPEED_TEST_STARTED

- **Severity:** DEBUG
- **Meaning:** A speed test has begun.
- **Trigger:** Scheduled full or lightweight speed test, or a manual test request.
- **Fields:** `Mode`, `Provider`, `TestServer`
- **Operator action:** None. Informational.

#### IPULSE-1002 SPEED_TEST_COMPLETED

- **Severity:** INFO
- **Meaning:** A speed test finished successfully.
- **Trigger:** Completion of a scheduled or manual speed test.
- **Fields:** `Download`, `Upload`, `Latency`, `Jitter`, `PacketLoss`, `Status`, `TestServer`, `Duration`, `Mode`, `BytesDown`, `BytesUp`, `Streams`
- **Operator action:** None. This is the primary performance record.

#### IPULSE-1003 SPEED_TEST_FAILED

- **Severity:** WARNING
- **Meaning:** A speed test could not be completed.
- **Trigger:** All configured endpoints failed, or the test was aborted by loss of connectivity.
- **Fields:** `Mode`, `Provider`, `TestServer`, `Error`, `Attempts`
- **Operator action:** Check Internet connectivity and the configured speed_test endpoints.

#### IPULSE-1004 THROUGHPUT_SAMPLE

- **Severity:** DEBUG
- **Meaning:** A lightweight throughput probe completed.
- **Trigger:** The lightweight throughput interval elapsed.
- **Fields:** `Download`, `Latency`, `Bytes`, `Duration`, `TestServer`
- **Operator action:** None. Feeds baselines between full tests.

#### IPULSE-1005 CONNECTIVITY_CHECK_OK

- **Severity:** DEBUG
- **Meaning:** A periodic health check succeeded.
- **Trigger:** The basic health interval elapsed and at least the required number of targets responded.
- **Fields:** `Targets`, `Succeeded`, `RTT`, `Method`
- **Operator action:** None.

#### IPULSE-1006 CONNECTIVITY_CHECK_FAILED

- **Severity:** WARNING
- **Meaning:** A periodic health check failed; diagnostics will run.
- **Trigger:** Fewer than the required number of health targets responded.
- **Fields:** `Targets`, `Succeeded`, `Failures`, `Method`
- **Operator action:** None required; iPulse escalates to layered diagnostics automatically.

#### IPULSE-1007 INTERNET_CONNECTIVITY_RESTORED

- **Severity:** NOTICE
- **Meaning:** Internet connectivity returned after a failure.
- **Trigger:** A health check succeeded while an outage was open.
- **Fields:** `OutageDuration`, `PreviousCause`, `Targets`
- **Operator action:** Review the closed outage record for the probable cause.

#### IPULSE-1008 HEALTH_SCORE_UPDATED

- **Severity:** DEBUG
- **Meaning:** The Internet health score was recomputed.
- **Trigger:** The health score interval elapsed.
- **Fields:** `Score`, `Availability`, `Download`, `Upload`, `Latency`, `Jitter`, `PacketLoss`, `DNS`
- **Operator action:** None.

#### IPULSE-1009 HEALTH_SCORE_DEGRADED

- **Severity:** WARNING
- **Meaning:** The Internet health score dropped below the configured threshold.
- **Trigger:** Score fell under health.warn_below for the configured persistence.
- **Fields:** `Score`, `Threshold`, `WorstComponent`, `ComponentScores`
- **Operator action:** Inspect the named worst component on the dashboard.

#### IPULSE-1010 SPEED_TEST_ENDPOINT_UNAVAILABLE

- **Severity:** NOTICE
- **Meaning:** A configured speed-test endpoint could not be used.
- **Trigger:** Endpoint selection failed for one endpoint while others remain usable.
- **Fields:** `Endpoint`, `Error`
- **Operator action:** Remove or replace the endpoint if the failure persists.

#### IPULSE-1011 SPEED_TEST_SKIPPED

- **Severity:** NOTICE
- **Meaning:** A scheduled speed test was skipped.
- **Trigger:** The link was already saturated by other traffic, or connectivity was down, or a test was already running.
- **Fields:** `Reason`, `Mode`, `ObservedMbps`
- **Operator action:** None. Skipping avoids both wasted bandwidth and misleading results.

### PERFORMANCE (2000-2999)

#### IPULSE-2001 DOWNLOAD_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Measured download throughput is substantially below its baseline.
- **Trigger:** Download fell more than alerts.download_degradation_percent below the time-aware baseline, for the required persistence.
- **Fields:** `BaselineDownload`, `CurrentDownload`, `Deviation`, `Bucket`, `Observations`, `ProbableCause`
- **Operator action:** Compare with upload utilisation and latency; if the link is idle, contact the ISP.

#### IPULSE-2002 UPLOAD_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Measured upload throughput is substantially below its baseline.
- **Trigger:** Upload fell more than alerts.upload_degradation_percent below the time-aware baseline.
- **Fields:** `BaselineUpload`, `CurrentUpload`, `Deviation`, `Bucket`, `Observations`, `ProbableCause`
- **Operator action:** Check for local upload saturation before escalating to the ISP.

#### IPULSE-2003 DOWNLOAD_BELOW_ISP_EXPECTATION

- **Severity:** WARNING
- **Meaning:** Download throughput is below the configured advertised ISP speed.
- **Trigger:** Download < expected_download_mbps by more than alerts.isp_shortfall_percent.
- **Fields:** `ExpectedDownload`, `MeasuredDownload`, `Shortfall`, `TestServer`, `SamplesBelow`, `SampleWindow`
- **Operator action:** Collect several samples, then raise with the ISP citing the stored history.

#### IPULSE-2004 UPLOAD_BELOW_ISP_EXPECTATION

- **Severity:** WARNING
- **Meaning:** Upload throughput is below the configured advertised ISP speed.
- **Trigger:** Upload < expected_upload_mbps by more than alerts.isp_shortfall_percent.
- **Fields:** `ExpectedUpload`, `MeasuredUpload`, `Shortfall`, `TestServer`, `SamplesBelow`, `SampleWindow`
- **Operator action:** As above.

#### IPULSE-2005 PERFORMANCE_RECOVERED

- **Severity:** NOTICE
- **Meaning:** A performance degradation cleared.
- **Trigger:** The offending metric returned within its recovery band for the required persistence.
- **Fields:** `Metric`, `Current`, `Baseline`, `DegradedFor`, `OriginalEvent`
- **Operator action:** None.

#### IPULSE-2006 THROUGHPUT_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Lightweight throughput probes are consistently below baseline.
- **Trigger:** Consecutive lightweight probes below the baseline band between full tests.
- **Fields:** `BaselineDownload`, `CurrentDownload`, `Deviation`, `Consecutive`
- **Operator action:** Wait for the next full speed test to confirm.

#### IPULSE-2101 LATENCY_SPIKE

- **Severity:** NOTICE
- **Meaning:** A short-lived latency increase was observed.
- **Trigger:** A single latency sample exceeded the baseline deviation threshold.
- **Fields:** `BaselineLatency`, `CurrentLatency`, `Deviation`, `Target`
- **Operator action:** None unless it becomes sustained.

#### IPULSE-2102 SUSTAINED_HIGH_LATENCY

- **Severity:** WARNING
- **Meaning:** Latency has stayed above baseline for an extended period.
- **Trigger:** Latency above threshold for alerts.sustained_latency_seconds.
- **Fields:** `BaselineLatency`, `CurrentLatency`, `Deviation`, `Duration`, `PacketLoss`, `ProbableCause`
- **Operator action:** Check local saturation, Wi-Fi quality, then the ISP.

#### IPULSE-2103 JITTER_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Latency variation increased significantly.
- **Trigger:** Jitter exceeded its baseline by alerts.jitter_degradation_percent.
- **Fields:** `BaselineJitter`, `CurrentJitter`, `Deviation`, `PacketLoss`, `Target`
- **Operator action:** Jitter harms real-time traffic; check Wi-Fi and local congestion.

#### IPULSE-2104 LATENCY_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Latency degraded relative to the established baseline.
- **Trigger:** Latency exceeded baseline by alerts.latency_degradation_percent with the required persistence.
- **Fields:** `BaselineLatency`, `CurrentLatency`, `Deviation`, `PacketLoss`, `UploadUtilization`, `DownloadUtilization`, `ProbableCause`
- **Operator action:** Use the ProbableCause field; saturation is the most common cause.

#### IPULSE-2105 PACKET_LOSS_DETECTED

- **Severity:** WARNING
- **Meaning:** Packet loss exceeded the configured threshold.
- **Trigger:** Measured loss above alerts.packet_loss_percent over the probe window.
- **Fields:** `PacketLoss`, `BaselineLoss`, `Sent`, `Received`, `Target`, `Latency`
- **Operator action:** Sustained loss on the first external hop points at the access link.

#### IPULSE-2106 PACKET_LOSS_CLEARED

- **Severity:** NOTICE
- **Meaning:** Packet loss returned to normal.
- **Trigger:** Loss below the recovery threshold for the required persistence.
- **Fields:** `PacketLoss`, `Duration`, `Target`
- **Operator action:** None.

#### IPULSE-2107 LOCAL_BANDWIDTH_SATURATION

- **Severity:** WARNING
- **Meaning:** Local link saturation is degrading Internet quality.
- **Trigger:** Correlation rule: bandwidth spike plus latency rise plus loss rise or throughput drop.
- **Fields:** `Direction`, `Utilization`, `BaselineLatency`, `CurrentLatency`, `PacketLoss`, `TopProcess`, `Evidence`, `ProbableCause`
- **Operator action:** Identify the named process or device consuming the link.

#### IPULSE-2108 DNS_RESPONSE_DEGRADATION

- **Severity:** WARNING
- **Meaning:** DNS resolution is measurably slower than baseline.
- **Trigger:** DNS response time above baseline by the configured percentage.
- **Fields:** `BaselineDNS`, `CurrentDNS`, `Deviation`, `Server`, `Name`
- **Operator action:** Try an alternate resolver; slow DNS is often mistaken for slow Internet.

#### IPULSE-2109 ROUTE_LATENCY_DEGRADATION

- **Severity:** NOTICE
- **Meaning:** Per-hop latency on a monitored path increased.
- **Trigger:** Hop RTT increase beyond threshold on a stable path.
- **Fields:** `Destination`, `Hop`, `HopAddress`, `BaselineRTT`, `CurrentRTT`, `Deviation`
- **Operator action:** Useful evidence for an ISP ticket; the first degraded hop localises the problem.

#### IPULSE-2110 UPSTREAM_PERFORMANCE_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Throughput is degraded and the local network is not the cause.
- **Trigger:** Correlation rule: throughput below baseline or plan, with no local saturation and no wireless degradation.
- **Fields:** `CurrentDownload`, `CurrentUpload`, `Deviation`, `Evidence`, `ProbableCause`
- **Operator action:** This is the evidence an ISP ticket needs: the local link was idle and healthy while throughput was low.

### AVAILABILITY (3000-3999)

#### IPULSE-3001 INTERNET_CONNECTIVITY_LOST

- **Severity:** ERROR
- **Meaning:** Internet connectivity is unavailable.
- **Trigger:** Health checks failed and layered diagnostics confirmed loss of Internet reachability.
- **Fields:** `GatewayReachable`, `DNSReachable`, `ExternalIPReachable`, `HTTPSReachable`, `InterfaceUp`, `ProbableCause`
- **Operator action:** Follow the ProbableCause classification.

#### IPULSE-3002 OUTAGE_STARTED

- **Severity:** ERROR
- **Meaning:** An outage record was opened.
- **Trigger:** Connectivity loss confirmed by diagnostics.
- **Fields:** `Classification`, `ProbableCause`, `Evidence`, `Interface`, `Gateway`
- **Operator action:** See the outage view on the dashboard.

#### IPULSE-3003 OUTAGE_ENDED

- **Severity:** NOTICE
- **Meaning:** An outage record was closed.
- **Trigger:** Connectivity was restored.
- **Fields:** `Classification`, `ProbableCause`, `Duration`, `Start`, `End`
- **Operator action:** None.

#### IPULSE-3004 ISP_OUTAGE

- **Severity:** ERROR
- **Meaning:** The failure is upstream of this network.
- **Trigger:** Gateway reachable and DNS working, but multiple independent Internet endpoints in different networks are unreachable.
- **Fields:** `GatewayReachable`, `DNSReachable`, `EndpointsTested`, `EndpointsReachable`, `Evidence`
- **Operator action:** Report to the ISP; local remediation will not help.

#### IPULSE-3005 DNS_FAILURE

- **Severity:** ERROR
- **Meaning:** Name resolution is failing while the network path works.
- **Trigger:** Gateway reachable and external IP literals reachable, but DNS queries fail.
- **Fields:** `ServersTested`, `ServersFailed`, `NamesTested`, `ExternalIPReachable`, `Evidence`
- **Operator action:** Switch resolvers or restart the local resolver service.

#### IPULSE-3006 GATEWAY_FAILURE

- **Severity:** ERROR
- **Meaning:** The default gateway is unreachable.
- **Trigger:** Interface is up with a valid address, but the gateway does not respond.
- **Fields:** `Gateway`, `Interface`, `InterfaceUp`, `LocalIP`, `Method`, `Evidence`
- **Operator action:** Check the router/AP and the local link.

#### IPULSE-3007 LOCAL_INTERFACE_FAILURE

- **Severity:** CRITICAL
- **Meaning:** No usable network interface.
- **Trigger:** No interface is up with a routable address, or the default route is missing.
- **Fields:** `Interfaces`, `InterfaceUp`, `LocalIP`, `DefaultRoute`, `Evidence`
- **Operator action:** Check cabling, Wi-Fi association, driver and DHCP.

#### IPULSE-3008 PARTIAL_CONNECTIVITY

- **Severity:** WARNING
- **Meaning:** Some Internet destinations are reachable and others are not.
- **Trigger:** Mixed reachability results across independent endpoints.
- **Fields:** `EndpointsTested`, `EndpointsReachable`, `Unreachable`, `Evidence`, `ProbableCause`
- **Operator action:** Often upstream routing or per-protocol filtering; check the unreachable list.

#### IPULSE-3009 ROUTING_FAILURE

- **Severity:** ERROR
- **Meaning:** Traffic is not being routed off the local network.
- **Trigger:** Gateway reachable but no external destination reachable at IP level, or the default route is invalid.
- **Fields:** `DefaultRoute`, `Gateway`, `Interface`, `Evidence`, `VPNActive`
- **Operator action:** Inspect the routing table and any VPN client.

#### IPULSE-3010 WIFI_DEGRADATION

- **Severity:** WARNING
- **Meaning:** Wi-Fi quality is degrading connectivity.
- **Trigger:** Weak RSSI or reduced link rate correlated with loss or latency on the wireless interface.
- **Fields:** `SSID`, `Signal`, `SignalPercent`, `LinkSpeed`, `Frequency`, `Channel`, `PacketLoss`, `GatewayRTT`, `ProbableCause`
- **Operator action:** Move closer to the AP, change channel, or use a wired link before blaming the ISP.

#### IPULSE-3011 DIAGNOSTICS_COMPLETED

- **Severity:** INFO
- **Meaning:** A diagnostic ladder run finished.
- **Trigger:** Automatic escalation after a failed health check, or a manual diagnostics request.
- **Fields:** `Classification`, `ProbableCause`, `Duration`, `Trigger`, `Evidence`
- **Operator action:** None.

#### IPULSE-3012 AVAILABILITY_REPORT

- **Severity:** INFO
- **Meaning:** Periodic availability summary.
- **Trigger:** The availability report interval elapsed.
- **Fields:** `Window`, `AvailabilityPercent`, `Outages`, `TotalDowntime`, `LongestOutage`, `MTBF`
- **Operator action:** None.

### TRAFFIC (4000-4999)

#### IPULSE-4001 BANDWIDTH_SPIKE_DOWNLOAD

- **Severity:** NOTICE
- **Meaning:** Inbound throughput spiked well above its time-aware baseline.
- **Trigger:** Robust z-score of rx rate exceeded the configured threshold, excluding iPulse's own tests.
- **Fields:** `Interface`, `CurrentRate`, `BaselineRate`, `Deviation`, `ZScore`, `Bucket`, `TopProcess`
- **Operator action:** Correlate with the connections view to identify the source.

#### IPULSE-4002 BANDWIDTH_SPIKE_UPLOAD

- **Severity:** WARNING
- **Meaning:** Outbound throughput spiked well above its time-aware baseline.
- **Trigger:** Robust z-score of tx rate exceeded the configured threshold, excluding iPulse's own tests.
- **Fields:** `Interface`, `CurrentRate`, `BaselineRate`, `Deviation`, `ZScore`, `Bucket`, `TopProcess`, `TopDestination`
- **Operator action:** Outbound spikes deserve attention: identify the process and destination.

#### IPULSE-4003 SUSTAINED_BANDWIDTH_USAGE

- **Severity:** NOTICE
- **Meaning:** Elevated throughput persisted for an extended period.
- **Trigger:** Rate above the baseline band continuously for alerts.sustained_bandwidth_seconds.
- **Fields:** `Interface`, `Direction`, `AverageRate`, `PeakRate`, `Duration`, `BytesTransferred`, `TopProcess`
- **Operator action:** Expected for large downloads/backups; investigate if unexplained.

#### IPULSE-4004 UNUSUAL_OUTBOUND_TRAFFIC

- **Severity:** WARNING
- **Meaning:** Outbound traffic volume is well above the historical pattern for this time.
- **Trigger:** Upload volume over the window exceeds the time-bucket baseline by the configured factor.
- **Fields:** `Interface`, `WindowBytes`, `BaselineBytes`, `Deviation`, `Bucket`, `TopProcess`, `TopDestination`, `Confidence`
- **Operator action:** Metadata only. Verify the responsible process is expected to upload.

#### IPULSE-4005 SUSTAINED_UPLOAD

- **Severity:** WARNING
- **Meaning:** A sustained outbound transfer is in progress.
- **Trigger:** Upload rate above the configured floor continuously for alerts.sustained_upload_seconds.
- **Fields:** `Interface`, `AverageRate`, `Duration`, `BytesSent`, `TopProcess`, `TopDestination`, `Confidence`
- **Operator action:** Confirm the transfer is intended (backup, sync, upload).

#### IPULSE-4006 LARGE_OUTBOUND_TRANSFER

- **Severity:** WARNING
- **Meaning:** A single destination received an unusually large outbound volume.
- **Trigger:** Bytes sent to one destination exceeded alerts.large_transfer_mb within the window.
- **Fields:** `Destination`, `BytesSent`, `Duration`, `Process`, `RemotePort`, `Protocol`, `FirstSeen`, `Confidence`
- **Operator action:** Verify the destination and the process. Metadata only; no payload is inspected.

#### IPULSE-4007 NEW_HIGH_VOLUME_DESTINATION

- **Severity:** WARNING
- **Meaning:** A destination first seen recently is receiving significant outbound traffic.
- **Trigger:** Destination newer than destinations.new_destination_window with bytes sent above the high-volume floor.
- **Fields:** `Destination`, `FirstSeen`, `BytesSent`, `BytesReceived`, `Process`, `RemotePort`, `ASN`, `Country`, `Confidence`
- **Operator action:** The combination of new and high-volume is the interesting part; verify it.

#### IPULSE-4008 UNUSUAL_OVERNIGHT_ACTIVITY

- **Severity:** NOTICE
- **Meaning:** Significant activity during a normally quiet period.
- **Trigger:** Traffic during the configured quiet hours exceeded that window's baseline.
- **Fields:** `Window`, `Direction`, `Bytes`, `BaselineBytes`, `Deviation`, `TopProcess`, `TopDestination`
- **Operator action:** Often scheduled updates or backups; confirm once and it becomes the baseline.

#### IPULSE-4009 PERIODIC_SPIKE_PATTERN

- **Severity:** INFO
- **Meaning:** Repeating traffic spikes with a regular period were detected.
- **Trigger:** Autocorrelation of spike timestamps found a dominant period with enough repetitions.
- **Fields:** `Period`, `Occurrences`, `Direction`, `AverageSpike`, `TopProcess`
- **Operator action:** Usually a scheduled task; recorded for context, not as a problem.

#### IPULSE-4010 TRAFFIC_BASELINE_ESTABLISHED

- **Severity:** INFO
- **Meaning:** A traffic baseline reached the minimum observation count and is now active.
- **Trigger:** Enough samples accumulated for a metric/time bucket.
- **Fields:** `Metric`, `Bucket`, `Observations`, `Mean`, `Median`, `StdDev`
- **Operator action:** None. Detection for that bucket starts now.

#### IPULSE-4011 CONNECTION_COUNT_ANOMALY

- **Severity:** NOTICE
- **Meaning:** The number of active connections deviates strongly from baseline.
- **Trigger:** Robust z-score of the active connection count exceeded the threshold.
- **Fields:** `Current`, `BaselineMedian`, `ZScore`, `Bucket`, `TopProcess`
- **Operator action:** Cross-check the connections and destinations views.

#### IPULSE-4012 APPLICATION_UPLOAD_ANOMALY

- **Severity:** WARNING
- **Meaning:** One application's upload volume is far above its own history.
- **Trigger:** Per-process upload volume exceeded that process's baseline by the configured factor.
- **Fields:** `Process`, `PID`, `ExecutablePath`, `User`, `BytesSent`, `BaselineBytes`, `Deviation`, `TopDestination`, `Confidence`
- **Operator action:** Verify the application is expected to upload this much.

### SECURITY (5000-5999)

#### IPULSE-5001 NEW_EXTERNAL_DESTINATION

- **Severity:** INFO
- **Meaning:** A previously unseen external destination was contacted.
- **Trigger:** A remote address/port pair with no prior history was observed.
- **Fields:** `Destination`, `RemotePort`, `Protocol`, `Process`, `PID`, `ReverseDNS`, `ASN`, `Organization`, `Country`
- **Operator action:** Informational. Most new destinations are benign.

#### IPULSE-5002 RARE_DESTINATION_CONTACT

- **Severity:** NOTICE
- **Meaning:** A destination contacted very rarely in the past was contacted again.
- **Trigger:** Destination frequency is below the rarity percentile over the history window.
- **Fields:** `Destination`, `Frequency`, `FirstSeen`, `LastSeen`, `Process`, `ASN`, `Country`
- **Operator action:** Context only; combine with volume and threat-intel signals.

#### IPULSE-5003 UNEXPECTED_DESTINATION_PORT

- **Severity:** NOTICE
- **Meaning:** An outbound connection used a port outside the normal profile.
- **Trigger:** Remote port not in the learned port profile and not in the configured expected set.
- **Fields:** `Destination`, `RemotePort`, `Protocol`, `Process`, `PID`, `PortProfile`
- **Operator action:** Verify the application legitimately uses this port.

#### IPULSE-5004 RAPID_DESTINATION_FANOUT

- **Severity:** WARNING
- **Meaning:** Many distinct external destinations were contacted in a short window.
- **Trigger:** Distinct remote addresses within the fanout window exceeded the threshold.
- **Fields:** `DistinctDestinations`, `Window`, `Process`, `PID`, `TopPorts`, `Confidence`
- **Operator action:** Possible scanning, peer-to-peer, or a crawler. Verify the process.

#### IPULSE-5101 KNOWN_MALICIOUS_DESTINATION

- **Severity:** ERROR
- **Meaning:** A connection matched a high-confidence indicator in local threat intelligence.
- **Trigger:** Remote IP/CIDR matched an imported indicator whose confidence is High.
- **Fields:** `RemoteIP`, `RemotePort`, `Protocol`, `Process`, `PID`, `ExecutablePath`, `User`, `ThreatSource`, `Indicator`, `Confidence`, `FeedUpdated`, `BytesSent`, `BytesReceived`
- **Operator action:** Investigate the process. iPulse does not block traffic; blocking is an operator decision.

#### IPULSE-5102 THREAT_INTELLIGENCE_MATCH

- **Severity:** WARNING
- **Meaning:** A connection matched local threat intelligence.
- **Trigger:** Remote IP, CIDR or domain matched an imported indicator.
- **Fields:** `Process`, `PID`, `RemoteIP`, `RemotePort`, `ThreatSource`, `Indicator`, `IndicatorType`, `Confidence`, `FeedUpdated`
- **Operator action:** Confirm the indicator is still valid; feeds carry false positives.

#### IPULSE-5103 MALICIOUS_DOMAIN_CONNECTION

- **Severity:** WARNING
- **Meaning:** A resolved or reverse-resolved domain matched a domain blocklist.
- **Trigger:** Domain observed via DNS monitoring or reverse DNS matched an imported domain indicator.
- **Fields:** `Domain`, `RemoteIP`, `Process`, `PID`, `ThreatSource`, `Indicator`, `Confidence`
- **Operator action:** As above.

#### IPULSE-5104 THREAT_FEED_IMPORTED

- **Severity:** INFO
- **Meaning:** A threat-intelligence feed was imported.
- **Trigger:** Scheduled or manual feed import completed.
- **Fields:** `Source`, `Format`, `Indicators`, `Added`, `Updated`, `Removed`, `Duration`, `Confidence`
- **Operator action:** None.

#### IPULSE-5105 THREAT_FEED_IMPORT_FAILED

- **Severity:** WARNING
- **Meaning:** A threat-intelligence feed could not be imported.
- **Trigger:** Fetch, parse or validation failure.
- **Fields:** `Source`, `Format`, `Error`, `LastSuccess`
- **Operator action:** Check the feed URL/path and format. Existing indicators are retained.

#### IPULSE-5201 INTERNAL_HOST_SWEEP

- **Severity:** WARNING
- **Meaning:** Possible host-sweep behaviour toward the local network.
- **Trigger:** Connections to more distinct private hosts than the configured threshold within the window.
- **Fields:** `DistinctHosts`, `Window`, `Process`, `PID`, `Ports`, `Subnets`, `FailedConnections`, `Confidence`, `Interpretation`
- **Operator action:** Possible lateral scanning behaviour. Verify whether the process is an approved scanner or management tool.

#### IPULSE-5202 POSSIBLE_PORT_SCAN

- **Severity:** WARNING
- **Meaning:** Possible port-scanning behaviour toward one or more hosts.
- **Trigger:** Connections to more distinct ports on a host than the configured threshold within the window, or sequential port progression.
- **Fields:** `TargetHost`, `DistinctPorts`, `Window`, `Sequential`, `Process`, `PID`, `FailedConnections`, `Confidence`, `Interpretation`
- **Operator action:** Possible scanning behaviour, not confirmed compromise. Verify the process.

#### IPULSE-5203 ABNORMAL_LATERAL_CONNECTIONS

- **Severity:** NOTICE
- **Meaning:** Internal connection behaviour is inconsistent with the learned baseline.
- **Trigger:** Internal connection count or distinct-peer count exceeded the baseline for this time bucket.
- **Fields:** `DistinctHosts`, `Connections`, `BaselineHosts`, `Deviation`, `Bucket`, `Process`, `Confidence`, `Interpretation`
- **Operator action:** Context signal; combine with sweep/scan events.

#### IPULSE-5204 REPEATED_INTERNAL_CONNECTION_FAILURES

- **Severity:** NOTICE
- **Meaning:** Many failed connection attempts to internal hosts.
- **Trigger:** SYN_SENT or refused internal connections above the threshold within the window.
- **Fields:** `FailedAttempts`, `DistinctHosts`, `Window`, `Ports`, `Process`, `PID`, `Confidence`, `Interpretation`
- **Operator action:** Often a misconfigured client; can also indicate discovery activity.

#### IPULSE-5205 REMOTE_ADMIN_PROTOCOL_SWEEP

- **Severity:** WARNING
- **Meaning:** Possible sweep of remote-administration ports across internal hosts.
- **Trigger:** Connections to SMB/RDP/SSH/WinRM/VNC ports on more distinct internal hosts than the threshold.
- **Fields:** `Protocols`, `DistinctHosts`, `Ports`, `Window`, `Process`, `PID`, `FailedConnections`, `Confidence`, `Interpretation`
- **Operator action:** Possible lateral movement reconnaissance. Verify against approved management tooling.

### DNS_ROUTING (6000-6999)

#### IPULSE-6001 DNS_RESOLUTION_OK

- **Severity:** DEBUG
- **Meaning:** A DNS probe succeeded.
- **Trigger:** The DNS interval elapsed and resolution succeeded.
- **Fields:** `Name`, `Server`, `ResponseTime`, `Answers`, `Protocol`
- **Operator action:** None.

#### IPULSE-6002 DNS_RESOLUTION_FAILED

- **Severity:** WARNING
- **Meaning:** A DNS probe failed.
- **Trigger:** Resolution failed or timed out on all configured resolvers.
- **Fields:** `Name`, `Server`, `Error`, `ServersTested`, `ServersFailed`, `Timeout`
- **Operator action:** Check the resolver and whether the network path is up.

#### IPULSE-6003 DNS_SERVER_CHANGED

- **Severity:** NOTICE
- **Meaning:** The system's configured resolvers changed.
- **Trigger:** The resolver list differs from the previous observation.
- **Fields:** `Previous`, `Current`, `Interface`, `VPNActive`
- **Operator action:** Expected after DHCP renewal or VPN connect; unexpected changes are worth review.

#### IPULSE-6004 DNS_SLOW_RESPONSE

- **Severity:** WARNING
- **Meaning:** DNS responses exceeded the configured latency threshold.
- **Trigger:** Response time above alerts.dns_slow_ms for the required persistence.
- **Fields:** `Name`, `Server`, `ResponseTime`, `Threshold`, `BaselineDNS`
- **Operator action:** Try an alternate resolver.

#### IPULSE-6005 DNS_PARTIAL_FAILURE

- **Severity:** NOTICE
- **Meaning:** Some resolvers answered and others did not.
- **Trigger:** Mixed per-resolver results in one probe cycle.
- **Fields:** `ServersTested`, `ServersFailed`, `FailedServers`, `WorkingServers`, `Name`
- **Operator action:** Consider removing the failing resolver from the configuration.

#### IPULSE-6101 PUBLIC_IP_CHANGED

- **Severity:** NOTICE
- **Meaning:** The public IP address changed.
- **Trigger:** A public IP probe returned a different address than the stored one.
- **Fields:** `Family`, `PreviousIP`, `NewIP`, `Interface`, `ASN`, `Organization`, `Country`, `VPNActive`, `Provider`, `CGNAT`
- **Operator action:** Normal for dynamic addressing. Not treated as a security incident on its own.

#### IPULSE-6102 PUBLIC_IP_UNAVAILABLE

- **Severity:** WARNING
- **Meaning:** The public IP could not be determined.
- **Trigger:** All configured public IP providers failed.
- **Fields:** `Family`, `ProvidersTested`, `Errors`
- **Operator action:** Usually a symptom of an outage rather than a problem itself.

#### IPULSE-6103 ISP_ASN_CHANGED

- **Severity:** NOTICE
- **Meaning:** The autonomous system serving this connection changed.
- **Trigger:** ASN for the current public IP differs from the previous observation.
- **Fields:** `PreviousASN`, `NewASN`, `PreviousOrg`, `NewOrg`, `PublicIP`, `VPNActive`
- **Operator action:** Expected on VPN connect, ISP failover or a network change.

#### IPULSE-6104 VPN_STATE_CHANGED

- **Severity:** NOTICE
- **Meaning:** A VPN or tunnel interface became active or inactive.
- **Trigger:** Tunnel interface appeared/disappeared, or the default route moved to a tunnel.
- **Fields:** `VPNActive`, `Interface`, `InterfaceType`, `DefaultRouteVia`, `PublicIP`, `PreviousPublicIP`, `DNSServers`
- **Operator action:** Explains public IP, DNS and route changes that follow.

#### IPULSE-6105 POSSIBLE_CGNAT_DETECTED

- **Severity:** INFO
- **Meaning:** The connection appears to be behind carrier-grade NAT.
- **Trigger:** The WAN-side address is in 100.64.0.0/10, or the observed public IP differs from every local address while no tunnel is active.
- **Fields:** `PublicIP`, `LocalWANAddress`, `Evidence`
- **Operator action:** Inbound connections will not work; relevant when diagnosing port forwarding.

#### IPULSE-6106 VPN_ROUTING_CHANGE

- **Severity:** NOTICE
- **Meaning:** A VPN or tunnel change moved the default route, the public address and the resolvers together.
- **Trigger:** Correlation rule: a tunnel or default-route change accompanied by a public IP, ASN or resolver change.
- **Fields:** `PublicIP`, `PreviousPublicIP`, `Interface`, `DefaultRouteVia`, `ASN`, `Evidence`, `ProbableCause`
- **Operator action:** None. This groups what would otherwise be several separate notices into one explanation.

#### IPULSE-6201 ROUTE_CHANGED

- **Severity:** NOTICE
- **Meaning:** A monitored path changed significantly.
- **Trigger:** Hop set for a monitored destination differs beyond the configured tolerance.
- **Fields:** `Destination`, `PreviousHops`, `CurrentHops`, `ChangedAt`, `PreviousPath`, `CurrentPath`, `VPNActive`
- **Operator action:** Normal ISP re-routing is common; correlate with latency changes.

#### IPULSE-6202 DEFAULT_GATEWAY_CHANGED

- **Severity:** NOTICE
- **Meaning:** The default gateway changed.
- **Trigger:** The default route's next hop or interface changed.
- **Fields:** `PreviousGateway`, `NewGateway`, `PreviousInterface`, `NewInterface`, `Metric`, `VPNActive`
- **Operator action:** Expected on network change, failover or VPN connect.

#### IPULSE-6203 HOP_COUNT_CHANGED

- **Severity:** INFO
- **Meaning:** The number of hops to a monitored destination changed.
- **Trigger:** Hop count differs from the previous measurement.
- **Fields:** `Destination`, `PreviousHopCount`, `CurrentHopCount`, `Delta`
- **Operator action:** None.

#### IPULSE-6204 TRACEROUTE_COMPLETED

- **Severity:** DEBUG
- **Meaning:** A path measurement completed.
- **Trigger:** The route monitor interval elapsed, or a manual traceroute was requested.
- **Fields:** `Destination`, `Hops`, `Duration`, `Path`, `Method`
- **Operator action:** None.

#### IPULSE-6205 TRACEROUTE_UNAVAILABLE

- **Severity:** NOTICE
- **Meaning:** Path measurement is unavailable on this host.
- **Trigger:** Raw/datagram ICMP sockets are not permitted for this process.
- **Fields:** `Reason`, `Platform`, `Remedy`
- **Operator action:** Grant CAP_NET_RAW on Linux, or run elevated on Windows, to enable path measurement.

### INTERFACE (7000-7999)

#### IPULSE-7001 INTERFACE_UP

- **Severity:** NOTICE
- **Meaning:** A network interface came up.
- **Trigger:** Interface operational state transitioned to up.
- **Fields:** `Interface`, `Type`, `MAC`, `Addresses`, `MTU`, `LinkSpeed`
- **Operator action:** None.

#### IPULSE-7002 INTERFACE_DOWN

- **Severity:** ERROR
- **Meaning:** A network interface went down.
- **Trigger:** Interface operational state transitioned to down or lost carrier.
- **Fields:** `Interface`, `Type`, `PreviousAddresses`, `WasDefaultRoute`
- **Operator action:** If this was the default-route interface, expect an outage record.

#### IPULSE-7003 INTERFACE_CHANGED

- **Severity:** NOTICE
- **Meaning:** The interface carrying the default route changed.
- **Trigger:** The default-route interface differs from the previous observation.
- **Fields:** `Previous`, `Current`, `PreviousType`, `CurrentType`, `VPNActive`
- **Operator action:** Expected on Wi-Fi/Ethernet handover or VPN connect.

#### IPULSE-7004 IP_ADDRESS_CHANGED

- **Severity:** NOTICE
- **Meaning:** A local IP address changed.
- **Trigger:** Address set on an interface differs from the previous observation.
- **Fields:** `Interface`, `Previous`, `Current`, `Family`, `Scope`
- **Operator action:** Expected after DHCP renewal.

#### IPULSE-7005 LINK_SPEED_CHANGED

- **Severity:** INFO
- **Meaning:** Negotiated link speed changed.
- **Trigger:** Reported interface speed differs from the previous observation.
- **Fields:** `Interface`, `PreviousSpeed`, `CurrentSpeed`, `Duplex`
- **Operator action:** A drop to a lower rate can indicate a cabling or driver problem.

#### IPULSE-7006 INTERFACE_ERRORS_RISING

- **Severity:** WARNING
- **Meaning:** Interface error or drop counters are increasing.
- **Trigger:** Delta of errors/drops per sample above the configured threshold.
- **Fields:** `Interface`, `RxErrors`, `TxErrors`, `RxDropped`, `TxDropped`, `Window`, `ErrorRate`
- **Operator action:** Usually physical: cable, port, driver or radio interference.

#### IPULSE-7101 WIFI_CONNECTED

- **Severity:** INFO
- **Meaning:** A wireless interface associated with a network.
- **Trigger:** Wi-Fi association observed.
- **Fields:** `Interface`, `SSID`, `BSSID`, `Signal`, `SignalPercent`, `LinkSpeed`, `Frequency`, `Channel`, `Band`
- **Operator action:** None. No credentials are collected.

#### IPULSE-7102 WIFI_DISCONNECTED

- **Severity:** WARNING
- **Meaning:** A wireless interface lost its association.
- **Trigger:** Wi-Fi association lost.
- **Fields:** `Interface`, `PreviousSSID`, `LastSignal`, `Duration`
- **Operator action:** None.

#### IPULSE-7103 WIFI_SIGNAL_DEGRADED

- **Severity:** WARNING
- **Meaning:** Wireless signal strength dropped below the configured threshold.
- **Trigger:** RSSI below wifi.weak_signal_dbm for the required persistence.
- **Fields:** `Interface`, `SSID`, `Signal`, `SignalPercent`, `BaselineSignal`, `Threshold`, `LinkSpeed`, `PacketLoss`
- **Operator action:** Weak signal explains latency and loss that would otherwise look like an ISP fault.

#### IPULSE-7104 WIFI_SSID_CHANGED

- **Severity:** NOTICE
- **Meaning:** The wireless network changed.
- **Trigger:** Associated SSID or BSSID differs from the previous observation.
- **Fields:** `Interface`, `PreviousSSID`, `CurrentSSID`, `PreviousBSSID`, `CurrentBSSID`, `Signal`
- **Operator action:** Roaming between APs is normal.

#### IPULSE-7105 WIFI_LINK_SPEED_DEGRADED

- **Severity:** WARNING
- **Meaning:** Wireless link rate dropped well below its baseline.
- **Trigger:** Link rate below the baseline band for the required persistence.
- **Fields:** `Interface`, `SSID`, `LinkSpeed`, `BaselineLinkSpeed`, `Deviation`, `Signal`, `Channel`
- **Operator action:** Interference or distance; consider changing channel or band.

#### IPULSE-7106 WIFI_MONITORING_UNAVAILABLE

- **Severity:** DEBUG
- **Meaning:** Wireless telemetry is unavailable on this host.
- **Trigger:** No wireless interface, or the platform API is unavailable/not permitted.
- **Fields:** `Reason`, `Platform`
- **Operator action:** Only relevant if this host does use Wi-Fi.

### SERVICE (8000-8999)

#### IPULSE-8001 AGENT_STARTED

- **Severity:** NOTICE
- **Meaning:** The iPulse agent started.
- **Trigger:** Service or foreground start-up completed.
- **Fields:** `Version`, `Commit`, `BuildDate`, `Platform`, `PID`, `User`, `Elevated`, `ConfigPath`, `DataDir`, `Mode`
- **Operator action:** None.

#### IPULSE-8002 AGENT_STOPPED

- **Severity:** NOTICE
- **Meaning:** The iPulse agent stopped.
- **Trigger:** Shutdown signal received and shutdown completed.
- **Fields:** `Reason`, `Uptime`, `Signal`, `EventsLogged`, `MeasurementsStored`
- **Operator action:** None.

#### IPULSE-8003 CONFIG_LOADED

- **Severity:** INFO
- **Meaning:** Configuration was loaded and validated.
- **Trigger:** Start-up, or a successful reload.
- **Fields:** `Path`, `Source`, `Warnings`, `Checksum`
- **Operator action:** None.

#### IPULSE-8004 CONFIG_RELOADED

- **Severity:** NOTICE
- **Meaning:** Configuration was reloaded at runtime.
- **Trigger:** SIGHUP on Linux, or a service control request on Windows.
- **Fields:** `Path`, `Changed`, `AppliedImmediately`, `RequiresRestart`
- **Operator action:** Some settings (dashboard bind address, database path) need a restart; they are listed.

#### IPULSE-8005 CONFIG_INVALID

- **Severity:** ERROR
- **Meaning:** Configuration failed validation and was not applied.
- **Trigger:** Validation errors during load or reload.
- **Fields:** `Path`, `Errors`, `UsingPrevious`
- **Operator action:** Fix the listed errors; the previous valid configuration stays active.

#### IPULSE-8006 SERVICE_INSTALLED

- **Severity:** NOTICE
- **Meaning:** The iPulse service was installed.
- **Trigger:** `ipulse service install` completed.
- **Fields:** `ServiceName`, `DisplayName`, `ExecPath`, `StartType`, `User`
- **Operator action:** None.

#### IPULSE-8007 SERVICE_REMOVED

- **Severity:** NOTICE
- **Meaning:** The iPulse service was removed.
- **Trigger:** `ipulse service uninstall` completed.
- **Fields:** `ServiceName`, `DataRetained`
- **Operator action:** None.

#### IPULSE-8008 DATABASE_OPENED

- **Severity:** INFO
- **Meaning:** The local database was opened.
- **Trigger:** Start-up.
- **Fields:** `Path`, `SchemaVersion`, `Migrations`, `SizeBytes`, `Journal`
- **Operator action:** None.

#### IPULSE-8009 RETENTION_PRUNE_COMPLETED

- **Severity:** INFO
- **Meaning:** Retention pruning finished.
- **Trigger:** The retention interval elapsed.
- **Fields:** `RowsDeleted`, `RowsRolledUp`, `Tables`, `Duration`, `SizeBefore`, `SizeAfter`, `Reclaimed`
- **Operator action:** None.

#### IPULSE-8010 LOG_ROTATED

- **Severity:** INFO
- **Meaning:** A log file was rotated.
- **Trigger:** Log file reached logging.max_file_mb, or a scheduled daily rotation occurred.
- **Fields:** `File`, `Archive`, `SizeBytes`, `Compressed`, `ArchivesRetained`, `ArchivesDeleted`
- **Operator action:** None.

#### IPULSE-8011 API_STARTED

- **Severity:** INFO
- **Meaning:** The REST API and dashboard are listening.
- **Trigger:** Start-up with dashboard.enabled true.
- **Fields:** `Address`, `Port`, `TLS`, `AuthRequired`, `Loopback`
- **Operator action:** None.

#### IPULSE-8012 API_STOPPED

- **Severity:** INFO
- **Meaning:** The REST API stopped listening.
- **Trigger:** Shutdown, or a listener error.
- **Fields:** `Reason`, `Requests`, `Duration`
- **Operator action:** None.

#### IPULSE-8013 SCHEDULER_TASK_SKIPPED

- **Severity:** DEBUG
- **Meaning:** A scheduled task was skipped because the previous run was still active.
- **Trigger:** Overlapping tick for a single-flight task.
- **Fields:** `Task`, `Interval`, `RunningFor`
- **Operator action:** Repeated skips mean the interval is too aggressive for this host or link.

#### IPULSE-8014 PRIVILEGE_LIMITED

- **Severity:** NOTICE
- **Meaning:** A monitoring function is degraded because of insufficient privileges.
- **Trigger:** A platform capability probe failed at start-up.
- **Fields:** `Feature`, `Required`, `Platform`, `Fallback`, `Impact`
- **Operator action:** See docs/security.md for the privilege matrix; the fallback in use is named.

#### IPULSE-8015 BASELINE_ESTABLISHED

- **Severity:** INFO
- **Meaning:** A metric baseline became usable.
- **Trigger:** A metric/time bucket reached baseline.min_observations.
- **Fields:** `Metric`, `Bucket`, `Observations`, `Mean`, `Median`, `P95`, `StdDev`
- **Operator action:** None. Detection for that metric and bucket starts now.

#### IPULSE-8016 MANUAL_TEST_REQUESTED

- **Severity:** INFO
- **Meaning:** A test was requested manually.
- **Trigger:** CLI or dashboard/API request.
- **Fields:** `Test`, `Source`, `Client`, `Parameters`
- **Operator action:** None.

### INTERNAL (9000-9999)

#### IPULSE-9001 INTERNAL_ERROR

- **Severity:** ERROR
- **Meaning:** An unexpected internal error occurred.
- **Trigger:** An error path with no more specific event.
- **Fields:** `Component`, `Operation`, `Error`
- **Operator action:** Report with the surrounding log context.

#### IPULSE-9002 DATABASE_ERROR

- **Severity:** ERROR
- **Meaning:** A database operation failed.
- **Trigger:** SQLite returned an error.
- **Fields:** `Operation`, `Table`, `Error`, `Retries`
- **Operator action:** Check disk space and file permissions on the data directory.

#### IPULSE-9003 COLLECTOR_ERROR

- **Severity:** WARNING
- **Meaning:** A collector failed to gather data.
- **Trigger:** A platform call or parse failed.
- **Fields:** `Collector`, `Error`, `Consecutive`, `Platform`
- **Operator action:** Isolated failures are tolerated; repeated ones indicate a platform problem.

#### IPULSE-9004 PROBE_ERROR

- **Severity:** WARNING
- **Meaning:** A network probe failed for a reason other than connectivity loss.
- **Trigger:** Socket, TLS or protocol error not attributable to an outage.
- **Fields:** `Probe`, `Target`, `Error`, `Consecutive`
- **Operator action:** Check the probe target configuration.

#### IPULSE-9005 PANIC_RECOVERED

- **Severity:** CRITICAL
- **Meaning:** A panic was recovered; the agent kept running.
- **Trigger:** A goroutine panicked and the supervisor recovered it.
- **Fields:** `Component`, `Panic`, `Stack`
- **Operator action:** This is a bug. Please report it with the stack field.

#### IPULSE-9006 LOG_SINK_ERROR

- **Severity:** ERROR
- **Meaning:** A log sink failed to write.
- **Trigger:** Filesystem, journald or Event Log write failure.
- **Fields:** `Sink`, `Error`, `Dropped`
- **Operator action:** Check disk space and permissions; other sinks continue.

#### IPULSE-9007 TASK_TIMEOUT

- **Severity:** WARNING
- **Meaning:** A scheduled task exceeded its timeout and was cancelled.
- **Trigger:** Task context deadline exceeded.
- **Fields:** `Task`, `Timeout`, `Interval`
- **Operator action:** Frequent timeouts suggest an unreachable target or too tight a timeout.

#### IPULSE-9008 CONFIG_WATCH_ERROR

- **Severity:** WARNING
- **Meaning:** The configuration file could not be watched for changes.
- **Trigger:** Watcher setup or read failure.
- **Fields:** `Path`, `Error`
- **Operator action:** Reload manually with SIGHUP or a service restart.

---

Total events: 117
