package agent

import "github.com/ipulse/ipulse/internal/events"

// buildMonitors constructs every collector, in dependency order.
//
// This function is the single place where the agent's collectors are assembled, so the
// set of things iPulse observes can be read at a glance. It is extended as each
// subsystem is added.
func (a *Agent) buildMonitors() []Monitor {
	var monitors []Monitor

	// Interface, route, resolver and wireless state. Everything else depends on knowing
	// which interface and gateway are in use, so this comes first.
	monitors = append(monitors, newInterfaceMonitor(a))

	// Latency, jitter and packet loss. The prober is shared with the connectivity
	// diagnostics so ICMP capability is detected once.
	lat := newLatencyMonitor(a)
	monitors = append(monitors, lat)

	// DNS resolution timing and failures.
	dns := newDNSMonitor(a)
	monitors = append(monitors, dns)

	// Health checks, the diagnostic ladder and the outage lifecycle.
	a.connectivity = newConnectivityMonitor(a, lat.Prober(), dns.Prober())
	monitors = append(monitors, a.connectivity)

	// Speed testing. The self-traffic accumulator is shared with the traffic monitor so
	// iPulse's own tests never register as bandwidth anomalies.
	if a.cfg.SpeedTest.Enabled {
		speed, err := newSpeedMonitor(a, a.selfTraffic)
		if err != nil {
			// A misconfigured speed test must not stop the rest of the monitoring.
			a.log.Emit(events.New(events.ConfigInvalid).WithSeverity(events.Error).
				WithField("Path", a.cfg.Path()).
				WithField("Errors", err.Error()).
				WithField("UsingPrevious", false).
				WithField("Detail", "speed testing is disabled for this run"))
		} else {
			a.speed = speed
			monitors = append(monitors, speed)
		}
	}

	// Interface throughput sampling. Detection of spikes lives in the anomaly
	// detectors, which consume the samples this publishes.
	if a.cfg.Traffic.Enabled {
		monitors = append(monitors, newTrafficMonitor(a))
	}

	// Active connection sampling, which feeds destination, threat and lateral analysis.
	if a.cfg.Connections.Enabled {
		a.connections = newConnectionMonitor(a)
		monitors = append(monitors, a.connections)

		// Destination history and novelty analysis, driven by the same snapshots.
		if a.cfg.Destinations.Enabled {
			dest := newDestinationMonitor(a)
			a.connections.AddConsumer(dest)
			monitors = append(monitors, dest)
		}

		// Threat-intelligence matching against the locally held indicators.
		if a.cfg.ThreatIntel.Enabled {
			threat := newThreatMonitor(a)
			a.connections.AddConsumer(threat)
			monitors = append(monitors, threat)
		}

		// Lateral movement heuristics over internal connections.
		if a.cfg.Lateral.Enabled {
			lat := newLateralMonitor(a)
			a.connections.AddConsumer(lat)
			monitors = append(monitors, lat)
		}
	}

	// Path measurement to a small set of stable destinations.
	if a.cfg.Routing.Enabled {
		monitors = append(monitors, newRouteMonitor(a))
	}

	// Public address discovery and ASN enrichment.
	if a.cfg.PublicIP.Enabled {
		monitors = append(monitors, newPublicIPMonitor(a))
	}

	// Baselines and anomaly detection. Registered as both a sample consumer (every
	// measurement feeds a baseline) and a connection consumer (so a traffic anomaly can
	// name the process most likely responsible).
	anomalyMon := newAnomalyMonitor(a)
	a.anomaly = anomalyMon
	a.consumers = append(a.consumers, anomalyMon)
	if a.connections != nil {
		a.connections.AddConsumer(anomalyMon)
	}
	monitors = append(monitors, anomalyMon)

	// The health score, computed from what has actually been measured.
	if a.cfg.Health.Enabled {
		monitors = append(monitors, newHealthMonitor(a))
	}

	// Correlation turns groups of symptoms into one conclusion. It is registered last
	// so it observes the events every other collector produces.
	if a.cfg.Correlation.Enabled {
		corr := newCorrelationMonitor(a)
		a.consumers = append(a.consumers, corr)
		monitors = append(monitors, corr)
	}

	return monitors
}
