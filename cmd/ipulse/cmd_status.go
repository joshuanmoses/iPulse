package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/database"
	"github.com/ipulse/ipulse/internal/events"
	"github.com/ipulse/ipulse/internal/service"
	"github.com/ipulse/ipulse/internal/version"
)

func init() {
	register(&command{
		Name:    "status",
		Summary: "show the current connection status",
		Usage: `ipulse status [flags]

Show the current Internet status: service state, health score, the most recent speed
test, live latency and loss, public address and interface.

Values come from the local database, so status works whether or not the agent is
running. A stale reading is labelled with its age.

Flags:
  --json   machine-readable output`,
		Run: runStatus,
	})
}

// statusView is the assembled status, also used for --json output.
type statusView struct {
	Service       string           `json:"service"`
	ServiceState  string           `json:"service_state"`
	Internet      string           `json:"internet"`
	HealthScore   float64          `json:"health_score"`
	DownloadMbps  float64          `json:"download_mbps"`
	UploadMbps    float64          `json:"upload_mbps"`
	LatencyMS     float64          `json:"latency_ms"`
	JitterMS      float64          `json:"jitter_ms"`
	PacketLossPct float64          `json:"packet_loss_pct"`
	DNSMS         float64          `json:"dns_ms,omitempty"`
	PublicIP      string           `json:"public_ip,omitempty"`
	ISP           string           `json:"isp,omitempty"`
	Interface     string           `json:"interface,omitempty"`
	LastSpeedTest time.Time        `json:"last_speed_test,omitempty"`
	Availability  float64          `json:"availability_percent_24h"`
	Outages24h    int              `json:"outages_24h"`
	CurrentOutage *database.Outage `json:"current_outage,omitempty"`
	Version       string           `json:"version"`
	Counts        map[string]int64 `json:"counts,omitempty"`
	Recent        []events.Event   `json:"-"`
}

func runStatus(e *env, args []string) error {
	fs := e.flags("status")
	if err := e.parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	defer e.close()

	view := statusView{Version: version.Version, Internet: "unknown"}

	mgr := service.NewManager()
	if st, err := mgr.Status(); err == nil {
		view.Service = st.Name
		view.ServiceState = string(st.State)
	}

	db, err := e.database()
	if err != nil {
		// Without a database there is still something useful to say.
		if e.jsonOut {
			return e.writeJSON(view)
		}
		fmt.Fprintf(e.out, "%s\n\n", e.bold(version.Product+" Internet Monitor"))
		e.kv([][2]string{
			{"Service", statusWord(e, view.ServiceState)},
			{"Internet", e.dim("unknown (no data yet)")},
		})
		fmt.Fprintf(e.out, "\n%v\n", err)
		return nil
	}

	fill := func(metric string, dst *float64) time.Time {
		m, ok, err := db.LatestMeasurement(ctx, metric, "")
		if err != nil || !ok {
			return time.Time{}
		}
		*dst = m.Value
		return m.Time
	}
	latencyAt := fill(database.MetricLatencyMS, &view.LatencyMS)
	fill(database.MetricJitterMS, &view.JitterMS)
	fill(database.MetricPacketLossPct, &view.PacketLossPct)
	fill(database.MetricDNSMS, &view.DNSMS)
	fill(database.MetricHealthScore, &view.HealthScore)

	if st, ok, err := db.LatestSpeedTest(ctx, database.SpeedModeFull); err == nil && ok {
		view.DownloadMbps, view.UploadMbps = st.DownloadMbps, st.UploadMbps
		view.LastSpeedTest = st.Time
		if view.LatencyMS == 0 {
			view.LatencyMS, view.JitterMS = st.LatencyMS, st.JitterMS
		}
	}
	if rec, ok, err := db.LatestPublicIP(ctx, "ipv4"); err == nil && ok {
		view.PublicIP = rec.NewIP
		view.ISP = rec.ASNOrg
		if view.ISP == "" {
			view.ISP = rec.ASN
		}
	}
	if ifaces, err := db.ListInterfaces(ctx); err == nil {
		for _, i := range ifaces {
			if i.IsDefault {
				view.Interface = i.Name
				break
			}
		}
	}
	if av, err := db.AvailabilitySince(ctx, time.Now().Add(-24*time.Hour)); err == nil {
		view.Availability = av.Percent
		view.Outages24h = av.Outages
	}
	if o, open, err := db.CurrentOutage(ctx); err == nil && open {
		oc := o
		view.CurrentOutage = &oc
	}
	if counts, err := db.Counts(ctx); err == nil {
		view.Counts = counts
	}

	// Internet state: an open outage means offline; otherwise a recent successful
	// measurement means online, and stale data is reported as unknown rather than
	// guessed at.
	switch {
	case view.CurrentOutage != nil:
		view.Internet = "offline"
	case !latencyAt.IsZero() && time.Since(latencyAt) < 5*time.Minute:
		view.Internet = "online"
	case !view.LastSpeedTest.IsZero() && time.Since(view.LastSpeedTest) < time.Hour:
		view.Internet = "online"
	default:
		view.Internet = "unknown"
	}

	if e.jsonOut {
		return e.writeJSON(view)
	}
	printStatus(e, view, latencyAt)
	return nil
}

func printStatus(e *env, v statusView, latencyAt time.Time) {
	fmt.Fprintf(e.out, "\n%s\n\n", e.bold(version.Product+" Internet Monitor"))

	internet := v.Internet
	switch internet {
	case "online":
		internet = e.green("Online")
	case "offline":
		internet = e.red("Offline")
	default:
		internet = e.dim("Unknown")
	}

	pairs := [][2]string{
		{"Service", statusWord(e, v.ServiceState)},
		{"Internet", internet},
	}
	if v.HealthScore > 0 {
		pairs = append(pairs, [2]string{"Health Score", healthWord(e, v.HealthScore)})
	}
	if v.DownloadMbps > 0 {
		pairs = append(pairs, [2]string{"Download", fmt.Sprintf("%.1f Mbps", v.DownloadMbps)})
	}
	if v.UploadMbps > 0 {
		pairs = append(pairs, [2]string{"Upload", fmt.Sprintf("%.1f Mbps", v.UploadMbps)})
	}
	if v.LatencyMS > 0 {
		pairs = append(pairs, [2]string{"Latency", fmt.Sprintf("%.1f ms", v.LatencyMS)})
	}
	if v.JitterMS > 0 {
		pairs = append(pairs, [2]string{"Jitter", fmt.Sprintf("%.1f ms", v.JitterMS)})
	}
	pairs = append(pairs, [2]string{"Packet Loss", fmt.Sprintf("%.1f%%", v.PacketLossPct)})
	if v.DNSMS > 0 {
		pairs = append(pairs, [2]string{"DNS", fmt.Sprintf("%.1f ms", v.DNSMS)})
	}
	if v.PublicIP != "" {
		pairs = append(pairs, [2]string{"Public IP", v.PublicIP})
	}
	if v.ISP != "" {
		pairs = append(pairs, [2]string{"ISP", v.ISP})
	}
	if v.Interface != "" {
		pairs = append(pairs, [2]string{"Interface", v.Interface})
	}
	if !v.LastSpeedTest.IsZero() {
		pairs = append(pairs, [2]string{"Last Speed Test", humanAge(v.LastSpeedTest)})
	}
	if v.Availability > 0 {
		pairs = append(pairs, [2]string{"Availability (24h)", fmt.Sprintf("%.3f%% (%d outages)", v.Availability, v.Outages24h)})
	}
	e.kv(pairs)

	if v.CurrentOutage != nil {
		o := v.CurrentOutage
		fmt.Fprintf(e.out, "\n%s %s since %s (%s)\n",
			e.red("OUTAGE"), o.Classification,
			o.Start.Format("15:04:05"), time.Since(o.Start).Round(time.Second))
		if o.ProbableCause != "" {
			fmt.Fprintf(e.out, "  probable cause: %s\n", o.ProbableCause)
		}
	}
	if !latencyAt.IsZero() && time.Since(latencyAt) > 5*time.Minute {
		fmt.Fprintf(e.out, "\n%s live measurements are stale (last %s); is the service running?\n",
			e.yellow("note:"), humanAge(latencyAt))
	}
	fmt.Fprintln(e.out)
}

func statusWord(e *env, state string) string {
	switch state {
	case "running":
		return e.green("Running")
	case "stopped":
		return e.yellow("Stopped")
	case "failed":
		return e.red("Failed")
	case "not-installed":
		return e.dim("Not installed")
	case "":
		return e.dim("unknown")
	default:
		return state
	}
}

func healthWord(e *env, score float64) string {
	s := fmt.Sprintf("%.0f/100", score)
	switch {
	case score >= 85:
		return e.green(s)
	case score >= 60:
		return e.yellow(s)
	default:
		return e.red(s)
	}
}

// ensure the context import is used even if future edits remove its other uses.
var _ = context.Background
