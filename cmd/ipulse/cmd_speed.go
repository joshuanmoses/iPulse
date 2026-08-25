package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ipulse/ipulse/internal/speedtest"
)

// testSpeed runs a full speed test from the command line, using the configured provider
// and endpoints. It runs in this process rather than asking the service, so it works on
// a host where the service is not installed.
func (e *env) testSpeed(ctx context.Context, te *testEnv) error {
	cfg := te.cfg
	if len(cfg.SpeedTest.Endpoints) == 0 {
		return fmt.Errorf("no speed-test endpoints are configured")
	}
	endpoints := make([]speedtest.ConfigEndpoint, 0, len(cfg.SpeedTest.Endpoints))
	for _, ep := range cfg.SpeedTest.Endpoints {
		endpoints = append(endpoints, speedtest.ConfigEndpoint{
			Name: ep.Name, DownloadURL: ep.DownloadURL, UploadURL: ep.UploadURL,
			LatencyURL: ep.LatencyURL, MaxStreams: ep.MaxStreams, Location: ep.Location,
			Enabled: ep.Enabled,
		})
	}
	engine, err := speedtest.NewEngine(speedtest.Settings{
		Provider:          cfg.SpeedTest.Provider,
		Endpoints:         speedtest.EndpointsFromConfig(endpoints),
		EndpointSelection: cfg.SpeedTest.EndpointSelection,
		Streams:           cfg.SpeedTest.Streams,
		Warmup:            cfg.SpeedTest.Warmup.D(),
		Duration:          cfg.SpeedTest.Duration.D(),
		UploadDuration:    cfg.SpeedTest.UploadDuration.D(),
		MaxDownloadBytes:  cfg.SpeedTest.MaxDownloadBytes,
		MaxUploadBytes:    cfg.SpeedTest.MaxUploadBytes,
		LightweightBytes:  cfg.SpeedTest.LightweightBytes,
		UploadEnabled:     cfg.SpeedTest.UploadEnabled,
		Timeout:           cfg.SpeedTest.Timeout.D(),
		ExpectedDownload:  cfg.SpeedTest.ExpectedDownloadMbps,
		ExpectedUpload:    cfg.SpeedTest.ExpectedUploadMbps,
	})
	if err != nil {
		return err
	}

	if !e.jsonOut {
		fmt.Fprintf(e.out, "%s\n", e.bold("Speed test"))
		fmt.Fprintf(e.out, "%s this transfers real data (up to %s down, %s up)\n",
			e.dim("note:"), humanBytes(cfg.SpeedTest.MaxDownloadBytes), humanBytes(cfg.SpeedTest.MaxUploadBytes))
	}

	res, err := engine.Run(ctx, speedtest.ModeManual)
	if err != nil {
		return err
	}
	if e.jsonOut {
		return e.writeJSON(res)
	}

	pairs := [][2]string{
		{"Server", fmt.Sprintf("%s (%s)", res.Endpoint.Name, res.Endpoint.Location)},
		{"Provider", res.Provider},
		{"Download", fmt.Sprintf("%.1f Mbps", res.Download.Mbps)},
	}
	if res.Download.P90Mbps > 0 {
		pairs = append(pairs, [2]string{"Download p90", fmt.Sprintf("%.1f Mbps", res.Download.P90Mbps)})
	}
	if res.Upload.Mbps > 0 {
		pairs = append(pairs, [2]string{"Upload", fmt.Sprintf("%.1f Mbps", res.Upload.Mbps)})
	}
	pairs = append(pairs,
		[2]string{"Latency", fmt.Sprintf("%.1f ms", float64(res.Latency.RTT)/float64(time.Millisecond))},
		[2]string{"Jitter", fmt.Sprintf("%.1f ms", float64(res.Latency.Jitter)/float64(time.Millisecond))},
		[2]string{"TCP connect", fmt.Sprintf("%.1f ms", float64(res.Latency.TCPConnect)/float64(time.Millisecond))},
		[2]string{"DNS", fmt.Sprintf("%.1f ms", float64(res.Latency.DNS)/float64(time.Millisecond))},
		[2]string{"Transferred", fmt.Sprintf("%s down, %s up",
			humanBytes(res.Download.Bytes), humanBytes(res.Upload.Bytes))},
		[2]string{"Duration", res.Duration.Round(100 * time.Millisecond).String()},
		[2]string{"Status", res.Status},
	)
	if cfg.SpeedTest.ExpectedDownloadMbps > 0 {
		pct := res.Download.Mbps / cfg.SpeedTest.ExpectedDownloadMbps * 100
		word := fmt.Sprintf("%.0f%% of the %.0f Mbps plan", pct, cfg.SpeedTest.ExpectedDownloadMbps)
		if pct < 100-cfg.Alerts.ISPShortfallPercent {
			word = e.yellow(word)
		} else {
			word = e.green(word)
		}
		pairs = append(pairs, [2]string{"vs plan (down)", word})
	}
	if cfg.SpeedTest.ExpectedUploadMbps > 0 && res.Upload.Mbps > 0 {
		pct := res.Upload.Mbps / cfg.SpeedTest.ExpectedUploadMbps * 100
		word := fmt.Sprintf("%.0f%% of the %.0f Mbps plan", pct, cfg.SpeedTest.ExpectedUploadMbps)
		if pct < 100-cfg.Alerts.ISPShortfallPercent {
			word = e.yellow(word)
		} else {
			word = e.green(word)
		}
		pairs = append(pairs, [2]string{"vs plan (up)", word})
	}
	fmt.Fprintln(e.out)
	e.kv(pairs)
	if res.Error != "" {
		fmt.Fprintf(e.out, "\n%s %s\n", e.yellow("warning:"), res.Error)
	}
	return nil
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
