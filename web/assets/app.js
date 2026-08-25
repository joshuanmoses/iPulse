/* iPulse dashboard.
 *
 * Vanilla JavaScript, no build step and no external dependency: the API serves this page
 * under a policy that forbids every external origin, and the whole dashboard has to work
 * on an air-gapped host. The charts are hand-drawn SVG for the same reason.
 */
'use strict';

// ---------------------------------------------------------------- API client

const API = '/api/v1/';

/** Token storage: only used when the operator has configured dashboard.auth_token. */
const auth = {
  get() { try { return sessionStorage.getItem('ipulse-token') || ''; } catch { return ''; } },
  set(v) { try { sessionStorage.setItem('ipulse-token', v); } catch { /* private mode */ } },
};

async function api(path, opts = {}) {
  const headers = Object.assign({ 'Accept': 'application/json' }, opts.headers || {});
  const token = auth.get();
  if (token) headers['X-iPulse-Token'] = token;

  const resp = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (resp.status === 401) {
    const token = window.prompt('This iPulse API requires a token (dashboard.auth_token):');
    if (token) { auth.set(token); return api(path, opts); }
    throw new Error('authentication required');
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { const body = await resp.json(); detail = body.message || body.error || detail; } catch { /* not JSON */ }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.json();
}

// ---------------------------------------------------------------- formatting

const fmt = {
  /** Bit rates, chosen so a value is never shown with a misleading number of digits. */
  rate(bps) {
    if (!isFinite(bps) || bps <= 0) return '0 bps';
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
    return Math.round(bps) + ' bps';
  },
  mbps(v) { return (v == null || !isFinite(v)) ? '—' : v.toFixed(1); },
  bytes(b) {
    if (!isFinite(b) || b <= 0) return '0 B';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return (i === 0 ? b.toFixed(0) : b.toFixed(1)) + ' ' + units[i];
  },
  ms(v) { return (v == null || !isFinite(v)) ? '—' : v.toFixed(1) + ' ms'; },
  pct(v, digits = 1) { return (v == null || !isFinite(v)) ? '—' : v.toFixed(digits) + '%'; },
  int(v) { return (v == null) ? '—' : Number(v).toLocaleString(); },
  time(ts) {
    if (!ts || ts.startsWith('0001')) return '—';
    const d = new Date(ts);
    return isNaN(d) ? '—' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },
  datetime(ts) {
    if (!ts || ts.startsWith('0001')) return '—';
    const d = new Date(ts);
    return isNaN(d) ? '—' : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },
  /** Relative age is how an operator reads a timestamp: "4 minutes ago", not a clock. */
  age(ts) {
    if (!ts || ts.startsWith('0001')) return 'never';
    const d = new Date(ts);
    if (isNaN(d)) return 'never';
    const secs = (Date.now() - d.getTime()) / 1000;
    if (secs < 0) return 'just now';
    if (secs < 5) return 'just now';
    if (secs < 60) return `${Math.floor(secs)}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  },
  /** Go durations arrive as nanoseconds or as strings depending on the field. */
  duration(v) {
    if (typeof v === 'string') return v;
    if (!isFinite(v) || v <= 0) return '0s';
    const s = v / 1e9;
    if (s < 1) return (s * 1000).toFixed(0) + 'ms';
    if (s < 60) return s.toFixed(1) + 's';
    if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  },
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function metric(label, value, unit, sub) {
  return el('div', { class: 'metric' },
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value' }, String(value), unit ? el('span', { class: 'unit', text: ' ' + unit }) : null),
    sub ? el('div', { class: 'sub', text: sub }) : null);
}

function table(node, columns, rows, renderRow) {
  clear(node);
  const thead = el('thead');
  const tr = el('tr');
  for (const c of columns) tr.appendChild(el('th', { class: c.num ? 'num' : null, text: c.label }));
  thead.appendChild(tr);
  node.appendChild(thead);

  const tbody = el('tbody');
  if (!rows || rows.length === 0) {
    tbody.appendChild(el('tr', {}, el('td', { colspan: String(columns.length) },
      el('div', { class: 'empty', text: 'Nothing recorded yet.' }))));
  } else {
    for (const row of rows) tbody.appendChild(renderRow(row));
  }
  node.appendChild(tbody);
}

function banner(kind, message) {
  const host = document.getElementById('banner');
  clear(host);
  if (message) host.appendChild(el('div', { class: 'banner ' + kind, text: message }));
}

// ---------------------------------------------------------------- charts

const SVG_NS = 'http://www.w3.org/2000/svg';

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v != null) node.setAttribute(k, String(v));
  }
  return node;
}

/**
 * lineChart draws one or more time series.
 *
 * Series: [{ name, colour, points: [{t: Date|string, v: number}], area: bool }]
 * A reference line (an ISP plan, a threshold) can be drawn with `reference`.
 */
function lineChart(svg, series, opts = {}) {
  clear(svg);
  const box = svg.getBoundingClientRect();
  const width = Math.max(320, box.width || 640);
  const height = Math.max(140, box.height || 190);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('preserveAspectRatio', 'none');

  const pad = { top: 10, right: 12, bottom: 22, left: 48 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const points = series.flatMap(s => s.points || []);
  if (points.length === 0) {
    svg.appendChild(svgEl('rect', { x: 0, y: 0, width, height, fill: 'transparent' }));
    const text = svgEl('text', { x: width / 2, y: height / 2, 'text-anchor': 'middle', class: 'axis' });
    text.textContent = opts.empty || 'No data for this window yet';
    svg.appendChild(text);
    return;
  }

  const times = points.map(p => new Date(p.t).getTime());
  const minT = opts.minT != null ? opts.minT : Math.min(...times);
  const maxT = opts.maxT != null ? opts.maxT : Math.max(...times);
  let minV = 0;
  let maxV = Math.max(...points.map(p => p.v));
  if (opts.reference != null) maxV = Math.max(maxV, opts.reference);
  if (opts.minZero === false) minV = Math.min(...points.map(p => p.v));
  if (maxV === minV) maxV = minV + 1;
  // A little headroom keeps the peak from touching the frame.
  maxV *= 1.08;

  const x = t => pad.left + (maxT === minT ? plotW / 2 : ((new Date(t).getTime() - minT) / (maxT - minT)) * plotW);
  const y = v => pad.top + plotH - ((v - minV) / (maxV - minV)) * plotH;

  // Horizontal gridlines and value labels.
  const ticks = 4;
  const axis = svgEl('g', { class: 'axis' });
  for (let i = 0; i <= ticks; i++) {
    const v = minV + ((maxV - minV) * i) / ticks;
    const yy = y(v);
    axis.appendChild(svgEl('line', { x1: pad.left, y1: yy, x2: width - pad.right, y2: yy, class: 'gridline' }));
    const label = svgEl('text', { x: pad.left - 6, y: yy + 3, 'text-anchor': 'end' });
    label.textContent = opts.formatValue ? opts.formatValue(v) : v.toFixed(0);
    axis.appendChild(label);
  }
  // Time labels at both ends and the middle.
  for (const frac of [0, 0.5, 1]) {
    const t = minT + (maxT - minT) * frac;
    const label = svgEl('text', {
      x: pad.left + plotW * frac, y: height - 6,
      'text-anchor': frac === 0 ? 'start' : frac === 1 ? 'end' : 'middle',
    });
    label.textContent = new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    axis.appendChild(label);
  }
  svg.appendChild(axis);

  if (opts.reference != null && isFinite(opts.reference)) {
    svg.appendChild(svgEl('line', {
      x1: pad.left, y1: y(opts.reference), x2: width - pad.right, y2: y(opts.reference), class: 'reference',
    }));
    const label = svgEl('text', {
      x: width - pad.right, y: y(opts.reference) - 4, 'text-anchor': 'end', class: 'axis',
    });
    label.textContent = opts.referenceLabel || '';
    svg.appendChild(label);
  }

  for (const s of series) {
    const pts = (s.points || []).slice().sort((a, b) => new Date(a.t) - new Date(b.t));
    if (pts.length === 0) continue;
    const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ');

    if (s.area) {
      const areaPath = `${d} L${x(pts[pts.length - 1].t).toFixed(1)},${y(minV).toFixed(1)} L${x(pts[0].t).toFixed(1)},${y(minV).toFixed(1)} Z`;
      svg.appendChild(svgEl('path', { d: areaPath, fill: s.colour, class: 'area' }));
    }
    svg.appendChild(svgEl('path', { d, stroke: s.colour, class: 'series' }));

    // Individual points are only drawn for sparse series, where a line alone would be
    // hard to read.
    if (pts.length <= 40) {
      for (const p of pts) {
        svg.appendChild(svgEl('circle', { cx: x(p.t), cy: y(p.v), r: 2.5, fill: s.colour }));
      }
    }
  }
}

function legend(node, series) {
  clear(node);
  for (const s of series) {
    if (!s.name) continue;
    node.appendChild(el('span', { class: 'key' },
      el('span', { class: 'swatch', style: `background:${s.colour}` }),
      el('span', { text: s.name })));
  }
}

const COLOURS = {
  download: 'var(--chart-1)',
  upload: 'var(--chart-2)',
  latency: 'var(--chart-1)',
  jitter: 'var(--chart-4)',
  loss: 'var(--chart-3)',
  dns: 'var(--chart-4)',
  rx: 'var(--chart-1)',
  tx: 'var(--chart-2)',
};

function toPoints(series) {
  return (series || []).map(p => ({ t: p.t, v: p.v }));
}

// ---------------------------------------------------------------- state

const state = {
  view: 'overview',
  status: null,
  timer: null,
  followTimer: null,
  lastEventID: 0,
};

// ---------------------------------------------------------------- views

async function renderOverview() {
  const data = await api('summary');
  state.status = data.status;

  const s = data.status || {};
  const av = data.availability_24h || {};
  const speed = data.last_speed_test || {};

  const host = document.getElementById('overview-metrics');
  clear(host);
  host.appendChild(metric('Health score', s.health_score ? s.health_score.toFixed(0) : '—', '/100',
    s.health_components ? worstComponent(s.health_components) : ''));
  host.appendChild(metric('Download', fmt.mbps(speed.download_mbps), 'Mbps',
    speed.time ? 'measured ' + fmt.age(speed.time) : 'no test yet'));
  host.appendChild(metric('Upload', fmt.mbps(speed.upload_mbps), 'Mbps',
    s.expected_upload_mbps ? `plan ${s.expected_upload_mbps} Mbps` : ''));
  host.appendChild(metric('Latency', fmt.mbps(s.latency_ms), 'ms',
    `jitter ${fmt.mbps(s.jitter_ms)} ms`));
  host.appendChild(metric('Packet loss', fmt.pct(s.packet_loss_pct), '', ''));
  host.appendChild(metric('Availability 24h', fmt.pct(av.availability_percent, 3), '',
    `${av.outages || 0} outage${av.outages === 1 ? '' : 's'}`));
  host.appendChild(metric('Active connections', fmt.int(s.active_connections), '',
    `${fmt.int(s.known_destinations)} destinations known`));
  host.appendChild(metric('Uptime', fmt.duration(s.uptime), '',
    s.threat_matches_24h ? `${s.threat_matches_24h} threat matches (24h)` : ''));

  // Connection facts.
  const conn = document.getElementById('overview-connection');
  clear(conn);
  const rows = [
    ['Status', s.status || 'unknown'],
    ['Public IPv4', s.public_ipv4 || '—'],
    ['Public IPv6', s.public_ipv6 || '—'],
    ['ISP', s.isp || '—'],
    ['ASN', s.asn || '—'],
    ['Interface', s.interface ? `${s.interface} (${s.interface_type || 'unknown'})` : '—'],
    ['Local address', s.local_ip || '—'],
    ['Gateway', s.gateway || '—'],
    ['Gateway RTT', s.gateway_rtt_ms ? fmt.ms(s.gateway_rtt_ms) : '—'],
    ['DNS', s.dns_ms ? fmt.ms(s.dns_ms) : '—'],
    ['VPN', s.vpn_active ? 'active' : 'not detected'],
    ['Current rate', `${fmt.rate(s.rx_bps)} down / ${fmt.rate(s.tx_bps)} up`],
  ];
  if (s.wifi) {
    rows.push(['Wi-Fi', `${s.wifi.ssid || 'unknown'} · ${s.wifi.signal_dbm} dBm (${s.wifi.signal_percent}%) · ${fmt.mbps(s.wifi.link_mbps)} Mbps · ch ${s.wifi.channel} ${s.wifi.band || ''}`]);
  }
  if (s.cgnat) rows.push(['CGNAT', 'this connection appears to be behind carrier-grade NAT']);
  for (const [k, v] of rows) {
    conn.appendChild(el('dt', { text: k }));
    conn.appendChild(el('dd', { text: String(v) }));
  }

  renderEventList(document.getElementById('overview-events'), (data.recent_events || []).slice(0, 12), true);

  // Charts.
  const [latency, dl, ul] = await Promise.all([
    api('measurements?metric=latency_ms&since=6h&bucket_seconds=120'),
    api('measurements?metric=download_mbps&since=7d&bucket_seconds=1800'),
    api('measurements?metric=upload_mbps&since=7d&bucket_seconds=1800'),
  ]);
  const latencySeries = [{ name: 'Latency', colour: COLOURS.latency, points: toPoints(latency.series), area: true }];
  lineChart(document.getElementById('chart-overview-latency'), latencySeries,
    { formatValue: v => v.toFixed(0) + ' ms' });
  legend(document.getElementById('legend-overview-latency'), latencySeries);

  const speedSeries = [
    { name: 'Download', colour: COLOURS.download, points: toPoints(dl.series) },
    { name: 'Upload', colour: COLOURS.upload, points: toPoints(ul.series) },
  ];
  lineChart(document.getElementById('chart-overview-speed'), speedSeries, {
    formatValue: v => v.toFixed(0),
    reference: s.expected_download_mbps || null,
    referenceLabel: s.expected_download_mbps ? `plan ${s.expected_download_mbps} Mbps` : '',
  });
  legend(document.getElementById('legend-overview-speed'), speedSeries);
}

function worstComponent(components) {
  let worst = null;
  for (const [name, value] of Object.entries(components)) {
    if (!worst || value < worst[1]) worst = [name, value];
  }
  return worst ? `weakest: ${worst[0].replace(/_/g, ' ')} ${worst[1].toFixed(0)}` : '';
}

async function renderSpeed() {
  const window_ = document.getElementById('speed-window').value;
  const bucket = { '6h': 300, '24h': 900, '7d': 3600, '30d': 21600 }[window_] || 900;

  const [speed, history, dl, ul] = await Promise.all([
    api(`speed?since=${window_}&limit=100`),
    api('speed/history'),
    api(`measurements?metric=download_mbps&since=${window_}&bucket_seconds=${bucket}`),
    api(`measurements?metric=upload_mbps&since=${window_}&bucket_seconds=${bucket}`),
  ]);

  const latest = speed.latest || {};
  const host = document.getElementById('speed-metrics');
  clear(host);
  host.appendChild(metric('Last download', fmt.mbps(latest.download_mbps), 'Mbps', fmt.age(latest.time)));
  host.appendChild(metric('Last upload', fmt.mbps(latest.upload_mbps), 'Mbps', latest.endpoint || ''));
  host.appendChild(metric('Plan', speed.expected_download_mbps ? `${speed.expected_download_mbps}/${speed.expected_upload_mbps}` : 'not set', 'Mbps',
    speed.expected_download_mbps ? 'configured ISP expectation' : 'set speed_test.expected_*_mbps'));
  const day = (history || {}).day || {};
  host.appendChild(metric('Median 24h', fmt.mbps(day.download && day.download.median), 'Mbps',
    day.samples ? `${day.samples} tests` : 'no tests yet'));

  const series = [
    { name: 'Download', colour: COLOURS.download, points: toPoints(dl.series) },
    { name: 'Upload', colour: COLOURS.upload, points: toPoints(ul.series) },
  ];
  lineChart(document.getElementById('chart-speed'), series, {
    formatValue: v => v.toFixed(0) + ' Mbps',
    reference: speed.expected_download_mbps || null,
    referenceLabel: speed.expected_download_mbps ? `plan ${speed.expected_download_mbps}` : '',
  });
  legend(document.getElementById('legend-speed'), series);

  // Historical analysis across the four windows.
  const windows = ['hour', 'day', 'week', 'month'];
  table(document.getElementById('speed-history'),
    [{ label: 'Window' }, { label: 'Tests', num: true }, { label: 'Mean', num: true },
     { label: 'Median', num: true }, { label: 'Min', num: true }, { label: 'Max', num: true },
     { label: 'p10', num: true }, { label: 'p90', num: true }, { label: 'Std dev', num: true },
     { label: 'Below median', num: true }, { label: 'Below plan', num: true }],
    windows.filter(w => history[w]).map(w => Object.assign({ window: w }, history[w])),
    row => {
      const d = row.download || {};
      return el('tr', {},
        el('td', { text: row.window }),
        el('td', { class: 'num', text: fmt.int(row.samples) }),
        el('td', { class: 'num', text: fmt.mbps(d.mean) }),
        el('td', { class: 'num', text: fmt.mbps(d.median) }),
        el('td', { class: 'num', text: fmt.mbps(d.min) }),
        el('td', { class: 'num', text: fmt.mbps(d.max) }),
        el('td', { class: 'num', text: fmt.mbps(d.p10) }),
        el('td', { class: 'num', text: fmt.mbps(d.p90) }),
        el('td', { class: 'num', text: fmt.mbps(d.stddev) }),
        el('td', { class: 'num', text: fmt.pct(row.download_percent_below_baseline) }),
        el('td', { class: 'num', text: row.expected_download_mbps ? fmt.pct(row.download_percent_below_expected) : '—' }));
    });

  table(document.getElementById('speed-tests'),
    [{ label: 'Time' }, { label: 'Mode' }, { label: 'Server' }, { label: 'Download', num: true },
     { label: 'Upload', num: true }, { label: 'Latency', num: true }, { label: 'Jitter', num: true },
     { label: 'Transferred', num: true }, { label: 'Status' }],
    speed.tests || [],
    t => el('tr', {},
      el('td', { text: fmt.datetime(t.time) }),
      el('td', { text: t.mode }),
      el('td', { text: t.endpoint || '—' }),
      el('td', { class: 'num', text: fmt.mbps(t.download_mbps) }),
      el('td', { class: 'num', text: fmt.mbps(t.upload_mbps) }),
      el('td', { class: 'num', text: fmt.ms(t.latency_ms) }),
      el('td', { class: 'num', text: fmt.ms(t.jitter_ms) }),
      el('td', { class: 'num', text: fmt.bytes((t.bytes_down || 0) + (t.bytes_up || 0)) }),
      el('td', {}, t.status === 'ok'
        ? el('span', { class: 'tag', text: 'ok' })
        : el('span', { class: 'tag flagged', text: t.status || 'failed' }))));
}

async function renderLatency() {
  const window_ = document.getElementById('latency-window').value;
  const bucket = { '1h': 60, '6h': 120, '24h': 600, '7d': 3600 }[window_] || 120;

  const [lat, jit, loss, dns] = await Promise.all([
    api(`measurements?metric=latency_ms&since=${window_}&bucket_seconds=${bucket}`),
    api(`measurements?metric=jitter_ms&since=${window_}&bucket_seconds=${bucket}`),
    api(`measurements?metric=packet_loss_pct&since=${window_}&bucket_seconds=${bucket}`),
    api(`measurements?metric=dns_ms&since=${window_}&bucket_seconds=${bucket}`),
  ]);

  const stats = lat.stats || {};
  const host = document.getElementById('latency-metrics');
  clear(host);
  host.appendChild(metric('Median latency', fmt.mbps(stats.median), 'ms', `${fmt.int(stats.count)} samples`));
  host.appendChild(metric('p95 latency', fmt.mbps(stats.p95), 'ms', `min ${fmt.mbps(stats.min)} max ${fmt.mbps(stats.max)}`));
  host.appendChild(metric('Median jitter', fmt.mbps((jit.stats || {}).median), 'ms', ''));
  host.appendChild(metric('Mean packet loss', fmt.pct((loss.stats || {}).mean), '', ''));

  const latSeries = [{ name: 'Latency', colour: COLOURS.latency, points: toPoints(lat.series), area: true }];
  lineChart(document.getElementById('chart-latency'), latSeries, { formatValue: v => v.toFixed(0) + ' ms' });
  legend(document.getElementById('legend-latency'), latSeries);

  lineChart(document.getElementById('chart-jitter'),
    [{ colour: COLOURS.jitter, points: toPoints(jit.series), area: true }],
    { formatValue: v => v.toFixed(1) + ' ms' });
  lineChart(document.getElementById('chart-loss'),
    [{ colour: COLOURS.loss, points: toPoints(loss.series), area: true }],
    { formatValue: v => v.toFixed(1) + '%' });
  lineChart(document.getElementById('chart-dns'),
    [{ colour: COLOURS.dns, points: toPoints(dns.series), area: true }],
    { formatValue: v => v.toFixed(0) + ' ms' });
}

async function renderAvailability() {
  const data = await api('outages?since=30d&limit=200');
  const av = data.availability || {};

  const host = document.getElementById('availability-metrics');
  clear(host);
  host.appendChild(metric('Availability 30d', fmt.pct(av.availability_percent, 4), '', ''));
  host.appendChild(metric('Outages', fmt.int(av.outages), '', 'in the last 30 days'));
  host.appendChild(metric('Total downtime', fmt.duration(av.downtime), '', ''));
  host.appendChild(metric('Longest outage', fmt.duration(av.longest_outage), '',
    av.mtbf ? 'MTBF ' + fmt.duration(av.mtbf) : ''));

  if (data.current) {
    banner('error', `Outage in progress since ${fmt.datetime(data.current.start)}: ${data.current.classification} — ${data.current.probable_cause || ''}`);
  }

  table(document.getElementById('outage-table'),
    [{ label: 'Started' }, { label: 'Ended' }, { label: 'Duration', num: true },
     { label: 'Classification' }, { label: 'Probable cause' }, { label: 'Interface' }, { label: 'Gateway' }],
    data.outages || [],
    o => el('tr', {},
      el('td', { text: fmt.datetime(o.start) }),
      el('td', { text: o.resolved ? fmt.datetime(o.end) : 'ongoing' }),
      el('td', { class: 'num', text: fmt.duration(o.duration) }),
      el('td', {}, el('span', { class: 'tag flagged', text: o.classification })),
      el('td', { class: 'wrap', text: o.probable_cause || '—' }),
      el('td', { text: o.interface || '—' }),
      el('td', { text: o.gateway || '—' })));

  const causes = Object.entries(av.by_cause || {}).map(([cause, count]) => ({ cause, count }));
  table(document.getElementById('outage-causes'),
    [{ label: 'Classification' }, { label: 'Occurrences', num: true }],
    causes.sort((a, b) => b.count - a.count),
    c => el('tr', {}, el('td', { text: c.cause }), el('td', { class: 'num', text: fmt.int(c.count) })));
}

async function renderTraffic() {
  const window_ = document.getElementById('traffic-window').value;
  const iface = document.getElementById('traffic-interface').value;
  const [traffic, ifaces, anomalies] = await Promise.all([
    api(`traffic?since=${window_}&interface=${encodeURIComponent(iface)}&limit=5000`),
    api('interfaces'),
    api('events?since=24h&limit=60&category=TRAFFIC&severity=notice'),
  ]);

  // Interface selector, populated once.
  const select = document.getElementById('traffic-interface');
  if (select.options.length <= 1) {
    for (const i of ifaces.interfaces || []) {
      if (i.type === 'loopback') continue;
      select.appendChild(el('option', { value: i.name, text: i.name }));
    }
  }

  const samples = traffic.samples || [];
  const rx = samples.map(s => ({ t: s.time, v: s.rx_bps }));
  const tx = samples.map(s => ({ t: s.time, v: s.tx_bps }));
  const current = traffic.current || {};

  const host = document.getElementById('traffic-metrics');
  clear(host);
  host.appendChild(metric('Current download', fmt.rate(current.rx_bps), '', ''));
  host.appendChild(metric('Current upload', fmt.rate(current.tx_bps), '', ''));
  const peakRx = Math.max(0, ...rx.map(p => p.v));
  const peakTx = Math.max(0, ...tx.map(p => p.v));
  host.appendChild(metric('Peak download', fmt.rate(peakRx), '', `over the last ${window_}`));
  host.appendChild(metric('Peak upload', fmt.rate(peakTx), '', `${samples.length} samples`));

  const series = [
    { name: 'Download', colour: COLOURS.rx, points: rx, area: true },
    { name: 'Upload', colour: COLOURS.tx, points: tx, area: true },
  ];
  lineChart(document.getElementById('chart-traffic'), series, { formatValue: v => fmt.rate(v) });
  legend(document.getElementById('legend-traffic'), series);

  renderEventList(document.getElementById('traffic-anomalies'), anomalies.events || [], false);
}

async function renderConnections() {
  const params = new URLSearchParams({
    since: document.getElementById('conn-window').value,
    limit: '500',
  });
  const q = document.getElementById('conn-search').value.trim();
  if (q) params.set('q', q);
  const proto = document.getElementById('conn-protocol').value;
  if (proto) params.set('protocol', proto);
  const scope = document.getElementById('conn-scope').value;
  if (scope) params.set('internal', scope);

  const data = await api('connections?' + params.toString());
  document.getElementById('conn-count').textContent = `${data.count} connections`;

  table(document.getElementById('conn-top'),
    [{ label: 'Process' }, { label: 'Connections', num: true }, { label: 'Queued out', num: true }, { label: 'Queued in', num: true }],
    data.top_processes || [],
    p => el('tr', {},
      el('td', { text: p.process }),
      el('td', { class: 'num', text: fmt.int(p.connections) }),
      el('td', { class: 'num', text: fmt.bytes(p.bytes_sent) }),
      el('td', { class: 'num', text: fmt.bytes(p.bytes_recv) })));

  table(document.getElementById('conn-table'),
    [{ label: 'Last seen' }, { label: 'Proto' }, { label: 'Process' }, { label: 'PID', num: true },
     { label: 'Local' }, { label: 'Remote' }, { label: 'State' }, { label: 'Scope' },
     { label: 'Duration', num: true }, { label: 'User' }],
    data.connections || [],
    c => el('tr', {},
      el('td', { text: fmt.time(c.last_seen) }),
      el('td', { text: c.protocol }),
      el('td', { text: c.process || '(unattributed)' }),
      el('td', { class: 'num', text: c.pid ? String(c.pid) : '—' }),
      el('td', { class: 'mono', text: endpoint(c.local_ip, c.local_port) }),
      el('td', { class: 'mono', text: endpoint(c.remote_ip, c.remote_port) }),
      el('td', { text: c.state || '—' }),
      el('td', {}, el('span', { class: 'tag', text: c.internal ? 'internal' : 'external' })),
      el('td', { class: 'num', text: fmt.duration(c.duration) }),
      el('td', { text: c.user || '—' })));
}

function endpoint(ip, port) {
  if (!ip) return '—';
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

async function renderDestinations() {
  const params = new URLSearchParams({ since: '30d', limit: '300' });
  const q = document.getElementById('dest-search').value.trim();
  if (q) params.set('q', q);
  params.set('order', document.getElementById('dest-order').value);
  if (document.getElementById('dest-flagged').checked) params.set('flagged', 'true');
  if (document.getElementById('dest-new').checked) params.set('new_since', '24h');

  const [data, threats] = await Promise.all([
    api('destinations?' + params.toString()),
    api('threats?since=30d&limit=100'),
  ]);
  document.getElementById('dest-count').textContent = `${(data.destinations || []).length} shown of ${data.total} known`;

  const summary = document.getElementById('threat-summary');
  clear(summary);
  const feeds = threats.feeds || [];
  summary.appendChild(el('p', { class: 'small muted' },
    `${fmt.int(threats.indicators)} indicators from ${feeds.length} feed${feeds.length === 1 ? '' : 's'}. ` +
    (feeds.length === 0 ? 'No feed is configured: iPulse contacts no third party unless you add one.' : '')));
  for (const f of feeds) {
    summary.appendChild(el('div', { class: 'small' },
      `${f.name}: ${fmt.int(f.indicators)} indicators, last success ${fmt.age(f.last_success)}` +
      (f.last_error ? ` — last error: ${f.last_error}` : '')));
  }

  table(document.getElementById('threat-table'),
    [{ label: 'Time' }, { label: 'Destination' }, { label: 'Process' }, { label: 'Indicator' },
     { label: 'Source' }, { label: 'Confidence' }],
    threats.matches || [],
    m => el('tr', {},
      el('td', { text: fmt.datetime(m.time) }),
      el('td', { class: 'mono', text: endpoint(m.remote_ip, m.remote_port) }),
      el('td', { text: m.process || '—' }),
      el('td', { class: 'mono', text: m.indicator }),
      el('td', { text: m.source }),
      el('td', {}, el('span', { class: 'tag flagged', text: m.confidence }))));

  table(document.getElementById('dest-table'),
    [{ label: 'Destination' }, { label: 'Proto' }, { label: 'Reverse DNS' }, { label: 'Organisation' },
     { label: 'Country' }, { label: 'Contacts', num: true }, { label: 'First seen' }, { label: 'Last seen' }, { label: '' }],
    data.destinations || [],
    d => {
      const isNew = (Date.now() - new Date(d.first_seen).getTime()) < 86400000;
      return el('tr', {},
        el('td', { class: 'mono', text: endpoint(d.remote_ip, d.remote_port) }),
        el('td', { text: d.protocol }),
        el('td', { class: 'wrap', text: d.reverse_dns || '—' }),
        el('td', { class: 'wrap', text: d.asn_org || d.asn || '—' }),
        el('td', { text: d.country || '—' }),
        el('td', { class: 'num', text: fmt.int(d.contacts) }),
        el('td', { text: fmt.age(d.first_seen) }),
        el('td', { text: fmt.age(d.last_seen) }),
        el('td', {},
          d.flagged ? el('span', { class: 'tag flagged', text: 'threat match' }) : null,
          isNew ? el('span', { class: 'tag new', text: 'new' }) : null,
          d.internal ? el('span', { class: 'tag', text: 'internal' }) : null));
    });
}

function renderEventList(host, events, compact) {
  clear(host);
  if (!events || events.length === 0) {
    host.appendChild(el('div', { class: 'empty', text: 'No events match this filter.' }));
    return;
  }
  for (const ev of events) {
    const node = el('div', { class: 'event' + (ev.suppressed ? ' suppressed' : '') });
    const head = el('div', { class: 'head' },
      el('span', { class: 'ts', text: fmt.datetime(ev.time) }),
      el('span', { class: 'sev sev-' + ev.severity, text: shortSeverity(ev.severity) }),
      el('span', { class: 'id', text: 'IPULSE-' + ev.code }),
      el('span', { class: 'name', text: ev.name }));
    if (ev.suppressed) head.appendChild(el('span', { class: 'tag', text: 'correlated' }));
    node.appendChild(head);

    if (ev.message) node.appendChild(el('div', { class: 'body', text: ev.message }));
    const fields = ev.fields || {};
    const keys = Object.keys(fields).sort();
    if (keys.length > 0) {
      const body = el('div', { class: 'body' });
      const shown = compact ? keys.slice(0, 6) : keys;
      shown.forEach((k, i) => {
        if (i > 0) body.appendChild(document.createTextNode('  '));
        body.appendChild(el('span', { class: 'field-key', text: k + '=' }));
        body.appendChild(document.createTextNode(fields[k]));
      });
      if (shown.length < keys.length) {
        body.appendChild(document.createTextNode(`  …${keys.length - shown.length} more`));
      }
      node.appendChild(body);
    }
    host.appendChild(node);
  }
}

function shortSeverity(s) {
  return { WARNING: 'WARN', CRITICAL: 'CRIT' }[s] || s;
}

async function renderEvents() {
  const params = new URLSearchParams({
    since: document.getElementById('event-window').value,
    limit: '300',
  });
  const sev = document.getElementById('event-severity').value;
  if (sev) params.set('severity', sev);
  const q = document.getElementById('event-search').value.trim();
  if (q) params.set('q', q);
  const cat = document.getElementById('event-category').value;
  if (cat) params.set('category', cat);
  const code = document.getElementById('event-code').value.trim();
  if (code) params.set('code', code);
  const proc = document.getElementById('event-process').value.trim();
  if (proc) params.set('process', proc);
  const dest = document.getElementById('event-destination').value.trim();
  if (dest) params.set('destination', dest);
  if (document.getElementById('event-suppressed').checked) params.set('include_suppressed', 'true');

  const data = await api('events?' + params.toString());
  const counts = data.by_severity || {};
  document.getElementById('event-summary').textContent =
    `${data.total} matching events. ` +
    Object.entries(counts).map(([k, v]) => `${k.toLowerCase()} ${v}`).join(', ');
  renderEventList(document.getElementById('event-list'), data.events || [], false);

  if ((data.events || []).length > 0) state.lastEventID = data.events[0].id;
}

async function populateCategories() {
  const select = document.getElementById('event-category');
  if (select.options.length > 1) return;
  try {
    const catalog = await api('events/catalog');
    const seen = new Set();
    for (const def of catalog) {
      if (seen.has(def.Category)) continue;
      seen.add(def.Category);
      select.appendChild(el('option', { value: def.Category, text: def.Category.toLowerCase().replace(/_/g, ' ') }));
    }
  } catch { /* the filter still works without the list */ }
}

async function renderDiagnostics() {
  const [tasks, privileges, ifaces, routes, summary] = await Promise.all([
    api('tasks'), api('privileges'), api('interfaces'), api('routes?limit=20'), api('summary'),
  ]);

  table(document.getElementById('task-table'),
    [{ label: 'Task' }, { label: 'Interval' }, { label: 'Runs', num: true }, { label: 'Failures', num: true },
     { label: 'Last run' }, { label: 'Duration', num: true }, { label: 'Next run' }],
    tasks.tasks || [],
    t => el('tr', {},
      el('td', { text: t.name }),
      el('td', { text: t.interval ? fmt.duration(t.interval) : 'manual' }),
      el('td', { class: 'num', text: fmt.int(t.runs) }),
      el('td', { class: 'num', text: fmt.int(t.failures) }),
      el('td', { text: fmt.age(t.last_run) }),
      el('td', { class: 'num', text: fmt.duration(t.last_duration) }),
      el('td', { text: t.next_run ? fmt.time(t.next_run) : '—' })));

  const report = privileges.privileges || {};
  table(document.getElementById('privilege-table'),
    [{ label: 'Feature' }, { label: 'Available' }, { label: 'Requires' }, { label: 'Fallback' }],
    report.features || [],
    f => el('tr', {},
      el('td', { class: 'wrap', text: f.feature }),
      el('td', {}, el('span', { class: 'tag' + (f.available ? '' : ' flagged'), text: f.available ? 'yes' : 'no' })),
      el('td', { class: 'wrap faint', text: f.required }),
      el('td', { class: 'wrap faint', text: f.fallback || '—' })));

  table(document.getElementById('interface-table'),
    [{ label: 'Interface' }, { label: 'Type' }, { label: 'State' }, { label: 'Addresses' },
     { label: 'Speed', num: true }, { label: 'Default' }],
    ifaces.interfaces || [],
    i => el('tr', {},
      el('td', { text: i.name }),
      el('td', { text: i.type }),
      el('td', {}, el('span', { class: 'tag' + (i.up ? '' : ' flagged'), text: i.up ? 'up' : 'down' })),
      el('td', { class: 'wrap mono', text: i.addresses || '—' }),
      el('td', { class: 'num', text: i.speed_mbps ? i.speed_mbps + ' Mbps' : '—' }),
      el('td', { text: i.is_default ? 'yes' : '' })));

  table(document.getElementById('route-table'),
    [{ label: 'Time' }, { label: 'Destination' }, { label: 'Hops', num: true }, { label: 'RTT', num: true }, { label: 'Changed' }],
    routes.paths || [],
    p => el('tr', {},
      el('td', { text: fmt.datetime(p.time) }),
      el('td', { text: p.destination }),
      el('td', { class: 'num', text: fmt.int(p.hop_count) }),
      el('td', { class: 'num', text: fmt.ms(p.rtt_ms) }),
      el('td', {}, p.changed ? el('span', { class: 'tag new', text: 'changed' }) : null)));

  const counts = Object.entries(summary.row_counts || {}).map(([table_, rows]) => ({ table: table_, rows }));
  table(document.getElementById('storage-table'),
    [{ label: 'Table' }, { label: 'Rows', num: true }],
    counts.sort((a, b) => b.rows - a.rows),
    c => el('tr', {}, el('td', { text: c.table }), el('td', { class: 'num', text: fmt.int(c.rows) })));
}

async function runTest(name, button) {
  const output = document.getElementById('test-output');
  clear(output);
  output.appendChild(el('div', { class: 'banner info' },
    el('span', { class: 'spinner' }), ` Running ${name}…`));
  button.disabled = true;
  try {
    const result = await api('tests/' + name, { method: 'POST' });
    clear(output);
    output.appendChild(el('div', { class: 'banner ' + (result.ok ? 'info' : 'error') },
      `${name}: ${result.ok ? 'completed' : 'failed'} in ${result.duration}` +
      (result.error ? ` — ${result.error}` : '')));
    if (result.status) {
      const dl = el('dl', { class: 'kv' });
      const s = result.status;
      const pairs = [
        ['Status', s.status], ['Latency', fmt.ms(s.latency_ms)], ['Jitter', fmt.ms(s.jitter_ms)],
        ['Packet loss', fmt.pct(s.packet_loss_pct)], ['Download', fmt.mbps(s.download_mbps) + ' Mbps'],
        ['Upload', fmt.mbps(s.upload_mbps) + ' Mbps'], ['Public IP', s.public_ipv4 || '—'],
      ];
      for (const [k, v] of pairs) { dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', { text: String(v) })); }
      output.appendChild(dl);
    }
  } catch (err) {
    clear(output);
    output.appendChild(el('div', { class: 'banner error', text: `${name}: ${err.message}` }));
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------- top bar

function renderTopStatus(status) {
  const host = document.getElementById('topstatus');
  clear(host);
  if (!status) return;

  const cls = { ONLINE: 'online', DEGRADED: 'degraded', OFFLINE: 'offline' }[status.status] || 'unknown';
  host.appendChild(el('span', { class: 'pill ' + cls },
    el('span', { class: 'dot' }), status.status || 'UNKNOWN'));

  if (status.health_score) {
    host.appendChild(el('span', { class: 'small muted', text: `health ${status.health_score.toFixed(0)}/100` }));
  }
  if (status.latency_ms) {
    host.appendChild(el('span', { class: 'small muted', text: `${fmt.ms(status.latency_ms)}` }));
  }
  if (status.download_mbps) {
    host.appendChild(el('span', { class: 'small muted', text: `${fmt.mbps(status.download_mbps)} Mbps` }));
  }
  document.getElementById('foot-status').textContent =
    `iPulse ${status.version || ''} · ${status.platform || ''} · uptime ${fmt.duration(status.uptime)} · ` +
    `data stays on this host`;
}

// ---------------------------------------------------------------- routing

const VIEWS = {
  overview: renderOverview,
  speed: renderSpeed,
  latency: renderLatency,
  availability: renderAvailability,
  traffic: renderTraffic,
  connections: renderConnections,
  destinations: renderDestinations,
  events: renderEvents,
  diagnostics: renderDiagnostics,
};

async function show(view) {
  if (!VIEWS[view]) view = 'overview';
  state.view = view;

  for (const section of document.querySelectorAll('section.view')) {
    section.classList.toggle('active', section.id === 'view-' + view);
  }
  for (const tab of document.querySelectorAll('nav.tabs a')) {
    tab.classList.toggle('active', tab.getAttribute('href') === '#' + view);
  }
  await refresh();
}

async function refresh() {
  try {
    banner('', '');
    await VIEWS[state.view]();
    // The top bar is refreshed from whatever the view already fetched where possible.
    if (state.view !== 'overview') {
      state.status = await api('status');
    }
    renderTopStatus(state.status);
  } catch (err) {
    banner('error', 'Could not load data: ' + err.message);
  }
}

function scheduleRefresh() {
  if (state.timer) clearInterval(state.timer);
  // Ten seconds is frequent enough to feel live without generating pointless load on a
  // machine whose job is to measure the network, not to serve a dashboard.
  state.timer = setInterval(() => {
    if (document.hidden) return;
    refresh().catch(() => { /* the banner already reports it */ });
  }, 10000);
}

function bind() {
  window.addEventListener('hashchange', () => show(location.hash.slice(1)));

  for (const id of ['speed-window', 'latency-window', 'traffic-window', 'traffic-interface',
    'conn-window', 'conn-protocol', 'conn-scope', 'event-severity', 'event-window',
    'event-category', 'dest-order']) {
    const node = document.getElementById(id);
    if (node) node.addEventListener('change', () => refresh());
  }
  for (const id of ['dest-flagged', 'dest-new', 'event-suppressed']) {
    const node = document.getElementById(id);
    if (node) node.addEventListener('change', () => refresh());
  }
  for (const id of ['conn-refresh', 'dest-refresh', 'event-refresh']) {
    const node = document.getElementById(id);
    if (node) node.addEventListener('click', () => refresh());
  }
  // Search boxes refresh on Enter rather than on every keystroke, so typing does not
  // generate a query per character.
  for (const id of ['conn-search', 'dest-search', 'event-search', 'event-code',
    'event-process', 'event-destination']) {
    const node = document.getElementById(id);
    if (node) node.addEventListener('keydown', e => { if (e.key === 'Enter') refresh(); });
  }

  const follow = document.getElementById('event-follow');
  if (follow) {
    follow.addEventListener('change', () => {
      if (state.followTimer) { clearInterval(state.followTimer); state.followTimer = null; }
      if (follow.checked) {
        state.followTimer = setInterval(() => {
          if (state.view === 'events' && !document.hidden) renderEvents().catch(() => {});
        }, 3000);
      }
    });
  }

  for (const button of document.querySelectorAll('#test-buttons button')) {
    button.addEventListener('click', () => runTest(button.dataset.test, button));
  }

  // Charts are drawn to the element's measured size, so a resize needs a redraw.
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => refresh().catch(() => {}), 250);
  });
}

async function init() {
  bind();
  populateCategories();
  try {
    const status = await api('status');
    state.status = status;
    document.getElementById('version').textContent = status.version || '';
    renderTopStatus(status);
  } catch (err) {
    banner('error', 'Cannot reach the iPulse API: ' + err.message);
  }
  await show(location.hash.slice(1) || 'overview');
  scheduleRefresh();
}

init();
