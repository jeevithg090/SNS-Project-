/**
 * UI controller for the DoS firewall simulator.
 *
 * Generates legitimate and attack traffic, feeds it through RateLimitFirewall
 * (rate-limiter.js) and renders the results. Packets can arrive at up to
 * ~2,000/s, so DOM work is batched: packets are queued and flushed a few
 * times per second instead of touching the DOM per packet.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  // ─── Constants ─────────────────────────────────────────────────────
  const ATTACKER_IPS = [
    '192.168.1.101', '10.0.0.44', '172.16.0.9', '192.168.0.250',
    '10.10.10.10', '203.0.113.77', '198.51.100.3',
  ];
  const LEGIT_IPS = ['192.168.1.5', '10.0.0.1', '172.20.0.3', '192.168.2.10'];
  const LEGIT_INTERVAL_MS = 800;
  const STATS_INTERVAL_MS = 500;
  const HISTORY_LENGTH = 40;
  const MAX_LOG = 80;
  const CHART_MIN_SCALE = 25; // pkt/s
  const THEME_KEY = 'dos-sim-theme';
  const numberFormat = new Intl.NumberFormat();

  // ─── Theme toggle (works even if the engine failed to load) ───────
  const themeToggle = $('theme-toggle');
  function syncThemeButton() {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    themeToggle.setAttribute('aria-label', `Switch to ${next} theme`);
    themeToggle.title = `Switch to ${next} theme`;
  }
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* ignore */ }
    syncThemeButton();
  });
  syncThemeButton();

  // ─── Elements ──────────────────────────────────────────────────────
  const el = {
    banner: $('status-banner'),
    statusTitle: $('status-title'),
    statusDetail: $('status-detail'),
    uptime: $('uptime'),
    total: $('stat-total'),
    allowed: $('stat-allowed'),
    blocked: $('stat-blocked'),
    ips: $('stat-ips'),
    rate: $('stat-rate'),
    rateSlider: $('sl-rate'),
    banSlider: $('sl-ban'),
    intensitySlider: $('sl-intensity'),
    rateOut: $('out-rate'),
    banOut: $('out-ban'),
    intensityOut: $('out-intensity'),
    intensityPps: $('intensity-pps'),
    attackBtn: $('btn-attack'),
    stopBtn: $('btn-stop'),
    resetBtn: $('btn-reset'),
    chart: $('traffic-bars'),
    chartPeak: $('chart-peak'),
    log: $('log-body'),
    logEmpty: $('log-empty'),
    logMax: $('log-max'),
    registry: $('registry-body'),
    registryEmpty: $('registry-empty'),
    registryCount: $('registry-count'),
  };

  if (typeof window.RateLimitFirewall !== 'function') {
    $('load-error').hidden = false;
    el.banner.dataset.state = 'error';
    el.statusTitle.textContent = 'Engine unavailable';
    el.statusDetail.textContent = 'The simulation cannot start because rate-limiter.js did not load.';
    for (const control of [el.attackBtn, el.stopBtn, el.resetBtn, el.rateSlider, el.banSlider, el.intensitySlider]) {
      control.disabled = true;
    }
    return;
  }

  // ─── State ─────────────────────────────────────────────────────────
  const firewall = new window.RateLimitFirewall({
    rateLimit: Number(el.rateSlider.value),
    banThreshold: Number(el.banSlider.value),
    windowMs: 1000,
  });

  let attackTimer = null;
  let isAttacking = false;
  let stats = freshStats();
  let history = new Array(HISTORY_LENGTH).fill(0);
  let lastRateSample = Date.now();
  const startTime = Date.now();

  let pendingLog = [];          // packets waiting to be rendered
  let flushScheduled = false;
  /** @type {Map<string, {countEl: HTMLElement, blocked: number}>} */
  const banned = new Map();

  function freshStats() {
    return { total: 0, allowed: 0, blocked: 0, rate: 0, sinceSample: 0, attackBlocked: 0 };
  }

  // ─── Traffic generation ────────────────────────────────────────────
  const pick = (list) => list[Math.floor(Math.random() * list.length)];

  /** Attack timing for an intensity level (1–5): faster ticks and bigger bursts. */
  function attackProfile(intensity) {
    const intervalMs = Math.max(10, 80 - intensity * 14);
    const packetsPerTick = intensity * 4;
    return { intervalMs, packetsPerTick, perSecond: Math.round((packetsPerTick * 1000) / intervalMs) };
  }

  function sendPacket(ip, fromAttacker) {
    const result = firewall.processPacket(ip, Date.now());
    stats.total++;
    stats.sinceSample++;
    if (result.action === 'ALLOW') {
      stats.allowed++;
    } else {
      stats.blocked++;
      if (fromAttacker) stats.attackBlocked++;
      if (firewall.bannedIPs.has(ip)) recordBan(ip);
    }
    pendingLog.push({ ip, action: result.action, reason: result.reason, time: new Date() });
    if (pendingLog.length > MAX_LOG) pendingLog = pendingLog.slice(-MAX_LOG);
    scheduleFlush();
  }

  function startAttack() {
    if (isAttacking) return;
    isAttacking = true;
    const { intervalMs, packetsPerTick } = attackProfile(Number(el.intensitySlider.value));
    attackTimer = setInterval(() => {
      for (let i = 0; i < packetsPerTick; i++) sendPacket(pick(ATTACKER_IPS), true);
    }, intervalMs);
    syncControls();
    setStatus('attack', 'Under attack', 'SYN flood in progress from 7 attacker IPs. Watch the registry as the rate limiter bans them.');
  }

  function stopAttack({ announce = true } = {}) {
    if (!isAttacking) return;
    isAttacking = false;
    clearInterval(attackTimer);
    attackTimer = null;
    syncControls();
    if (announce) {
      const bans = firewall.bannedIPs.size;
      setStatus(
        'stopped',
        'Attack stopped',
        `${numberFormat.format(stats.attackBlocked)} attack packets blocked and ${bans} attacker ${bans === 1 ? 'IP' : 'IPs'} banned. Legitimate traffic is still flowing.`,
      );
    }
  }

  function resetAll() {
    stopAttack({ announce: false });
    firewall.reset();
    stats = freshStats();
    history = new Array(HISTORY_LENGTH).fill(0);
    pendingLog = [];
    banned.clear();
    el.log.replaceChildren(el.logEmpty);
    el.registry.replaceChildren(el.registryEmpty);
    renderStats();
    renderChart();
    renderRegistryCount();
    setStatus('idle', 'Firewall active', 'Simulation reset. Counters, bans and the log are cleared.');
  }

  // ─── Rendering ─────────────────────────────────────────────────────
  function setStatus(state, title, detail) {
    el.banner.dataset.state = state;
    el.statusTitle.textContent = title;
    el.statusDetail.textContent = detail;
  }

  function syncControls() {
    el.attackBtn.setAttribute('aria-pressed', String(isAttacking));
    el.attackBtn.querySelector('span').textContent = isAttacking ? 'Attack running' : 'Launch attack';
    el.stopBtn.disabled = !isAttacking;
  }

  // Flush at most ~8 times per second: fast enough to feel live, slow enough to read.
  const FLUSH_INTERVAL_MS = 120;
  function scheduleFlush() {
    if (flushScheduled) return;
    flushScheduled = true;
    setTimeout(() => requestAnimationFrame(flushLog), FLUSH_INTERVAL_MS);
  }

  function flushLog() {
    flushScheduled = false;
    if (!pendingLog.length) return;
    el.logEmpty.remove();
    const fragment = document.createDocumentFragment();
    // Newest first.
    for (let i = pendingLog.length - 1; i >= 0; i--) fragment.append(logRow(pendingLog[i]));
    pendingLog = [];
    el.log.prepend(fragment);
    while (el.log.children.length > MAX_LOG) el.log.lastElementChild.remove();
  }

  function logRow({ ip, action, reason, time }) {
    const row = document.createElement('div');
    row.className = `log-row ${action === 'ALLOW' ? 'allow' : 'block'}`;
    row.append(
      span('log-time', time.toLocaleTimeString([], { hour12: false })),
      span('log-ip', ip),
      span('log-action', action),
      span('log-msg', reason),
    );
    return row;
  }

  function span(className, text) {
    const node = document.createElement('span');
    node.className = className;
    node.textContent = text;
    return node;
  }

  function recordBan(ip) {
    let entry = banned.get(ip);
    if (!entry) {
      el.registryEmpty.remove();
      const card = document.createElement('div');
      card.className = 'ban';
      const countEl = span('ban-meta', '');
      card.append(
        span('ban-ip', ip),
        span('tag tag-danger', 'Banned'),
        countEl,
      );
      el.registry.prepend(card);
      entry = { countEl, blocked: 0, since: new Date().toLocaleTimeString([], { hour12: false }) };
      banned.set(ip, entry);
      renderRegistryCount();
      el.statusDetail.textContent = `Banned ${ip}. ${banned.size} of ${ATTACKER_IPS.length} attacker IPs banned so far.`;
    }
    entry.blocked++;
    entry.countEl.textContent = `since ${entry.since} · ${numberFormat.format(entry.blocked)} packets dropped`;
  }

  function renderRegistryCount() {
    el.registryCount.textContent = `${banned.size} banned`;
  }

  function renderStats() {
    el.total.textContent = numberFormat.format(stats.total);
    el.allowed.textContent = numberFormat.format(stats.allowed);
    el.blocked.textContent = numberFormat.format(stats.blocked);
    el.ips.textContent = numberFormat.format(firewall.bannedIPs.size);
    el.rate.textContent = numberFormat.format(stats.rate);
  }

  const bars = Array.from({ length: HISTORY_LENGTH }, () => {
    const bar = document.createElement('div');
    bar.className = 'bar';
    return bar;
  });
  el.chart.append(...bars);

  function renderChart() {
    const peak = Math.max(...history);
    // A floor on the scale keeps idle background traffic from filling the chart.
    const scale = Math.max(peak, CHART_MIN_SCALE);
    history.forEach((value, i) => {
      const ratio = value / scale;
      bars[i].style.height = `${Math.max(2, ratio * 100)}%`;
      bars[i].dataset.level = ratio > 0.7 ? 'high' : ratio > 0.3 ? 'mid' : 'low';
    });
    el.chartPeak.textContent = numberFormat.format(peak);
  }

  // ─── Controls ──────────────────────────────────────────────────────
  function renderSliderOutputs() {
    const rate = Number(el.rateSlider.value);
    const ban = Number(el.banSlider.value);
    const intensity = Number(el.intensitySlider.value);
    el.rateOut.textContent = `${rate} pkt/s`;
    el.banOut.textContent = `${ban} ${ban === 1 ? 'violation' : 'violations'}`;
    el.intensityOut.textContent = `${intensity} / 5`;
    el.intensityPps.textContent = numberFormat.format(attackProfile(intensity).perSecond);
    el.rateSlider.setAttribute('aria-valuetext', `${rate} packets per second`);
    el.banSlider.setAttribute('aria-valuetext', `${ban} ${ban === 1 ? 'violation' : 'violations'}`);
    el.intensitySlider.setAttribute('aria-valuetext', `level ${intensity} of 5`);
  }

  el.rateSlider.addEventListener('input', () => {
    firewall.rateLimit = Number(el.rateSlider.value);
    renderSliderOutputs();
  });
  el.banSlider.addEventListener('input', () => {
    firewall.banThreshold = Number(el.banSlider.value);
    renderSliderOutputs();
  });
  el.intensitySlider.addEventListener('input', () => {
    renderSliderOutputs();
    if (isAttacking) {
      // Restart the flood at the new rate without changing the status message.
      clearInterval(attackTimer);
      isAttacking = false;
      startAttack();
    }
  });

  // The launch button is a toggle: pressing it again stops the attack.
  el.attackBtn.addEventListener('click', () => (isAttacking ? stopAttack() : startAttack()));
  el.stopBtn.addEventListener('click', () => {
    stopAttack();
    el.attackBtn.focus();
  });
  el.resetBtn.addEventListener('click', resetAll);

  document.querySelectorAll('input[name="log-filter"]').forEach((radio) => {
    radio.addEventListener('change', () => { el.log.dataset.filter = radio.value; });
  });

  // ─── Timers ────────────────────────────────────────────────────────
  setInterval(() => sendPacket(pick(LEGIT_IPS), false), LEGIT_INTERVAL_MS);

  setInterval(() => {
    const now = Date.now();
    const elapsed = Math.max((now - lastRateSample) / 1000, 0.1);
    stats.rate = Math.round(stats.sinceSample / elapsed);
    stats.sinceSample = 0;
    lastRateSample = now;
    history.push(stats.rate);
    if (history.length > HISTORY_LENGTH) history.shift();
    renderStats();
    renderChart();
  }, STATS_INTERVAL_MS);

  setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000);
    const pad = (n) => String(n).padStart(2, '0');
    el.uptime.textContent = `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
  }, 1000);

  // ─── Init ──────────────────────────────────────────────────────────
  el.logMax.textContent = MAX_LOG;
  renderSliderOutputs();
  renderChart();
  syncControls();
})();
