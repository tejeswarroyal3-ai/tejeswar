/**
 * Aegis-DL: Global Threat Telemetry Geo-Map
 * High-performance canvas-based world map visualizing live attack arcs,
 * zero-day origins, sensor nodes, and real-time mitigation telemetry.
 */

(function () {
  const canvas = document.getElementById('threatGeoMap');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = canvas.parentElement.clientWidth);
  let height = (canvas.height = 360);

  window.addEventListener('resize', () => {
    if (!canvas.parentElement) return;
    width = canvas.width = canvas.parentElement.clientWidth;
    height = canvas.height = 360;
  });

  // Enterprise Sensor Hubs (Target nodes)
  const sensors = [
    { name: "US-East (N. Virginia)", x: 0.28, y: 0.38, ip: "192.0.2.1", status: "Protected", zeroDaysBlocked: 14 },
    { name: "EU-Central (Frankfurt)", x: 0.52, y: 0.32, ip: "198.51.100.8", status: "Protected", zeroDaysBlocked: 28 },
    { name: "AP-East (Tokyo)", x: 0.86, y: 0.40, ip: "203.0.113.12", status: "Protected", zeroDaysBlocked: 19 },
    { name: "AP-South (Mumbai)", x: 0.70, y: 0.50, ip: "198.51.100.45", status: "Protected", zeroDaysBlocked: 9 },
    { name: "AP-Southeast (Singapore)", x: 0.78, y: 0.60, ip: "203.0.113.88", status: "Protected", zeroDaysBlocked: 22 },
    { name: "SA-East (São Paulo)", x: 0.35, y: 0.75, ip: "192.0.2.99", status: "Protected", zeroDaysBlocked: 7 }
  ];

  // Attack Origin Candidates
  const attackOrigins = [
    { x: 0.18, y: 0.32, country: "US-West" },
    { x: 0.48, y: 0.26, country: "Northern Europe" },
    { x: 0.64, y: 0.28, country: "Central Asia" },
    { x: 0.75, y: 0.36, country: "East Asia" },
    { x: 0.55, y: 0.62, country: "Central Africa" },
    { x: 0.38, y: 0.68, country: "South America" }
  ];

  let attackArcs = [];
  let filterMode = 'all'; // 'all', 'zeroday', 'known'

  class AttackArc {
    constructor(origin, target, isZeroDay) {
      this.origin = origin;
      this.target = target;
      this.isZeroDay = isZeroDay;
      this.progress = 0;
      this.speed = Math.random() * 0.015 + 0.012;
      this.color = isZeroDay ? '#f43f5e' : '#f59e0b';
    }

    update() {
      this.progress += this.speed;
      return this.progress < 1;
    }

    draw() {
      const x1 = this.origin.x * width;
      const y1 = this.origin.y * height;
      const x2 = this.target.x * width;
      const y2 = this.target.y * height;

      // Bezier curve arc
      const cx = (x1 + x2) / 2;
      const cy = Math.min(y1, y2) - 50;

      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.quadraticCurveTo(cx, cy, x2, y2);
      ctx.strokeStyle = this.isZeroDay ? 'rgba(244, 63, 94, 0.25)' : 'rgba(245, 158, 11, 0.2)';
      ctx.lineWidth = this.isZeroDay ? 2 : 1.5;
      ctx.stroke();

      // Traveling packet dot
      const t = this.progress;
      const curX = (1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * cx + t * t * x2;
      const curY = (1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * cy + t * t * y2;

      ctx.beginPath();
      ctx.arc(curX, curY, this.isZeroDay ? 3.5 : 2.5, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.shadowColor = this.color;
      ctx.shadowBlur = 10;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function spawnAttack() {
    const origin = attackOrigins[Math.floor(Math.random() * attackOrigins.length)];
    const target = sensors[Math.floor(Math.random() * sensors.length)];
    const isZeroDay = Math.random() < 0.45;

    if (filterMode === 'zeroday' && !isZeroDay) return;
    if (filterMode === 'known' && isZeroDay) return;

    if (attackArcs.length < 18) {
      attackArcs.push(new AttackArc(origin, target, isZeroDay));
      if (isZeroDay) {
        target.zeroDaysBlocked++;
        updateSensorInfo(target);
      }
    }
  }

  function updateSensorInfo(sensor) {
    const el = document.getElementById('geoMapSelectedSensor');
    if (!el) return;
    el.innerHTML = `
      <div style="font-weight:700; color:var(--text-primary); font-size:0.9rem;">📍 ${sensor.name}</div>
      <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">IP: ${sensor.ip} | Aegis eBPF Hook Active</div>
      <div style="font-size:0.8rem; color:var(--emerald-primary); margin-top:2px;">Zero-Days Blocked: <strong style="color:#f43f5e;">${sensor.zeroDaysBlocked}</strong></div>
    `;
  }

  // Draw simplified high-tech world continent dots
  function drawMapGrid() {
    ctx.fillStyle = 'rgba(15, 23, 42, 0.5)';
    ctx.fillRect(0, 0, width, height);

    // Subtle coordinate lines
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.06)';
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Draw sensors
    sensors.forEach((s) => {
      const sx = s.x * width;
      const sy = s.y * height;

      // Outer ripple
      ctx.beginPath();
      ctx.arc(sx, sy, 8, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.4)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Inner core
      ctx.beginPath();
      ctx.arc(sx, sy, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#00f0ff';
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Label
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillStyle = '#94a3b8';
      ctx.fillText(s.name.split(' ')[0], sx + 10, sy + 3);
    });
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);
    drawMapGrid();

    attackArcs = attackArcs.filter((arc) => {
      const active = arc.update();
      if (active) arc.draw();
      return active;
    });

    requestAnimationFrame(animate);
  }

  setInterval(spawnAttack, 450);
  animate();

  // Expose filter switcher
  window.setGeoMapFilter = function (mode, btn) {
    filterMode = mode;
    document.querySelectorAll('[data-geomap-filter]').forEach((b) => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
  };

  // Expose click sensor inspection
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    let found = null;
    sensors.forEach((s) => {
      const sx = s.x * width;
      const sy = s.y * height;
      if (Math.hypot(clickX - sx, clickY - sy) < 18) {
        found = s;
      }
    });

    if (found) {
      updateSensorInfo(found);
      if (window.cyberAudio) window.cyberAudio.playBeep(784, 'sine', 0.1);
    }
  });

  // Init initial sensor info
  updateSensorInfo(sensors[0]);
})();
