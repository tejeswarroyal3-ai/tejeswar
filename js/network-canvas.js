/**
 * Aegis-DL: Dynamic Cyber Network & Neural Particle Graph
 * Interactive background simulating network topology, packet flow, and anomaly spikes
 */

(function () {
  const canvas = document.getElementById('networkCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initNodes();
  });

  const mouse = {
    x: width / 2,
    y: height / 2,
    radius: 160,
    isHovered: false
  };

  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.isHovered = true;
  });

  window.addEventListener('mouseleave', () => {
    mouse.isHovered = false;
  });

  const NODE_COUNT = Math.min(Math.floor((width * height) / 16000), 75);
  let nodes = [];
  let packets = [];

  class NetworkNode {
    constructor(x, y) {
      this.x = x || Math.random() * width;
      this.y = y || Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.45;
      this.vy = (Math.random() - 0.5) * 0.45;
      this.baseRadius = Math.random() * 2 + 2;
      this.radius = this.baseRadius;
      this.isGateway = Math.random() < 0.12;
      this.isAnomalous = false;
      this.anomalyTimer = 0;
      this.color = this.isGateway ? '#8b5cf6' : '#00f0ff';
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0 || this.x > width) this.vx *= -1;
      if (this.y < 0 || this.y > height) this.vy *= -1;

      // Mouse repulsion/attraction effect
      if (mouse.isHovered) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          this.x -= (dx / dist) * force * 1.5;
          this.y -= (dy / dist) * force * 1.5;
        }
      }

      if (this.isAnomalous) {
        this.anomalyTimer--;
        if (this.anomalyTimer <= 0) {
          this.isAnomalous = false;
          this.color = this.isGateway ? '#8b5cf6' : '#00f0ff';
        }
      }
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = this.isAnomalous ? '#f43f5e' : this.color;
      ctx.shadowColor = this.isAnomalous ? '#f43f5e' : this.color;
      ctx.shadowBlur = this.isGateway || this.isAnomalous ? 12 : 5;
      ctx.fill();
      ctx.shadowBlur = 0;

      if (this.isGateway || this.isAnomalous) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius * 2.2, 0, Math.PI * 2);
        ctx.strokeStyle = this.isAnomalous ? 'rgba(244, 63, 94, 0.4)' : 'rgba(139, 92, 246, 0.35)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }

    triggerAnomaly() {
      this.isAnomalous = true;
      this.anomalyTimer = 180; // 3 seconds at 60fps
      this.color = '#f43f5e';
    }
  }

  class Packet {
    constructor(fromNode, toNode, isAttack = false) {
      this.from = fromNode;
      this.to = toNode;
      this.progress = 0;
      this.speed = Math.random() * 0.012 + 0.008;
      this.isAttack = isAttack;
    }

    update() {
      this.progress += this.speed;
      return this.progress < 1;
    }

    draw() {
      const currentX = this.from.x + (this.to.x - this.from.x) * this.progress;
      const currentY = this.from.y + (this.to.y - this.from.y) * this.progress;

      ctx.beginPath();
      ctx.arc(currentX, currentY, this.isAttack ? 3 : 2, 0, Math.PI * 2);
      ctx.fillStyle = this.isAttack ? '#f43f5e' : '#38bdf8';
      ctx.shadowColor = this.isAttack ? '#f43f5e' : '#38bdf8';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function initNodes() {
    nodes = [];
    for (let i = 0; i < NODE_COUNT; i++) {
      nodes.push(new NetworkNode());
    }
  }

  initNodes();

  // Periodically spawn packets along edges
  setInterval(() => {
    if (nodes.length < 2) return;
    const from = nodes[Math.floor(Math.random() * nodes.length)];
    // Find closest neighbor
    let closest = null;
    let minD = 180;
    nodes.forEach((n) => {
      if (n !== from) {
        const d = Math.hypot(n.x - from.x, n.y - from.y);
        if (d < minD) {
          minD = d;
          closest = n;
        }
      }
    });

    if (closest && packets.length < 25) {
      const isAttack = Math.random() < 0.2;
      packets.push(new Packet(from, closest, isAttack));
      if (isAttack && Math.random() < 0.3) {
        from.triggerAnomaly();
      }
    }
  }, 350);

  function animate() {
    ctx.clearRect(0, 0, width, height);

    // Draw neural edges between nearby nodes
    const maxDistance = 140;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.hypot(dx, dy);

        if (dist < maxDistance) {
          const alpha = (1 - dist / maxDistance) * 0.18;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);

          if (nodes[i].isAnomalous || nodes[j].isAnomalous) {
            ctx.strokeStyle = `rgba(244, 63, 94, ${alpha * 1.8})`;
          } else {
            ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
          }
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }
    }

    // Update and draw nodes
    nodes.forEach((node) => {
      node.update();
      node.draw();
    });

    // Update and draw packets
    packets = packets.filter((packet) => {
      const active = packet.update();
      if (active) packet.draw();
      return active;
    });

    requestAnimationFrame(animate);
  }

  animate();

  // Expose function to trigger custom network alert simulation
  window.triggerGlobalNetworkAlert = function () {
    const anomalousNodes = nodes.filter((n) => Math.random() < 0.4);
    anomalousNodes.forEach((n) => n.triggerAnomaly());
  };
})();
