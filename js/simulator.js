/**
 * Aegis-DL: Interactive Zero-Day Threat Detection Simulator
 * Models the inference flow of the Hybrid Deep Learning IDS:
 * 1. Feature Preprocessing & Tensor Encoding
 * 2. Spatial-Temporal Convolutional BiLSTM
 * 3. Latent Manifold Reconstruction Error (VAE / Autoencoder)
 * 4. Open-Set Recognition (Extreme Value Theory / Mahalanobis Distance)
 * 5. SHAP Feature Attribution & Dynamic eBPF Mitigation Rule Synthesis
 */

const AttackPresets = {
  zeroday_c2: {
    name: "Zero-Day APT Stealth C2 Beaconing",
    tag: "Zero-Day Exploit",
    type: "zeroday",
    entropy: 7.82,
    duration: 1840,
    jitter: 84.5,
    bytes: 4920,
    synAckRatio: 1.05,
    latentDist: 9.42,
    proto: "TCP/443 (Encrypted Tunnel)",
    srcIp: "198.51.100.42",
    dstIp: "10.0.4.15",
    description: "Novel polymorphic C2 channel using timing-jittered heartbeat with pseudo-TLS framing not observed in training distribution."
  },
  polymorphic_ransomware: {
    name: "Polymorphic Ransomware Lateral Movement",
    tag: "Zero-Day Exploit",
    type: "zeroday",
    entropy: 7.95,
    duration: 410,
    jitter: 12.2,
    bytes: 142000,
    synAckRatio: 2.8,
    latentDist: 8.85,
    proto: "SMB/445 (RPC Obfuscated)",
    srcIp: "172.16.8.109",
    dstIp: "172.16.8.254",
    description: "Rapid lateral scanning and automated token theft utilizing an unpatched SMB v3 buffer overflow."
  },
  known_ddos: {
    name: "Mirai-Class Distributed SYN Flood",
    tag: "Known Attack",
    type: "known",
    entropy: 2.15,
    duration: 85,
    jitter: 1.8,
    bytes: 284000,
    synAckRatio: 98.4,
    latentDist: 3.12,
    proto: "TCP/80 (SYN Flood)",
    srcIp: "185.220.101.5",
    dstIp: "10.0.1.50",
    description: "High-volume symmetric SYN flood matching established supervised signature manifold with 99.7% classifier match."
  },
  known_sqli: {
    name: "Obfuscated Web Application Exploit",
    tag: "Known Attack",
    type: "known",
    entropy: 5.64,
    duration: 290,
    jitter: 14.5,
    bytes: 8400,
    synAckRatio: 1.1,
    latentDist: 4.2,
    proto: "HTTP/8080 (REST API)",
    srcIp: "203.0.113.88",
    dstIp: "10.0.2.10",
    description: "Multi-encoded SQL injection payload targeting authorization middleware."
  },
  benign_stream: {
    name: "Benign Corporate Video / TLS Stream",
    tag: "Benign Traffic",
    type: "benign",
    entropy: 6.12,
    duration: 1240,
    jitter: 8.5,
    bytes: 65400,
    synAckRatio: 0.98,
    latentDist: 1.45,
    proto: "TLS 1.3 / UDP 443 (QUIC)",
    srcIp: "10.0.3.45",
    dstIp: "142.250.190.46",
    description: "Standard WebRTC/QUIC multimedia stream conforming closely to normal latent manifold distribution."
  }
};

class ThreatSimulator {
  constructor() {
    this.currentPreset = 'zeroday_c2';
    this.tauThreshold = 5.0; // Anomaly threshold
    this.initElements();
    this.bindEvents();
    this.loadPreset('zeroday_c2');
  }

  initElements() {
    this.entropySlider = document.getElementById('simEntropy');
    this.entropyVal = document.getElementById('simEntropyVal');
    this.durationSlider = document.getElementById('simDuration');
    this.durationVal = document.getElementById('simDurationVal');
    this.jitterSlider = document.getElementById('simJitter');
    this.jitterVal = document.getElementById('simJitterVal');
    this.latentSlider = document.getElementById('simLatent');
    this.latentVal = document.getElementById('simLatentVal');
    this.tauSlider = document.getElementById('simTau');
    this.tauVal = document.getElementById('simTauVal');

    this.verdictBox = document.getElementById('simVerdictBox');
    this.verdictIcon = document.getElementById('simVerdictIcon');
    this.verdictTitle = document.getElementById('simVerdictTitle');
    this.verdictBadge = document.getElementById('simVerdictBadge');
    this.verdictSub = document.getElementById('simVerdictSub');

    this.anomalyScoreEl = document.getElementById('simAnomalyScore');
    this.confidenceEl = document.getElementById('simConfidence');
    this.latencyEl = document.getElementById('simLatency');

    this.shapContainer = document.getElementById('simShapBars');
    this.mitigationCode = document.getElementById('simMitigationCode');
    this.simAnalyzeBtn = document.getElementById('simAnalyzeBtn');
  }

  bindEvents() {
    // Preset buttons
    document.querySelectorAll('[data-preset]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        document.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.loadPreset(btn.getAttribute('data-preset'));
      });
    });

    // Slider input listeners
    const sliders = [
      { el: this.entropySlider, valEl: this.entropyVal, suffix: ' bits' },
      { el: this.durationSlider, valEl: this.durationVal, suffix: ' ms' },
      { el: this.jitterSlider, valEl: this.jitterVal, suffix: ' %' },
      { el: this.latentSlider, valEl: this.latentVal, suffix: ' σ' },
      { el: this.tauSlider, valEl: this.tauVal, suffix: ' σ' }
    ];

    sliders.forEach(({ el, valEl, suffix }) => {
      if (!el) return;
      el.addEventListener('input', () => {
        valEl.textContent = el.value + suffix;
        if (el === this.tauSlider) {
          this.tauThreshold = parseFloat(el.value);
        }
      });
    });

    if (this.simAnalyzeBtn) {
      this.simAnalyzeBtn.addEventListener('click', () => {
        this.runInference();
      });
    }
  }

  loadPreset(presetKey) {
    const p = AttackPresets[presetKey];
    if (!p) return;
    this.currentPreset = presetKey;

    if (this.entropySlider) this.entropySlider.value = p.entropy;
    if (this.entropyVal) this.entropyVal.textContent = p.entropy + ' bits';

    if (this.durationSlider) this.durationSlider.value = p.duration;
    if (this.durationVal) this.durationVal.textContent = p.duration + ' ms';

    if (this.jitterSlider) this.jitterSlider.value = p.jitter;
    if (this.jitterVal) this.jitterVal.textContent = p.jitter + ' %';

    if (this.latentSlider) this.latentSlider.value = p.latentDist;
    if (this.latentVal) this.latentVal.textContent = p.latentDist + ' σ';

    this.runInference(p);
  }

  runInference(presetOverride = null) {
    const entropy = parseFloat(this.entropySlider ? this.entropySlider.value : 7.5);
    const duration = parseFloat(this.durationSlider ? this.durationSlider.value : 1000);
    const jitter = parseFloat(this.jitterSlider ? this.jitterSlider.value : 50);
    const latentDist = parseFloat(this.latentSlider ? this.latentSlider.value : 8.5);
    const threshold = this.tauThreshold;

    const preset = presetOverride || AttackPresets[this.currentPreset] || AttackPresets.zeroday_c2;

    // Button animation
    if (this.simAnalyzeBtn) {
      this.simAnalyzeBtn.innerHTML = `<span class="spinner-border"></span> Deep Learning Inference...`;
      this.simAnalyzeBtn.disabled = true;
    }

    setTimeout(() => {
      if (this.simAnalyzeBtn) {
        this.simAnalyzeBtn.innerHTML = `<span>⚡ Run Hybrid Model Inference</span>`;
        this.simAnalyzeBtn.disabled = false;
      }

      // Hybrid Inference Logic:
      // 1. Latent Reconstruction & Open-Set Distance
      const isReconstructionAnomaly = latentDist > threshold;
      const isEntropyAbnormal = entropy > 7.4 || entropy < 2.5;

      let classification = 'benign';
      let confidence = 0;
      let anomalyScore = (latentDist / 12) * 100;
      anomalyScore = Math.min(Math.max(anomalyScore, 2.5), 99.8).toFixed(1);

      if (latentDist > threshold) {
        if (latentDist > 7.0 || jitter > 60) {
          classification = 'zeroday';
          confidence = (92.5 + Math.random() * 6).toFixed(1);
        } else {
          classification = 'known';
          confidence = (94.0 + Math.random() * 5).toFixed(1);
        }
      } else {
        if (entropy < 2.5 && latentDist > 3.0) {
          classification = 'known';
          confidence = (96.5 + Math.random() * 3).toFixed(1);
        } else {
          classification = 'benign';
          confidence = (97.8 + Math.random() * 2).toFixed(1);
          anomalyScore = (Math.random() * 12 + 3).toFixed(1);
        }
      }

      // Realistic inference latency (simulating PyTorch + TensorRT / ONNX)
      const latencyMs = (1.8 + Math.random() * 0.8).toFixed(2);
      if (this.latencyEl) this.latencyEl.textContent = `${latencyMs} ms`;

      // Update Verdict UI
      this.updateVerdictUI(classification, anomalyScore, confidence, preset);

      // Compute & Render SHAP Explanations
      this.renderShapExplanations(classification, { entropy, duration, jitter, latentDist });

      // Generate eBPF / XDP Firewall Rule
      this.generateMitigationRule(classification, preset);

      // Trigger visual network anomaly pulse
      if (classification === 'zeroday' && window.triggerGlobalNetworkAlert) {
        window.triggerGlobalNetworkAlert();
      }

      // Append to live terminal log
      this.logToTelemetry(classification, preset, anomalyScore, latencyMs);
    }, 280);
  }

  updateVerdictUI(type, anomalyScore, confidence, preset) {
    if (this.anomalyScoreEl) this.anomalyScoreEl.textContent = `${anomalyScore}%`;
    if (this.confidenceEl) this.confidenceEl.textContent = `${confidence}%`;

    if (type === 'zeroday') {
      this.verdictIcon.innerHTML = '🚨';
      this.verdictIcon.style.background = 'rgba(244, 63, 94, 0.2)';
      this.verdictIcon.style.border = '1px solid #f43f5e';
      this.verdictTitle.textContent = 'ZERO-DAY THREAT DETECTED';
      this.verdictTitle.style.color = '#f43f5e';
      this.verdictBadge.textContent = 'OPEN-SET NOVELTY ATTRIBUTION';
      this.verdictBadge.className = 'verdict-badge badge-zeroday';
      this.verdictSub.textContent = preset.description || 'Out-of-Distribution latent representation flagged novel exploit signature.';
    } else if (type === 'known') {
      this.verdictIcon.innerHTML = '⚠️';
      this.verdictIcon.style.background = 'rgba(245, 158, 11, 0.2)';
      this.verdictIcon.style.border = '1px solid #f59e0b';
      this.verdictTitle.textContent = 'KNOWN ATTACK MITIGATED';
      this.verdictTitle.style.color = '#f59e0b';
      this.verdictBadge.textContent = 'SUPERVISED CLASSIFIER MATCH';
      this.verdictBadge.className = 'verdict-badge badge-known';
      this.verdictSub.textContent = preset.description || 'Flow signature matches learned attack manifold pattern.';
    } else {
      this.verdictIcon.innerHTML = '🛡️';
      this.verdictIcon.style.background = 'rgba(16, 185, 129, 0.2)';
      this.verdictIcon.style.border = '1px solid #10b981';
      this.verdictTitle.textContent = 'BENIGN NORMAL TRAFFIC';
      this.verdictTitle.style.color = '#10b981';
      this.verdictBadge.textContent = 'CONFORMS TO NORMAL MANIFOLD';
      this.verdictBadge.className = 'verdict-badge badge-benign';
      this.verdictSub.textContent = preset.description || 'Flow parameters reside within the calibrated normal traffic distribution.';
    }
  }

  renderShapExplanations(type, features) {
    if (!this.shapContainer) return;

    let weights = [];
    if (type === 'zeroday') {
      weights = [
        { name: 'Latent Distance (DM)', val: '+0.58', pct: 88, color: '#f43f5e', pos: true },
        { name: 'Payload Entropy', val: '+0.42', pct: 72, color: '#f43f5e', pos: true },
        { name: 'IAT Variance Jitter', val: '+0.31', pct: 54, color: '#fb7185', pos: true },
        { name: 'Temporal Conv Rep', val: '+0.19', pct: 36, color: '#f43f5e', pos: true },
        { name: 'Flow Duration', val: '-0.08', pct: 15, color: '#38bdf8', pos: false }
      ];
    } else if (type === 'known') {
      weights = [
        { name: 'SYN/ACK Ratio', val: '+0.64', pct: 92, color: '#f59e0b', pos: true },
        { name: 'Packet Byte Rate', val: '+0.48', pct: 78, color: '#f59e0b', pos: true },
        { name: 'BiLSTM State Match', val: '+0.33', pct: 58, color: '#f59e0b', pos: true },
        { name: 'Port Correlation', val: '+0.21', pct: 40, color: '#fbbf24', pos: true },
        { name: 'Latent Reconstruction', val: '+0.12', pct: 24, color: '#f59e0b', pos: true }
      ];
    } else {
      weights = [
        { name: 'Latent Conformity', val: '-0.62', pct: 90, color: '#10b981', pos: false },
        { name: 'Regular Entropy (6.1)', val: '-0.45', pct: 74, color: '#10b981', pos: false },
        { name: 'Expected Handshake', val: '-0.38', pct: 60, color: '#34d399', pos: false },
        { name: 'Flow Continuity', val: '-0.25', pct: 42, color: '#10b981', pos: false },
        { name: 'Port Protocol Alignment', val: '-0.14', pct: 25, color: '#10b981', pos: false }
      ];
    }

    let html = '';
    weights.forEach((w) => {
      html += `
        <div class="shap-row">
          <div class="shap-feat-name" title="${w.name}">${w.name}</div>
          <div class="shap-bar-track">
            <div class="shap-bar-fill" style="width: ${w.pct}%; background: ${w.color};"></div>
          </div>
          <div class="shap-val" style="color: ${w.color};">${w.val}</div>
        </div>
      `;
    });

    this.shapContainer.innerHTML = html;
  }

  generateMitigationRule(type, preset) {
    if (!this.mitigationCode) return;

    if (type === 'zeroday') {
      this.mitigationCode.innerHTML = `
<span style="color:#64748b;"># eBPF / XDP Autonomous Zero-Day Mitigation Filter</span>
<span style="color:#00f0ff;">SEC</span>(<span style="color:#a78bfa;">"xdp/aegis_zeroday_filter"</span>)
<span style="color:#38bdf8;">int</span> <span style="color:#f43f5e;">filter_quarantine</span>(<span style="color:#38bdf8;">struct</span> xdp_md *ctx) {
  <span style="color:#94a3b8;">/* Drop novel flow: ${preset.srcIp} -> ${preset.dstIp} */</span>
  <span style="color:#00f0ff;">if</span> (ip->saddr == <span style="color:#a78bfa;">INET_ATON("${preset.srcIp}")</span>) {
    bpf_trace_printk(<span style="color:#a78bfa;">"[AEGIS-ALERT] Zero-Day Blocked! Score: %d\\n"</span>, 96);
    <span style="color:#f43f5e;font-weight:700;">return XDP_DROP;</span>
  }
  <span style="color:#10b981;">return XDP_PASS;</span>
}`;
    } else if (type === 'known') {
      this.mitigationCode.innerHTML = `
<span style="color:#64748b;"># Linux Kernel Netfilter / iptables Auto-Rule</span>
iptables -A INPUT -p tcp -s ${preset.srcIp} --dport 80 -m limit --limit 5/sec -j ACCEPT
iptables -A INPUT -p tcp -s ${preset.srcIp} -j DROP
<span style="color:#94a3b8;"># Status: SYN-Flood Mitigated on eth0 [Rate-Limited & Blacklisted]</span>`;
    } else {
      this.mitigationCode.innerHTML = `
<span style="color:#64748b;"># Traffic Verification Passed</span>
<span style="color:#10b981;">[STATUS]</span> Flow conforms to benign baseline manifold.
<span style="color:#38bdf8;">eBPF Policy:</span> XDP_PASS (Zero Latency Forwarding)`;
    }
  }

  logToTelemetry(type, preset, score, latency) {
    const stream = document.getElementById('heroTerminalStream');
    if (!stream) return;

    const time = new Date().toTimeString().split(' ')[0];
    const item = document.createElement('div');
    item.className = 'terminal-line';

    let tagHtml = '';
    if (type === 'zeroday') {
      tagHtml = `<span class="term-tag zeroday">ZERO-DAY ALERT</span>`;
    } else if (type === 'known') {
      tagHtml = `<span class="term-tag" style="background:rgba(245,158,11,0.2);color:#f59e0b;">KNOWN ATTACK</span>`;
    } else {
      tagHtml = `<span class="term-tag normal">BENIGN FLOW</span>`;
    }

    item.innerHTML = `
      <span class="term-time">[${time}]</span>
      ${tagHtml}
      <span class="term-msg">${preset.srcIp} &rarr; ${preset.proto} | score: ${score}% | ${latency}ms</span>
    `;

    stream.insertBefore(item, stream.firstChild);

    // Keep up to 12 items
    while (stream.children.length > 12) {
      stream.removeChild(stream.lastChild);
    }
  }
}

// Instantiate on DOM load
document.addEventListener('DOMContentLoaded', () => {
  window.threatSimulator = new ThreatSimulator();
});
