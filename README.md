# Aegis-DL: Hybrid Deep Learning IDS for Zero-Day Network Attack Detection (v2.5 Upgrade)

A cutting-edge, highly interactive, production-grade website for your **Hybrid Deep Learning Intrusion Detection System (IDS)** specializing in autonomous **Zero-Day Network Attack Detection**.

---

## 🌟 What's New in v2.5: Interactive & Fully Functional Features

1. **Client-Side PCAP Ingest & Packet Hex Dissector (`#pcap-inspector`)**:
   - **Preloaded Real Captures**: Toggle between `CIC-IDS2017-ZeroDay-Subset.pcap`, `WannaCry-Ransomware-SMB-Flow.pcap`, `Mirai-Botnet-SynFlood.pcap`, and `Benign-Enterprise-TLS.pcap`.
   - **Real File Upload & Drag-and-Drop**: Drop any custom `.pcap`, `.csv`, `.json`, or `.log` file to parse and dissect client-side!
   - **Hex & ASCII Dissector**: Click on any packet row to inspect its raw bytes, header breakdown, and entropy.
   - **1D-CNN Spatial Attention Heatmap**: Highlights exactly which bytes triggered the deep neural network's anomaly alert.
   - **Batch Deep Learning Inference**: Processes all flows in the capture and exports a downloadable audit report (`.json`).

2. **Interactive Global Threat Telemetry Geo-Map (`#threat-map`)**:
   - Real-time animated canvas world map tracking incoming zero-day exploits attacking honeypots worldwide.
   - Attack filters: *All Attack Arcs*, *Zero-Days Only*, or *Known Threats Only*.
   - Clickable sensor hubs (Frankfurt, Virginia, Tokyo, Mumbai, Singapore, São Paulo) showing active perimeter metrics and eBPF drop counters.

3. **2D Neural Latent Manifold Explorer (`#latent-space`)**:
   - Visualizes the 2D bottleneck representations ($z_1, z_2$) produced by the Variational Autoencoder.
   - Real-time interactive sliders for **Reconstruction Threshold ($\tau$)** and **Weibull Tail Parameter ($\eta$)**.
   - Metric distance selectors (**Mahalanobis**, **Euclidean**, **Cosine**).
   - Dynamically recomputes Zero-Day Recall and False Positive Rate on the fly!

4. **Multi-Format Autonomous Firewall Policy Exporter (`#firewall-exporter`)**:
   - Automatically synthesizes quarantine policies in 5 formats:
     - **eBPF / XDP C Code** (`.c`)
     - **Linux iptables / nftables script** (`.sh`)
     - **Snort 3 / Suricata Rules** (`.rules`)
     - **Palo Alto PAN-OS XML** (`.xml`)
     - **Sigma Threat Hunting Rule** (`.yml`)
   - **One-Click Actions**: "Copy Directive", "Download Policy File", and "Export Full Audit Markdown Report".
   - **Virtual Kernel Test Runner**: Click "Test Policy in Kernel Sandbox" to simulate in-kernel drop verification.

5. **Procedural Web Audio Cyber Alert Synthesizer**:
   - Built with the native browser **Web Audio API** (requires zero external audio files or downloads).
   - Generates realistic radar pings, telemetry clicks, and audible zero-day alarm sirens.
   - One-click toggle in the header: `🔊 Audio: ON / OFF`.

6. **Interactive Attack Simulator & SHAP Explainability (`#simulator`)**:
   - 5 Attack Presets + fine-tuning sliders for Shannon Entropy, Jitter, Flow Duration, and Latent Distance.
   - Instant SHAP feature attribution bars detailing why the deep learning model flagged or cleared the traffic.

7. **Empirical Benchmarks & Academic Theory (`#benchmarks`, `#methodology`)**:
   - Interactive Chart.js ROC curve (AUC 0.998), Precision-Recall curve, and Latency scalability chart.
   - Multi-dataset evaluation across **CIC-IDS2017**, **UNSW-NB15**, and **CSE-CIC-IDS2018**.
   - LaTeX mathematical formulations for the Joint Objective Loss and OpenMax EVT probability.
   - Copyable BibTeX citation snippet.

---

## 🚀 How to Run and Preview the Website

### Option 1: Direct File Launch (No Server Needed)
Simply open `index.html` in any modern web browser (Google Chrome, Microsoft Edge, Brave, Mozilla Firefox). All scripts, canvases, audio synthesizers, and charts run 100% client-side with zero dependencies!

```
file:///C:/Users/tejur/.gemini/antigravity/scratch/zero-day-ids-web/index.html
```

### Option 2: Local HTTP Server (Python)
If you prefer running a local server:
```powershell
cd "C:\Users\tejur\.gemini\antigravity\scratch\zero-day-ids-web"
python -m SimpleHTTPServer 8000
# Open http://localhost:8000 in your browser
```

---

## 📁 Project Architecture

```
zero-day-ids-web/
├── index.html            # Complete semantic HTML5 single-page application
├── css/
│   └── styles.css        # Cyberpunk glassmorphism design system & responsive styling
├── js/
│   ├── network-canvas.js # Interactive neural graph & packet flow background
│   ├── audio-alerts.js   # Procedural Web Audio API cyber synth & alarm sirens
│   ├── simulator.js      # Zero-Day inference simulation & SHAP calculation engine
│   ├── pcap-analyzer.js  # Packet dissector, hex dump inspector & batch file upload
│   ├── geomap.js         # Real-time global threat canvas geo-map & sensor telemetry
│   ├── latent-space.js   # 2D latent manifold scatter & dynamic threshold recalculation
│   ├── report-export.js  # Multi-format firewall generator (eBPF, iptables, Snort)
│   ├── charts.js         # Interactive Chart.js benchmarks (ROC, PR, Latency, Protocols)
│   └── app.js            # Architecture tabs, smooth scrolling, theme toggle & BibTeX copy
└── README.md             # Project documentation and presentation guide
```

---

## 🎯 Perfect For
- Academic Project Defense & Viva Voce presentations.
- Research Paper Companion Website & GitHub Repository showcase.
- Cybersecurity portfolio and AI Security demonstration.
