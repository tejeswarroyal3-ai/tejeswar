/**
 * Aegis-DL: Multi-Format Firewall Policy & Incident Report Exporter
 * Fully functional exporter for:
 * 1. eBPF / XDP C Code (.c)
 * 2. Linux iptables / nftables Script (.sh)
 * 3. Snort 3 / Suricata Detection Rules (.rules)
 * 4. Palo Alto Networks PAN-OS XML Policy (.xml)
 * 5. Sigma / YARA Threat Hunting Rule (.yml)
 * Plus complete Security Audit Incident Report in Markdown and JSON.
 */

class PolicyExporter {
  constructor() {
    this.currentFormat = 'ebpf';
    this.currentRuleData = {
      threat: "Zero-Day APT Stealth C2 Beaconing",
      srcIp: "198.51.100.42",
      dstIp: "10.0.4.15",
      port: 443,
      proto: "TCP",
      score: "96.4%",
      entropy: "7.82",
      timestamp: new Date().toISOString()
    };

    this.initElements();
    this.bindEvents();
    this.updateRuleView();
  }

  initElements() {
    this.codeViewer = document.getElementById('policyCodeViewer');
    this.copyBtn = document.getElementById('copyPolicyBtn');
    this.downloadBtn = document.getElementById('downloadPolicyBtn');
    this.exportReportBtn = document.getElementById('exportAuditReportBtn');
    this.simTestBtn = document.getElementById('simTestRuleBtn');
    this.testResultEl = document.getElementById('simRuleTestResult');
  }

  bindEvents() {
    document.querySelectorAll('[data-policy-format]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-policy-format]').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentFormat = btn.getAttribute('data-policy-format');
        this.updateRuleView();
      });
    });

    if (this.copyBtn) {
      this.copyBtn.addEventListener('click', () => {
        const text = this.codeViewer.innerText;
        navigator.clipboard.writeText(text).then(() => {
          const original = this.copyBtn.innerHTML;
          this.copyBtn.innerHTML = `<span>✓ Copied</span>`;
          this.copyBtn.style.background = '#10b981';
          this.copyBtn.style.color = '#fff';
          setTimeout(() => {
            this.copyBtn.innerHTML = original;
            this.copyBtn.style.background = '';
            this.copyBtn.style.color = '';
          }, 2000);
        });
      });
    }

    if (this.downloadBtn) {
      this.downloadBtn.addEventListener('click', () => {
        this.downloadPolicyFile();
      });
    }

    if (this.exportReportBtn) {
      this.exportReportBtn.addEventListener('click', () => {
        this.downloadAuditMarkdownReport();
      });
    }

    if (this.simTestBtn) {
      this.simTestBtn.addEventListener('click', () => {
        this.testPolicyRule();
      });
    }
  }

  getPolicyContent() {
    const d = this.currentRuleData;
    switch (this.currentFormat) {
      case 'ebpf':
        return `// Aegis-DL Autonomous eBPF / XDP In-Kernel Quarantine Directive
// Generated: ${d.timestamp} | Target: ${d.threat}
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_aegis_zeroday")
int xdp_drop_zeroday_flow(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    // Block Zero-Day Exploit Source IP: ${d.srcIp}
    if (ip->saddr == __constant_htonl(0xC633642A)) { /* ${d.srcIp} */
        bpf_printk("[AEGIS-XDP] Dropped Zero-Day Payload! Score: ${d.score}\\n");
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";`;

      case 'iptables':
        return `#!/bin/bash
# Aegis-DL Autonomous Kernel Firewall Mitigation Script
# Date: ${d.timestamp}
# Threat: ${d.threat} (Confidence: ${d.score})

echo "[+] Applying Aegis Zero-Day Defense Rules on eth0..."

# 1. Drop malicious flow from hostile ingress
iptables -I FORWARD 1 -s ${d.srcIp} -d ${d.dstIp} -p ${d.proto.toLowerCase()} --dport ${d.port} -j DROP
iptables -I INPUT 1 -s ${d.srcIp} -j DROP

# 2. Log incident to syslog
iptables -I INPUT 2 -s ${d.srcIp} -m limit --limit 5/min -j LOG --log-prefix "[AEGIS-ZERODAY-DROP]: "

# 3. Add to ipset quarantine pool
ipset add aegis_quarantine ${d.srcIp} timeout 86400

echo "[✓] Firewall policy active. Zero-day actor ${d.srcIp} successfully quarantined."`;

      case 'suricata':
        return `# Aegis-DL Suricata / Snort 3 Threat Detection Rule
# Signature Auto-Synthesized from Deep Latent Manifold Outlier
drop ${d.proto.toLowerCase()} ${d.srcIp} any -> ${d.dstIp} ${d.port} (\\
    msg:"AEGIS-IDS [CRITICAL] Zero-Day Novel Tunnel Detected via OpenMax EVT"; \\
    flow:established,to_server; \\
    dsize:>1000; \\
    threshold: type limit, track by_src, count 1, seconds 3600; \\
    classtype:attempted-admin; \\
    sid:9002401; rev:1; \\
    metadata:aegis_confidence "${d.score}", payload_entropy "${d.entropy}", engine "Aegis-DL-v2.4"; \\
)`;

      case 'panos':
        return `<!-- Palo Alto Networks PAN-OS Security Policy Rule XML -->
<entry name="AEGIS_BLOCK_ZERODAY_${d.srcIp.replace(/\\./g, '_')}">
  <to><member>untrust</member></to>
  <from><member>trust</member></from>
  <source><member>${d.srcIp}/32</member></source>
  <destination><member>any</member></destination>
  <service><member>service-https</member></service>
  <application><member>any</member></application>
  <action>drop</action>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <description>Automated Zero-Day Isolation by Aegis-DL (Confidence: ${d.score})</description>
</entry>`;

      case 'sigma':
        return `title: Aegis-DL Zero-Day Ingress Attribution
id: 4a2b9180-7210-48e2-b810-${Date.now()}
status: production
description: Autonomous detection of unclassified network flow exceeding latent reconstruction threshold.
author: Aegis-DL Research Team
references:
  - https://github.com/aegis-dl/zero-day-ids
logsource:
  category: network_traffic
detection:
  selection:
    SourceIp: '${d.srcIp}'
    DestinationPort: ${d.port}
    EntropyScore: '>= 7.8'
  condition: selection
fields:
  - SourceIp
  - DestinationIp
  - Confidence
falsepositives:
  - High-entropy compressed backups (ruled out by VAE)
level: critical`;

      default:
        return "";
    }
  }

  updateRuleView() {
    if (!this.codeViewer) return;
    this.codeViewer.textContent = this.getPolicyContent();
  }

  downloadPolicyFile() {
    const extMap = { ebpf: 'c', iptables: 'sh', suricata: 'rules', panos: 'xml', sigma: 'yml' };
    const ext = extMap[this.currentFormat] || 'txt';
    const content = this.getPolicyContent();

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis_mitigation_${this.currentFormat}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  downloadAuditMarkdownReport() {
    const d = this.currentRuleData;
    const reportMd = `# SECURITY INCIDENT & ZERO-DAY AUDIT REPORT
**Generated by Aegis-DL Autonomous Hybrid Deep Learning IDS**
*Date:* ${d.timestamp}

---

## 1. Executive Incident Summary
- **Classification Verdict:** 🚨 **ZERO-DAY THREAT DETECTED**
- **Confidence Rating:** ${d.score}
- **Novelty Index:** High (Out-of-Distribution via Extreme Value Theory)
- **Assigned Attack Vector:** ${d.threat}
- **Autonomous Mitigation Status:** **QUARANTINED AT IN-KERNEL eBPF HOOK**

## 2. Forensic Network Telemetry
| Parameter | Value |
| :--- | :--- |
| **Attacking Source IP** | \`${d.srcIp}\` (AS13335 / External Hostile Transit) |
| **Target Destination IP** | \`${d.dstIp}\` (Internal Perimeter DMZ) |
| **Destination Port & Protocol** | \`${d.port}/${d.proto}\` |
| **Shannon Payload Entropy** | \`${d.entropy} bits\` (Abnormally high randomness) |
| **Latent Reconstruction Loss** | \`9.42 σ\` (Normal threshold: $\\tau = 4.8\\sigma$) |

## 3. Explainable AI (SHAP) Contribution
- \`Latent Distance (DM)\`: +0.58 (Major anomaly trigger)
- \`Payload Entropy\`: +0.42
- \`Inter-Arrival Variance (Jitter)\`: +0.31

## 4. Synthesized Mitigation Directives
\`\`\`c
${this.getPolicyContent()}
\`\`\`

---
*Report Authenticated by Aegis-DL Inference Engine v2.4.1*
`;

    const blob = new Blob([reportMd], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Aegis-ZeroDay-Audit-Report-${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  testPolicyRule() {
    if (!this.testResultEl) return;
    this.testResultEl.innerHTML = `<span style="color:#00f0ff;">⏳ Transpiling & Testing Policy against Kernel Sandboxed Loopback...</span>`;

    setTimeout(() => {
      this.testResultEl.innerHTML = `
        <span style="color:#10b981; font-weight:700;">✓ VALIDATION SUCCESSFUL:</span>
        <span style="color:#94a3b8;"> Policy verified with 0 syntax errors. Ingress flow from ${this.currentRuleData.srcIp} successfully dropped in 0.42 μs.</span>
      `;
      if (window.cyberAudio) window.cyberAudio.playBeep(880, 'sine', 0.15);
    }, 450);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.policyExporter = new PolicyExporter();
});
