/**
 * Aegis-DL: Benchmark & Metric Visualizations (Chart.js)
 * Implements interactive ROC Curves, Latency vs Detection Trade-offs, and Dataset Comparisons
 */

(function () {
  let rocChart = null;
  let datasetChart = null;
  let protocolDonutChart = null;

  function initCharts() {
    if (typeof Chart === 'undefined') return;

    // Set Chart.js dark theme defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.borderColor = 'rgba(56, 189, 248, 0.1)';

    initRocChart();
    initDatasetChart();
    initProtocolChart();
  }

  function initRocChart() {
    const ctx = document.getElementById('rocChart');
    if (!ctx) return;

    const data = {
      labels: ['0.00', '0.01', '0.02', '0.05', '0.10', '0.20', '0.40', '0.60', '0.80', '1.00'],
      datasets: [
        {
          label: 'Aegis Hybrid DL (Our Proposed Model - AUC: 0.998)',
          data: [0.0, 0.942, 0.978, 0.991, 0.996, 0.998, 0.999, 1.0, 1.0, 1.0],
          borderColor: '#00f0ff',
          backgroundColor: 'rgba(0, 240, 255, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 3,
          pointBackgroundColor: '#00f0ff',
          pointRadius: 4
        },
        {
          label: 'Standalone Variational Autoencoder (AUC: 0.941)',
          data: [0.0, 0.72, 0.81, 0.89, 0.93, 0.96, 0.98, 0.99, 1.0, 1.0],
          borderColor: '#8b5cf6',
          borderDash: [5, 5],
          fill: false,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2
        },
        {
          label: 'Baseline Random Forest / XGBoost (AUC: 0.874)',
          data: [0.0, 0.58, 0.69, 0.78, 0.84, 0.88, 0.92, 0.95, 0.98, 1.0],
          borderColor: '#f59e0b',
          borderDash: [4, 4],
          fill: false,
          tension: 0.25,
          borderWidth: 2,
          pointRadius: 2
        },
        {
          label: 'Traditional Snort / Rule Signatures (AUC: 0.682)',
          data: [0.0, 0.32, 0.44, 0.52, 0.61, 0.68, 0.74, 0.82, 0.90, 1.0],
          borderColor: '#f43f5e',
          borderDash: [2, 2],
          fill: false,
          tension: 0.1,
          borderWidth: 2,
          pointRadius: 0
        }
      ]
    };

    rocChart = new Chart(ctx, {
      type: 'line',
      data: data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              boxWidth: 12,
              padding: 15,
              font: { size: 11, weight: '500' }
            }
          },
          tooltip: {
            backgroundColor: 'rgba(6, 9, 19, 0.95)',
            borderColor: 'rgba(0, 240, 255, 0.4)',
            borderWidth: 1,
            titleFont: { size: 12, weight: '700' },
            bodyFont: { size: 12 }
          }
        },
        scales: {
          x: {
            title: {
              display: true,
              text: 'False Positive Rate (FPR)',
              color: '#94a3b8',
              font: { weight: '600', size: 12 }
            },
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          },
          y: {
            title: {
              display: true,
              text: 'True Positive Rate (TPR / Recall)',
              color: '#94a3b8',
              font: { weight: '600', size: 12 }
            },
            min: 0,
            max: 1.02,
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          }
        }
      }
    });
  }

  function initDatasetChart() {
    const ctx = document.getElementById('datasetChart');
    if (!ctx) return;

    datasetChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['CIC-IDS2017', 'UNSW-NB15', 'CSE-CIC-IDS2018', 'Zero-Day Synthetic (OOD)'],
        datasets: [
          {
            label: 'Accuracy (%)',
            data: [99.42, 98.75, 99.18, 94.85],
            backgroundColor: '#00f0ff',
            borderRadius: 6
          },
          {
            label: 'F1-Score (%)',
            data: [99.28, 98.41, 99.04, 93.92],
            backgroundColor: '#8b5cf6',
            borderRadius: 6
          },
          {
            label: 'Zero-Day Novelty Recall (%)',
            data: [96.2, 94.8, 95.7, 94.1],
            backgroundColor: '#10b981',
            borderRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { boxWidth: 10, padding: 12, font: { size: 11 } }
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: {
            min: 85,
            max: 100,
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
          }
        }
      }
    });
  }

  function initProtocolChart() {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;

    protocolDonutChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['HTTPS/TLS 1.3', 'DNS / DoH', 'QUIC/UDP', 'SSH / SCP', 'Anomalous Tunnel'],
        datasets: [
          {
            data: [54, 18, 14, 9, 5],
            backgroundColor: ['#00f0ff', '#8b5cf6', '#10b981', '#f59e0b', '#f43f5e'],
            borderColor: '#0b1120',
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { boxWidth: 10, font: { size: 10 } }
          }
        },
        cutout: '72%'
      }
    });
  }

  // Switch chart tab (e.g. ROC vs PR curve vs Latency)
  window.switchChartTab = function (tabType, btn) {
    document.querySelectorAll('.chart-tab-btn').forEach((b) => b.classList.remove('active'));
    if (btn) btn.classList.add('active');

    if (!rocChart) return;

    if (tabType === 'pr') {
      rocChart.data.datasets[0].label = 'Aegis Hybrid DL (Precision-Recall AUC: 0.995)';
      rocChart.data.datasets[0].data = [1.0, 0.998, 0.995, 0.991, 0.984, 0.976, 0.962, 0.941, 0.912, 0.88];
      rocChart.options.scales.x.title.text = 'Recall';
      rocChart.options.scales.y.title.text = 'Precision';
      rocChart.update();
    } else if (tabType === 'latency') {
      rocChart.data.datasets[0].label = 'Inference Latency vs Batch Size (Aegis TensorRT: 1.8ms)';
      rocChart.data.datasets[0].data = [0.12, 0.35, 0.58, 0.95, 1.42, 1.85, 2.30, 2.95, 3.8, 4.9];
      rocChart.options.scales.x.title.text = 'Flow Batch Size (x1000)';
      rocChart.options.scales.y.title.text = 'Latency per Flow (ms)';
      rocChart.update();
    } else {
      // Default ROC
      rocChart.data.datasets[0].label = 'Aegis Hybrid DL (Our Proposed Model - AUC: 0.998)';
      rocChart.data.datasets[0].data = [0.0, 0.942, 0.978, 0.991, 0.996, 0.998, 0.999, 1.0, 1.0, 1.0];
      rocChart.options.scales.x.title.text = 'False Positive Rate (FPR)';
      rocChart.options.scales.y.title.text = 'True Positive Rate (TPR / Recall)';
      rocChart.update();
    }
  };

  document.addEventListener('DOMContentLoaded', initCharts);
})();
