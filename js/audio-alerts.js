/**
 * Aegis-DL: Cyber Audio Synthesizer (Web Audio API)
 * Zero external audio files required. Generates cyber telemetry beeps,
 * sonar pings, and zero-day alarm sirens procedurally.
 */

class CyberAudioEngine {
  constructor() {
    this.audioCtx = null;
    this.isEnabled = false;
    this.volume = 0.25;
    this.initControls();
  }

  initAudio() {
    if (!this.audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    }
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }
  }

  initControls() {
    const toggleBtn = document.getElementById('audioToggleBtn');
    if (!toggleBtn) return;

    toggleBtn.addEventListener('click', () => {
      this.initAudio();
      this.isEnabled = !this.isEnabled;
      if (this.isEnabled) {
        toggleBtn.innerHTML = `🔊 Audio: <strong>ON</strong>`;
        toggleBtn.classList.add('audio-active');
        this.playBeep(880, 'sine', 0.1, 0.15);
      } else {
        toggleBtn.innerHTML = `🔇 Audio: <strong>OFF</strong>`;
        toggleBtn.classList.remove('audio-active');
      }
    });
  }

  playBeep(freq = 440, type = 'sine', duration = 0.15, gainVal = null) {
    if (!this.isEnabled || !this.audioCtx) return;
    try {
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.audioCtx.currentTime);

      const vol = gainVal !== null ? gainVal : this.volume;
      gain.gain.setValueAtTime(vol, this.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.audioCtx.currentTime + duration);

      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      osc.start();
      osc.stop(this.audioCtx.currentTime + duration);
    } catch (err) {
      console.warn("Audio playback error:", err);
    }
  }

  playZeroDayAlarm() {
    if (!this.isEnabled || !this.audioCtx) return;
    try {
      const now = this.audioCtx.currentTime;
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();

      osc.type = 'sawtooth';
      // Alarm frequency modulation (glissando down-up)
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.linearRampToValueAtTime(1400, now + 0.15);
      osc.frequency.linearRampToValueAtTime(700, now + 0.3);

      gain.gain.setValueAtTime(this.volume * 0.8, now);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);

      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      osc.start();
      osc.stop(now + 0.35);
    } catch (e) {
      console.warn("Alarm audio error:", e);
    }
  }

  playBenignPing() {
    if (!this.isEnabled || !this.audioCtx) return;
    this.playBeep(1046.5, 'sine', 0.12, this.volume * 0.4); // C6 tone
  }
}

// Global instance
window.cyberAudio = new CyberAudioEngine();
