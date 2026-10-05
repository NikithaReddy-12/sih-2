import { store } from '../state/store.js';

class TelemetryGenerator {
  constructor() {
    this.intervalId = null;
    this.clockIntervalId = null;
    this.logIntervalId = null;
    this.streamActive = true;
    this.speed = 1; // 1x, 2x, 5x
    this.liveLogs = [];
    this.logCounter = 0;
  }

  start() {
    // Live clock update
    this.clockIntervalId = setInterval(() => {
      const clockEl = document.getElementById('clock-sync');
      if (clockEl) {
        const now = new Date();
        const h = String(now.getUTCHours()).padStart(2, '0');
        const m = String(now.getUTCMinutes()).padStart(2, '0');
        const s = String(now.getUTCSeconds()).padStart(2, '0');
        clockEl.textContent = `${h}:${m}:${s} UTC`;
      }
    }, 1000);

    // Live EPS jitter
    this.intervalId = setInterval(() => {
      if (this.streamActive) {
        store.updateEPS();
      }
    }, 2000);

    // Stream new live log entries periodically
    this.logIntervalId = setInterval(() => {
      if (this.streamActive) {
        this._addNewLog();
      }
    }, 3500);

    // Initial synthetic raw stream logs
    this.initLogs();
  }

  _addNewLog() {
    const protocols = ['SMB', 'RPC', 'HTTPS', 'DNS', 'LDAP', 'KERBEROS', 'TCP_SYN'];
    const sources = ['194.26.29.112', '10.4.1.17', '10.4.12.103', '10.4.12.5', '185.190.140.32'];
    const destinations = ['10.4.1.17:445', '10.4.12.103:8080', '10.4.12.5:3389', '10.4.99.12:1433', '10.4.12.18:88'];
    const actions = ['ALLOW', 'DROP', 'ALERT', 'QUARANTINE_FLAG', 'AUDIT_PASS'];

    const p = protocols[Math.floor(Math.random() * protocols.length)];
    const src = sources[Math.floor(Math.random() * sources.length)];
    const dst = destinations[Math.floor(Math.random() * destinations.length)];
    const act = actions[Math.floor(Math.random() * actions.length)];
    const now = new Date();
    const timestamp = `${String(now.getUTCHours()).padStart(2,'0')}:${String(now.getUTCMinutes()).padStart(2,'0')}:${String(now.getUTCSeconds()).padStart(2,'0')}`;

    this.logCounter++;
    this.liveLogs.unshift({
      id: `log-live-${this.logCounter}`,
      timestamp,
      protocol: p,
      src,
      dst,
      action: act,
      payload: `LEN=${Math.floor(Math.random() * 1200 + 64)} TTL=54 FLAGS=[ACK,PSH] HASH=${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
      mitre: p === 'KERBEROS' ? 'T1558 (Kerberoasting)' : p === 'SMB' ? 'T1021.002 (SMB/Windows Admin Shares)' : 'T1046 (Network Service Discovery)'
    });

    // Cap log buffer at 60 entries
    if (this.liveLogs.length > 60) {
      this.liveLogs.pop();
    }
  }

  initLogs() {
    const protocols = ['SMB', 'RPC', 'HTTPS', 'DNS', 'LDAP', 'KERBEROS', 'TCP_SYN'];
    const sources = ['194.26.29.112', '10.4.1.17', '10.4.12.103', '10.4.12.5', '185.190.140.32'];
    const destinations = ['10.4.1.17:445', '10.4.12.103:8080', '10.4.12.5:3389', '10.4.99.12:1433', '10.4.12.18:88'];
    const actions = ['ALLOW', 'DROP', 'ALERT', 'QUARANTINE_FLAG', 'AUDIT_PASS'];

    for (let i = 0; i < 25; i++) {
      const p = protocols[Math.floor(Math.random() * protocols.length)];
      const src = sources[Math.floor(Math.random() * sources.length)];
      const dst = destinations[Math.floor(Math.random() * destinations.length)];
      const act = actions[Math.floor(Math.random() * actions.length)];
      const timestamp = new Date(Date.now() - (25 - i) * 8000).toISOString().substring(11, 19);

      this.liveLogs.push({
        id: `log-${i}`,
        timestamp,
        protocol: p,
        src,
        dst,
        action: act,
        payload: `LEN=${Math.floor(Math.random() * 1200 + 64)} TTL=54 FLAGS=[ACK,PSH] HASH=${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
        mitre: p === 'KERBEROS' ? 'T1558 (Kerberoasting)' : p === 'SMB' ? 'T1021.002 (SMB/Windows Admin Shares)' : 'T1046 (Network Service Discovery)'
      });
    }
  }

  getLogs() {
    return this.liveLogs;
  }

  pause() {
    this.streamActive = false;
  }

  resume() {
    this.streamActive = true;
  }

  setSpeed(multiplier) {
    this.speed = multiplier;
  }
}

export const telemetry = new TelemetryGenerator();
