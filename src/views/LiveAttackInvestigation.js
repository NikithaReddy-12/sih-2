import { store } from '../state/store.js';
import { telemetry } from '../engine/telemetryGenerator.js';

export function renderLiveAttackInvestigation(container) {
  let selectedLog = null;
  let protocolFilter = 'ALL';
  let isPaused = false;

  const update = () => {
    const logs = telemetry.getLogs();
    const filtered = protocolFilter === 'ALL' 
      ? logs 
      : logs.filter(l => l.protocol === protocolFilter);

    const activeLog = selectedLog || filtered[0] || {};

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header Banner -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="inline-block w-2 h-2 rounded-full ${isPaused ? 'bg-secondary' : 'bg-primary animate-pulse'}"></span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">
                ${isPaused ? 'SENSOR STREAM PAUSED' : 'LIVE TELEMETRY INGESTION ACTIVE (42.8K EPS)'}
              </span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">LIVE ATTACK INVESTIGATION</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Deep packet &amp; host telemetry sensor feed. Correlate raw network frames with MITRE ATT&amp;CK heuristics.
            </p>
          </div>

          <div class="flex items-center gap-space-xs flex-wrap">
            <button id="pause-stream-btn" class="px-space-sm py-space-xs rounded-DEFAULT bg-surface-container-high hover:bg-surface-variant font-telemetry-sm text-telemetry-sm text-on-surface flex items-center gap-1 transition-colors cursor-pointer border border-surface-container-highest/40">
              <span class="material-symbols-outlined text-[16px]">${isPaused ? 'play_arrow' : 'pause'}</span>
              <span>${isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
            </button>
            <button id="isolate-source-btn" class="px-space-sm py-space-xs rounded-DEFAULT bg-error-container hover:bg-error text-on-error-container font-telemetry-sm text-telemetry-sm font-semibold flex items-center gap-1 transition-colors cursor-pointer">
              <span class="material-symbols-outlined text-[16px]">block</span>
              <span>Filter Actor (194.26.29.112)</span>
            </button>
          </div>
        </div>

        <!-- Filter Bar -->
        <div class="flex items-center justify-between flex-wrap gap-space-sm bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
          <div class="flex items-center gap-space-xs flex-wrap font-telemetry-sm text-telemetry-sm">
            <span class="font-label-caps text-label-caps uppercase text-on-surface-variant font-semibold">Protocol Filter:</span>
            ${['ALL', 'SMB', 'KERBEROS', 'RPC', 'HTTPS', 'DNS'].map(p => `
              <button class="px-space-xs py-space-2xs rounded-DEFAULT cursor-pointer font-mono ${protocolFilter === p ? 'bg-primary text-on-primary font-bold' : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}" data-proto="${p}">
                ${p}
              </button>
            `).join('')}
          </div>
          <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">
            Showing ${filtered.length} packets • Capture Buffer: 256KB
          </div>
        </div>

        <!-- Split View: Stream Table & Deep Packet Inspector -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
          <!-- Live Stream Table (7 cols) -->
          <div class="lg:col-span-7 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 flex flex-col justify-between">
            <div class="overflow-x-auto max-h-[560px] overflow-y-auto">
              <table class="w-full text-left font-telemetry-sm text-telemetry-sm">
                <thead class="bg-surface-container-lowest font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider sticky top-0 border-b border-surface-container-highest/30">
                  <tr>
                    <th class="py-space-xs px-space-sm">Time</th>
                    <th class="py-space-xs px-space-sm">Proto</th>
                    <th class="py-space-xs px-space-sm">Source</th>
                    <th class="py-space-xs px-space-sm">Destination</th>
                    <th class="py-space-xs px-space-sm">Action</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-container-highest/20">
                  ${filtered.map(l => {
                    const isSelected = activeLog.id === l.id;
                    return `
                      <tr class="cursor-pointer transition-colors ${isSelected ? 'bg-surface-container-high text-primary font-semibold' : 'hover:bg-surface-container text-on-surface'}" data-log-id="${l.id}">
                        <td class="py-space-xs px-space-sm font-mono text-on-surface-variant">${l.timestamp}</td>
                        <td class="py-space-xs px-space-sm">
                          <span class="px-space-xs py-space-2xs rounded-DEFAULT bg-surface-container font-mono text-[10px] font-bold ${l.protocol === 'KERBEROS' ? 'text-secondary' : l.protocol === 'SMB' ? 'text-error' : 'text-primary'}">
                            ${l.protocol}
                          </span>
                        </td>
                        <td class="py-space-xs px-space-sm font-mono">${l.src}</td>
                        <td class="py-space-xs px-space-sm font-mono">${l.dst}</td>
                        <td class="py-space-xs px-space-sm">
                          <span class="font-label-caps text-[9px] uppercase px-space-xs py-space-2xs rounded-DEFAULT ${l.action === 'DROP' ? 'bg-error-container/30 text-error' : l.action === 'ALERT' ? 'bg-secondary-container/20 text-secondary' : 'bg-primary/10 text-primary'}">
                            ${l.action}
                          </span>
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <!-- Deep Packet & Heuristic Inspector (5 cols) -->
          <div class="lg:col-span-5 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 flex flex-col justify-between space-y-space-md">
            <div>
              <div class="flex items-center justify-between pb-space-xs border-b border-surface-container-highest/30">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">troubleshoot</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface text-base">Payload &amp; TTP Inspector</h2>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-primary font-mono font-bold">${activeLog.id || 'N/A'}</span>
              </div>

              <!-- Metadata Grid -->
              <div class="grid grid-cols-2 gap-space-xs my-space-sm text-telemetry-sm font-telemetry-sm font-mono">
                <div class="bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30">
                  <span class="text-on-surface-variant text-[10px] block font-sans">Source IP</span>
                  <span class="text-error font-bold">${activeLog.src || 'N/A'}</span>
                </div>
                <div class="bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30">
                  <span class="text-on-surface-variant text-[10px] block font-sans">Destination</span>
                  <span class="text-primary font-bold">${activeLog.dst || 'N/A'}</span>
                </div>
              </div>

              <!-- MITRE Mapping Card -->
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-secondary/30 mb-space-sm">
                <div class="flex items-center justify-between mb-1">
                  <span class="font-label-caps text-label-caps text-secondary uppercase font-bold">MITRE ATT&amp;CK Heuristic</span>
                  <span class="font-telemetry-sm text-[10px] bg-secondary/20 text-secondary px-1 rounded-DEFAULT font-mono">CONFIDENCE: 94%</span>
                </div>
                <div class="font-headline-md text-sm text-on-surface font-semibold font-mono">${activeLog.mitre || 'T1046 Network Service Discovery'}</div>
                <p class="font-body-sm text-xs text-on-surface-variant mt-1">
                  Adversary attempting credential scraping via ticket requests or lateral share RPC pipes.
                </p>
              </div>

              <!-- Raw Payload Decoder -->
              <div class="space-y-space-2xs">
                <div class="flex items-center justify-between font-label-caps text-[10px] text-on-surface-variant uppercase">
                  <span>Raw Hex Frame Stream</span>
                  <span>HEX / ASCII DUMP</span>
                </div>
                <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT font-mono text-[11px] text-primary/90 overflow-x-auto border border-surface-container-highest/40 leading-relaxed max-h-48 overflow-y-auto">
                  <code>
0000  45 00 00 3c 1c 46 40 00 40 06 b1 e6 0a 04 01 11  E..<..@.@.......<br/>
0010  0a 04 0c 67 01 bd 1f 90 00 00 00 00 a0 02 72 10  ...g..........r.<br/>
0020  28 92 00 00 02 04 05 b4 04 02 08 0a 00 24 3d 76  (............$=v<br/>
0030  ff ff ff ff 53 4d 42 72 00 00 00 00 18 53 c8 00  ....SMBr.....S..<br/>
                  </code>
                </div>
              </div>
            </div>

            <!-- Action footer -->
            <div class="pt-space-xs border-t border-surface-container-highest/30 flex items-center justify-between">
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Sensor ID: EDR-US-EAST-01</span>
              <button id="inspect-full-asset" class="text-primary hover:underline font-telemetry-sm text-telemetry-sm flex items-center gap-1 cursor-pointer">
                <span>Inspect Target Host</span>
                <span class="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    // Event listeners
    container.querySelectorAll('[data-proto]').forEach(btn => {
      btn.addEventListener('click', () => {
        protocolFilter = btn.getAttribute('data-proto');
        update();
      });
    });

    container.querySelectorAll('[data-log-id]').forEach(tr => {
      tr.addEventListener('click', () => {
        const id = tr.getAttribute('data-log-id');
        selectedLog = logs.find(l => l.id === id);
        update();
      });
    });

    const pauseBtn = container.querySelector('#pause-stream-btn');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        isPaused = !isPaused;
        if (isPaused) telemetry.pause();
        else telemetry.resume();
        update();
      });
    }

    const isolateBtn = container.querySelector('#isolate-source-btn');
    if (isolateBtn) {
      isolateBtn.addEventListener('click', () => {
        alert("Egress drop rule deployed at perimeter firewall for IP 194.26.29.112.");
      });
    }

    const inspectBtn = container.querySelector('#inspect-full-asset');
    if (inspectBtn) {
      inspectBtn.addEventListener('click', () => {
        store.openNodeDetail('PC-017');
      });
    }
  };

  update();
  store.subscribeView(update);

  // Auto-refresh log list every 4 seconds to show new live entries
  let liveRefreshId = setInterval(() => {
    if (!isPaused && container.isConnected) {
      update();
    } else if (!container.isConnected) {
      clearInterval(liveRefreshId);
    }
  }, 4000);
}
