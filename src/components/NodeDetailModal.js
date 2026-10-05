import { store } from '../state/store.js';

export function renderNodeDetailModal(container) {
  const update = () => {
    const state = store.getState();
    const node = state.selectedNode;
    if (!state.nodeDetailModalOpen || !node) {
      container.innerHTML = '';
      return;
    }

    const isIsolated = node.isolated;

    container.innerHTML = `
      <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-container-lowest/80 backdrop-blur-md p-space-md" id="node-modal-backdrop">
        <div class="bg-surface-container-low max-w-xl w-full p-space-lg rounded-DEFAULT shadow-2xl border border-surface-container-highest flex flex-col gap-space-md animate-in fade-in zoom-in-95 duration-150">
          <div class="flex items-center justify-between border-b border-surface-container-highest pb-space-sm">
            <div class="flex items-center gap-space-sm">
              <div class="w-10 h-10 rounded-DEFAULT ${isIsolated ? 'bg-error-container/30 text-error' : 'bg-primary-container/20 text-primary'} flex items-center justify-center">
                <span class="material-symbols-outlined text-[24px]">${isIsolated ? 'gpp_bad' : 'dns'}</span>
              </div>
              <div class="flex flex-col">
                <span class="font-headline-md text-headline-md text-on-surface font-bold">${node.name}</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">${node.ip} • ${node.subnet || 'External'}</span>
              </div>
            </div>
            <button class="text-on-surface-variant hover:text-on-surface" id="close-node-btn">
              <span class="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>

          <!-- Status Pill Strip -->
          <div class="flex items-center justify-between bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/60">
            <div class="flex flex-col">
              <span class="font-label-caps text-[10px] text-on-surface-variant uppercase">CONTAINMENT STATUS</span>
              <span class="font-telemetry-sm text-telemetry-sm font-bold ${isIsolated ? 'text-error flex items-center gap-1' : 'text-primary flex items-center gap-1'}">
                <span class="w-2 h-2 rounded-full ${isIsolated ? 'bg-error' : 'bg-primary animate-pulse'}"></span>
                ${isIsolated ? 'QUARANTINED (ISOLATED)' : 'ACTIVE IN FABRIC'}
              </span>
            </div>
            <div class="flex flex-col text-right">
              <span class="font-label-caps text-[10px] text-on-surface-variant uppercase">RISK LEVEL</span>
              <span class="font-headline-md text-headline-md ${node.riskScore > 75 ? 'text-error' : 'text-secondary'} font-bold">
                ${node.riskScore || 50}/100
              </span>
            </div>
          </div>

          <!-- Technical Specs -->
          <div class="grid grid-cols-2 gap-space-xs text-telemetry-sm font-telemetry-sm">
            <div class="bg-surface-container p-space-xs rounded-DEFAULT flex flex-col">
              <span class="text-on-surface-variant text-[10px]">Operating System:</span>
              <span class="text-on-surface truncate">${node.os || 'N/A'}</span>
            </div>
            <div class="bg-surface-container p-space-xs rounded-DEFAULT flex flex-col">
              <span class="text-on-surface-variant text-[10px]">Asset Role:</span>
              <span class="text-on-surface truncate">${node.role || 'N/A'}</span>
            </div>
            <div class="bg-surface-container p-space-xs rounded-DEFAULT flex flex-col">
              <span class="text-on-surface-variant text-[10px]">Security Tier:</span>
              <span class="text-primary truncate font-semibold">${node.tier || 'Tier 2'}</span>
            </div>
            <div class="bg-surface-container p-space-xs rounded-DEFAULT flex flex-col">
              <span class="text-on-surface-variant text-[10px]">Agent Telemetry:</span>
              <span class="text-on-surface truncate">${node.agentStatus || 'Sensors Active'}</span>
            </div>
          </div>

          <!-- CVEs and Threat Exposure -->
          <div class="space-y-space-2xs">
            <span class="font-label-caps text-[10px] text-on-surface-variant uppercase">Detected Vulnerabilities &amp; Artifacts</span>
            <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT space-y-1 text-telemetry-sm font-telemetry-sm">
              ${(node.cves && node.cves.length > 0) ? node.cves.map(c => `
                <div class="flex items-center justify-between text-error bg-error-container/10 px-space-xs py-1 rounded-DEFAULT">
                  <span class="flex items-center gap-1"><span class="material-symbols-outlined text-[14px]">warning</span> ${c}</span>
                  <span class="text-[10px] uppercase font-bold">CRITICAL EXPLOIT</span>
                </div>
              `).join('') : `
                <div class="text-on-surface-variant text-[11px]">No active unpatched perimeter vulnerabilities flagged.</div>
              `}
            </div>
          </div>

          <!-- Action Controls -->
          <div class="flex items-center justify-between pt-space-xs border-t border-surface-container-highest mt-space-xs">
            <span class="text-on-surface-variant font-telemetry-sm text-telemetry-sm">EDR Agent v4.2 Synced</span>
            <div class="flex items-center gap-space-xs">
              <button id="toggle-isolation-btn" class="px-space-md py-space-sm rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold transition-all flex items-center gap-1 shadow-md ${
                isIsolated 
                  ? 'bg-secondary text-on-secondary hover:bg-secondary-container' 
                  : 'bg-error-container hover:bg-error text-on-error-container'
              }">
                <span class="material-symbols-outlined text-[16px]">${isIsolated ? 'lock_open' : 'block'}</span>
                <span>${isIsolated ? 'Release Quarantine' : 'Quarantine / Isolate Host'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    const closeBtn = container.querySelector('#close-node-btn');
    const backdrop = container.querySelector('#node-modal-backdrop');
    const toggleBtn = container.querySelector('#toggle-isolation-btn');

    if (closeBtn) closeBtn.addEventListener('click', () => store.closeNodeDetail());
    if (backdrop) backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) store.closeNodeDetail();
    });
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        store.quarantineNode(node.id);
        // Refresh detail view
        store.openNodeDetail(node.id);
      });
    }
  };

  update();
  store.subscribe(update);
}
