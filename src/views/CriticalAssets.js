import { store } from '../state/store.js';

export function renderCriticalAssets(container) {
  let tierFilter = 'ALL';

  const update = () => {
    const state = store.getState();
    const nodes = Object.values(state.nodes).filter(n => n.id !== 'EXT-01');

    const filtered = tierFilter === 'ALL'
      ? nodes
      : nodes.filter(n => n.tier.toLowerCase().includes(tierFilter.toLowerCase()));

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">hub</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">INFRASTRUCTURE INVENTORY</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">CRITICAL ASSETS &amp; CROWN JEWELS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              High-value targets, domain relays, and privileged jumpboxes mapped into zero-trust defensive fabrics.
            </p>
          </div>

          <!-- Tier Filter -->
          <div class="flex items-center gap-space-xs bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase px-1">TIER:</span>
            ${['ALL', 'Tier 0', 'Tier 1', 'Tier 2', 'Tier 3'].map(t => `
              <button class="px-space-sm py-space-xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold cursor-pointer font-mono ${tierFilter === t ? 'bg-primary text-on-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface'}" data-tier="${t}">
                ${t.toUpperCase()}
              </button>
            `).join('')}
          </div>
        </div>

        <!-- Asset Cards Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-space-md">
          ${filtered.map(node => {
            const isIso = node.isolated;
            return `
              <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border ${isIso ? 'border-primary/60 ring-1 ring-primary/30' : 'border-surface-container-high/40'} flex flex-col justify-between space-y-space-sm">
                <div>
                  <div class="flex items-center justify-between mb-space-xs">
                    <span class="font-label-caps text-[9px] uppercase px-space-xs py-space-2xs rounded-DEFAULT font-bold ${node.tier.includes('0') ? 'bg-error-container text-on-error-container' : 'bg-surface-container text-primary'}">
                      ${node.tier}
                    </span>
                    <span class="font-telemetry-sm text-telemetry-sm font-bold font-mono ${node.riskScore > 75 ? 'text-error' : 'text-secondary'}">
                      RISK: ${node.riskScore}/100
                    </span>
                  </div>

                  <div class="flex items-center gap-space-xs">
                    <div class="w-10 h-10 rounded-DEFAULT ${isIso ? 'bg-primary/20 text-primary' : 'bg-surface-container-high text-on-surface'} flex items-center justify-center">
                      <span class="material-symbols-outlined text-[22px]">${isIso ? 'verified_user' : 'dns'}</span>
                    </div>
                    <div>
                      <h3 class="font-headline-md text-headline-md text-on-surface font-bold text-sm truncate">${node.name}</h3>
                      <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">${node.ip}</span>
                    </div>
                  </div>

                  <div class="my-space-sm space-y-1 text-telemetry-sm font-telemetry-sm font-mono text-on-surface-variant">
                    <div class="flex justify-between">
                      <span>Subnet:</span>
                      <span class="text-on-surface">${node.subnet || 'DMZ'}</span>
                    </div>
                    <div class="flex justify-between">
                      <span>OS:</span>
                      <span class="text-on-surface truncate max-w-[160px]">${node.os || 'N/A'}</span>
                    </div>
                    <div class="flex justify-between">
                      <span>Telemetry Agent:</span>
                      <span class="text-primary">${node.agentStatus || 'Active'}</span>
                    </div>
                  </div>
                </div>

                <div class="pt-space-xs border-t border-surface-container-highest/30 flex items-center justify-between">
                  <button class="text-primary hover:underline font-telemetry-sm text-telemetry-sm flex items-center gap-1 cursor-pointer" data-detail-id="${node.id}">
                    <span>Inspect Specs</span>
                    <span class="material-symbols-outlined text-[14px]">arrow_forward</span>
                  </button>

                  <button class="px-space-sm py-1 rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold transition-all cursor-pointer ${isIso ? 'bg-secondary text-on-secondary hover:bg-secondary-container' : 'bg-error-container/30 hover:bg-error-container text-error'}" data-toggle-iso="${node.id}">
                    ${isIso ? 'Release' : 'Isolate'}
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;

    container.querySelectorAll('[data-tier]').forEach(btn => {
      btn.addEventListener('click', () => {
        tierFilter = btn.getAttribute('data-tier');
        update();
      });
    });

    container.querySelectorAll('[data-detail-id]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-detail-id');
        store.openNodeDetail(id);
      });
    });

    container.querySelectorAll('[data-toggle-iso]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-toggle-iso');
        store.quarantineNode(id);
      });
    });
  };

  update();
  store.subscribeView(update);
}
