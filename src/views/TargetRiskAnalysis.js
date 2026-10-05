import { store } from '../state/store.js';

export function renderTargetRiskAnalysis(container) {
  let selectedAsset = 'DATABASE-01';

  const update = () => {
    const state = store.getState();
    const nodes = state.nodes;
    const targetNode = nodes[selectedAsset] || nodes['DATABASE-01'];

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">crisis_alert</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">ASSET EXPOSURE &amp; CENTRALITY</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">TARGET RISK &amp; BLAST RADIUS ANALYSIS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Algorithmic graph centrality (PageRank &amp; betweenness) assessing cascading operational collapse if targeted assets fall.
            </p>
          </div>

          <button id="isolate-selected-asset-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-md flex items-center gap-space-xs cursor-pointer">
            <span class="material-symbols-outlined text-[18px]">security</span>
            <span>Enforce Tier Isolation (${selectedAsset})</span>
          </button>
        </div>

        <!-- Centrality Score Matrix Table -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
          <!-- Asset Table (8 cols) -->
          <div class="lg:col-span-8 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-sm">
            <div class="flex items-center justify-between">
              <h2 class="font-headline-md text-headline-md text-on-surface">Target Vulnerability &amp; Reachability Index</h2>
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Sorted by Compromise Likelihood</span>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left font-body-sm text-body-sm">
                <thead class="bg-surface-container-lowest font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider border-b border-surface-container-highest/30">
                  <tr>
                    <th class="py-space-sm px-space-md">Asset Identifier</th>
                    <th class="py-space-sm px-space-md">Tier</th>
                    <th class="py-space-sm px-space-md">Reachability</th>
                    <th class="py-space-sm px-space-md">Risk Score</th>
                    <th class="py-space-sm px-space-md text-right">Status</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-container-highest/20 font-telemetry-sm text-telemetry-sm">
                  ${Object.values(nodes).filter(n => n.id !== 'EXT-01').map(n => {
                    const isSelected = n.id === selectedAsset;
                    return `
                      <tr 
                        class="cursor-pointer transition-colors ${isSelected ? 'bg-surface-container-high text-primary font-bold' : 'hover:bg-surface-container text-on-surface'}"
                        data-asset-row="${n.id}"
                      >
                        <td class="py-space-sm px-space-md">
                          <div class="flex items-center gap-space-xs">
                            <span class="material-symbols-outlined text-[18px] ${n.isolated ? 'text-primary' : 'text-on-surface-variant'}">${n.isolated ? 'verified_user' : 'dns'}</span>
                            <span class="font-semibold">${n.name}</span>
                          </div>
                        </td>
                        <td class="py-space-sm px-space-md font-mono">${n.tier}</td>
                        <td class="py-space-sm px-space-md font-mono">${n.isolated ? '0.00 (Isolated)' : n.riskScore > 80 ? '0.89 (Direct Hop)' : '0.45 (Secondary)'}</td>
                        <td class="py-space-sm px-space-md font-mono font-bold ${n.riskScore > 75 ? 'text-error' : 'text-secondary'}">${n.riskScore}/100</td>
                        <td class="py-space-sm px-space-md text-right">
                          <span class="font-label-caps text-[9px] uppercase px-space-xs py-space-2xs rounded-DEFAULT ${n.isolated ? 'bg-primary/20 text-primary font-bold' : 'bg-surface-container text-on-surface-variant'}">
                            ${n.isolated ? 'QUARANTINED' : 'ACTIVE IN FABRIC'}
                          </span>
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <!-- Selected Asset Blast Radius Inspector (4 cols) -->
          <div class="lg:col-span-4 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 flex flex-col justify-between space-y-space-sm">
            <div>
              <div class="flex items-center justify-between pb-space-xs border-b border-surface-container-highest/30">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">hub</span>
                  <h3 class="font-headline-md text-headline-md text-on-surface">Blast Radius Analysis</h3>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-primary font-mono font-bold">${targetNode.id}</span>
              </div>

              <!-- Selected Asset Specs -->
              <div class="my-space-sm space-y-space-xs text-telemetry-sm font-telemetry-sm">
                <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT flex justify-between">
                  <span class="text-on-surface-variant">Asset Hostname:</span>
                  <span class="text-on-surface font-mono">${targetNode.hostname || targetNode.ip}</span>
                </div>
                <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT flex justify-between">
                  <span class="text-on-surface-variant">Network Subnet:</span>
                  <span class="text-on-surface font-mono">${targetNode.subnet || 'DMZ'}</span>
                </div>
                <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT flex justify-between">
                  <span class="text-on-surface-variant">Security Role:</span>
                  <span class="text-primary font-mono">${targetNode.role}</span>
                </div>
              </div>

              <!-- Cascading Impact Metrics -->
              <div class="space-y-space-xs pt-space-xs">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Cascading Impact if Compromised</span>
                <div>
                  <div class="flex justify-between text-telemetry-sm font-telemetry-sm mb-1">
                    <span class="text-on-surface">Immediate Peer Nodes Infected:</span>
                    <span class="text-error font-bold font-mono">4 Systems</span>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
                    <div class="bg-error h-full rounded-full" style="width: 80%"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between text-telemetry-sm font-telemetry-sm mb-1">
                    <span class="text-on-surface">Financial Transaction Halt:</span>
                    <span class="text-error font-bold font-mono">100% Critical Vault</span>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
                    <div class="bg-error h-full rounded-full" style="width: 100%"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between text-telemetry-sm font-telemetry-sm mb-1">
                    <span class="text-on-surface">Regulatory Breach Fine Exposure:</span>
                    <span class="text-secondary font-bold font-mono">$18.5M (GDPR/PCI)</span>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
                    <div class="bg-secondary h-full rounded-full" style="width: 65%"></div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Deep Inspect button -->
            <button id="inspect-target-modal-btn" class="w-full py-space-sm bg-surface-container-high hover:bg-surface-variant text-on-surface font-telemetry-sm text-telemetry-sm font-semibold rounded-DEFAULT transition-colors flex items-center justify-center gap-1 cursor-pointer">
              <span class="material-symbols-outlined text-[16px]">visibility</span>
              <span>Open Host Specification Modal</span>
            </button>
          </div>
        </div>
      </div>
    `;

    // Event listeners
    container.querySelectorAll('[data-asset-row]').forEach(row => {
      row.addEventListener('click', () => {
        selectedAsset = row.getAttribute('data-asset-row');
        update();
      });
    });

    const isolateBtn = container.querySelector('#isolate-selected-asset-btn');
    if (isolateBtn) {
      isolateBtn.addEventListener('click', () => {
        store.quarantineNode(selectedAsset);
      });
    }

    const modalBtn = container.querySelector('#inspect-target-modal-btn');
    if (modalBtn) {
      modalBtn.addEventListener('click', () => {
        store.openNodeDetail(selectedAsset);
      });
    }
  };

  update();
  store.subscribeView(update);
}
