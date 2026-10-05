import { store } from '../state/store.js';

export function renderPredictedAttackPath(container) {
  let zoomLevel = 1;

  const update = () => {
    const state = store.getState();
    const isIsolated = state.nodes['PC-017']?.isolated;
    const isRecalibrating = state.recalibrating;

    container.innerHTML = `
      <div class="flex flex-col w-full gap-space-md">
        <!-- Top Command Ribbon -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="flex flex-col gap-space-2xs min-w-0">
            <div class="flex items-center gap-space-sm flex-wrap">
              <span class="font-label-caps text-label-caps bg-error-container text-on-error-container px-space-xs py-space-2xs rounded-DEFAULT uppercase tracking-wider font-semibold">
                ${isIsolated ? 'THREAT VECTOR CONTAINED' : 'Live Threat Vector'}
              </span>
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-medium font-mono">CAMPAIGN-PX-9821</span>
              <span class="inline-block w-1 h-1 rounded-full bg-outline-variant"></span>
              <span class="font-telemetry-sm text-telemetry-sm text-primary font-medium flex items-center gap-space-2xs">
                <span class="w-2 h-2 rounded-full bg-primary animate-pulse inline-block"></span>
                ACTIVE NEURAL GRAPH
              </span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-semibold tracking-tight">PREDICTED ATTACK PATH ANALYSIS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-2xl">
              Dynamic probabilistic graph mapping observed adversarial trajectory and AI-projected progression vectors.
            </p>
          </div>

          <!-- Right Controls: Case Selector & Action -->
          <div class="flex flex-col sm:flex-row items-start sm:items-center gap-space-sm w-full lg:w-auto">
            <div class="relative flex items-center bg-surface-container-lowest px-space-sm py-space-xs rounded-DEFAULT shadow-inner min-w-[320px] border border-surface-container-highest/30">
              <span class="material-symbols-outlined text-[18px] text-error mr-space-xs">crisis_alert</span>
              <div class="flex flex-col min-w-0 flex-1">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Active Emulation Profile</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface font-semibold truncate font-mono">Campaign #PX-9821 (APT-29 Derivative)</span>
              </div>
              <span class="font-telemetry-sm text-telemetry-sm text-error bg-error-container/20 px-space-xs py-space-2xs rounded-DEFAULT ml-space-xs uppercase font-mono">ACTIVE</span>
            </div>

            <div class="flex items-center gap-space-xs">
              <button 
                id="graph-recalibrate-btn" 
                class="flex items-center gap-space-2xs px-space-sm py-space-xs bg-surface-container hover:bg-surface-container-high text-on-surface rounded-DEFAULT transition-all font-telemetry-sm text-telemetry-sm shadow-sm cursor-pointer border border-surface-container-highest/40"
              >
                <span class="material-symbols-outlined text-[16px] text-primary ${isRecalibrating ? 'animate-spin' : ''}">autorenew</span>
                <span>${isRecalibrating ? 'Calculating...' : 'Recalibrate'}</span>
              </button>
              <button 
                id="graph-deploy-intercept"
                class="flex items-center gap-space-2xs px-space-sm py-space-xs bg-primary hover:bg-primary-fixed-dim text-on-primary font-semibold rounded-DEFAULT transition-all font-telemetry-sm text-telemetry-sm shadow-md cursor-pointer"
              >
                <span class="material-symbols-outlined text-[16px]">security</span>
                <span>Deploy Intercept</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Legend Ribbon -->
        <div class="flex items-center justify-between flex-wrap gap-space-sm bg-surface-container-lowest px-space-md py-space-xs rounded-DEFAULT text-on-surface-variant font-telemetry-sm text-telemetry-sm shadow-sm border border-surface-container-highest/30">
          <div class="flex items-center gap-space-md flex-wrap">
            <span class="font-label-caps text-label-caps uppercase text-on-surface font-semibold tracking-wider">Vector Dynamics:</span>
            <div class="flex items-center gap-space-xs">
              <span class="w-4 h-0.5 bg-error inline-block rounded-full"></span>
              <span class="text-on-surface">Observed Trajectory</span>
              <span class="text-on-surface-variant text-[10px]">(Confirmed Breach)</span>
            </div>
            <div class="flex items-center gap-space-xs">
              <span class="w-4 h-0.5 bg-primary-container inline-block border-b-2 border-dashed border-primary-container"></span>
              <span class="text-primary font-medium">Predicted Vectors</span>
              <span class="text-on-surface-variant text-[10px]">(AI Projected)</span>
            </div>
            <div class="flex items-center gap-space-xs">
              <span class="w-4 h-0.5 bg-secondary inline-block border-b border-dashed border-secondary"></span>
              <span class="text-secondary font-medium">Alternative Paths</span>
              <span class="text-on-surface-variant text-[10px]">(Low/Med Prob)</span>
            </div>
            <div class="flex items-center gap-space-xs">
              <span class="w-2.5 h-2.5 rounded-full bg-primary-fixed flex items-center justify-center animate-ping text-[8px] text-on-primary"></span>
              <span class="text-primary font-semibold">Disruption Recommendation</span>
            </div>
          </div>
          <div class="flex items-center gap-space-sm text-on-surface-variant">
            <span class="flex items-center gap-space-2xs"><span class="w-1.5 h-1.5 rounded-full bg-primary"></span> Bayesian Engine Active</span>
            <span class="text-outline-variant">|</span>
            <span class="font-mono">Graph Epoch: #${state.telemetry.epoch}</span>
          </div>
        </div>

        <!-- Main Split Canvas Layout (16 Cols Graph, 8 Cols Telemetry Panel) -->
        <div class="grid grid-cols-1 xl:grid-cols-24 gap-space-md items-start w-full">
          <!-- LEFT & CENTER: Interactive Attack Graph Workspace (16 Cols) -->
          <div class="xl:col-span-16 flex flex-col gap-space-sm">
            <div class="relative bg-surface-container-lowest rounded-DEFAULT p-space-md min-h-[760px] flex flex-col justify-between overflow-hidden shadow-xl border border-surface-container-high/40">
              <!-- Technical Grid Micro-Texture -->
              <svg class="absolute inset-0 w-full h-full opacity-15 pointer-events-none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <pattern height="32" id="tactical-grid-pat" patternUnits="userSpaceOnUse" width="32">
                    <path class="text-outline-variant" d="M 32 0 L 0 0 0 32" fill="none" stroke="currentColor" stroke-width="0.5"></path>
                    <circle class="text-primary" cx="32" cy="0" fill="currentColor" r="0.75"></circle>
                  </pattern>
                </defs>
                <rect fill="url(#tactical-grid-pat)" height="100%" width="100%"></rect>
              </svg>

              <!-- Ambient Glow Backdrops -->
              <div class="absolute -top-12 -left-12 w-64 h-64 bg-error-container/10 rounded-full blur-3xl pointer-events-none"></div>
              <div class="absolute top-1/2 left-1/3 w-80 h-80 bg-primary-container/10 rounded-full blur-3xl pointer-events-none"></div>
              <div class="absolute -bottom-16 right-16 w-72 h-72 bg-tertiary-container/10 rounded-full blur-3xl pointer-events-none"></div>

              <!-- Graph Workspace Header / Action Bar -->
              <div class="relative z-10 flex items-center justify-between pb-space-xs border-b border-surface-container-highest/30">
                <div class="flex items-center gap-space-sm">
                  <span class="font-label-caps text-label-caps text-primary bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT uppercase tracking-wider font-semibold">Graph Topo-Matrix v4.2</span>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Cluster: US-EAST-DMZ &amp; Core-LAN</span>
                </div>
                <div class="flex items-center gap-space-2xs bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT border border-surface-container-highest/40">
                  <button id="zoom-in-btn" class="p-space-2xs text-on-surface-variant hover:text-primary transition-colors cursor-pointer" title="Zoom In">
                    <span class="material-symbols-outlined text-[16px]">zoom_in</span>
                  </button>
                  <button id="zoom-out-btn" class="p-space-2xs text-on-surface-variant hover:text-primary transition-colors cursor-pointer" title="Zoom Out">
                    <span class="material-symbols-outlined text-[16px]">zoom_out</span>
                  </button>
                  <button id="zoom-reset-btn" class="p-space-2xs text-on-surface-variant hover:text-primary transition-colors cursor-pointer font-telemetry-sm text-telemetry-sm font-mono" title="Reset Zoom">
                    ${Math.round(zoomLevel * 100)}%
                  </button>
                  <span class="w-px h-3 bg-outline-variant"></span>
                  <button id="export-topo-btn" class="p-space-2xs text-on-surface-variant hover:text-primary transition-colors cursor-pointer" title="Export Topology (JSON)">
                    <span class="material-symbols-outlined text-[16px]">share</span>
                  </button>
                </div>
              </div>

              <!-- Graph Canvas Content Container -->
              <div class="relative z-10 flex-1 my-space-sm flex flex-col justify-between py-space-sm transition-transform duration-200" id="graph-zoom-canvas" style="transform: scale(${zoomLevel}); transform-origin: top left;">
                <!-- NODE 1: EXTERNAL SOURCE -->
                <div class="flex items-center justify-start w-full">
                  <div class="w-full max-w-sm bg-surface-container-high/90 backdrop-blur-md p-space-sm rounded-DEFAULT shadow-lg hover:bg-surface-container-highest transition-all group cursor-pointer border border-error/40" data-inspect="EXT-01">
                    <div class="flex items-center justify-between mb-space-2xs">
                      <span class="font-label-caps text-label-caps bg-error-container text-on-error-container px-space-xs py-space-2xs rounded-DEFAULT font-bold flex items-center gap-1">
                        <span class="w-1.5 h-1.5 rounded-full bg-error animate-ping"></span> INTRUDER ORIGIN
                      </span>
                      <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold">Observed State</span>
                    </div>
                    <div class="flex items-center justify-between">
                      <div class="flex flex-col min-w-0">
                        <div class="flex items-center gap-space-2xs">
                          <span class="material-symbols-outlined text-error text-[18px]">public_off</span>
                          <span class="font-headline-md text-headline-md text-on-surface font-semibold truncate">EXTERNAL SOURCE</span>
                        </div>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">IP: 194.26.29.112 (AS49505)</span>
                      </div>
                      <div class="text-right">
                        <span class="font-label-caps text-label-caps text-on-surface-variant block">Threat Signature</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold font-mono">CVE-2023-4966</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- VECTOR 1 -> 2: SOLID RED CONNECTOR -->
                <div class="flex items-center ml-12 my-space-2xs">
                  <div class="flex items-center gap-space-sm bg-surface-container-lowest/90 px-space-sm py-space-2xs rounded-DEFAULT shadow-md border border-surface-container-highest/40">
                    <div class="flex flex-col items-center">
                      <span class="w-0.5 h-6 bg-error"></span>
                      <span class="material-symbols-outlined text-error text-[16px] -my-1">arrow_downward</span>
                    </div>
                    <div class="flex flex-col">
                      <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold flex items-center gap-space-2xs font-mono">
                        Port Scan &amp; Exploit Vector (Observed 10:01 UTC)
                      </span>
                      <span class="font-body-sm text-body-sm text-on-surface-variant">Citrix NetScaler Gateway Unauthenticated Memory Leak</span>
                    </div>
                  </div>
                </div>

                <!-- NODE 2: PC-017 (Observed Compromised Node with Disruption Badge) -->
                <div class="flex items-center justify-start ml-6 w-full">
                  <div class="w-full max-w-md bg-surface-container-high/95 backdrop-blur-md p-space-sm rounded-DEFAULT shadow-xl hover:bg-surface-container-highest transition-all relative border-2 ${isIsolated ? 'border-primary' : 'border-error/50'} cursor-pointer" data-inspect="PC-017">
                    <!-- Target Recommendation Badge Pin -->
                    <div class="absolute -top-3 -right-2 ${isIsolated ? 'bg-primary' : 'bg-primary-container text-on-primary-container'} px-space-xs py-space-2xs rounded-DEFAULT font-label-caps text-label-caps uppercase flex items-center gap-1 shadow-md font-bold">
                      <span class="material-symbols-outlined text-[14px]">shield</span>
                      ${isIsolated ? 'QUARANTINE ENFORCED' : 'Recommended Cutoff Point'}
                    </div>

                    <div class="flex items-center justify-between mb-space-2xs">
                      <div class="flex items-center gap-space-xs">
                        <span class="font-label-caps text-label-caps ${isIsolated ? 'bg-primary/20 text-primary' : 'bg-error-container text-on-error-container'} px-space-xs py-space-2xs rounded-DEFAULT font-bold">
                          ${isIsolated ? 'HOST QUARANTINED' : 'COMPROMISED HOST'}
                        </span>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">Subnet: 10.4.1.0/24</span>
                      </div>
                      <span class="font-telemetry-sm text-telemetry-sm font-mono font-bold ${isIsolated ? 'text-primary' : 'text-error'}">
                        ${isIsolated ? 'RISK: 24/100' : 'RISK: 91/100'}
                      </span>
                    </div>

                    <div class="flex items-center justify-between">
                      <div class="flex flex-col min-w-0">
                        <div class="flex items-center gap-space-2xs">
                          <span class="material-symbols-outlined text-[20px] ${isIsolated ? 'text-primary' : 'text-error'}">laptop_mac</span>
                          <span class="font-headline-md text-headline-md text-on-surface font-semibold truncate">PC-017 (Dev-Ops Workstation)</span>
                        </div>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.1.17 • Host Agent: Sensor-Active</span>
                      </div>
                      <div class="text-right">
                        <span class="font-label-caps text-label-caps text-on-surface-variant block">CRITICALITY</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-secondary font-semibold">Tier 3 (4/10)</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- VECTOR 2 -> 3: SOLID RED / SEVERED CONNECTOR -->
                <div class="flex items-center ml-20 my-space-2xs">
                  <div class="flex items-center gap-space-sm bg-surface-container-lowest/90 px-space-sm py-space-2xs rounded-DEFAULT shadow-md border ${isIsolated ? 'border-primary/40' : 'border-surface-container-highest/40'}">
                    <div class="flex flex-col items-center">
                      <span class="w-0.5 h-6 ${isIsolated ? 'bg-primary' : 'bg-error'}"></span>
                      <span class="material-symbols-outlined text-[16px] -my-1 ${isIsolated ? 'text-primary' : 'text-error'}">${isIsolated ? 'block' : 'arrow_downward'}</span>
                    </div>
                    <div class="flex flex-col">
                      <span class="font-telemetry-sm text-telemetry-sm font-semibold flex items-center gap-space-2xs font-mono ${isIsolated ? 'text-primary' : 'text-error'}">
                        ${isIsolated ? 'PATH SEVERED: Traversal Bridge Disconnected' : 'Lateral SMB Movement (Observed 10:09 UTC)'}
                      </span>
                      <span class="font-body-sm text-body-sm text-on-surface-variant">
                        ${isIsolated ? 'Zero packets routed to SERVER-03 via local interface shutdown' : 'PsExec invocation using stolen service account token svc-billing'}
                      </span>
                    </div>
                  </div>
                </div>

                <!-- NODE 3: SERVER-03 (Active Pivot Point) -->
                <div class="flex items-center justify-start ml-12 w-full">
                  <div class="w-full max-w-lg bg-surface-container-high/95 backdrop-blur-md p-space-sm rounded-DEFAULT shadow-2xl transition-all relative border border-surface-container-highest/50 cursor-pointer hover:bg-surface-container-highest" data-inspect="SERVER-03">
                    <div class="flex items-center justify-between mb-space-2xs">
                      <div class="flex items-center gap-space-xs">
                        <span class="font-label-caps text-label-caps ${isIsolated ? 'bg-secondary/20 text-secondary' : 'bg-error-container text-on-error-container'} px-space-xs py-space-2xs rounded-DEFAULT font-bold flex items-center gap-1">
                          <span class="w-1.5 h-1.5 rounded-full ${isIsolated ? 'bg-secondary' : 'bg-error'}"></span> 
                          ${isIsolated ? 'ISOLATED THREAT SOURCE' : 'ACTIVE INFILTRATED PIVOT'}
                        </span>
                        <span class="font-telemetry-sm text-telemetry-sm text-primary font-mono">STATIONARY THREAT</span>
                      </div>
                      <span class="font-telemetry-sm text-telemetry-sm text-error font-mono font-bold">RISK: 96/100</span>
                    </div>
                    <div class="flex items-center justify-between">
                      <div class="flex flex-col min-w-0">
                        <div class="flex items-center gap-space-2xs">
                          <span class="material-symbols-outlined text-error text-[20px]">dns</span>
                          <span class="font-headline-md text-headline-md text-on-surface font-semibold truncate">SERVER-03 (App Server / Core LAN)</span>
                        </div>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.12.103 • OS: Linux Kernel 5.15 LTS</span>
                      </div>
                      <div class="text-right">
                        <span class="font-label-caps text-label-caps text-on-surface-variant block">CRITICALITY</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold">Tier 2 (7/10)</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- BRANCH JUNCTION (MAIN CYAN PATH vs AMBER FORKS) -->
                <div class="grid grid-cols-1 md:grid-cols-12 gap-space-sm items-start ml-16 my-space-xs">
                  <!-- MAIN PREDICTED VECTOR (CYAN DASHED) -> LEADS TO ADMIN-02 -->
                  <div class="md:col-span-7 flex flex-col gap-space-xs">
                    <div class="bg-surface-container-lowest/90 px-space-sm py-space-xs rounded-DEFAULT shadow-md flex items-center gap-space-sm border border-surface-container-highest/40">
                      <div class="flex flex-col items-center">
                        <span class="w-0.5 h-8 bg-primary-container inline-block"></span>
                        <span class="material-symbols-outlined text-primary-container text-[18px] -my-1">arrow_downward</span>
                      </div>
                      <div class="flex flex-col">
                        <div class="flex items-center gap-space-xs">
                          <span class="font-label-caps text-label-caps bg-primary-container text-on-primary-container font-bold px-space-xs py-space-2xs rounded-DEFAULT">
                            ${isIsolated ? '12% PROBABILITY' : '87% PROBABILITY'}
                          </span>
                          <span class="font-telemetry-sm text-telemetry-sm text-primary font-medium font-mono">
                            ${isIsolated ? 'De-escalated' : 'Horizon: 4–7 min'}
                          </span>
                        </div>
                        <span class="font-body-sm text-body-sm text-on-surface font-medium">Privilege Escalation Vector</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Discovered Kerberos ticket in LSASS cache pointing to Jumphost</span>
                      </div>
                    </div>

                    <!-- NODE 4: ADMIN-02 (Predicted Next Target) -->
                    <div class="w-full bg-surface-container-high/95 backdrop-blur-md p-space-sm rounded-DEFAULT shadow-2xl transition-all relative border border-primary/40 cursor-pointer hover:bg-surface-container-highest" data-inspect="ADMIN-02">
                      <div class="flex items-center justify-between mb-space-2xs">
                        <div class="flex items-center gap-space-xs">
                          <span class="font-label-caps text-label-caps bg-primary-container text-on-primary-container px-space-xs py-space-2xs rounded-DEFAULT font-bold flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-on-primary-container animate-ping"></span> PREDICTED NEXT TARGET
                          </span>
                          <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Core Jumpbox</span>
                        </div>
                        <span class="font-telemetry-sm text-telemetry-sm text-secondary font-mono font-bold">PROJECTED RISK: 84/100</span>
                      </div>
                      <div class="flex items-center justify-between">
                        <div class="flex flex-col min-w-0">
                          <div class="flex items-center gap-space-2xs">
                            <span class="material-symbols-outlined text-primary text-[20px]">admin_panel_settings</span>
                            <span class="font-headline-md text-headline-md text-primary font-semibold truncate">ADMIN-02 (Privileged Jumphost)</span>
                          </div>
                          <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.12.5 • RDP / SSH Dual Bastion</span>
                        </div>
                        <div class="text-right">
                          <span class="font-label-caps text-label-caps text-on-surface-variant block">CRITICALITY</span>
                          <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold">Tier 1 (9/10)</span>
                        </div>
                      </div>
                    </div>

                    <!-- VECTOR 4 -> 5: PREDICTED FINAL HOP -->
                    <div class="bg-surface-container-lowest/90 px-space-sm py-space-xs rounded-DEFAULT shadow-md flex items-center gap-space-sm border border-surface-container-highest/40">
                      <div class="flex flex-col items-center">
                        <span class="w-0.5 h-8 bg-primary-container inline-block"></span>
                        <span class="material-symbols-outlined text-primary-container text-[18px] -my-1">arrow_downward</span>
                      </div>
                      <div class="flex flex-col">
                        <div class="flex items-center gap-space-xs">
                          <span class="font-label-caps text-label-caps bg-primary-container text-on-primary-container font-bold px-space-xs py-space-2xs rounded-DEFAULT">
                            ${isIsolated ? '14% PROBABILITY' : '68% PROBABILITY'}
                          </span>
                          <span class="font-telemetry-sm text-telemetry-sm ${isIsolated ? 'text-primary' : 'text-error'} font-medium font-mono">
                            ${isIsolated ? 'Safeguarded' : 'Final Target Vector • Exfiltration Risk'}
                          </span>
                        </div>
                        <span class="font-body-sm text-body-sm text-on-surface font-medium">Direct DB Access &amp; Pipeline Breach</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">SQL Server Master Key exposure &amp; cloud snapshot replication</span>
                      </div>
                    </div>

                    <!-- NODE 5: DATABASE-01 (Crown Jewel Target) -->
                    <div class="w-full bg-surface-container-high/95 backdrop-blur-md p-space-sm rounded-DEFAULT shadow-2xl transition-all relative border border-error/50 cursor-pointer hover:bg-surface-container-highest" data-inspect="DATABASE-01">
                      <div class="flex items-center justify-between mb-space-2xs">
                        <div class="flex items-center gap-space-xs">
                          <span class="font-label-caps text-label-caps bg-error-container text-on-error-container px-space-xs py-space-2xs rounded-DEFAULT font-bold flex items-center gap-1">
                            <span class="material-symbols-outlined text-[12px]">warning</span> CROWN JEWEL TARGET
                          </span>
                          <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">PCI-DSS Vault</span>
                        </div>
                        <span class="font-telemetry-sm text-telemetry-sm text-error font-mono font-bold">CRITICALITY: 10/10</span>
                      </div>
                      <div class="flex items-center justify-between">
                        <div class="flex flex-col min-w-0">
                          <div class="flex items-center gap-space-2xs">
                            <span class="material-symbols-outlined text-tertiary-fixed-dim text-[20px]">database</span>
                            <span class="font-headline-md text-headline-md text-tertiary-fixed font-semibold truncate">DATABASE-01 (Customer SQL Cluster)</span>
                          </div>
                          <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.99.12 • Multi-AZ Sharded Production Primary</span>
                        </div>
                        <div class="text-right">
                          <span class="font-label-caps text-label-caps text-on-surface-variant block">DATA AT RISK</span>
                          <span class="font-telemetry-sm text-telemetry-sm text-error font-semibold font-mono">4.8M Records</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- ALTERNATIVE BRANCHES (AMBER DASHED FORKS) (5 Cols) -->
                  <div class="md:col-span-5 flex flex-col gap-space-sm pl-space-xs">
                    <div class="flex items-center gap-space-xs text-secondary font-label-caps text-label-caps uppercase font-bold">
                      <span class="material-symbols-outlined text-[16px]">fork_right</span>
                      <span>Branch Trajectories</span>
                    </div>

                    <!-- Branch A: IDENTITY-SERVER -->
                    <div class="bg-surface-container/70 p-space-sm rounded-DEFAULT flex flex-col gap-space-2xs hover:bg-surface-container-high transition-all cursor-pointer border border-surface-container-highest/40" data-inspect="IDENTITY-SERVER">
                      <div class="flex items-center justify-between">
                        <span class="font-label-caps text-label-caps text-secondary font-bold font-mono">24% Probability</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Alt Branch A</span>
                      </div>
                      <div class="flex items-center gap-space-xs">
                        <span class="material-symbols-outlined text-secondary text-[16px]">fingerprint</span>
                        <span class="font-headline-md text-headline-md text-on-surface text-[14px] truncate">IDENTITY-SERVER</span>
                      </div>
                      <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.12.18 (Active Directory DC-02)</span>
                      <div class="flex items-center justify-between text-[11px] pt-space-2xs border-t border-surface-container-highest/20 font-mono">
                        <span class="text-on-surface-variant">Criticality: 9/10</span>
                        <span class="text-secondary font-semibold">Risk: 62/100</span>
                      </div>
                    </div>

                    <!-- Branch B: FILE-07 -->
                    <div class="bg-surface-container/70 p-space-sm rounded-DEFAULT flex flex-col gap-space-2xs hover:bg-surface-container-high transition-all cursor-pointer border border-surface-container-highest/40" data-inspect="FILE-07">
                      <div class="flex items-center justify-between">
                        <span class="font-label-caps text-label-caps text-secondary font-bold font-mono">31% Probability</span>
                        <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Alt Branch B</span>
                      </div>
                      <div class="flex items-center gap-space-xs">
                        <span class="material-symbols-outlined text-secondary text-[16px]">folder_shared</span>
                        <span class="font-headline-md text-headline-md text-on-surface text-[14px] truncate">FILE-07 (Internal SMB Share)</span>
                      </div>
                      <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">10.4.14.80 (NAS Engineering)</span>
                      <div class="flex items-center justify-between text-[11px] pt-space-2xs border-t border-surface-container-highest/20 font-mono">
                        <span class="text-on-surface-variant">Criticality: 6/10</span>
                        <span class="text-secondary font-semibold">Risk: 55/100</span>
                      </div>
                    </div>

                    <!-- Fast Tactical Intercept Card -->
                    <div class="bg-surface-container-high p-space-sm rounded-DEFAULT mt-space-xs shadow-md border border-primary/30">
                      <div class="flex items-center gap-space-xs mb-space-2xs">
                        <span class="material-symbols-outlined text-primary text-[16px]">alt_route</span>
                        <span class="font-label-caps text-label-caps uppercase text-primary font-bold">Decoy Strategy</span>
                      </div>
                      <p class="font-body-sm text-body-sm text-on-surface-variant mb-space-xs">
                        Deploy synthetic canary credentials on SERVER-03 to divert path toward isolated honeynet FILE-07-HONEY.
                      </p>
                      <button id="arm-lure-btn" class="w-full py-space-2xs bg-surface-container hover:bg-surface-container-lowest text-primary font-telemetry-sm text-telemetry-sm rounded-DEFAULT transition-colors cursor-pointer border border-primary/20">
                        Arm Lure Trap
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Graph Footer Telemetry Metadata -->
              <div class="relative z-10 flex items-center justify-between pt-space-xs bg-surface-container-lowest text-on-surface-variant font-telemetry-sm text-telemetry-sm border-t border-surface-container-highest/30">
                <div class="flex items-center gap-space-md font-mono">
                  <span>Graph Nodes: <strong class="text-on-surface">6 Active</strong></span>
                  <span>Projected Paths: <strong class="text-on-surface">3 Computed</strong></span>
                  <span>Entropy Factor: <strong class="text-secondary">0.142 (Low)</strong></span>
                </div>
                <div class="flex items-center gap-space-2xs">
                  <span class="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
                  <span class="text-primary font-medium">Real-Time Heuristic Flow Online</span>
                </div>
              </div>
            </div>
          </div>

          <!-- RIGHT: Dedicated Telemetry & Reasoning Panel (8 Cols) -->
          <div class="xl:col-span-8 flex flex-col gap-space-md">
            <!-- 1. PATH FORECAST SUMMARY -->
            <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-lg flex flex-col gap-space-sm border border-surface-container-high/40">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">timeline</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">Path Forecast Summary</h2>
                </div>
                <span class="font-label-caps text-label-caps bg-primary-container text-on-primary-container px-space-xs py-space-2xs rounded-DEFAULT font-bold">TOP HYPOTHESIS</span>
              </div>

              <!-- Most Probable Breadcrumb Trail -->
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT flex flex-col gap-space-2xs border border-surface-container-highest/30">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Most Probable Attack Path Sequence</span>
                <div class="flex items-center flex-wrap gap-space-2xs font-telemetry-sm text-telemetry-sm font-mono">
                  <span class="bg-error-container text-on-error-container px-space-xs py-space-2xs rounded-DEFAULT font-semibold">PC-017</span>
                  <span class="text-error font-bold">→</span>
                  <span class="bg-error-container text-on-error-container px-space-xs py-space-2xs rounded-DEFAULT font-semibold">SERVER-03</span>
                  <span class="text-primary font-bold">→</span>
                  <span class="bg-primary-container text-on-primary-container px-space-xs py-space-2xs rounded-DEFAULT font-semibold">ADMIN-02</span>
                  <span class="text-primary font-bold">→</span>
                  <span class="bg-tertiary-container text-on-tertiary-container px-space-xs py-space-2xs rounded-DEFAULT font-semibold">DATABASE-01</span>
                </div>
              </div>

              <!-- Metric Cards Bento inside Summary -->
              <div class="grid grid-cols-2 gap-space-xs pt-space-2xs">
                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Path Probability</span>
                  <div class="flex items-baseline gap-space-xs my-space-2xs">
                    <span class="font-headline-lg text-headline-lg text-primary font-bold font-mono">${isIsolated ? '14%' : '68%'}</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Compound</span>
                  </div>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Bayesian Prior Model</span>
                </div>

                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Horizon Window</span>
                  <div class="flex items-baseline gap-space-xs my-space-2xs">
                    <span class="font-headline-lg text-headline-lg text-secondary font-bold font-mono">4–12m</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Remaining</span>
                  </div>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Pre-lateral escalation</span>
                </div>

                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Est. Compromise Time</span>
                  <div class="flex items-baseline gap-space-xs my-space-2xs">
                    <span class="font-headline-md text-headline-md text-error font-bold font-mono">~11:18 UTC</span>
                  </div>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Velocity: 0.44 hops/min</span>
                </div>

                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Business Impact</span>
                  <div class="flex items-baseline gap-space-xs my-space-2xs">
                    <span class="font-headline-md text-headline-md text-error font-bold">${isIsolated ? 'MINIMAL' : 'CRITICAL'}</span>
                  </div>
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Tier 0 Exfiltration</span>
                </div>
              </div>
            </div>

            <!-- 2. AI REASONING PANEL ('WHY DID THE AI PREDICT THIS?') -->
            <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-lg flex flex-col gap-space-sm border border-surface-container-high/40">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">psychology</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">AI Reasoning Protocol</h2>
                </div>
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase font-mono">XAI-ATT&amp;CK-MAPPED</span>
              </div>
              <p class="font-body-sm text-body-sm text-on-surface-variant">
                Verifiable evidence points validating the compound trajectory selection:
              </p>

              <!-- Checkmark Evidence List -->
              <div class="flex flex-col gap-space-2xs">
                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/20">
                  <span class="material-symbols-outlined text-primary text-[18px] mt-0.5 shrink-0">check_circle</span>
                  <div class="flex flex-col min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">Active lateral movement observed from PC-017</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Sensor alert EDR-8890 confirmed RPC named pipe creation at 10:09 UTC</span>
                  </div>
                </div>

                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/20">
                  <span class="material-symbols-outlined text-primary text-[18px] mt-0.5 shrink-0">check_circle</span>
                  <div class="flex flex-col min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">Cached credential relationship discovered on SERVER-03</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Direct linkage to high-privilege account svc-jump-admin residing in memory</span>
                  </div>
                </div>

                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/20">
                  <span class="material-symbols-outlined text-primary text-[18px] mt-0.5 shrink-0">check_circle</span>
                  <div class="flex flex-col min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">Direct network accessibility over Port 3389 / RDP</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Subnet routing policy ALLOW_LAN_JUMP verified between SERVER-03 and ADMIN-02</span>
                  </div>
                </div>

                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/20">
                  <span class="material-symbols-outlined text-primary text-[18px] mt-0.5 shrink-0">check_circle</span>
                  <div class="flex flex-col min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">94.2% structural similarity to historical attack sequences</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Conforms to APT-29 / Sandworm Cloud Hopper playbook telemetry clusters</span>
                  </div>
                </div>

                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/20">
                  <span class="material-symbols-outlined text-primary text-[18px] mt-0.5 shrink-0">check_circle</span>
                  <div class="flex flex-col min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">Existing privileged access relationship to DATABASE-01</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">ADMIN-02 holds hardcoded SQL sysadmin connection string in environment</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- 3. AI CONFIDENCE METER & SYSTEM BASELINE -->
            <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-lg flex flex-col gap-space-sm border border-surface-container-high/40">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">speed</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface font-semibold">AI Confidence Meter</h2>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-primary font-bold font-mono">91% (HIGH)</span>
              </div>

              <!-- 10-Block Segmented Confidence Bar -->
              <div class="flex items-center gap-1.5 w-full py-space-2xs">
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-primary rounded-DEFAULT"></div>
                <div class="h-3 flex-1 bg-surface-container-highest rounded-DEFAULT"></div>
              </div>

              <div class="grid grid-cols-2 gap-space-xs text-on-surface-variant font-telemetry-sm text-telemetry-sm">
                <div class="bg-surface-container-lowest p-space-xs rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Calibration Error</span>
                  <span class="text-on-surface font-mono font-semibold">0.031 (Brier Loss)</span>
                </div>
                <div class="bg-surface-container-lowest p-space-xs rounded-DEFAULT flex flex-col border border-surface-container-highest/30">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Training Baseline</span>
                  <span class="text-on-surface font-mono font-semibold">42,000 verified kills</span>
                </div>
              </div>

              <div class="bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30">
                <p class="font-telemetry-sm text-telemetry-sm text-on-surface-variant leading-relaxed">
                  <span class="text-primary font-semibold">Explanatory Note:</span> Model confidence is derived from topological connectivity, cached credential graphs, and real-time temporal velocity.
                </p>
              </div>

              <!-- Launch to simulator -->
              <button 
                id="launch-simulator-btn"
                class="mt-space-xs w-full py-space-sm px-space-md bg-primary hover:bg-primary-fixed-dim text-on-primary font-headline-md text-headline-md font-semibold rounded-DEFAULT text-center transition-all flex items-center justify-center gap-space-xs shadow-md cursor-pointer"
              >
                <span>Launch Defense Simulator with this Path</span>
                <span class="material-symbols-outlined text-[18px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    // Event listeners
    const recalcBtn = container.querySelector('#graph-recalibrate-btn');
    if (recalcBtn) recalcBtn.addEventListener('click', () => store.recalibrateGraph());

    const interceptBtn = container.querySelector('#graph-deploy-intercept');
    if (interceptBtn) interceptBtn.addEventListener('click', () => store.openApprovalModal());

    const launchSimBtn = container.querySelector('#launch-simulator-btn');
    if (launchSimBtn) launchSimBtn.addEventListener('click', () => store.setModule('defense-simulation'));

    const armLureBtn = container.querySelector('#arm-lure-btn');
    if (armLureBtn) {
      armLureBtn.addEventListener('click', () => {
        armLureBtn.textContent = 'Lure Armed (Honeynet Active)';
        armLureBtn.classList.add('bg-primary/20', 'text-primary');
        alert("Synthetic Honeytoken dispatched on SERVER-03 pointing to isolated trap FILE-07-HONEY.");
      });
    }

    const zoomInBtn = container.querySelector('#zoom-in-btn');
    const zoomOutBtn = container.querySelector('#zoom-out-btn');
    const zoomResetBtn = container.querySelector('#zoom-reset-btn');
    const zoomCanvas = container.querySelector('#graph-zoom-canvas');

    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', () => {
        zoomLevel = Math.min(1.5, zoomLevel + 0.1);
        if (zoomCanvas) zoomCanvas.style.transform = `scale(${zoomLevel})`;
        if (zoomResetBtn) zoomResetBtn.textContent = `${Math.round(zoomLevel * 100)}%`;
      });
    }
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', () => {
        zoomLevel = Math.max(0.7, zoomLevel - 0.1);
        if (zoomCanvas) zoomCanvas.style.transform = `scale(${zoomLevel})`;
        if (zoomResetBtn) zoomResetBtn.textContent = `${Math.round(zoomLevel * 100)}%`;
      });
    }
    if (zoomResetBtn) {
      zoomResetBtn.addEventListener('click', () => {
        zoomLevel = 1;
        if (zoomCanvas) zoomCanvas.style.transform = `scale(${zoomLevel})`;
        zoomResetBtn.textContent = '100%';
      });
    }

    const exportBtn = container.querySelector('#export-topo-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        const topoData = {
          cluster: "US-EAST-DMZ & Core-LAN",
          epoch: state.telemetry.epoch,
          nodes: state.nodes,
          activeCampaign: state.activeCaseId
        };
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(topoData, null, 2));
        const dlAnchor = document.createElement('a');
        dlAnchor.setAttribute("href", dataStr);
        dlAnchor.setAttribute("download", `predictx-topology-${Date.now()}.json`);
        dlAnchor.click();
      });
    }

    container.querySelectorAll('[data-inspect]').forEach(el => {
      el.addEventListener('click', () => {
        const nodeId = el.getAttribute('data-inspect');
        store.openNodeDetail(nodeId);
      });
    });
  };

  update();
  store.subscribeView(update);
}
