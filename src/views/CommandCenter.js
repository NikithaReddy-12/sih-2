import { store } from '../state/store.js';

export function renderCommandCenter(container) {
  const update = () => {
    const state = store.getState();
    const t = state.telemetry;
    const isIsolated = state.nodes['PC-017']?.isolated;
    const isRecalibrating = state.recalibrating;

    // Filter timeline events
    const filter = state.timelineFilter;
    const filteredEvents = filter === 'ALL' 
      ? state.timeline 
      : state.timeline.filter(e => e.type === filter);

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- TOP STRATEGIC STATEMENT & COMMAND HEADER -->
        <div class="relative bg-surface-container-low rounded-DEFAULT p-space-md shadow-sm overflow-hidden border border-surface-container-high/40">
          <div class="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-primary-container/10 via-transparent to-transparent pointer-events-none"></div>
          <div class="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-space-sm relative z-10">
            <div>
              <div class="flex items-center gap-space-xs mb-space-2xs">
                <span class="inline-flex items-center gap-1.5 px-space-xs py-space-2xs rounded-DEFAULT bg-primary-container/10 text-primary font-telemetry-sm text-telemetry-sm">
                  <span class="w-1.5 h-1.5 rounded-full bg-primary-container animate-ping"></span>
                  AUTONOMOUS HEURISTICS ACTIVE
                </span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">|</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant tracking-wider">HORIZON PROTOCOL: TACTICAL-EDGE</span>
              </div>
              <h1 class="font-headline-xl text-headline-xl text-primary tracking-tight">COMMAND CENTER</h1>
              <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
              <p class="font-body-md text-body-md text-on-surface-variant mt-space-2xs max-w-4xl">
                Real-time attacker behaviour analysis, probabilistic attack forecasting and proactive attack path disruption.
              </p>
            </div>
            
            <div class="flex items-center gap-space-xs self-start xl:self-auto">
              <div class="bg-surface-container px-space-sm py-space-xs rounded-DEFAULT flex items-center gap-space-xs border border-surface-container-highest/30">
                <span class="material-symbols-outlined text-[16px] text-primary">sensors</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">TELEMETRY SYNC:</span>
                <span class="font-telemetry-sm text-telemetry-sm text-primary font-semibold" id="clock-sync">10:11:42 UTC</span>
              </div>
              <button 
                id="re-index-btn"
                class="bg-surface-container-high hover:bg-surface-variant text-on-surface font-telemetry-sm text-telemetry-sm px-space-sm py-space-xs rounded-DEFAULT flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span class="material-symbols-outlined text-[16px] ${isRecalibrating ? 'animate-spin text-primary' : ''}">refresh</span> 
                ${isRecalibrating ? 'Re-Indexing...' : 'Re-Index Graph'}
              </button>
            </div>
          </div>

          <!-- Doctrine Sub-Banner -->
          <div class="mt-space-md p-space-sm bg-surface-container-lowest rounded-DEFAULT flex items-start sm:items-center gap-space-sm border border-surface-container-highest/40">
            <div class="w-7 h-7 rounded-DEFAULT bg-primary/10 flex items-center justify-center shrink-0">
              <span class="material-symbols-outlined text-primary text-[18px]">verified_user</span>
            </div>
            <div class="flex-1">
              <span class="font-label-caps text-label-caps text-primary tracking-widest block uppercase">Strategic Disruption Mandate</span>
              <p class="font-body-sm text-body-sm text-on-surface italic">
                "We don't wait for an attack to reach its target. We analyze the attacker's footsteps, forecast where they are likely to move next, and help defend the path before critical impact."
              </p>
            </div>
            <div class="hidden md:flex items-center gap-space-xs font-telemetry-sm text-telemetry-sm text-primary-fixed-dim bg-surface-container-high px-space-xs py-space-2xs rounded-DEFAULT whitespace-nowrap">
              <span>MODEL: v4.2-NEURAL-GRAPH (Epoch #${t.epoch})</span>
            </div>
          </div>
        </div>

        <!-- TOP 6 KPI METRIC CARDS -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-space-sm">
          <!-- Card 1 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-error/50 transition-colors" data-nav="attack-cases">
            <div class="absolute top-0 left-0 bottom-0 w-1 bg-error"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Active Cases</span>
              <span class="material-symbols-outlined text-error text-[18px]">crisis_alert</span>
            </div>
            <div class="my-space-xs">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold text-on-surface">${t.activeCases}</div>
              <div class="font-telemetry-sm text-telemetry-sm text-error mt-space-2xs flex items-center gap-1">
                <span class="w-1.5 h-1.5 rounded-full bg-error"></span> 2 critical progression
              </div>
            </div>
            <div class="font-body-sm text-body-sm text-on-surface-variant/70 truncate">Global SOC incident pool</div>
          </div>

          <!-- Card 2 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-secondary/50 transition-colors" data-nav="live-attack-investigation">
            <div class="absolute top-0 left-0 bottom-0 w-1 bg-secondary-container"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Observed Events</span>
              <span class="material-symbols-outlined text-secondary text-[18px]">fingerprint</span>
            </div>
            <div class="my-space-xs">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold text-on-surface">${t.observedEvents}</div>
              <div class="font-telemetry-sm text-telemetry-sm text-secondary mt-space-2xs flex items-center gap-1">
                <span class="w-1.5 h-1.5 rounded-full bg-secondary"></span> MITRE ATT&amp;CK mapped
              </div>
            </div>
            <div class="font-body-sm text-body-sm text-on-surface-variant/70 truncate">T1021, T1046, T1110</div>
          </div>

          <!-- Card 3 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-primary/50 transition-colors" data-nav="predicted-attack-path">
            <div class="absolute top-0 left-0 bottom-0 w-1 bg-primary-container"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Predicted Paths</span>
              <span class="material-symbols-outlined text-primary-fixed-dim text-[18px]">account_tree</span>
            </div>
            <div class="my-space-xs">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold text-primary">${t.predictedPaths}</div>
              <div class="font-telemetry-sm text-telemetry-sm text-primary-fixed-dim mt-space-2xs flex items-center gap-1">
                <span class="w-1.5 h-1.5 rounded-full bg-primary-container animate-pulse"></span> Active probabilistic runs
              </div>
            </div>
            <div class="font-body-sm text-body-sm text-on-surface-variant/70 truncate">Next vector convergence</div>
          </div>

          <!-- Card 4 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-primary/50 transition-colors" data-nav="critical-assets">
            <div class="absolute top-0 left-0 bottom-0 w-1 bg-tertiary-fixed-dim"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Critical Targets</span>
              <span class="material-symbols-outlined text-tertiary text-[18px]">hub</span>
            </div>
            <div class="my-space-xs">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold text-on-surface">${t.criticalTargets}</div>
              <div class="font-telemetry-sm text-telemetry-sm text-error mt-space-2xs truncate">
                DB-01, ADM-02, ID, FILE-07
              </div>
            </div>
            <div class="font-body-sm text-body-sm text-on-surface-variant/70 truncate">Tier-1 production nodes</div>
          </div>

          <!-- Card 5 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-error/50 transition-colors" data-nav="target-risk-analysis">
            <div class="absolute top-0 left-0 bottom-0 w-1 ${t.overallRisk > 60 ? 'bg-error-container' : 'bg-primary'}"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Overall Cyber Risk</span>
              <span class="material-symbols-outlined ${t.overallRisk > 60 ? 'text-error' : 'text-primary'} text-[18px]">speed</span>
            </div>
            <div class="my-space-xs flex items-baseline gap-1">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold ${t.overallRisk > 60 ? 'text-error' : 'text-primary'}">${t.overallRisk}</div>
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">/100</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-telemetry-sm text-telemetry-sm ${t.overallRisk > 60 ? 'text-error' : 'text-primary'} font-semibold">
                ${t.overallRisk > 60 ? 'HIGH - ELEVATED' : 'MODERATE - CONTAINED'}
              </span>
              <div class="w-12 h-1.5 bg-surface-container-high rounded-full overflow-hidden">
                <div class="h-full ${t.overallRisk > 60 ? 'bg-error' : 'bg-primary'} rounded-full transition-all duration-500" style="width: ${t.overallRisk}%;"></div>
              </div>
            </div>
          </div>

          <!-- Card 6 -->
          <div class="bg-surface-container-low p-space-sm rounded-DEFAULT flex flex-col justify-between shadow-sm relative overflow-hidden border border-surface-container-high/30 cursor-pointer hover:border-primary/50 transition-colors" data-nav="ai-performance-and-learning">
            <div class="absolute top-0 left-0 bottom-0 w-1 bg-primary"></div>
            <div class="flex items-center justify-between">
              <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">Events Analyzed</span>
              <span class="material-symbols-outlined text-primary text-[18px]">query_stats</span>
            </div>
            <div class="my-space-xs">
              <div class="font-telemetry-lg text-[28px] leading-7 font-bold text-on-surface">${t.eventsToday}</div>
              <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-space-2xs">
                Today (Ingestion 24h)
              </div>
            </div>
            <div class="font-telemetry-sm text-telemetry-sm text-primary flex items-center justify-between">
              <span>Latency:</span>
              <span class="font-semibold">${t.latency} avg inference</span>
            </div>
          </div>
        </div>

        <!-- MAIN SECTION: LIVE ATTACK FORECAST & INTENT -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
          <!-- LEFT/CENTER PANEL: CASE #PX-9821 FORECAST GRAPH & TARGET PROJECTION (Col 7) -->
          <div class="lg:col-span-7 bg-surface-container-low rounded-DEFAULT p-space-md shadow-md flex flex-col justify-between space-y-space-md border border-surface-container-high/40">
            <div>
              <!-- Case Subheader Bar -->
              <div class="flex flex-wrap items-center justify-between gap-space-xs pb-space-xs border-b border-surface-container-highest/40">
                <div class="flex items-center gap-space-xs">
                  <span class="w-2 h-2 rounded-full ${isIsolated ? 'bg-primary' : 'bg-error animate-ping'}"></span>
                  <span class="font-label-caps text-label-caps text-primary tracking-widest uppercase">Live Attack Campaign</span>
                  <span class="bg-surface-container-lowest font-telemetry-sm text-telemetry-sm px-space-xs py-space-2xs text-on-surface rounded-DEFAULT font-bold">CASE #PX-9821</span>
                  ${isIsolated ? `
                    <span class="bg-primary/20 text-primary px-space-xs py-space-2xs rounded-DEFAULT font-label-caps text-[9px] uppercase font-bold">DISRUPTED AT HOP 1</span>
                  ` : ''}
                </div>
                <div class="flex items-center gap-space-xs">
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Neural Confidence:</span>
                  <span class="font-telemetry-sm text-telemetry-sm bg-primary-container/15 text-primary px-space-xs py-space-2xs rounded-DEFAULT font-bold">91% HIGH</span>
                </div>
              </div>

              <!-- Visual Path Progression Breadcrumb -->
              <div class="mt-space-sm bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
                <div class="flex items-center justify-between text-telemetry-sm font-telemetry-sm mb-space-xs text-on-surface-variant">
                  <span>TACTICAL KILL-CHAIN TRAJECTORY</span>
                  <span class="text-primary font-semibold">PREDICTED HORIZON: 4–7 MIN</span>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-space-xs items-center">
                  <!-- Stage 1: Current -->
                  <div class="p-space-xs rounded-DEFAULT relative overflow-hidden border border-surface-container-highest/40 ${isIsolated ? 'bg-primary/10' : 'bg-error-container/20'}">
                    <div class="flex items-center justify-between mb-space-2xs">
                      <span class="font-label-caps text-label-caps ${isIsolated ? 'text-primary' : 'text-error'}">
                        ${isIsolated ? 'QUARANTINED' : 'CURRENT STAGE'}
                      </span>
                      <span class="w-2 h-2 rounded-full ${isIsolated ? 'bg-primary' : 'bg-error'}"></span>
                    </div>
                    <div class="font-headline-md text-headline-md text-on-surface text-sm font-semibold">LATERAL MOVEMENT</div>
                    <div class="font-telemetry-sm text-telemetry-sm ${isIsolated ? 'text-primary' : 'text-error'} mt-space-2xs font-bold">
                      ${isIsolated ? 'CONTAINED (CUTOFF)' : 'IN PROGRESS'}
                    </div>
                    <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">Node: SERVER-03</div>
                  </div>

                  <!-- Stage 2: Probable Next -->
                  <div class="bg-secondary-container/20 p-space-xs rounded-DEFAULT relative overflow-hidden border border-surface-container-highest/40">
                    <div class="flex items-center justify-between mb-space-2xs">
                      <span class="font-label-caps text-label-caps text-secondary">PROBABLE NEXT MOVE</span>
                      <span class="material-symbols-outlined text-secondary text-[14px]">arrow_forward</span>
                    </div>
                    <div class="font-headline-md text-headline-md text-on-surface text-sm font-semibold">PRIVILEGE ESCALATION</div>
                    <div class="font-telemetry-sm text-telemetry-sm text-secondary mt-space-2xs font-bold">
                      ${isIsolated ? 'DE-ESCALATED (12%)' : 'FORECASTED (87%)'}
                    </div>
                    <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">Node: ADMIN-02</div>
                  </div>

                  <!-- Stage 3: End Target -->
                  <div class="bg-surface-container-high/40 p-space-xs rounded-DEFAULT relative overflow-hidden border border-surface-container-highest/40">
                    <div class="flex items-center justify-between mb-space-2xs">
                      <span class="font-label-caps text-label-caps text-on-surface-variant">POTENTIAL TARGET</span>
                      <span class="material-symbols-outlined text-on-surface-variant text-[14px]">flag</span>
                    </div>
                    <div class="font-headline-md text-headline-md text-on-surface text-sm font-semibold">DATA EXFILTRATION</div>
                    <div class="font-telemetry-sm text-telemetry-sm ${isIsolated ? 'text-primary' : 'text-error'} mt-space-2xs font-bold">
                      ${isIsolated ? 'SAFEGUARDED (14%)' : 'IMPACT: CATASTROPHIC'}
                    </div>
                    <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">Node: DATABASE-01</div>
                  </div>
                </div>

                <!-- Micro Probability Progress Bar -->
                <div class="mt-space-sm">
                  <div class="flex justify-between items-center text-telemetry-sm font-telemetry-sm mb-1">
                    <span class="text-on-surface-variant">Next Step Trajectory Certainty:</span>
                    <span class="text-primary font-bold">
                      ${isIsolated ? '14% Probability (Severed)' : '87% Probability (Neural Weight 0.874)'}
                    </span>
                  </div>
                  <div class="w-full bg-surface-container-high h-2 rounded-full overflow-hidden flex">
                    <div class="h-full ${isIsolated ? 'bg-secondary' : 'bg-primary-container'} transition-all duration-500" style="width: ${isIsolated ? '14%' : '87%'};"></div>
                  </div>
                </div>
              </div>

              <!-- Target Nodes Breakdown Cards -->
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-space-sm mt-space-sm">
                <!-- Likely Next Target -->
                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col justify-between border border-surface-container-highest/30 cursor-pointer hover:bg-surface-container-high transition-colors" data-inspect="ADMIN-02">
                  <div>
                    <div class="flex items-center justify-between mb-space-xs">
                      <span class="font-label-caps text-label-caps text-secondary uppercase">Likely Next Target</span>
                      <span class="px-space-xs py-space-2xs bg-secondary-container/20 text-secondary text-telemetry-sm font-telemetry-sm rounded-DEFAULT">Tier 1 Target</span>
                    </div>
                    <div class="flex items-center gap-space-xs">
                      <span class="material-symbols-outlined text-secondary text-[22px]">laptop_mac</span>
                      <div>
                        <div class="font-telemetry-lg text-telemetry-lg text-on-surface font-bold">ADMIN-02</div>
                        <div class="font-body-sm text-body-sm text-on-surface-variant">Local Domain Controller Relay</div>
                      </div>
                    </div>
                  </div>
                  <div class="mt-space-sm pt-space-xs bg-surface-container-lowest/60 p-space-xs rounded-DEFAULT">
                    <div class="flex justify-between font-telemetry-sm text-telemetry-sm">
                      <span class="text-on-surface-variant">Target Intercept Prob:</span>
                      <span class="text-secondary font-bold">${isIsolated ? '18%' : '84%'}</span>
                    </div>
                    <div class="flex justify-between font-telemetry-sm text-telemetry-sm mt-1">
                      <span class="text-on-surface-variant">Est. Time to Breach:</span>
                      <span class="text-error font-bold">${isIsolated ? 'NEUTRALIZED' : '04m:28s'}</span>
                    </div>
                  </div>
                </div>

                <!-- Potential Final Target -->
                <div class="bg-surface-container p-space-sm rounded-DEFAULT flex flex-col justify-between border border-surface-container-highest/30 cursor-pointer hover:bg-surface-container-high transition-colors" data-inspect="DATABASE-01">
                  <div>
                    <div class="flex items-center justify-between mb-space-xs">
                      <span class="font-label-caps text-label-caps text-error uppercase">Potential Final Target</span>
                      <span class="px-space-xs py-space-2xs bg-error-container/30 text-error text-telemetry-sm font-telemetry-sm rounded-DEFAULT">Critical Crown Jewel</span>
                    </div>
                    <div class="flex items-center gap-space-xs">
                      <span class="material-symbols-outlined text-error text-[22px]">database</span>
                      <div>
                        <div class="font-telemetry-lg text-telemetry-lg text-on-surface font-bold">DATABASE-01</div>
                        <div class="font-body-sm text-body-sm text-on-surface-variant">Production Financial Core Vault</div>
                      </div>
                    </div>
                  </div>
                  <div class="mt-space-sm pt-space-xs bg-surface-container-lowest/60 p-space-xs rounded-DEFAULT">
                    <div class="flex justify-between font-telemetry-sm text-telemetry-sm">
                      <span class="text-on-surface-variant">Path Convergence Prob:</span>
                      <span class="text-primary font-bold">${isIsolated ? '14%' : '68%'}</span>
                    </div>
                    <div class="flex justify-between font-telemetry-sm text-telemetry-sm mt-1">
                      <span class="text-on-surface-variant">Business Consequence:</span>
                      <span class="text-error font-bold uppercase tracking-wider">${isIsolated ? 'DISRUPTED' : 'CATASTROPHIC'}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Quick Actions Toolbelt -->
            <div class="flex flex-wrap items-center justify-between gap-space-xs pt-space-xs mt-space-sm border-t border-surface-container-highest/40">
              <div class="flex items-center gap-space-xs">
                <button 
                  class="bg-primary-container text-on-primary-container hover:bg-primary font-telemetry-sm text-telemetry-sm font-semibold px-space-sm py-space-xs rounded-DEFAULT flex items-center gap-1 shadow-sm transition-colors cursor-pointer"
                  data-nav="defense-simulation"
                >
                  <span class="material-symbols-outlined text-[16px]">shield_with_heart</span>
                  Simulate Disruption
                </button>
                <button 
                  class="bg-surface-container-high hover:bg-surface-variant text-on-surface font-telemetry-sm text-telemetry-sm px-space-sm py-space-xs rounded-DEFAULT flex items-center gap-1 transition-colors cursor-pointer"
                  data-nav="predicted-attack-path"
                >
                  <span class="material-symbols-outlined text-[16px]">schema</span>
                  View Vector Graph
                </button>
              </div>

              <button 
                id="cmd-isolate-btn"
                class="${isIsolated ? 'bg-primary/20 text-primary border border-primary/40' : 'bg-error-container/30 hover:bg-error-container text-error hover:text-on-error-container'} font-telemetry-sm text-telemetry-sm font-semibold px-space-sm py-space-xs rounded-DEFAULT flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span class="material-symbols-outlined text-[16px]">${isIsolated ? 'verified' : 'block'}</span>
                ${isIsolated ? 'PC-017 Quarantined' : 'Isolate PC-017 (Auth Req)'}
              </button>
            </div>
          </div>

          <!-- RIGHT PANEL: ATTACKER INTENT FORECAST & INTEL (Col 5) -->
          <div class="lg:col-span-5 bg-surface-container-low rounded-DEFAULT p-space-md shadow-md flex flex-col justify-between border border-surface-container-high/40">
            <div>
              <div class="flex items-center justify-between pb-space-xs border-b border-surface-container-highest/30">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-secondary text-[20px]">psychology</span>
                  <span class="font-headline-md text-headline-md text-on-surface text-base">Attacker Intent Probability</span>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Updated 12s ago</span>
              </div>

              <!-- Intent Probability Bars -->
              <div class="space-y-space-xs mt-space-sm">
                <div>
                  <div class="flex justify-between items-center font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface font-medium">Data Exfiltration</span>
                    <div class="flex items-center gap-2">
                      <span class="text-error font-semibold">High</span>
                      <span class="text-on-surface font-bold">76%</span>
                    </div>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden">
                    <div class="h-full bg-error rounded-full" style="width: 76%;"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between items-center font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface font-medium">Credential Theft</span>
                    <div class="flex items-center gap-2">
                      <span class="text-secondary font-semibold">Elevated</span>
                      <span class="text-on-surface font-bold">64%</span>
                    </div>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden">
                    <div class="h-full bg-secondary rounded-full" style="width: 64%;"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between items-center font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface font-medium">Privilege Escalation</span>
                    <div class="flex items-center gap-2">
                      <span class="text-secondary font-semibold">Moderate-High</span>
                      <span class="text-on-surface font-bold">58%</span>
                    </div>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden">
                    <div class="h-full bg-secondary-container rounded-full" style="width: 58%;"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between items-center font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface font-medium">Ransomware Deployment</span>
                    <div class="flex items-center gap-2">
                      <span class="text-on-surface-variant font-semibold">Low</span>
                      <span class="text-on-surface font-bold">21%</span>
                    </div>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden">
                    <div class="h-full bg-surface-variant rounded-full" style="width: 21%;"></div>
                  </div>
                </div>

                <div>
                  <div class="flex justify-between items-center font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface font-medium">Service Disruption</span>
                    <div class="flex items-center gap-2">
                      <span class="text-on-surface-variant font-semibold">Low</span>
                      <span class="text-on-surface font-bold">12%</span>
                    </div>
                  </div>
                  <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden">
                    <div class="h-full bg-surface-variant rounded-full" style="width: 12%;"></div>
                  </div>
                </div>
              </div>

              <!-- AI Narrative Assessment Box -->
              <div class="mt-space-md p-space-sm bg-surface-container-lowest rounded-DEFAULT relative border border-surface-container-highest/30">
                <div class="flex items-center gap-space-xs mb-space-2xs">
                  <span class="material-symbols-outlined text-primary text-[16px]">smart_toy</span>
                  <span class="font-label-caps text-label-caps text-primary tracking-wider uppercase">AI Strategic Analysis</span>
                </div>
                <p class="font-body-sm text-body-sm text-on-surface leading-relaxed">
                  "Observed lateral movement, credential access attempts and privileged asset relationships indicate a probable progression toward sensitive data infrastructure."
                </p>
                <div class="mt-space-xs flex items-center justify-between text-telemetry-sm font-telemetry-sm text-on-surface-variant">
                  <span>Corroboration: 14 similar past campaigns</span>
                  <span class="text-primary font-mono font-semibold">Cosine match: 0.94</span>
                </div>
              </div>
            </div>

            <!-- Footer Micro Intelligence -->
            <div class="mt-space-md pt-space-xs flex items-center justify-between border-t border-surface-container-highest/30">
              <div class="flex items-center gap-space-xs">
                <span class="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Forecasting Model: GraphTransformer-X9</span>
              </div>
              <button class="text-primary hover:underline font-telemetry-sm text-telemetry-sm flex items-center gap-1 cursor-pointer" data-nav="ai-performance-and-learning">
                Inspect Model Features <span class="material-symbols-outlined text-[14px]">chevron_right</span>
              </button>
            </div>
          </div>
        </div>

        <!-- BOTTOM SECTION: LIVE ATTACK EVOLUTION TIMELINE & DISRUPTION BAR -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
          <!-- TIMELINE CONTAINER (Col 8) -->
          <div class="lg:col-span-8 bg-surface-container-low rounded-DEFAULT p-space-md shadow-md border border-surface-container-high/40">
            <div class="flex flex-wrap items-center justify-between gap-space-xs mb-space-sm">
              <div>
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">timeline</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface text-base">Live Attack Evolution Timeline</h2>
                </div>
                <p class="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
                  Sequential fusion of confirmed telemetry events and forward-looking neural predictions.
                </p>
              </div>

              <!-- Interactive Timeline Filter Tabs -->
              <div class="flex flex-wrap items-center gap-space-xs text-telemetry-sm font-telemetry-sm" id="timeline-filters">
                <button class="px-space-xs py-space-2xs rounded-DEFAULT cursor-pointer ${filter === 'ALL' ? 'bg-primary text-on-primary font-bold' : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}" data-filter="ALL">
                  ALL (${state.timeline.length})
                </button>
                <button class="px-space-xs py-space-2xs rounded-DEFAULT cursor-pointer flex items-center gap-1 ${filter === 'OBSERVED' ? 'bg-error-container text-on-error-container font-bold' : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}" data-filter="OBSERVED">
                  <span class="w-1.5 h-1.5 rounded-full bg-error"></span> OBSERVED
                </button>
                <button class="px-space-xs py-space-2xs rounded-DEFAULT cursor-pointer flex items-center gap-1 ${filter === 'PREDICTED' ? 'bg-primary-container text-on-primary-container font-bold' : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}" data-filter="PREDICTED">
                  <span class="w-1.5 h-1.5 rounded-full bg-primary"></span> PREDICTED
                </button>
                <button class="px-space-xs py-space-2xs rounded-DEFAULT cursor-pointer flex items-center gap-1 ${filter === 'RECOMMENDED' ? 'bg-secondary text-on-secondary font-bold' : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}" data-filter="RECOMMENDED">
                  <span class="w-1.5 h-1.5 rounded-full bg-secondary"></span> RECOMMENDED
                </button>
              </div>
            </div>

            <!-- Timeline Items -->
            <div class="relative space-y-space-xs max-h-[460px] overflow-y-auto pr-1">
              ${filteredEvents.map(item => `
                <div class="flex items-start gap-space-sm p-space-xs bg-surface-container-lowest/80 rounded-DEFAULT relative overflow-hidden border border-surface-container-highest/30 hover:bg-surface-container-high transition-colors">
                  <div class="absolute left-0 top-0 bottom-0 w-1 ${item.borderClass}"></div>
                  <span class="font-telemetry-md text-telemetry-md text-on-surface-variant shrink-0 w-14 text-center pt-0.5 font-mono">${item.time}</span>
                  <span class="px-space-xs py-space-2xs rounded-DEFAULT font-label-caps text-label-caps shrink-0 ${item.badgeClass}">
                    ${item.type}
                  </span>
                  <div class="flex-1 min-w-0">
                    <span class="font-body-sm text-body-sm text-on-surface font-medium">${item.title}</span>
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant ml-2 truncate block sm:inline font-mono">${item.details}</span>
                  </div>
                  <span class="material-symbols-outlined text-on-surface-variant text-[16px] shrink-0">${item.icon}</span>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- MINI DEFENSE DISRUPTION PREVIEW BAR (Col 4) -->
          <div class="lg:col-span-4 bg-surface-container-low rounded-DEFAULT p-space-md shadow-md flex flex-col justify-between border border-surface-container-high/40">
            <div>
              <div class="flex items-center justify-between pb-space-xs border-b border-surface-container-highest/30">
                <div class="flex items-center gap-space-xs">
                  <span class="material-symbols-outlined text-primary text-[20px]">shield</span>
                  <h2 class="font-headline-md text-headline-md text-on-surface text-base">Disruption Engine</h2>
                </div>
                <span class="px-space-xs py-space-2xs bg-secondary-container/20 text-secondary text-telemetry-sm font-telemetry-sm rounded-DEFAULT font-bold">ACTION READY</span>
              </div>

              <div class="mt-space-sm bg-surface-container p-space-sm rounded-DEFAULT border border-surface-container-highest/40">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider block mb-1">Recommended Proactive Intervention</span>
                <div class="font-headline-md text-headline-md text-primary font-bold">ISOLATE PC-017</div>
                <p class="font-body-sm text-body-sm text-on-surface-variant mt-1">
                  Isolating the pivot node cuts off the active credential bridge before lateral payload injection on ADMIN-02.
                </p>
              </div>

              <!-- Before & After Risk Drop Meter -->
              <div class="mt-space-md space-y-space-sm">
                <div>
                  <div class="flex justify-between font-telemetry-sm text-telemetry-sm mb-1">
                    <span class="text-on-surface-variant">Projected Campaign Risk:</span>
                    <span class="font-bold text-on-surface">91/100 → <span class="text-primary font-bold">38/100</span></span>
                  </div>
                  <div class="relative w-full bg-surface-container-lowest h-3 rounded-full overflow-hidden">
                    <div class="h-full bg-error rounded-full opacity-30 absolute top-0 left-0" style="width: 91%;"></div>
                    <div class="h-full bg-primary rounded-full relative z-10 transition-all duration-700" style="width: 38%;"></div>
                  </div>
                  <div class="flex justify-between font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">
                    <span>Unmitigated: 91</span>
                    <span class="text-primary font-bold">Post-Disruption: 38 (-58%)</span>
                  </div>
                </div>

                <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT flex items-center justify-between border border-surface-container-highest/40">
                  <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Disruption Efficacy Score</span>
                  <span class="font-telemetry-lg text-telemetry-lg text-primary font-bold">94%</span>
                </div>
              </div>
            </div>

            <div class="mt-space-md pt-space-xs">
              <button 
                class="w-full bg-primary text-on-primary hover:bg-primary-container font-telemetry-sm text-telemetry-sm font-bold py-space-sm px-space-md rounded-DEFAULT flex items-center justify-center gap-space-xs shadow-md transition-all cursor-pointer"
                data-nav="defense-simulation"
              >
                <span>TEST IN DEFENSE SIMULATOR</span>
                <span class="material-symbols-outlined text-[16px]">arrow_forward</span>
              </button>
              <div class="flex items-center justify-between text-telemetry-sm font-telemetry-sm text-on-surface-variant/70 mt-space-xs px-1">
                <span>Non-destructive dry run</span>
                <span>Zero network interruption</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Bind event listeners
    const reIndexBtn = container.querySelector('#re-index-btn');
    if (reIndexBtn) {
      reIndexBtn.addEventListener('click', () => store.recalibrateGraph());
    }

    const isolateBtn = container.querySelector('#cmd-isolate-btn');
    if (isolateBtn) {
      isolateBtn.addEventListener('click', () => {
        if (!state.nodes['PC-017']?.isolated) {
          store.openApprovalModal();
        } else {
          store.openNodeDetail('PC-017');
        }
      });
    }

    container.querySelectorAll('[data-nav]').forEach(el => {
      el.addEventListener('click', () => {
        const dest = el.getAttribute('data-nav');
        store.setModule(dest);
      });
    });

    container.querySelectorAll('[data-inspect]').forEach(el => {
      el.addEventListener('click', () => {
        const nodeId = el.getAttribute('data-inspect');
        store.openNodeDetail(nodeId);
      });
    });

    container.querySelectorAll('#timeline-filters button').forEach(btn => {
      btn.addEventListener('click', () => {
        const f = btn.getAttribute('data-filter');
        store.setTimelineFilter(f);
      });
    });
  };

  update();
  store.subscribeView(update);
}
