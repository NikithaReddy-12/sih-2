import { store } from '../state/store.js';

export function renderDefenseSimulation(container) {
  let recalculating = false;

  const update = () => {
    const state = store.getState();
    const activeOptId = state.activeSimulationOption || 'option-2';
    const opt = state.simulationScenarios[activeOptId] || state.simulationScenarios['option-2'];
    const isEnforced = state.simulationApplied;

    container.innerHTML = `
      <div class="flex flex-col w-full gap-space-lg">
        <!-- TOP CONTEXT BANNER & STATUS NOTIFICATION -->
        <div class="flex flex-col gap-space-xs">
          <!-- Tactical Sandbox Mode Banner -->
          <div class="relative overflow-hidden bg-surface-container-low px-space-md py-space-sm rounded-DEFAULT flex flex-wrap items-center justify-between gap-space-sm shadow-sm border border-surface-container-high/30">
            <div class="absolute left-0 top-0 bottom-0 w-1 bg-secondary"></div>
            <div class="flex items-center gap-space-sm">
              <span class="relative flex h-2.5 w-2.5">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75"></span>
                <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-secondary"></span>
              </span>
              <span class="font-label-caps text-label-caps text-secondary uppercase tracking-widest font-bold">
                ${isEnforced ? 'PRODUCTION POLICY ENFORCED' : 'PREDICTIVE SANDBOX ACTIVE'}
              </span>
              <span class="text-on-surface-variant font-telemetry-sm text-telemetry-sm">—</span>
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface font-medium">
                ${isEnforced ? 'TICKET #SEC-9921-ISO ACTIVE IN PRODUCTION FABRIC' : 'SIMULATED RUN ONLY, ZERO PRODUCTION IMPACT'}
              </span>
            </div>
            <div class="flex items-center gap-space-sm">
              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">SANDBOX ENGINE: <span class="text-primary font-bold">v4.2-NEURAL-SIM</span></span>
              <span class="bg-surface-container-high px-space-xs py-space-2xs rounded-DEFAULT font-label-caps text-label-caps text-primary uppercase">EPHEMERAL BRANCH #SIM-8049</span>
            </div>
          </div>

          <!-- Header Block -->
          <div class="flex flex-col lg:flex-row lg:items-end justify-between gap-space-md pt-space-xs">
            <div>
              <div class="flex items-center gap-space-xs mb-space-2xs">
                <span class="material-symbols-outlined text-primary text-[20px]">shield_with_heart</span>
                <span class="font-label-caps text-label-caps text-primary tracking-widest uppercase">COGNITIVE COUNTERMEASURE SUITE</span>
              </div>
              <h1 class="font-headline-xl text-headline-xl text-primary tracking-tight">DEFENSE IMPACT SIMULATOR</h1>
              <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
              <p class="font-body-md text-body-md text-on-surface-variant">Test defensive interventions before applying them to the production environment.</p>
            </div>

            <!-- Live Context Strip -->
            <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT flex flex-wrap items-center gap-space-md shadow-sm border border-surface-container-highest/30">
              <div class="flex flex-col">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">ACTIVE ATTACK PATH</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface font-semibold flex items-center gap-1 font-mono">
                  <span class="text-error cursor-pointer hover:underline" data-inspect="PC-017">PC-017</span>
                  <span class="text-on-surface-variant">→</span>
                  <span class="text-secondary cursor-pointer hover:underline" data-inspect="SERVER-03">SERVER-03</span>
                  <span class="text-on-surface-variant">→</span>
                  <span class="text-secondary cursor-pointer hover:underline" data-inspect="ADMIN-02">ADMIN-02</span>
                  <span class="text-on-surface-variant">→</span>
                  <span class="text-error font-bold cursor-pointer hover:underline" data-inspect="DATABASE-01">DATABASE-01</span>
                </span>
              </div>

              <div class="h-6 w-px bg-surface-container-high hidden sm:block"></div>

              <div class="flex flex-col">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">CURRENT DB COMPROMISE</span>
                <div class="flex items-center gap-space-xs">
                  <span class="font-telemetry-lg text-telemetry-lg text-error font-bold font-mono">68%</span>
                  <span class="material-symbols-outlined text-[14px] text-error">trending_up</span>
                </div>
              </div>

              <div class="h-6 w-px bg-surface-container-high hidden sm:block"></div>

              <div class="flex flex-col">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">CURRENT CYBER RISK</span>
                <div class="flex items-center gap-space-xs">
                  <span class="font-telemetry-lg text-telemetry-lg text-error font-bold font-mono">91<span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">/100</span></span>
                  <span class="bg-error-container text-on-error-container px-space-2xs rounded-DEFAULT font-label-caps text-label-caps uppercase font-bold">CRITICAL</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- AI DEFENSE RECOMMENDATION HERO CARD -->
        <div class="relative bg-surface-container-low rounded-DEFAULT p-space-lg shadow-xl overflow-hidden border border-surface-container-high/40">
          <div class="absolute -right-24 -top-24 w-96 h-96 rounded-full bg-primary-container/5 blur-3xl pointer-events-none"></div>
          <div class="relative z-10 flex flex-col gap-space-md">
            <!-- Card Top Badge Row -->
            <div class="flex flex-wrap items-center justify-between gap-space-sm">
              <div class="flex items-center gap-space-sm">
                <span class="inline-flex items-center gap-1 bg-primary-container/15 text-primary px-space-sm py-space-2xs rounded-DEFAULT font-label-caps text-label-caps uppercase tracking-wider font-bold">
                  <span class="material-symbols-outlined text-[14px]">psychology</span> 
                  ${opt.id === 'option-2' ? 'AI OPTIMAL INTERVENTION' : 'ALTERNATE SIMULATED VECTOR'}
                </span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">CONFIDENCE HEURISTIC: <strong class="text-primary font-mono">${opt.effectiveness > 90 ? '97.8%' : '84.2%'}</strong></span>
              </div>

              <!-- Prominent Status Safety Stamp -->
              <div class="flex items-center gap-space-xs ${isEnforced ? 'bg-primary/20 text-primary border border-primary/40' : 'bg-secondary/10 text-secondary'} px-space-md py-space-xs rounded-DEFAULT shadow-inner">
                <span class="material-symbols-outlined text-[18px]">${isEnforced ? 'verified' : 'verified_user'}</span>
                <span class="font-telemetry-sm text-telemetry-sm tracking-wider font-bold">
                  ${isEnforced ? 'ENFORCED IN PRODUCTION' : 'SIMULATED — NOT EXECUTED'}
                </span>
              </div>
            </div>

            <!-- Action Proposal Headline -->
            <div class="flex flex-col xl:flex-row xl:items-center justify-between gap-space-md bg-surface-container-lowest/60 p-space-md rounded-DEFAULT border border-surface-container-highest/30">
              <div class="flex items-start gap-space-md">
                <div class="w-12 h-12 rounded-DEFAULT bg-primary-container/10 flex items-center justify-center shrink-0">
                  <span class="material-symbols-outlined text-primary text-[28px]">phonelink_erase</span>
                </div>
                <div>
                  <div class="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider">SELECTED MITIGATION VECTOR</div>
                  <div class="font-headline-lg text-headline-lg text-primary tracking-tight font-bold">${opt.title}</div>
                  <p class="font-body-md text-body-md text-on-surface mt-space-2xs max-w-2xl">
                    ${opt.tradeoff}
                  </p>
                </div>
              </div>

              <!-- Disruption Efficiency Badge Component -->
              <div class="bg-surface-container-high px-space-lg py-space-sm rounded-DEFAULT flex items-center justify-between xl:flex-col xl:items-end gap-space-xs shrink-0 border border-surface-container-highest/40">
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider">NET DISRUPTION EFFICIENCY</span>
                <div class="flex items-baseline gap-1">
                  <span class="font-headline-xl text-headline-xl text-primary font-bold tracking-tight font-mono">${opt.disruptionGain}%</span>
                  <span class="font-telemetry-sm text-telemetry-sm text-primary-fixed-dim">GAIN</span>
                </div>
                <div class="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden mt-space-2xs">
                  <div class="bg-primary-container h-full rounded-full transition-all duration-500" style="width: ${opt.disruptionGain}%"></div>
                </div>
              </div>
            </div>

            <!-- Impact Metric Comparative Matrix -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-space-md">
              <!-- Metric 1: DB Probability -->
              <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT flex flex-col justify-between gap-space-sm border border-surface-container-highest/30">
                <div class="flex items-center justify-between">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">DATABASE COMPROMISE PROBABILITY</span>
                  <span class="material-symbols-outlined text-primary text-[18px]">storage</span>
                </div>
                <div class="flex items-center justify-between pt-space-xs">
                  <div class="flex flex-col">
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">BEFORE SIM</span>
                    <span class="font-headline-md text-headline-md text-error line-through font-bold font-mono">68%</span>
                  </div>
                  <div class="flex items-center text-primary">
                    <span class="material-symbols-outlined text-[20px]">east</span>
                  </div>
                  <div class="flex flex-col text-right">
                    <span class="font-telemetry-sm text-telemetry-sm text-primary">AFTER SIM</span>
                    <span class="font-headline-md text-headline-md text-primary font-bold font-mono">${opt.newDbProb}%</span>
                  </div>
                </div>
                <div class="bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm text-primary flex items-center justify-between">
                  <span>DELTA:</span>
                  <strong class="font-bold font-mono">-${68 - opt.newDbProb}% INTRUSION RISK</strong>
                </div>
              </div>

              <!-- Metric 2: Cyber Risk Score -->
              <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT flex flex-col justify-between gap-space-sm border border-surface-container-highest/30">
                <div class="flex items-center justify-between">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">OVERALL CYBER RISK INDEX</span>
                  <span class="material-symbols-outlined text-secondary text-[18px]">speed</span>
                </div>
                <div class="flex items-center justify-between pt-space-xs">
                  <div class="flex flex-col">
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">BEFORE SIM</span>
                    <span class="font-headline-md text-headline-md text-error line-through font-bold font-mono">91<span class="font-telemetry-sm text-telemetry-sm">/100</span></span>
                  </div>
                  <div class="flex items-center text-primary">
                    <span class="material-symbols-outlined text-[20px]">east</span>
                  </div>
                  <div class="flex flex-col text-right">
                    <span class="font-telemetry-sm text-telemetry-sm text-secondary">AFTER SIM</span>
                    <span class="font-headline-md text-headline-md text-secondary font-bold font-mono">${opt.newRiskScore}<span class="font-telemetry-sm text-telemetry-sm">/100</span></span>
                  </div>
                </div>
                <div class="bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm text-secondary flex items-center justify-between">
                  <span>POSTURE:</span>
                  <strong class="font-bold">${opt.newRiskScore < 45 ? 'CRITICAL → MODERATE' : 'CRITICAL → ELEVATED'}</strong>
                </div>
              </div>

              <!-- Metric 3: Attack Path Continuity -->
              <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT flex flex-col justify-between gap-space-sm border border-surface-container-highest/30">
                <div class="flex items-center justify-between">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">KILL CHAIN CONTINUITY</span>
                  <span class="material-symbols-outlined text-primary text-[18px]">account_tree</span>
                </div>
                <div class="flex items-center justify-between pt-space-xs">
                  <div class="flex flex-col">
                    <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">BEFORE SIM</span>
                    <span class="font-telemetry-lg text-telemetry-lg text-error font-bold flex items-center gap-1 font-mono">
                      <span class="inline-block w-2 h-2 rounded-full bg-error animate-pulse"></span> ACTIVE
                    </span>
                  </div>
                  <div class="flex items-center text-primary">
                    <span class="material-symbols-outlined text-[20px]">east</span>
                  </div>
                  <div class="flex flex-col text-right">
                    <span class="font-telemetry-sm text-telemetry-sm text-primary">AFTER SIM</span>
                    <span class="font-telemetry-lg text-telemetry-lg text-primary font-bold flex items-center gap-1 justify-end font-mono">
                      <span class="material-symbols-outlined text-[16px] text-primary">block</span> DISRUPTED
                    </span>
                  </div>
                </div>
                <div class="bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm text-primary flex items-center justify-between">
                  <span>CHAIN STATE:</span>
                  <strong class="font-bold">${opt.killChainState}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- ATTACK PATH DISRUPTION FLOW VISUAL -->
        <div class="bg-surface-container-low rounded-DEFAULT p-space-lg shadow-md flex flex-col gap-space-md border border-surface-container-high/40">
          <div class="flex flex-wrap items-center justify-between gap-space-sm">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">timeline</span>
              <h2 class="font-headline-md text-headline-md text-on-surface">SYNTHETIC PATH CONTAINMENT TOPOLOGY</h2>
            </div>
            <div class="flex items-center gap-space-sm">
              <div class="flex items-center gap-1">
                <span class="w-2.5 h-2.5 rounded-full bg-error"></span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Compromised</span>
              </div>
              <div class="flex items-center gap-1">
                <span class="w-2.5 h-2.5 rounded-full bg-primary"></span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Quarantined Cut</span>
              </div>
              <div class="flex items-center gap-1">
                <span class="w-2.5 h-2.5 rounded-full bg-surface-bright"></span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Safeguarded Downstream</span>
              </div>
            </div>
          </div>

          <!-- Step-by-Step Disruption Graph -->
          <div class="bg-surface-container-lowest p-space-lg rounded-DEFAULT flex flex-col gap-space-lg border border-surface-container-highest/30">
            <!-- Graph Node Sequence -->
            <div class="flex items-center justify-between overflow-x-auto pb-space-sm pt-space-xs gap-space-xs min-w-[700px]">
              <!-- Node: External Attacker -->
              <div class="flex flex-col items-center gap-space-xs text-center min-w-[110px] cursor-pointer hover:scale-105 transition-transform" data-inspect="EXT-01">
                <div class="w-12 h-12 rounded-DEFAULT bg-error/15 text-error flex items-center justify-center shadow-sm border border-error/30">
                  <span class="material-symbols-outlined text-[24px]">skull</span>
                </div>
                <span class="font-label-caps text-label-caps text-error uppercase">EXTERNAL ACTOR</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface font-mono">194.26.29.112</span>
              </div>

              <!-- Link 1 -->
              <div class="flex-1 flex flex-col items-center px-space-xs">
                <div class="w-full h-0.5 bg-error/80 relative">
                  <span class="absolute right-0 -top-1 material-symbols-outlined text-[10px] text-error leading-none">arrow_forward_ios</span>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-error mt-1 font-mono">Exploit</span>
              </div>

              <!-- Node: PC-017 (TARGETED DISRUPTION POINT) -->
              <div class="relative flex flex-col items-center gap-space-xs text-center min-w-[130px] p-space-xs bg-surface-container-high rounded-DEFAULT shadow-md border-2 ${opt.id === 'option-2' ? 'border-primary' : 'border-surface-container-highest'} cursor-pointer hover:scale-105 transition-transform" data-inspect="PC-017">
                <div class="absolute -top-3 px-space-xs py-space-2xs bg-primary text-on-primary font-label-caps text-label-caps uppercase rounded-DEFAULT font-bold shadow-sm">
                  DISRUPT HERE
                </div>
                <div class="w-12 h-12 rounded-DEFAULT bg-primary/20 text-primary flex items-center justify-center">
                  <span class="material-symbols-outlined text-[24px]">desktop_windows</span>
                </div>
                <span class="font-label-caps text-label-caps text-primary font-bold uppercase">PC-017</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant truncate max-w-[120px] font-mono">dev-wks-017.lan</span>
              </div>

              <!-- Link 2: Severed -->
              <div class="flex-1 flex flex-col items-center px-space-xs relative">
                <div class="w-full h-0.5 bg-surface-bright flex items-center justify-center relative">
                  <div class="w-7 h-7 rounded-full bg-surface-container-lowest flex items-center justify-center z-10 shadow-sm text-primary border border-primary/40">
                    <span class="material-symbols-outlined text-[16px]">gpp_bad</span>
                  </div>
                </div>
                <span class="font-label-caps text-label-caps text-primary uppercase mt-1 tracking-wider font-bold">PATH SEVERED</span>
              </div>

              <!-- Node: SERVER-03 -->
              <div class="flex flex-col items-center gap-space-xs text-center min-w-[110px] opacity-75 cursor-pointer hover:opacity-100 hover:scale-105 transition-all" data-inspect="SERVER-03">
                <div class="w-12 h-12 rounded-DEFAULT bg-surface-container-high text-on-surface-variant flex items-center justify-center border border-surface-container-highest/50">
                  <span class="material-symbols-outlined text-[24px]">dns</span>
                </div>
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">SERVER-03</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">App Middleware</span>
              </div>

              <!-- Link 3 -->
              <div class="flex-1 flex flex-col items-center px-space-xs">
                <div class="w-full h-0.5 bg-surface-container-high relative">
                  <span class="absolute right-0 -top-1 material-symbols-outlined text-[10px] text-on-surface-variant leading-none">arrow_forward_ios</span>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">Neutralized</span>
              </div>

              <!-- Node: ADMIN-02 -->
              <div class="flex flex-col items-center gap-space-xs text-center min-w-[110px] opacity-75 cursor-pointer hover:opacity-100 hover:scale-105 transition-all" data-inspect="ADMIN-02">
                <div class="w-12 h-12 rounded-DEFAULT bg-surface-container-high text-on-surface-variant flex items-center justify-center border border-surface-container-highest/50">
                  <span class="material-symbols-outlined text-[24px]">badge</span>
                </div>
                <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">ADMIN-02</span>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">Jumpbox Console</span>
              </div>

              <!-- Link 4 -->
              <div class="flex-1 flex flex-col items-center px-space-xs">
                <div class="w-full h-0.5 bg-surface-container-high relative">
                  <span class="absolute right-0 -top-1 material-symbols-outlined text-[10px] text-on-surface-variant leading-none">arrow_forward_ios</span>
                </div>
                <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1">Neutralized</span>
              </div>

              <!-- Node: DATABASE-01 (CRITICAL CROWN JEWEL) -->
              <div class="flex flex-col items-center gap-space-xs text-center min-w-[120px] cursor-pointer hover:scale-105 transition-transform" data-inspect="DATABASE-01">
                <div class="w-12 h-12 rounded-DEFAULT bg-primary-container/15 text-primary flex items-center justify-center shadow-sm border border-primary/40">
                  <span class="material-symbols-outlined text-[24px]">database</span>
                </div>
                <span class="font-label-caps text-label-caps text-primary font-bold uppercase">DATABASE-01</span>
                <span class="font-telemetry-sm text-telemetry-sm text-primary font-bold">PROTECTED</span>
              </div>
            </div>

            <!-- Strategic Explanation Callout -->
            <div class="bg-surface-container-low p-space-md rounded-DEFAULT flex items-start gap-space-md border border-surface-container-high/40">
              <span class="material-symbols-outlined text-primary text-[24px] mt-0.5 shrink-0">tips_and_updates</span>
              <div class="flex flex-col gap-space-2xs">
                <span class="font-label-caps text-label-caps text-primary tracking-wide uppercase">STRATEGIC DISRUPTION REASONING</span>
                <p class="font-body-md text-body-md text-on-surface">
                  <strong>Earliest intervention point with highest security benefit (${opt.disruptionGain}% containment) and lowest business impact.</strong>
                  Executing ${opt.title} suffocates the attacker's lateral pivoting before credential dump operations against <span class="font-telemetry-sm text-telemetry-sm text-secondary font-mono">svc-backup-admin</span> can be staged toward SERVER-03.
                </p>
              </div>
            </div>
          </div>
        </div>

        <!-- MULTI-OPTION DEFENSE COMPARISON MATRIX -->
        <div class="flex flex-col gap-space-sm">
          <div class="flex flex-wrap items-center justify-between gap-space-sm">
            <div>
              <h2 class="font-headline-md text-headline-md text-on-surface">SIMULATED INTERVENTION COMPARISON MATRIX</h2>
              <p class="font-body-sm text-body-sm text-on-surface-variant">Comparative analysis of simulated countermeasures graded against blast radius and containment depth. (Click any row to test)</p>
            </div>
            <div class="flex items-center gap-space-xs text-on-surface-variant font-telemetry-sm text-telemetry-sm">
              <span>5 SCENARIOS EVALUATED</span>
            </div>
          </div>

          <!-- Comparative Table Container -->
          <div class="bg-surface-container-low rounded-DEFAULT overflow-hidden shadow-sm border border-surface-container-high/40">
            <div class="overflow-x-auto">
              <table class="w-full text-left font-body-sm text-body-sm">
                <thead class="bg-surface-container-lowest font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider border-b border-surface-container-highest/30">
                  <tr>
                    <th class="py-space-sm px-space-md">Intervention Vector</th>
                    <th class="py-space-sm px-space-md">Security Effectiveness</th>
                    <th class="py-space-sm px-space-md">Operational Impact</th>
                    <th class="py-space-sm px-space-md">Simulated Trade-Off / Blast Radius</th>
                    <th class="py-space-sm px-space-md text-right">Simulation State</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-container-highest/20 font-telemetry-sm text-telemetry-sm">
                  ${Object.values(state.simulationScenarios).map(sc => {
                    const isSelected = sc.id === activeOptId;
                    const isAiPick = sc.id === 'option-2';

                    return `
                      <tr 
                        class="cursor-pointer transition-colors ${isSelected ? 'bg-surface-container-high/80' : 'bg-surface-container-low hover:bg-surface-container'}"
                        data-select-scenario="${sc.id}"
                      >
                        <td class="py-space-sm px-space-md relative">
                          ${isSelected ? '<div class="absolute left-0 top-0 bottom-0 w-1 bg-primary"></div>' : ''}
                          <div class="flex items-center gap-space-sm">
                            <span class="w-2 h-2 rounded-full ${isSelected ? 'bg-primary animate-pulse' : 'bg-on-surface-variant'}"></span>
                            <div class="flex flex-col">
                              <div class="flex items-center gap-space-xs">
                                <span class="font-headline-md text-headline-md ${isSelected ? 'text-primary' : 'text-on-surface'} font-bold">${sc.title}</span>
                                ${isAiPick ? '<span class="bg-primary text-on-primary font-label-caps text-[9px] px-space-xs py-space-2xs rounded-DEFAULT font-bold uppercase">AI RECOMMENDED</span>' : ''}
                              </div>
                              <span class="font-telemetry-sm text-telemetry-sm text-on-surface-variant">${sc.target}</span>
                            </div>
                          </div>
                        </td>

                        <td class="py-space-sm px-space-md">
                          <div class="flex items-center gap-space-sm">
                            <span class="font-telemetry-md text-telemetry-md ${isSelected ? 'text-primary font-bold' : 'text-on-surface'} font-mono">${sc.effectiveness}%</span>
                            <div class="w-16 bg-surface-container-lowest h-1.5 rounded-full overflow-hidden">
                              <div class="${isSelected ? 'bg-primary' : 'bg-secondary'} h-full transition-all duration-300" style="width: ${sc.effectiveness}%"></div>
                            </div>
                          </div>
                        </td>

                        <td class="py-space-sm px-space-md">
                          <span class="inline-flex items-center gap-1 bg-surface-container-high px-space-xs py-space-2xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm ${sc.impactClass}">
                            ${sc.operationalImpact}
                          </span>
                        </td>

                        <td class="py-space-sm px-space-md text-on-surface font-body-sm text-body-sm">
                          ${sc.tradeoff}
                        </td>

                        <td class="py-space-sm px-space-md text-right">
                          <span class="font-label-caps text-label-caps px-space-xs py-space-2xs rounded-DEFAULT uppercase ${isSelected ? 'bg-primary/20 text-primary font-bold' : 'bg-surface-container text-on-surface-variant'}">
                            ${isSelected ? 'ACTIVE PICK' : sc.statusLabel}
                          </span>
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ACTION CONTROLS & COMPLIANCE DOCK -->
        <div class="sticky bottom-4 z-30 bg-surface-container-lowest/95 backdrop-blur-md p-space-md rounded-DEFAULT shadow-2xl flex flex-col md:flex-row items-center justify-between gap-space-md border border-surface-container-highest/40">
          <!-- Left Compliance Notice -->
          <div class="flex items-center gap-space-md w-full md:w-auto">
            <div class="w-10 h-10 rounded-DEFAULT bg-surface-container flex items-center justify-center shrink-0">
              <span class="material-symbols-outlined text-primary text-[22px]">policy</span>
            </div>
            <div class="flex flex-col">
              <div class="flex items-center gap-space-xs">
                <span class="font-label-caps text-label-caps text-primary uppercase font-bold">GOVERNANCE PROTOCOL ACTIVE</span>
                <span class="bg-surface-container px-space-xs py-space-2xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm text-on-surface-variant font-medium">IR-402 COMPLIANT</span>
              </div>
              <p class="font-body-sm text-body-sm text-on-surface-variant max-w-xl">
                Triggers SecOps approval workflow under Incident Response Policy IR-402. Human authorization required before any production enforcement.
              </p>
            </div>
          </div>

          <!-- Right Interaction CTA Group -->
          <div class="flex items-center gap-space-sm w-full md:w-auto justify-end">
            <!-- Simulate Secondary Action -->
            <button 
              id="re-simulate-btn"
              class="flex items-center gap-space-xs px-space-md py-space-sm rounded-DEFAULT bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors font-body-sm text-body-sm font-semibold shadow-sm cursor-pointer"
            >
              <span class="material-symbols-outlined text-[18px] text-primary ${recalculating ? 'animate-spin' : ''}">replay</span>
              <span>${recalculating ? 'Recalculating...' : 'Re-Simulate Variations'}</span>
            </button>

            <!-- Request Defense Approval (Controlled CTA) -->
            <button 
              id="request-approval-btn"
              class="flex items-center gap-space-xs px-space-lg py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary transition-all font-body-sm text-body-sm font-bold shadow-[0_0_16px_rgba(0,240,255,0.25)] cursor-pointer"
            >
              <span class="material-symbols-outlined text-[18px]">verified</span>
              <span>${isEnforced ? 'Defense Enforced (View Ticket)' : 'Request Defense Approval'}</span>
            </button>
          </div>
        </div>
      </div>
    `;

    // Bind event listeners
    container.querySelectorAll('[data-select-scenario]').forEach(row => {
      row.addEventListener('click', () => {
        const scId = row.getAttribute('data-select-scenario');
        store.setSimulationOption(scId);
      });
    });

    container.querySelectorAll('[data-inspect]').forEach(el => {
      el.addEventListener('click', () => {
        const nodeId = el.getAttribute('data-inspect');
        store.openNodeDetail(nodeId);
      });
    });

    const resimBtn = container.querySelector('#re-simulate-btn');
    if (resimBtn) {
      resimBtn.addEventListener('click', () => {
        recalculating = true;
        update();
        setTimeout(() => {
          recalculating = false;
          store.notify();
        }, 800);
      });
    }

    const reqBtn = container.querySelector('#request-approval-btn');
    if (reqBtn) {
      reqBtn.addEventListener('click', () => {
        store.openApprovalModal();
      });
    }
  };

  update();
  store.subscribeView(update);
}
