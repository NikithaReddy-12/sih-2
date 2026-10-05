import { store } from '../state/store.js';

export function renderReports(container) {
  const update = () => {
    const state = store.getState();
    const t = state.telemetry;

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">summarize</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">GOVERNANCE &amp; AUDIT INTELLIGENCE</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">TACTICAL DISRUPTION &amp; INCIDENT REPORTS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Certified SecOps post-action reports, regulatory compliance certifications, and disruption efficacy documentation.
            </p>
          </div>

          <div class="flex items-center gap-space-xs">
            <button id="print-report-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-surface-container-high hover:bg-surface-variant text-on-surface font-telemetry-sm text-telemetry-sm flex items-center gap-1 transition-colors cursor-pointer border border-surface-container-highest/40">
              <span class="material-symbols-outlined text-[16px]">print</span>
              <span>Print / Save as PDF</span>
            </button>
            <button id="export-json-report-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-md flex items-center gap-space-xs cursor-pointer">
              <span class="material-symbols-outlined text-[18px]">download</span>
              <span>Export Full Audit (JSON)</span>
            </button>
          </div>
        </div>

        <!-- Printable Report Preview Container -->
        <div class="bg-surface-container-low p-space-lg rounded-DEFAULT shadow-xl border border-surface-container-high/40 space-y-space-md print:bg-white print:text-black">
          <!-- Report Header -->
          <div class="flex items-center justify-between pb-space-sm border-b border-surface-container-highest/40">
            <div>
              <div class="font-label-caps text-label-caps text-primary font-bold tracking-widest uppercase">PREDICT-X CYBERSECURITY DEFENSE REPORT</div>
              <h2 class="font-headline-xl text-headline-xl text-on-surface font-bold">EXECUTIVE DISRUPTION SUMMARY: CAMPAIGN #PX-9821</h2>
              <div class="font-telemetry-sm text-telemetry-sm text-on-surface-variant mt-1 font-mono">Classification: TOP SECRET // SOC LEVEL 3 // TLP:AMBER</div>
            </div>
            <div class="text-right font-telemetry-sm text-telemetry-sm font-mono text-on-surface-variant">
              <div>Date: ${new Date().toLocaleDateString()}</div>
              <div>Generated: 10:14:02 UTC</div>
              <div class="text-primary font-bold">Status: ${state.simulationApplied ? 'DISRUPTED & CONTAINED' : 'ACTIVE INTERCEPT'}</div>
            </div>
          </div>

          <!-- Executive Findings -->
          <div class="space-y-space-xs">
            <h3 class="font-headline-md text-headline-md text-on-surface font-bold">1. Executive Overview</h3>
            <p class="font-body-md text-body-md text-on-surface-variant leading-relaxed">
              At 10:01 UTC, automated telemetry detected an external breach origin from 194.26.29.112 targeting perimeter workstation PC-017 via CVE-2023-4966. Within 8 minutes, the adversary attempted lateral SMB pivoting toward application middleware SERVER-03.
              PREDICT-X Graph Neural Forecaster identified a 91% probability kill-chain trajectory targeting the primary Financial SQL Vault (DATABASE-01).
            </p>
          </div>

          <!-- Quantitative Metrics Table -->
          <div class="space-y-space-xs">
            <h3 class="font-headline-md text-headline-md text-on-surface font-bold">2. Disruption Impact &amp; KPI Metrics</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-space-sm font-telemetry-sm text-telemetry-sm font-mono">
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
                <span class="text-on-surface-variant block">Unmitigated Risk</span>
                <span class="font-headline-lg text-error font-bold">91/100</span>
              </div>
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
                <span class="text-on-surface-variant block">Post-Disruption Risk</span>
                <span class="font-headline-lg text-primary font-bold">38/100</span>
              </div>
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
                <span class="text-on-surface-variant block">Net Containment Gain</span>
                <span class="font-headline-lg text-primary font-bold">94.2%</span>
              </div>
              <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT border border-surface-container-highest/30">
                <span class="text-on-surface-variant block">Crown Jewel Vault</span>
                <span class="font-headline-lg text-primary font-bold">PROTECTED</span>
              </div>
            </div>
          </div>

          <!-- Policy Compliance Signoff -->
          <div class="bg-surface-container-lowest p-space-md rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between">
            <div class="space-y-1">
              <span class="font-label-caps text-label-caps text-primary uppercase font-bold">POLICY IR-402 COMPLIANCE VERIFICATION</span>
              <p class="font-body-sm text-body-sm text-on-surface-variant">
                Human authorization authorized by SOC Commander Col. Marcus Vance. Automated network containment applied with zero downstream production outage.
              </p>
            </div>
            <div class="text-right font-mono text-telemetry-sm text-primary font-bold shrink-0">
              SIGNATURE: 0x9B42...SEC
            </div>
          </div>
        </div>
      </div>
    `;

    const printBtn = container.querySelector('#print-report-btn');
    if (printBtn) {
      printBtn.addEventListener('click', () => {
        window.print();
      });
    }

    const exportJsonBtn = container.querySelector('#export-json-report-btn');
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', () => {
        const reportData = {
          reportTitle: "PREDICT-X Disruption Audit",
          campaign: state.activeCaseId,
          timestamp: new Date().toISOString(),
          telemetry: state.telemetry,
          nodes: state.nodes,
          simulationApplied: state.simulationApplied,
          approvalTicket: state.approvalTicket
        };
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
        const dlAnchor = document.createElement('a');
        dlAnchor.setAttribute("href", dataStr);
        dlAnchor.setAttribute("download", `predictx-report-${state.activeCaseId}-${Date.now()}.json`);
        dlAnchor.click();
      });
    }
  };

  update();
  store.subscribeView(update);
}
