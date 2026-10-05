import { store } from '../state/store.js';

export function renderLiveBehaviourSignals(container) {
  let severityFilter = 'ALL';
  const signals = [
    {
      id: 'SIG-104',
      title: 'Kerberoasting SPN Ticket Request Anomaly',
      source: 'PC-017 (j.miller)',
      score: 94,
      severity: 'CRITICAL',
      time: '10:06:12',
      details: 'Over 18 RC4 encrypted service ticket requests observed in 40 seconds targeting svc-backup-admin.',
      ttp: 'T1558.003'
    },
    {
      id: 'SIG-103',
      title: 'PsExec Named Pipe Creation over SMB',
      source: 'SERVER-03 (svc-billing-daemon)',
      score: 88,
      severity: 'HIGH',
      time: '10:09:02',
      details: 'Named pipe \\pipe\\psexecsvc instantiated by non-interactive remote session.',
      ttp: 'T1021.002'
    },
    {
      id: 'SIG-102',
      title: 'Unusual Off-Hours RPC Ingress',
      source: '194.26.29.112',
      score: 72,
      severity: 'HIGH',
      time: '10:01:45',
      details: 'Perimeter gateway detected high-frequency probing across RPC endpoint mapper port 135.',
      ttp: 'T1046'
    },
    {
      id: 'SIG-101',
      title: 'LSASS Memory Dumping Probe',
      source: 'PC-017',
      score: 91,
      severity: 'CRITICAL',
      time: '10:07:18',
      details: 'MiniDumpWriteDump API invoked against lsass.exe process handle by unverified binary.',
      ttp: 'T1003.001'
    },
    {
      id: 'SIG-100',
      title: 'Cross-VPC Peering Volume Spike',
      source: 'SERVER-03',
      score: 54,
      severity: 'MEDIUM',
      time: '09:58:30',
      details: 'Egress rate increased by 310% compared to typical baseline 7-day rolling window.',
      ttp: 'T1020'
    }
  ];

  const update = () => {
    const filtered = severityFilter === 'ALL'
      ? signals
      : signals.filter(s => s.severity === severityFilter);

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">activity_zone</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">UEBA SIGNAL FABRIC</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">LIVE BEHAVIOURAL SIGNALS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Real-time user &amp; host entity anomaly telemetry. Detects credential abuse, lateral stagers, and execution variance.
            </p>
          </div>

          <!-- Severity Filter -->
          <div class="flex items-center gap-space-xs bg-surface-container-lowest p-space-xs rounded-DEFAULT border border-surface-container-highest/30">
            <span class="font-label-caps text-label-caps text-on-surface-variant uppercase px-1">Severity:</span>
            ${['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => `
              <button class="px-space-sm py-space-xs rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold cursor-pointer font-mono ${severityFilter === sev ? 'bg-primary text-on-primary shadow-sm' : 'text-on-surface-variant hover:text-on-surface'}" data-sev="${sev}">
                ${sev}
              </button>
            `).join('')}
          </div>
        </div>

        <!-- Signals Feed -->
        <div class="space-y-space-xs">
          ${filtered.map(sig => `
            <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-sm border border-surface-container-high/40 flex flex-col md:flex-row md:items-center justify-between gap-space-md hover:bg-surface-container transition-colors">
              <div class="flex items-start gap-space-sm min-w-0">
                <div class="w-10 h-10 rounded-DEFAULT ${sig.severity === 'CRITICAL' ? 'bg-error-container/30 text-error' : 'bg-secondary-container/20 text-secondary'} flex items-center justify-center shrink-0 mt-0.5">
                  <span class="material-symbols-outlined text-[20px]">${sig.severity === 'CRITICAL' ? 'crisis_alert' : 'warning'}</span>
                </div>
                <div class="space-y-space-2xs min-w-0">
                  <div class="flex items-center gap-space-xs flex-wrap">
                    <span class="font-headline-md text-headline-md text-on-surface font-semibold">${sig.title}</span>
                    <span class="px-space-xs py-space-2xs font-label-caps text-[9px] rounded-DEFAULT ${sig.severity === 'CRITICAL' ? 'bg-error text-on-error font-bold' : 'bg-secondary text-on-secondary font-bold'}">
                      ${sig.severity}
                    </span>
                    <span class="font-telemetry-sm text-telemetry-sm text-primary font-mono">${sig.ttp}</span>
                  </div>
                  <p class="font-body-sm text-body-sm text-on-surface-variant">${sig.details}</p>
                  <div class="flex items-center gap-space-md font-telemetry-sm text-telemetry-sm text-on-surface-variant font-mono">
                    <span>Source: <strong class="text-on-surface">${sig.source}</strong></span>
                    <span>•</span>
                    <span>Observed: ${sig.time} UTC</span>
                  </div>
                </div>
              </div>

              <div class="flex items-center gap-space-sm shrink-0 self-end md:self-center">
                <div class="flex flex-col text-right">
                  <span class="font-label-caps text-label-caps text-on-surface-variant uppercase">ANOMALY SCORE</span>
                  <span class="font-telemetry-lg text-telemetry-lg font-bold font-mono ${sig.score > 85 ? 'text-error' : 'text-secondary'}">${sig.score}/100</span>
                </div>
                <button class="px-space-sm py-space-xs bg-primary-container text-on-primary-container font-telemetry-sm text-telemetry-sm font-bold rounded-DEFAULT hover:bg-primary transition-colors cursor-pointer" onclick="alert('Disruption countermeasure dispatched for ${sig.id}')">
                  Isolate Vector
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    container.querySelectorAll('[data-sev]').forEach(btn => {
      btn.addEventListener('click', () => {
        severityFilter = btn.getAttribute('data-sev');
        update();
      });
    });
  };

  update();
  store.subscribeView(update);
}
