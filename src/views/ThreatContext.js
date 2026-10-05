import { store } from '../state/store.js';

export function renderThreatContext(container) {
  const update = () => {
    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">policy</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">GLOBAL THREAT INTEL FEED</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">THREAT ACTOR DOSSIER &amp; TTP CONTEXT</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Attribution correlation, known adversary TTP playbooks, and active Indicators of Compromise (IOCs).
            </p>
          </div>

          <button class="px-space-md py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-md flex items-center gap-space-xs cursor-pointer" onclick="alert('CTI Feeds synced with MISP and US-CERT.')">
            <span class="material-symbols-outlined text-[18px]">sync</span>
            <span>Sync Threat Feeds</span>
          </button>
        </div>

        <!-- Actor Hero Dossier -->
        <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 flex flex-col md:flex-row gap-space-md">
          <div class="w-20 h-20 rounded-DEFAULT bg-error-container/20 border border-error/30 flex items-center justify-center shrink-0 text-error">
            <span class="material-symbols-outlined text-[48px]">smart_toy</span>
          </div>
          <div class="space-y-space-xs flex-1">
            <div class="flex items-center gap-space-xs flex-wrap">
              <span class="font-headline-lg text-headline-lg text-on-surface font-bold">APT-29 Derivative (Midnight Blizzard / Nobelium)</span>
              <span class="font-label-caps text-label-caps bg-error text-on-error px-space-xs py-space-2xs rounded-DEFAULT font-bold uppercase">NATION-STATE TIER 1</span>
            </div>
            <p class="font-body-md text-body-md text-on-surface-variant leading-relaxed">
              Highly sophisticated cyber espionage threat actor associated with the Russian Foreign Intelligence Service (SVR). Known for stealthy lateral traversal, abuse of OAuth authentication tokens, and targeting cloud hosting &amp; financial core infrastructure.
            </p>
            <div class="flex items-center gap-space-md font-telemetry-sm text-telemetry-sm font-mono text-on-surface-variant pt-space-xs border-t border-surface-container-highest/30">
              <span>Primary Vector: <strong class="text-error">CVE-2023-4966 (Citrix Bleed)</strong></span>
              <span>•</span>
              <span>C2 Infrastructure: <strong class="text-on-surface">194.26.29.112 (AS49505)</strong></span>
              <span>•</span>
              <span>Target: <strong class="text-primary font-bold">Financial Database Cluster</strong></span>
            </div>
          </div>
        </div>

        <!-- IOC Table & TTP Matrix -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
          <!-- IOC List (6 cols) -->
          <div class="lg:col-span-6 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-sm">
            <h3 class="font-headline-md text-headline-md text-on-surface font-bold">Confirmed Indicators of Compromise (IOCs)</h3>
            <div class="space-y-space-xs">
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between font-mono text-telemetry-sm text-telemetry-sm">
                <div>
                  <span class="text-error block font-bold">194.26.29.112</span>
                  <span class="text-on-surface-variant text-[10px]">C2 External Relay • Russia</span>
                </div>
                <span class="bg-error-container/30 text-error px-1 py-0.5 rounded-DEFAULT text-[9px] uppercase font-bold">Malicious</span>
              </div>
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between font-mono text-telemetry-sm text-telemetry-sm">
                <div>
                  <span class="text-secondary block font-bold">SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f...</span>
                  <span class="text-on-surface-variant text-[10px]">CobaltStrike Stager Beacon Payload</span>
                </div>
                <span class="bg-secondary-container/30 text-secondary px-1 py-0.5 rounded-DEFAULT text-[9px] uppercase font-bold">Signature Match</span>
              </div>
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between font-mono text-telemetry-sm text-telemetry-sm">
                <div>
                  <span class="text-primary block font-bold">domain: telemetry-cdn-check[.]org</span>
                  <span class="text-on-surface-variant text-[10px]">Fast-Flux DNS C2 Domain</span>
                </div>
                <span class="bg-primary-container/20 text-primary px-1 py-0.5 rounded-DEFAULT text-[9px] uppercase font-bold">Sinkholed</span>
              </div>
            </div>
          </div>

          <!-- TTP Playbook (6 cols) -->
          <div class="lg:col-span-6 bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-sm">
            <h3 class="font-headline-md text-headline-md text-on-surface font-bold">MITRE ATT&amp;CK Tactical Playbook</h3>
            <div class="space-y-space-xs text-body-sm text-body-sm">
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-start gap-space-sm">
                <span class="font-mono text-error font-bold text-xs shrink-0">T1190</span>
                <div>
                  <span class="font-semibold text-on-surface block">Exploit Public-Facing Application</span>
                  <span class="text-on-surface-variant text-xs">Utilized unauthenticated buffer overflow on Citrix NetScaler perimeter gateway.</span>
                </div>
              </div>
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-start gap-space-sm">
                <span class="font-mono text-secondary font-bold text-xs shrink-0">T1021.002</span>
                <div>
                  <span class="font-semibold text-on-surface block">SMB/Windows Admin Shares</span>
                  <span class="text-on-surface-variant text-xs">Pivoting laterally between internal nodes using remote service token execution.</span>
                </div>
              </div>
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-start gap-space-sm">
                <span class="font-mono text-primary font-bold text-xs shrink-0">T1558.003</span>
                <div>
                  <span class="font-semibold text-on-surface block">Kerberoasting</span>
                  <span class="text-on-surface-variant text-xs">Requesting RC4-HMAC service tickets for service accounts to crack passwords offline.</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  };

  update();
  store.subscribeView(update);
}
