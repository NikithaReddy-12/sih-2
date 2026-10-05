import { store } from '../state/store.js';

export function renderAttackCases(container) {
  const update = () => {
    const state = store.getState();
    const cases = state.cases;
    const activeCaseId = state.activeCaseId;

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">work_history</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">SOC INCIDENT REPOSITORY</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">ATTACK CASES &amp; CAMPAIGN POOL</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Catalog of active and resolved adversarial campaigns mapped into topological neural disruption graphs.
            </p>
          </div>

          <button id="new-case-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-md flex items-center gap-space-xs cursor-pointer">
            <span class="material-symbols-outlined text-[18px]">add</span>
            <span>Register New Threat Campaign</span>
          </button>
        </div>

        <!-- Cases Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-space-md">
          ${cases.map(c => {
            const isCurrent = c.id === activeCaseId;
            return `
              <div 
                class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border ${isCurrent ? 'border-primary ring-1 ring-primary/40' : 'border-surface-container-high/40'} flex flex-col justify-between space-y-space-sm cursor-pointer hover:bg-surface-container transition-all"
                data-case-id="${c.id}"
              >
                <div>
                  <div class="flex items-center justify-between mb-space-xs">
                    <div class="flex items-center gap-space-xs">
                      <span class="font-label-caps text-label-caps uppercase px-space-xs py-space-2xs rounded-DEFAULT font-bold ${c.severity === 'CRITICAL' ? 'bg-error-container text-on-error-container' : c.severity === 'HIGH' ? 'bg-secondary-container text-on-secondary-container' : 'bg-surface-container text-on-surface'}">
                        ${c.severity}
                      </span>
                      <span class="font-telemetry-sm text-telemetry-sm text-on-surface font-mono font-bold">${c.id}</span>
                    </div>
                    <span class="font-telemetry-sm text-telemetry-sm text-primary font-mono font-semibold">Confidence: ${c.confidence}</span>
                  </div>

                  <h3 class="font-headline-md text-headline-md text-on-surface font-bold">${c.title}</h3>

                  <div class="my-space-sm space-y-1 font-telemetry-sm text-telemetry-sm font-mono">
                    <div class="flex items-center justify-between text-on-surface-variant">
                      <span>Attacker IP:</span>
                      <span class="text-error font-semibold">${c.attacker}</span>
                    </div>
                    <div class="flex items-center justify-between text-on-surface-variant">
                      <span>Observed Vector:</span>
                      <span class="text-on-surface">${c.observedHops}</span>
                    </div>
                    <div class="flex items-center justify-between text-on-surface-variant">
                      <span>Predicted Convergence:</span>
                      <span class="text-primary">${c.predictedHops}</span>
                    </div>
                  </div>
                </div>

                <div class="flex items-center justify-between pt-space-xs border-t border-surface-container-highest/30">
                  <span class="font-label-caps text-[10px] uppercase font-bold ${c.status.includes('ACTIVE') ? 'text-primary flex items-center gap-1' : 'text-on-surface-variant'}">
                    ${c.status.includes('ACTIVE') ? '<span class="w-1.5 h-1.5 rounded-full bg-primary animate-ping"></span>' : ''}
                    ${c.status}
                  </span>
                  <button class="font-telemetry-sm text-telemetry-sm text-primary hover:underline flex items-center gap-1">
                    <span>${isCurrent ? 'Currently Active' : 'Switch to this Case'}</span>
                    <span class="material-symbols-outlined text-[14px]">arrow_forward</span>
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;

    container.querySelectorAll('[data-case-id]').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.getAttribute('data-case-id');
        store.selectCase(id);
        store.setModule('command-center');
      });
    });

    const newBtn = container.querySelector('#new-case-btn');
    if (newBtn) {
      newBtn.addEventListener('click', () => {
        const id = `PX-${Math.floor(Math.random() * 800 + 9000)}`;
        store.state.cases.unshift({
          id,
          title: `Case #${id}: Automated Sandbox Anomaly`,
          attacker: '198.51.100.44 (Unknown Origin)',
          observedHops: 'WS-012 → DMZ-01',
          predictedHops: 'DMZ-01 → CORP-DC',
          severity: 'HIGH',
          confidence: '85%',
          status: 'ACTIVE_INTERCEPT_PENDING',
          updated: 'Just now'
        });
        store.selectCase(id);
        update();
      });
    }
  };

  update();
  store.subscribeView(update);
}
