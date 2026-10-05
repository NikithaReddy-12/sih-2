import { store } from '../state/store.js';

export function renderApprovalModal(container) {
  const update = () => {
    const state = store.getState();
    if (!state.approvalModalOpen) {
      container.innerHTML = '';
      return;
    }

    container.innerHTML = `
      <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-container-lowest/85 backdrop-blur-md p-space-md" id="approval-modal-backdrop">
        <div class="bg-surface-container-low max-w-xl w-full p-space-lg rounded-DEFAULT shadow-2xl border border-primary/40 flex flex-col gap-space-md animate-in fade-in zoom-in-95 duration-150">
          <div class="flex items-center justify-between border-b border-surface-container-highest pb-space-sm">
            <div class="flex items-center gap-space-xs text-primary">
              <span class="material-symbols-outlined text-[24px]">verified_user</span>
              <span class="font-headline-md text-headline-md text-on-surface">SOC Authorization Required</span>
            </div>
            <button class="text-on-surface-variant hover:text-on-surface" id="close-approval-btn">
              <span class="material-symbols-outlined text-[20px]">close</span>
            </button>
          </div>

          <div class="bg-primary/10 border border-primary/30 p-space-sm rounded-DEFAULT flex items-center gap-space-sm">
            <span class="material-symbols-outlined text-primary text-[24px] shrink-0">shield</span>
            <p class="font-body-sm text-body-sm text-on-surface">
              You are authorizing the immediate automated network quarantine of <strong class="text-primary font-telemetry-sm">PC-017</strong> under Incident Response Policy <strong class="text-secondary font-telemetry-sm">IR-402</strong>.
            </p>
          </div>

          <div class="bg-surface-container-lowest p-space-sm rounded-DEFAULT flex flex-col gap-space-2xs font-telemetry-sm text-telemetry-sm border border-surface-container-highest/60">
            <div class="flex justify-between text-on-surface-variant">
              <span>Target Asset:</span>
              <span class="text-on-surface font-semibold">PC-017 (dev-wks-017.lan • 10.4.1.17)</span>
            </div>
            <div class="flex justify-between text-on-surface-variant">
              <span>Intervention Method:</span>
              <span class="text-on-surface">Zero-Trust Host EDR Agent Disconnect</span>
            </div>
            <div class="flex justify-between text-on-surface-variant">
              <span>Disruption Efficacy:</span>
              <span class="text-primary font-bold">94.2% Containment Gain</span>
            </div>
            <div class="flex justify-between text-on-surface-variant">
              <span>Projected Risk Reduction:</span>
              <span class="text-secondary font-bold">91/100 → 38/100 (-58%)</span>
            </div>
            <div class="flex justify-between text-on-surface-variant">
              <span>Authorization Standard:</span>
              <span class="text-primary font-bold">Policy IR-402 Level 3 (Col. Marcus Vance)</span>
            </div>
          </div>

          <div class="flex items-center justify-between text-telemetry-sm text-on-surface-variant pt-space-xs">
            <span class="flex items-center gap-1">
              <span class="w-2 h-2 rounded-full bg-secondary"></span>
              Human-in-the-Loop Safeguard Active
            </span>
            <span>Ticket: #SEC-9921-ISO</span>
          </div>

          <div class="flex justify-end gap-space-sm mt-space-xs pt-space-xs border-t border-surface-container-highest">
            <button id="cancel-approval-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm font-semibold transition-colors">
              Cancel
            </button>
            <button id="confirm-approval-btn" class="px-space-lg py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-[0_0_16px_rgba(0,240,255,0.3)] transition-all flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-[18px]">verified</span>
              <span>Authorize &amp; Quarantine Host</span>
            </button>
          </div>
        </div>
      </div>
    `;

    const closeBtn = container.querySelector('#close-approval-btn');
    const cancelBtn = container.querySelector('#cancel-approval-btn');
    const confirmBtn = container.querySelector('#confirm-approval-btn');
    const backdrop = container.querySelector('#approval-modal-backdrop');

    if (closeBtn) closeBtn.addEventListener('click', () => store.closeApprovalModal());
    if (cancelBtn) cancelBtn.addEventListener('click', () => store.closeApprovalModal());
    if (backdrop) backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) store.closeApprovalModal();
    });
    if (confirmBtn) {
      confirmBtn.addEventListener('click', () => {
        store.confirmDefenseApproval();
      });
    }
  };

  update();
  store.subscribe(update);
}
