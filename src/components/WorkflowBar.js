import { store } from '../state/store.js';
import { STAGES, SAVED_ALERTS, stageIndex } from './workflow.js';

export function renderWorkflowBar(container) {
  const update = () => {
    const current = store.getState().currentModule;
    if (current === 'attack-forecast') { container.innerHTML = ''; return; }
    const i = stageIndex(current);
    if (i < 0) { container.innerHTML = ''; return; }
    const prev = STAGES[i - 1];
    const next = STAGES[i + 1];
    const last = i === STAGES.length - 1;

    container.innerHTML = `
      <div class="fixed bottom-0 left-64 right-0 h-16 z-40 bg-surface/95 backdrop-blur border-t border-outline-variant/30 flex items-center justify-between px-6">
        <div class="flex items-center gap-4">
          <span class="text-body-sm text-on-surface-variant">Step ${i + 1} of ${STAGES.length}</span>
          <div class="flex gap-1.5" aria-hidden="true">
            ${STAGES.map((_, k) => `<span class="h-1 w-8 rounded-full ${k <= i ? 'bg-primary-container' : 'bg-outline-variant/60'}"></span>`).join('')}
          </div>
        </div>
        <div class="flex items-center gap-3">
          ${prev ? `<button data-go="${prev.id}" class="px-4 py-2 rounded-lg text-body-md text-on-surface-variant hover:bg-surface-container-high">Back</button>` : ''}
          <button data-go="${last ? SAVED_ALERTS.id : next.id}" class="px-4 py-2 rounded-lg bg-primary-container text-on-primary-container text-body-md font-semibold hover:brightness-110">
            ${last ? 'Finish and view saved alerts' : `Continue to ${next.label.toLowerCase()}`}
          </button>
        </div>
      </div>`;
    container.querySelectorAll('[data-go]').forEach(b =>
      b.addEventListener('click', () => { store.setModule(b.dataset.go); window.scrollTo({ top: 0 }); }));
  };
  update();
  store.subscribe(update);
}
