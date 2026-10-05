import { store } from '../state/store.js';

export function renderSettings(container) {
  let confThreshold = 65;
  let decayRate = 0.05;
  let horizonMinutes = 7;

  const update = () => {
    const state = store.getState();

    container.innerHTML = `
      <div class="flex flex-col w-full space-y-space-md">
        <!-- Header -->
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40">
          <div class="space-y-space-2xs">
            <div class="flex items-center gap-space-xs">
              <span class="material-symbols-outlined text-primary text-[20px]">tune</span>
              <span class="font-label-caps text-label-caps text-primary uppercase font-mono">SYSTEM CONFIGURATION</span>
            </div>
            <h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">PLATFORM SETTINGS &amp; HYPERPARAMETERS</h1>
            <span class="inline-flex items-center px-2 py-0.5 rounded border border-secondary/50 text-secondary font-label-caps text-label-caps uppercase tracking-wide">Illustrative simulation</span>
            <p class="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
              Neural inference tuning, sensor connector fabric, sound preferences, and role-based SOC access governance.
            </p>
          </div>

          <button id="save-settings-btn" class="px-space-md py-space-sm rounded-DEFAULT bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-bold shadow-md flex items-center gap-space-xs cursor-pointer">
            <span class="material-symbols-outlined text-[18px]">save</span>
            <span>Save Configuration</span>
          </button>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-space-md">
          <!-- Neural Hyperparameters -->
          <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-md">
            <div class="flex items-center gap-space-xs pb-space-xs border-b border-surface-container-highest/30">
              <span class="material-symbols-outlined text-primary text-[20px]">psychology</span>
              <h2 class="font-headline-md text-headline-md text-on-surface font-bold">Neural Inference Hyperparameters</h2>
            </div>

            <!-- Slider 1 -->
            <div class="space-y-1">
              <div class="flex justify-between font-telemetry-sm text-telemetry-sm">
                <span class="text-on-surface font-medium">Trajectory Forecast Confidence Threshold:</span>
                <span class="text-primary font-bold font-mono" id="conf-val">${confThreshold}%</span>
              </div>
              <input id="conf-slider" type="range" min="50" max="95" value="${confThreshold}" class="w-full accent-primary cursor-pointer"/>
              <span class="font-body-sm text-xs text-on-surface-variant">Triggers automated proactive defense warnings when path probability exceeds threshold.</span>
            </div>

            <!-- Slider 2 -->
            <div class="space-y-1">
              <div class="flex justify-between font-telemetry-sm text-telemetry-sm">
                <span class="text-on-surface font-medium">Bayesian Prior Decay Rate (λ):</span>
                <span class="text-secondary font-bold font-mono" id="decay-val">${decayRate}</span>
              </div>
              <input id="decay-slider" type="range" min="0.01" max="0.2" step="0.01" value="${decayRate}" class="w-full accent-secondary cursor-pointer"/>
              <span class="font-body-sm text-xs text-on-surface-variant">Exponential weighting applied to historical threat playbook observation bins.</span>
            </div>

            <!-- Slider 3 -->
            <div class="space-y-1">
              <div class="flex justify-between font-telemetry-sm text-telemetry-sm">
                <span class="text-on-surface font-medium">Default Ephemeral Horizon Window:</span>
                <span class="text-primary font-bold font-mono" id="horizon-val">${horizonMinutes} Minutes</span>
              </div>
              <input id="horizon-slider" type="range" min="3" max="30" value="${horizonMinutes}" class="w-full accent-primary cursor-pointer"/>
              <span class="font-body-sm text-xs text-on-surface-variant">Tactical lead time window computed for proactive firewall/EDR intervention.</span>
            </div>
          </div>

          <!-- Sensor Connectors & Governance -->
          <div class="bg-surface-container-low p-space-md rounded-DEFAULT shadow-md border border-surface-container-high/40 space-y-space-md">
            <div class="flex items-center gap-space-xs pb-space-xs border-b border-surface-container-highest/30">
              <span class="material-symbols-outlined text-primary text-[20px]">sensors</span>
              <h2 class="font-headline-md text-headline-md text-on-surface font-bold">Telemetry Connectors &amp; Audio</h2>
            </div>

            <div class="space-y-space-xs">
              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between">
                <div>
                  <span class="font-headline-md text-sm font-semibold text-on-surface block">CrowdStrike / Microsoft Defender EDR Tap</span>
                  <span class="font-telemetry-sm text-xs text-on-surface-variant">Endpoint process hooks and named pipe surveillance</span>
                </div>
                <span class="bg-primary/20 text-primary font-label-caps text-[9px] px-2 py-1 rounded-DEFAULT font-bold">CONNECTED</span>
              </div>

              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between">
                <div>
                  <span class="font-headline-md text-sm font-semibold text-on-surface block">Core Gigamon / Zeek NDR Network Tap</span>
                  <span class="font-telemetry-sm text-xs text-on-surface-variant">East-West lateral packet mirroring</span>
                </div>
                <span class="bg-primary/20 text-primary font-label-caps text-[9px] px-2 py-1 rounded-DEFAULT font-bold">CONNECTED</span>
              </div>

              <div class="p-space-xs bg-surface-container-lowest rounded-DEFAULT border border-surface-container-highest/30 flex items-center justify-between">
                <div>
                  <span class="font-headline-md text-sm font-semibold text-on-surface block">Tactical Audio Feedback</span>
                  <span class="font-telemetry-sm text-xs text-on-surface-variant">Synthesize radar chirps, alarm beeps, and mitigation chimes</span>
                </div>
                <button id="toggle-audio-settings-btn" class="px-space-sm py-1 rounded-DEFAULT font-telemetry-sm text-telemetry-sm font-bold ${state.soundEnabled ? 'bg-primary text-on-primary' : 'bg-surface-container text-on-surface-variant'}">
                  ${state.soundEnabled ? 'ENABLED' : 'MUTED'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    const confSlider = container.querySelector('#conf-slider');
    const decaySlider = container.querySelector('#decay-slider');
    const horizonSlider = container.querySelector('#horizon-slider');

    if (confSlider) {
      confSlider.addEventListener('input', (e) => {
        confThreshold = e.target.value;
        container.querySelector('#conf-val').textContent = `${confThreshold}%`;
      });
    }

    if (decaySlider) {
      decaySlider.addEventListener('input', (e) => {
        decayRate = e.target.value;
        container.querySelector('#decay-val').textContent = `${decayRate}`;
      });
    }

    if (horizonSlider) {
      horizonSlider.addEventListener('input', (e) => {
        horizonMinutes = e.target.value;
        container.querySelector('#horizon-val').textContent = `${horizonMinutes} Minutes`;
      });
    }

    const audioBtn = container.querySelector('#toggle-audio-settings-btn');
    if (audioBtn) {
      audioBtn.addEventListener('click', () => {
        store.toggleSound();
        update();
      });
    }

    const saveBtn = container.querySelector('#save-settings-btn');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => {
        alert("Platform hyperparameters and telemetry connectors successfully re-indexed.");
      });
    }
  };

  update();
  store.subscribeView(update);
}
