import { brandLogoMarkup } from './BrandLogo.js';

export function renderLanding(container, onOpen) {
  container.innerHTML = `
    <main class="min-h-screen bg-surface text-on-surface flex flex-col items-center justify-center px-space-md py-space-lg">
      <section class="w-full max-w-3xl flex flex-col items-center text-center">
        <div class="text-primary mb-space-md">${brandLogoMarkup('h-20 w-20')}</div>
        <h1 class="font-headline-lg text-[clamp(3rem,10vw,6rem)] leading-none text-on-surface font-bold tracking-[0.12em]">PREDICT-X</h1>
        <p class="font-headline-md text-headline-md text-on-surface-variant mt-space-sm">Forecast host-level attacks before they complete</p>
        <div class="mt-space-lg space-y-space-xs font-body-md text-on-surface-variant">
          <p>Learns how each host's behaviour evolves</p>
          <p>Forecasts the next five minutes with a MITRE stage</p>
          <p>Explains every flag, fully offline</p>
        </div>
        <button id="open-console" type="button" class="mt-space-lg px-space-lg py-space-sm rounded-DEFAULT bg-primary-container text-on-primary-container font-body-md font-semibold hover:brightness-110 transition">
          Open console
        </button>
      </section>
      <footer class="mt-auto pt-space-lg font-telemetry-sm text-telemetry-sm text-on-surface-variant text-center">
        Prototype - offline - CSE-CIC-IDS2018 (NetFlow-V3)
      </footer>
    </main>`;

  container.querySelector('#open-console').addEventListener('click', onOpen);
}
