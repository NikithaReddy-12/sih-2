import { STAGES } from './workflow.js';

export function isAuthed() {
  try { return sessionStorage.getItem('px-auth') === '1'; } catch { return false; }
}
export function signOut() {
  try { sessionStorage.removeItem('px-auth'); } catch {}
  location.reload();
}

export function renderLogin(container, onSuccess) {
  container.innerHTML = `
    <div class="fixed inset-0 z-[100] bg-surface flex">
      <section class="hidden lg:flex flex-1 flex-col justify-center px-16 bg-surface-container-lowest border-r border-outline-variant/30">
        <h1 class="text-[44px] leading-[1.1] font-semibold tracking-tight text-on-surface max-w-xl">See the attack before it reaches your crown jewels.</h1>
        <p class="mt-4 text-body-lg text-on-surface-variant max-w-md">PREDICT-X turns recorded network behaviour into a forecast, and a forecast into a decision you can approve.</p>
        <ol class="mt-12 space-y-5 max-w-md">
          ${STAGES.map((s, i) => `
            <li class="flex items-center gap-4">
              <span class="w-8 h-8 rounded-full border border-primary-fixed-dim/50 text-primary-fixed-dim flex items-center justify-center text-telemetry-md">${i + 1}</span>
              <div><div class="text-body-lg text-on-surface font-medium">${s.label}</div><div class="text-body-sm text-on-surface-variant">${s.hint}</div></div>
            </li>`).join('')}
        </ol>
      </section>
      <section class="flex-1 flex items-center justify-center p-8">
        <form id="login-form" class="w-full max-w-sm" novalidate>
          <h2 class="text-headline-lg text-on-surface">Sign in</h2>
          <p class="text-body-md text-on-surface-variant mt-1 mb-8">Use your analyst account to open the console.</p>
          <label class="block text-body-sm text-on-surface-variant mb-1" for="lg-user">Username</label>
          <input id="lg-user" autocomplete="username" value="analyst" class="w-full mb-4 px-3 py-2.5 bg-surface-container-low border border-outline-variant rounded-lg text-body-md text-on-surface focus:border-primary-container" />
          <label class="block text-body-sm text-on-surface-variant mb-1" for="lg-pass">Password</label>
          <input id="lg-pass" type="password" autocomplete="current-password" value="predictx" class="w-full mb-2 px-3 py-2.5 bg-surface-container-low border border-outline-variant rounded-lg text-body-md text-on-surface focus:border-primary-container" />
          <p id="lg-err" class="text-body-sm text-error h-5" role="alert"></p>
          <button type="submit" class="mt-4 w-full py-2.5 rounded-lg bg-primary-container text-on-primary-container text-body-md font-semibold hover:brightness-110 transition">Sign in</button>
          <p class="mt-4 text-body-sm text-on-surface-variant">Demo account is pre-filled.</p>
          <p class="mt-1 text-body-sm text-on-surface-variant">Demo sign-in only: a front-end screen, not real authentication.</p>
        </form>
      </section>
    </div>`;

  container.querySelector('#login-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const u = container.querySelector('#lg-user').value.trim();
    const p = container.querySelector('#lg-pass').value;
    if (!u || !p) { container.querySelector('#lg-err').textContent = 'Enter a username and password.'; return; }
    try { sessionStorage.setItem('px-auth', '1'); } catch {}
    container.innerHTML = '';
    onSuccess();
  });
}
