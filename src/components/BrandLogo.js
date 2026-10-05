export function brandLogoMarkup(className = 'h-12 w-12') {
  return `
    <svg class="${className}" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="PREDICT-X shield radar logo">
      <path d="M44 9a27 27 0 0 1 11 11M48 3a35 35 0 0 1 14 14" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
      <path d="M28 10 46 17v13c0 12-7.4 21.1-18 27-10.6-5.9-18-15-18-27V17l18-7Z" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>
      <path d="M20 31h17m-7-7 7 7-7 7" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}
