/**
 * Runtime browser version check.
 *
 * Compares the current browser version against minimum versions
 * generated at build time via browserslist('last 1 year, not dead').
 *
 * The MIN_BROWSER_VERSIONS constant is replaced at build time by the Vite
 * define plugin with actual version numbers from browserslist.
 *
 * Supported browsers: Chrome (including Brave, Vivaldi, Arc), Edge, Firefox, Safari, Opera, Samsung Internet.
 * Edge is Chromium-based since v79, so it shares Chrome's version numbering.
 */

// Replaced at build time — see vault vite.config.ts
declare const __MIN_BROWSER_VERSIONS__: Record<string, number>;

interface BrowserInfo {
  name: string;
  version: number;
}

/**
 * Parse the User-Agent string to extract browser name and major version.
 * Returns null if the browser cannot be identified.
 */
function detectBrowser(): BrowserInfo | null {
  const ua = navigator.userAgent;

  // Order matters: check specific browsers before generic Chromium

  // Firefox
  const firefox = ua.match(/Firefox\/(\d+)/);

  if (firefox) {
    return { name: 'firefox', version: parseInt(firefox[1], 10) };
  }

  // Samsung Internet
  const samsung = ua.match(/SamsungBrowser\/(\d+)/);

  if (samsung) {
    return { name: 'samsung', version: parseInt(samsung[1], 10) };
  }

  // Opera (Chromium-based)
  const opera = ua.match(/OPR\/(\d+)/);

  if (opera) {
    return { name: 'opera', version: parseInt(opera[1], 10) };
  }

  // Edge (Chromium-based, v79+)
  const edge = ua.match(/Edg\/(\d+)/);

  if (edge) {
    return { name: 'edge', version: parseInt(edge[1], 10) };
  }

  // Chrome (also matches Brave, Vivaldi, Arc — they all report Chrome/XXX)
  const chrome = ua.match(/Chrome\/(\d+)/);

  if (chrome) {
    return { name: 'chrome', version: parseInt(chrome[1], 10) };
  }

  // Safari (must be after Chrome check — Chrome on macOS also has Safari in UA)
  const safari = ua.match(/Version\/(\d+).*Safari/);

  if (safari) {
    return { name: 'safari', version: parseInt(safari[1], 10) };
  }

  return null;
}

export interface BrowserCheckResult {
  supported: boolean;
  browser: BrowserInfo | null;
  minVersion: number | null;
}

/**
 * Check if the current browser meets the minimum version requirements.
 */
export function checkBrowserVersion(): BrowserCheckResult {
  const browser = detectBrowser();

  if (!browser) {
    // Unknown browser — cannot verify, let it through with a warning
    return { supported: false, browser: null, minVersion: null };
  }

  const minVersions: Record<string, number> = typeof __MIN_BROWSER_VERSIONS__ !== 'undefined' ? __MIN_BROWSER_VERSIONS__ : {};

  const minVersion = minVersions[browser.name] ?? null;

  if (minVersion === null) {
    // Browser not in our list — let it through
    return { supported: true, browser, minVersion: null };
  }

  return {
    supported: browser.version >= minVersion,
    browser,
    minVersion,
  };
}
