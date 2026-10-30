/**
 * Build-time script to generate minimum browser versions from browserslist.
 * Used by the vault Vite config to inject __MIN_BROWSER_VERSIONS__ at build time.
 */
import browserslist from 'browserslist';

// Map browserslist browser names to our runtime detection names
const BROWSER_NAME_MAP: Record<string, string> = {
  chrome: 'chrome',
  edge: 'edge',
  firefox: 'firefox',
  safari: 'safari',
  opera: 'opera',
  samsung: 'samsung',
};

export function getMinBrowserVersions(): Record<string, number> {
  const result = browserslist('last 1 year, not dead');
  const minVersions: Record<string, number> = {};

  for (const entry of result) {
    const [browserslistName, version] = entry.split(' ');
    const ourName = BROWSER_NAME_MAP[browserslistName];

    if (!ourName) continue;

    const majorVersion = Math.floor(parseFloat(version));

    if (!minVersions[ourName] || majorVersion < minVersions[ourName]) {
      minVersions[ourName] = majorVersion;
    }
  }

  return minVersions;
}
