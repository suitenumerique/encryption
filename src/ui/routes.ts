// Interface routes and the path<->route mapping, kept free of React and design
// system imports so the routing can be unit-tested without pulling the whole app.
import { type SettingsSection, isSettingsSection } from '@encryption/src/shared/settings-section';

export type Route =
  | 'onboarding'
  | 'backup'
  | 'restore'
  | 'settings'
  | 'emergency-access'
  | 'recovery-council'
  | 'council-custodian'
  | 'council-request'
  | 'device-approval'
  | 'verify-recipients'
  | 'recipient-profile'
  | 'docs-user'
  | 'docs-technical'
  | 'login'
  | 'auth-callback';

export function getRouteFromPath(path: string): Route | null {
  const routes: Record<string, Route> = {
    '/onboarding': 'onboarding',
    '/backup': 'backup',
    '/restore': 'restore',
    '/settings': 'settings',
    '/emergency-access': 'emergency-access',
    '/recovery-council': 'recovery-council',
    '/council-custodian': 'council-custodian',
    '/council-request': 'council-request',
    '/device-approval': 'device-approval',
    '/verify-recipients': 'verify-recipients',
    '/recipient-profile': 'recipient-profile',
    '/docs': 'docs-user',
    '/docs/user': 'docs-user',
    '/docs/technical': 'docs-technical',
    '/login': 'login',
    '/auth/callback': 'auth-callback',
  };

  if (routes[path]) return routes[path];

  return getSettingsSectionFromPath(path) ? 'settings' : null;
}

/** The single flow a product opened (`/settings/<section>`), or null for the encryption home. */
export function getSettingsSectionFromPath(path: string): SettingsSection | null {
  const match = /^\/settings\/([a-z-]+)$/.exec(path);

  return match && isSettingsSection(match[1]) ? match[1] : null;
}

// Primary path for a route, for real in-app navigation (pushState). Only the
// interface routes we navigate to programmatically need an entry here.
export const PATH_FOR_ROUTE: Partial<Record<Route, string>> = {
  onboarding: '/onboarding',
  backup: '/backup',
  restore: '/restore',
  settings: '/settings',
  'emergency-access': '/emergency-access',
  'recovery-council': '/recovery-council',
  'council-custodian': '/council-custodian',
  'council-request': '/council-request',
  'device-approval': '/device-approval',
  'verify-recipients': '/verify-recipients',
  'recipient-profile': '/recipient-profile',
};
