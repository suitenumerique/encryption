// Interface routes and the path<->route mapping, kept free of React/Cunningham
// imports so the routing can be unit-tested without pulling the whole app.

export type Route =
  | 'onboarding'
  | 'backup'
  | 'restore'
  | 'settings'
  | 'emergency-access'
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
    '/device-approval': 'device-approval',
    '/verify-recipients': 'verify-recipients',
    '/recipient-profile': 'recipient-profile',
    '/docs': 'docs-user',
    '/docs/user': 'docs-user',
    '/docs/technical': 'docs-technical',
    '/login': 'login',
    '/auth/callback': 'auth-callback',
  };

  return routes[path] ?? null;
}

// Primary path for a route, for real in-app navigation (pushState). Only the
// interface routes we navigate to programmatically need an entry here.
export const PATH_FOR_ROUTE: Partial<Record<Route, string>> = {
  onboarding: '/onboarding',
  backup: '/backup',
  restore: '/restore',
  settings: '/settings',
  'emergency-access': '/emergency-access',
  'device-approval': '/device-approval',
  'verify-recipients': '/verify-recipients',
  'recipient-profile': '/recipient-profile',
};
