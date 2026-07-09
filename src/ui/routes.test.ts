import { PATH_FOR_ROUTE, getRouteFromPath } from '@encryption/src/ui/routes';

describe('interface routes', () => {
  it('maps /verify-recipients to the verify-recipients route', () => {
    expect(getRouteFromPath('/verify-recipients')).toBe('verify-recipients');
  });

  it('maps /recipient-profile to the recipient-profile route', () => {
    expect(getRouteFromPath('/recipient-profile')).toBe('recipient-profile');
  });

  it('maps the other known interface paths', () => {
    expect(getRouteFromPath('/onboarding')).toBe('onboarding');
    expect(getRouteFromPath('/device-approval')).toBe('device-approval');
    expect(getRouteFromPath('/settings')).toBe('settings');
  });

  it('returns null for an unknown path', () => {
    expect(getRouteFromPath('/nope')).toBeNull();
  });

  it('exposes a navigable path for verify-recipients', () => {
    expect(PATH_FOR_ROUTE['verify-recipients']).toBe('/verify-recipients');
  });

  it('exposes a navigable path for recipient-profile', () => {
    expect(PATH_FOR_ROUTE['recipient-profile']).toBe('/recipient-profile');
  });
});
