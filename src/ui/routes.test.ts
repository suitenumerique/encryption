import { describe, expect, it } from 'vitest';

import { PATH_FOR_ROUTE, getRouteFromPath, getSettingsSectionFromPath } from '@encryption/src/ui/routes';

describe('interface routes', () => {
  it('maps /verify-recipients to the verify-recipients route', () => {
    expect(getRouteFromPath('/verify-recipients')).toBe('verify-recipients');
  });

  it('maps /recipient-profile to the recipient-profile route', () => {
    expect(getRouteFromPath('/recipient-profile')).toBe('recipient-profile');
  });

  it('maps /emergency-access to the emergency-access route', () => {
    expect(getRouteFromPath('/emergency-access')).toBe('emergency-access');
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

  it('exposes a navigable path for emergency-access', () => {
    expect(PATH_FOR_ROUTE['emergency-access']).toBe('/emergency-access');
  });

  it('maps the recovery council screens, opened on their own or as a settings section', () => {
    expect(getRouteFromPath('/recovery-council')).toBe('recovery-council');
    expect(getRouteFromPath('/council-custodian')).toBe('council-custodian');
    expect(getSettingsSectionFromPath('/settings/recovery-council')).toBe('recovery-council');
    expect(getSettingsSectionFromPath('/settings/custodian')).toBe('custodian');
  });

  it('maps a settings section to the settings route and its section', () => {
    expect(getRouteFromPath('/settings/manage')).toBe('settings');
    expect(getSettingsSectionFromPath('/settings/manage')).toBe('manage');
    expect(getSettingsSectionFromPath('/settings/trusted-contacts')).toBe('trusted-contacts');
    expect(getSettingsSectionFromPath('/settings')).toBeNull();
  });

  it('refuses an unknown settings section', () => {
    expect(getRouteFromPath('/settings/nope')).toBeNull();
    expect(getSettingsSectionFromPath('/settings/nope')).toBeNull();
  });
});
