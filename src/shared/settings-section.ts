// The flows a product may open directly, one at a time, from its own account page
// (`openSettings(section)` in the SDK, `/settings/<section>` in the interface).
// Without a section the interface shows its own encryption home, which leads to
// the same flows. Spelled out as a union (not derived from the list) so the
// SDK's published declaration carries the names themselves.
export type SettingsSection =
  | 'manage'
  | 'add-device'
  | 'verification-code'
  | 'recovery-phrase'
  | 'trusted-contacts'
  | 'recovery-council'
  | 'custodian';

export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  'manage',
  'add-device',
  'verification-code',
  'recovery-phrase',
  'trusted-contacts',
  'recovery-council',
  'custodian',
];

export function isSettingsSection(value: string): value is SettingsSection {
  return (SETTINGS_SECTIONS as readonly string[]).includes(value);
}
