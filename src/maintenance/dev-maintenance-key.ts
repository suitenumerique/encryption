/**
 * The DEVELOPMENT maintenance key, committed on purpose: `.env.test` configures its
 * public key, so documents created in the demo products carry a `maintenanceKey`
 * that this phrase opens in the maintenance tool. A fixture, never for a real
 * deployment: anyone can read it here, and the server refuses its public key
 * (`dev-maintenance-public-keys.ts`) in production.
 */
export const DEV_MAINTENANCE_PHRASE =
  'février dossier silence panorama défrayer trafic déphaser économie aubaine coder abriter intuitif planer offenser livreur pinceau adroit hurler panache soigneux adverbe avouer réanimer odeur';

/**
 * A second development key, the one rotation tests move the copies to (the tool's
 * tests, and the products' recovery fixtures). Never configured anywhere: it stands
 * for an organization's next key.
 */
export const DEV_NEXT_MAINTENANCE_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
