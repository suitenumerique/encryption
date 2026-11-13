import { authRoute } from '@encryption/src/server/routes/auth';
import { browserReportsRoute } from '@encryption/src/server/routes/browser-reports';
import { emergencyAccessRoute } from '@encryption/src/server/routes/emergency-access';
import { maintenanceEscrowRoute } from '@encryption/src/server/routes/maintenance-escrow';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import { recoveryCouncilRoute } from '@encryption/src/server/routes/recovery-council';
import { securityTxtRoute } from '@encryption/src/server/routes/security-txt';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { versionRoute } from '@encryption/src/server/routes/versions';

// Every route plugin of the API, registered by the server and audited as one list by
// auth-tiers.test.ts, so a new plugin cannot escape that test.
export const API_ROUTE_PLUGINS = [
  browserReportsRoute,
  securityTxtRoute,
  versionRoute,
  authRoute,
  publicKeysRoute,
  maintenanceEscrowRoute,
  vaultRoute,
  emergencyAccessRoute,
  recoveryCouncilRoute,
];
