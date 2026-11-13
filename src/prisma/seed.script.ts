import { cleanup, seed } from '@encryption/src/prisma/seed';

seed()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await cleanup();
  });
