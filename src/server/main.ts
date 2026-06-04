import { env } from '@encryption/src/server/env';
import { createServer } from '@encryption/src/server/server';

async function main() {
  const app = await createServer();

  app.listen({ port: env.PORT, host: env.HOST }, (err, address) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }

    app.log.info(`Server listening at ${address}`);
    app.log.info(`Vault: ${env.VAULT_URL}`);
    app.log.info(`UI: ${env.UI_URL}`);
  });
}

main();
