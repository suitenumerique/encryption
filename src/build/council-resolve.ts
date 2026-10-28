/**
 * The internal user id to write in RECOVERY_COUNCILS for a custodian, from their
 * email: `npm run council:resolve -- rssi@numerique.gouv.fr`.
 *
 * Only users who signed in at least once exist. An address held by several
 * accounts over time is listed with each, the most recent first, and whether
 * that account has set up encryption (a custodian must have, to be pinned).
 */
import { prisma } from '@encryption/src/prisma/client';

async function main() {
  const email = process.argv[2]?.trim().toLowerCase();

  if (!email) {
    console.error('Usage: npm run council:resolve -- <email>');
    process.exit(2);
  }

  const users = await prisma.user.findMany({ where: { email }, orderBy: { updatedAt: 'desc' } });

  if (users.length === 0) {
    console.error(`No account with the email ${email}: the person must sign in to the encryption service once.`);
    process.exit(1);
  }

  for (const user of users) {
    const identity = await prisma.identity.findFirst({ where: { userId: user.id, disabledAt: null } });
    console.log(`${user.id}  ${identity ? 'encryption set up' : 'encryption NOT set up yet'}  (last updated ${user.updatedAt.toISOString()})`);
  }

  console.log(`\n{ "userId": "${users[0].id}", "email": "${email}" }`);
  await prisma.$disconnect();
}

void main();
