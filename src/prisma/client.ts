import { PrismaPg } from '@prisma/adapter-pg';

import { PrismaClient } from '@encryption/src/generated/prisma/client';

/**
 * The PostgreSQL schema the tables live in, read from the `?schema=` parameter of
 * the connection string, as the migration tooling reads it. Deployments put it
 * in a dedicated schema (see README); a local database can simply use `public`.
 */
export function databaseSchema(databaseUrl: string | undefined): string {
  // No URL means no database in this process (unit tests import route modules
  // without one): the client is created lazily and never connects.
  if (!databaseUrl) return 'public';

  return new URL(databaseUrl).searchParams.get('schema') ?? 'public';
}

function createPrismaClient(): PrismaClient {
  const url = process.env.DATABASE_URL;
  const adapter = new PrismaPg({ connectionString: url }, { schema: databaseSchema(url) });

  return new PrismaClient({
    adapter,
    log: process.env.NODE_ENV === 'production' ? ['error'] : ['error', 'warn'],
  });
}

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;
