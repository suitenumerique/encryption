import { PrismaPg } from '@prisma/adapter-pg';

import { PrismaClient } from '@encryption/src/generated/prisma/client';
import { databaseSchema } from '@encryption/src/prisma/database-schema';

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
