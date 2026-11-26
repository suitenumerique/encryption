import path from 'node:path';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: path.join(__dirname, 'src/prisma/schema.prisma'),
  migrations: {
    path: path.join(__dirname, 'src/prisma/migrations'),
    seed: 'tsx src/prisma/seed.script.ts',
  },
  datasource: {
    url: process.env.DATABASE_URL ?? '',
  },
});
