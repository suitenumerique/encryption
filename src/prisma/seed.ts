import { prisma } from '@encryption/src/prisma/client';

export async function seed() {
  console.log('Seeding database...');

  // No seed data needed for now - public keys are created by users

  console.log('Database seeded successfully.');
}

export async function cleanup() {
  await prisma.$disconnect();
}
