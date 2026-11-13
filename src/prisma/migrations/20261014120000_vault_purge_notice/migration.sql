-- AlterTable
ALTER TABLE "vault_keyring" ADD COLUMN     "purge_notice_at" TIMESTAMP(3),
ADD COLUMN     "purge_scheduled_at" TIMESTAMP(3);
