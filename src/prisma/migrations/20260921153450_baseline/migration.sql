-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "encryption";

-- CreateEnum
CREATE TYPE "encryption"."SignatureAlgo" AS ENUM ('ed25519');

-- CreateEnum
CREATE TYPE "encryption"."EncryptionAlgo" AS ENUM ('x-wing');

-- CreateEnum
CREATE TYPE "encryption"."VaultItemType" AS ENUM ('identity', 'encryptionKey', 'tofu', 'active');

-- CreateEnum
CREATE TYPE "encryption"."VaultCredentialType" AS ENUM ('primary', 'emergency');

-- CreateEnum
CREATE TYPE "encryption"."EmergencyAccessStatus" AS ENUM ('invited', 'confirmed', 'recovery_requested', 'recovery_approved');

-- CreateTable
CREATE TABLE "encryption"."users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "language" TEXT NOT NULL DEFAULT 'en',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."oidc_accounts" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "disabled_at" TIMESTAMP(3),

    CONSTRAINT "oidc_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."identities" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "signature_public_key" BYTEA NOT NULL,
    "algo" "encryption"."SignatureAlgo" NOT NULL DEFAULT 'ed25519',
    "generation" INTEGER NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "disabled_at" TIMESTAMP(3),
    "previous_identity_id" UUID,
    "continuity_signature" BYTEA,

    CONSTRAINT "identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."encryption_keys" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "identity_id" UUID NOT NULL,
    "encryption_public_key" BYTEA NOT NULL,
    "algo" "encryption"."EncryptionAlgo" NOT NULL DEFAULT 'x-wing',
    "key_binding_signature" BYTEA NOT NULL,
    "version" INTEGER NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "disabled_at" TIMESTAMP(3),

    CONSTRAINT "encryption_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."key_possession_challenges" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "encryption_public_key" BYTEA NOT NULL,
    "signature_public_key" BYTEA NOT NULL,
    "key_binding_signature" BYTEA NOT NULL,
    "version" INTEGER NOT NULL,
    "signed_created_at" TIMESTAMP(3) NOT NULL,
    "expected_hmac" BYTEA NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "key_possession_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_items" (
    "id" UUID NOT NULL,
    "vault_id" UUID NOT NULL,
    "item_id" TEXT NOT NULL,
    "type" "encryption"."VaultItemType" NOT NULL,
    "ciphertext" TEXT NOT NULL,
    "revision_date" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_meta" (
    "vault_id" UUID NOT NULL,
    "account_revision" INTEGER NOT NULL DEFAULT 0,
    "manifest" TEXT NOT NULL,
    "manifest_sig" BYTEA NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_meta_pkey" PRIMARY KEY ("vault_id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_keyring" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "identity_id" UUID NOT NULL,
    "disabled_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_keyring_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_credentials" (
    "id" UUID NOT NULL,
    "vault_id" UUID NOT NULL,
    "type" "encryption"."VaultCredentialType" NOT NULL,
    "wrapped_vrk" TEXT NOT NULL,
    "auth_public_key" BYTEA NOT NULL,
    "auth_pub_sig" BYTEA NOT NULL,
    "kdf_ops" INTEGER NOT NULL,
    "kdf_mem" INTEGER NOT NULL,
    "lang" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."emergency_access" (
    "id" UUID NOT NULL,
    "grantor_user_id" UUID NOT NULL,
    "grantee_user_id" UUID NOT NULL,
    "status" "encryption"."EmergencyAccessStatus" NOT NULL,
    "wait_time_days" INTEGER NOT NULL,
    "credential_id" UUID NOT NULL,
    "wrapped_phrase_for_grantee" TEXT NOT NULL,
    "grantee_identity_id" UUID NOT NULL,
    "grantee_key_version" INTEGER NOT NULL,
    "escrow_signature" BYTEA NOT NULL,
    "escrow_created_at" TIMESTAMP(3) NOT NULL,
    "recovery_requested_at" TIMESTAMP(3),
    "last_notified_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "emergency_access_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_challenges" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "nonce" BYTEA NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption"."vault_approvals" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "request_id" TEXT NOT NULL,
    "device_public_key" TEXT NOT NULL,
    "wrapped_vrk_for_device" TEXT,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "oidc_accounts_user_id_idx" ON "encryption"."oidc_accounts"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_accounts_issuer_subject_key" ON "encryption"."oidc_accounts"("issuer", "subject");

-- CreateIndex
CREATE UNIQUE INDEX "identities_signature_public_key_key" ON "encryption"."identities"("signature_public_key");

-- CreateIndex
CREATE INDEX "identities_user_id_disabled_at_idx" ON "encryption"."identities"("user_id", "disabled_at");

-- CreateIndex
CREATE UNIQUE INDEX "identities_user_id_generation_key" ON "encryption"."identities"("user_id", "generation");

-- CreateIndex
CREATE UNIQUE INDEX "encryption_keys_encryption_public_key_key" ON "encryption"."encryption_keys"("encryption_public_key");

-- CreateIndex
CREATE INDEX "encryption_keys_user_id_disabled_at_idx" ON "encryption"."encryption_keys"("user_id", "disabled_at");

-- CreateIndex
CREATE INDEX "encryption_keys_user_id_created_at_idx" ON "encryption"."encryption_keys"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "encryption_keys_identity_id_idx" ON "encryption"."encryption_keys"("identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "encryption_keys_user_id_version_key" ON "encryption"."encryption_keys"("user_id", "version");

-- CreateIndex
CREATE INDEX "key_possession_challenges_user_id_idx" ON "encryption"."key_possession_challenges"("user_id");

-- CreateIndex
CREATE INDEX "key_possession_challenges_expires_at_idx" ON "encryption"."key_possession_challenges"("expires_at");

-- CreateIndex
CREATE INDEX "vault_items_vault_id_idx" ON "encryption"."vault_items"("vault_id");

-- CreateIndex
CREATE UNIQUE INDEX "vault_items_vault_id_item_id_key" ON "encryption"."vault_items"("vault_id", "item_id");

-- CreateIndex
CREATE INDEX "vault_keyring_user_id_idx" ON "encryption"."vault_keyring"("user_id");

-- CreateIndex
CREATE INDEX "vault_keyring_user_id_disabled_at_idx" ON "encryption"."vault_keyring"("user_id", "disabled_at");

-- CreateIndex
CREATE INDEX "vault_credentials_vault_id_idx" ON "encryption"."vault_credentials"("vault_id");

-- CreateIndex
CREATE UNIQUE INDEX "emergency_access_credential_id_key" ON "encryption"."emergency_access"("credential_id");

-- CreateIndex
CREATE INDEX "emergency_access_grantee_user_id_idx" ON "encryption"."emergency_access"("grantee_user_id");

-- CreateIndex
CREATE INDEX "emergency_access_grantee_identity_id_idx" ON "encryption"."emergency_access"("grantee_identity_id");

-- CreateIndex
CREATE INDEX "emergency_access_status_recovery_requested_at_idx" ON "encryption"."emergency_access"("status", "recovery_requested_at");

-- CreateIndex
CREATE UNIQUE INDEX "emergency_access_grantor_user_id_grantee_user_id_key" ON "encryption"."emergency_access"("grantor_user_id", "grantee_user_id");

-- CreateIndex
CREATE INDEX "vault_challenges_user_id_idx" ON "encryption"."vault_challenges"("user_id");

-- CreateIndex
CREATE INDEX "vault_challenges_expires_at_idx" ON "encryption"."vault_challenges"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "vault_approvals_request_id_key" ON "encryption"."vault_approvals"("request_id");

-- CreateIndex
CREATE INDEX "vault_approvals_user_id_idx" ON "encryption"."vault_approvals"("user_id");

-- CreateIndex
CREATE INDEX "vault_approvals_expires_at_idx" ON "encryption"."vault_approvals"("expires_at");

-- AddForeignKey
ALTER TABLE "encryption"."oidc_accounts" ADD CONSTRAINT "oidc_accounts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."identities" ADD CONSTRAINT "identities_previous_identity_id_fkey" FOREIGN KEY ("previous_identity_id") REFERENCES "encryption"."identities"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."identities" ADD CONSTRAINT "identities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."encryption_keys" ADD CONSTRAINT "encryption_keys_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."encryption_keys" ADD CONSTRAINT "encryption_keys_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "encryption"."identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."key_possession_challenges" ADD CONSTRAINT "key_possession_challenges_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_items" ADD CONSTRAINT "vault_items_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "encryption"."vault_keyring"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_meta" ADD CONSTRAINT "vault_meta_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "encryption"."vault_keyring"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_keyring" ADD CONSTRAINT "vault_keyring_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_keyring" ADD CONSTRAINT "vault_keyring_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "encryption"."identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_credentials" ADD CONSTRAINT "vault_credentials_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "encryption"."vault_keyring"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."emergency_access" ADD CONSTRAINT "emergency_access_grantor_user_id_fkey" FOREIGN KEY ("grantor_user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."emergency_access" ADD CONSTRAINT "emergency_access_grantee_user_id_fkey" FOREIGN KEY ("grantee_user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."emergency_access" ADD CONSTRAINT "emergency_access_grantee_identity_id_fkey" FOREIGN KEY ("grantee_identity_id") REFERENCES "encryption"."identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."emergency_access" ADD CONSTRAINT "emergency_access_credential_id_fkey" FOREIGN KEY ("credential_id") REFERENCES "encryption"."vault_credentials"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_challenges" ADD CONSTRAINT "vault_challenges_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "encryption"."vault_approvals" ADD CONSTRAINT "vault_approvals_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "encryption"."users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

