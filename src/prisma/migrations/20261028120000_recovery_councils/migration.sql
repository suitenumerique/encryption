-- CreateEnum
CREATE TYPE "CouncilRosterStatus" AS ENUM ('proposed', 'active', 'superseded');

-- CreateEnum
CREATE TYPE "CouncilRequestStatus" AS ENUM ('open', 'released', 'completed', 'aborted');

-- CreateEnum
CREATE TYPE "CouncilReshareStatus" AS ENUM ('open', 'completed', 'cancelled');

-- AlterEnum
ALTER TYPE "VaultCredentialType" ADD VALUE 'council';

-- CreateTable
CREATE TABLE "council_roster_versions" (
    "id" UUID NOT NULL,
    "council_id" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "threshold" INTEGER NOT NULL,
    "status" "CouncilRosterStatus" NOT NULL,
    "previous_roster_hash" BYTEA NOT NULL,
    "roster_hash" BYTEA NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "activated_at" TIMESTAMP(3),

    CONSTRAINT "council_roster_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_roster_members" (
    "id" UUID NOT NULL,
    "roster_version_id" UUID NOT NULL,
    "slot" INTEGER NOT NULL,
    "user_id" UUID NOT NULL,
    "identity_id" UUID NOT NULL,

    CONSTRAINT "council_roster_members_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_roster_signatures" (
    "id" UUID NOT NULL,
    "roster_version_id" UUID NOT NULL,
    "identity_id" UUID NOT NULL,
    "signature" BYTEA NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "council_roster_signatures_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_escrows" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "council_id" TEXT NOT NULL,
    "credential_id" UUID NOT NULL,
    "roster_version_id" UUID NOT NULL,
    "threshold" INTEGER NOT NULL,
    "generation" INTEGER NOT NULL DEFAULT 1,
    "signed_roster_version_id" UUID NOT NULL,
    "signed_threshold" INTEGER NOT NULL,
    "signed_shares" JSONB NOT NULL,
    "signed_commitments" BYTEA NOT NULL,
    "commitments" BYTEA NOT NULL,
    "secret_commitment" BYTEA NOT NULL,
    "escrow_signature" BYTEA NOT NULL,
    "escrow_created_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "council_escrows_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_capsules" (
    "id" UUID NOT NULL,
    "escrow_id" UUID NOT NULL,
    "generation" INTEGER NOT NULL,
    "slot" INTEGER NOT NULL,
    "identity_id" UUID NOT NULL,
    "wrapped_share" TEXT,
    "session_id" UUID,
    "checked_at" TIMESTAMP(3),
    "invalid" BOOLEAN NOT NULL DEFAULT false,
    "faulty_helper_slot" INTEGER,

    CONSTRAINT "council_capsules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_requests" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "escrow_id" UUID NOT NULL,
    "ephemeral_public_key" BYTEA NOT NULL,
    "status" "CouncilRequestStatus" NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "released_at" TIMESTAMP(3),
    "closed_at" TIMESTAMP(3),

    CONSTRAINT "council_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_contributions" (
    "id" UUID NOT NULL,
    "request_id" UUID NOT NULL,
    "slot" INTEGER NOT NULL,
    "custodian_identity_id" UUID NOT NULL,
    "wrapped_share" TEXT NOT NULL,
    "in_person" BOOLEAN NOT NULL,
    "signature" BYTEA NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "council_contributions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_reshare_sessions" (
    "id" UUID NOT NULL,
    "council_id" TEXT NOT NULL,
    "source_roster_version_id" UUID NOT NULL,
    "target_roster_version_id" UUID NOT NULL,
    "helper_slots" INTEGER[],
    "status" "CouncilReshareStatus" NOT NULL,
    "created_by_user_id" UUID NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closed_at" TIMESTAMP(3),

    CONSTRAINT "council_reshare_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_reshare_keys" (
    "id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "helper_slot" INTEGER NOT NULL,
    "recipient_slot" INTEGER NOT NULL,
    "wrapped_transfer_key" TEXT NOT NULL,
    "signature" BYTEA NOT NULL,

    CONSTRAINT "council_reshare_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_subshares" (
    "id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "escrow_id" UUID NOT NULL,
    "helper_slot" INTEGER NOT NULL,
    "recipient_slot" INTEGER NOT NULL,
    "sealed" TEXT NOT NULL,

    CONSTRAINT "council_subshares_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "council_reshare_commitments" (
    "id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "escrow_id" UUID NOT NULL,
    "helper_slot" INTEGER NOT NULL,
    "commitments" BYTEA NOT NULL,
    "signature" BYTEA NOT NULL,

    CONSTRAINT "council_reshare_commitments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "council_roster_versions_council_id_status_idx" ON "council_roster_versions"("council_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "council_roster_versions_council_id_version_key" ON "council_roster_versions"("council_id", "version");

-- CreateIndex
CREATE INDEX "council_roster_members_user_id_idx" ON "council_roster_members"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_roster_members_roster_version_id_slot_key" ON "council_roster_members"("roster_version_id", "slot");

-- CreateIndex
CREATE UNIQUE INDEX "council_roster_members_roster_version_id_user_id_key" ON "council_roster_members"("roster_version_id", "user_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_roster_signatures_roster_version_id_identity_id_key" ON "council_roster_signatures"("roster_version_id", "identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_escrows_credential_id_key" ON "council_escrows"("credential_id");

-- CreateIndex
CREATE INDEX "council_escrows_user_id_idx" ON "council_escrows"("user_id");

-- CreateIndex
CREATE INDEX "council_escrows_council_id_roster_version_id_idx" ON "council_escrows"("council_id", "roster_version_id");

-- CreateIndex
CREATE INDEX "council_capsules_identity_id_idx" ON "council_capsules"("identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_capsules_escrow_id_generation_slot_key" ON "council_capsules"("escrow_id", "generation", "slot");

-- CreateIndex
CREATE INDEX "council_requests_user_id_status_idx" ON "council_requests"("user_id", "status");

-- CreateIndex
CREATE INDEX "council_requests_escrow_id_status_idx" ON "council_requests"("escrow_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "council_contributions_request_id_slot_key" ON "council_contributions"("request_id", "slot");

-- CreateIndex
CREATE INDEX "council_reshare_sessions_council_id_status_idx" ON "council_reshare_sessions"("council_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "council_reshare_keys_session_id_helper_slot_recipient_slot_key" ON "council_reshare_keys"("session_id", "helper_slot", "recipient_slot");

-- CreateIndex
CREATE INDEX "council_subshares_escrow_id_idx" ON "council_subshares"("escrow_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_subshares_session_id_escrow_id_helper_slot_recipien_key" ON "council_subshares"("session_id", "escrow_id", "helper_slot", "recipient_slot");

-- CreateIndex
CREATE INDEX "council_reshare_commitments_escrow_id_idx" ON "council_reshare_commitments"("escrow_id");

-- CreateIndex
CREATE UNIQUE INDEX "council_reshare_commitments_session_id_escrow_id_helper_slo_key" ON "council_reshare_commitments"("session_id", "escrow_id", "helper_slot");

-- AddForeignKey
ALTER TABLE "council_roster_members" ADD CONSTRAINT "council_roster_members_roster_version_id_fkey" FOREIGN KEY ("roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_roster_members" ADD CONSTRAINT "council_roster_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_roster_members" ADD CONSTRAINT "council_roster_members_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_roster_signatures" ADD CONSTRAINT "council_roster_signatures_roster_version_id_fkey" FOREIGN KEY ("roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_roster_signatures" ADD CONSTRAINT "council_roster_signatures_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_escrows" ADD CONSTRAINT "council_escrows_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_escrows" ADD CONSTRAINT "council_escrows_credential_id_fkey" FOREIGN KEY ("credential_id") REFERENCES "vault_credentials"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_escrows" ADD CONSTRAINT "council_escrows_roster_version_id_fkey" FOREIGN KEY ("roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_escrows" ADD CONSTRAINT "council_escrows_signed_roster_version_id_fkey" FOREIGN KEY ("signed_roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_capsules" ADD CONSTRAINT "council_capsules_escrow_id_fkey" FOREIGN KEY ("escrow_id") REFERENCES "council_escrows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_capsules" ADD CONSTRAINT "council_capsules_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_capsules" ADD CONSTRAINT "council_capsules_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "council_reshare_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_requests" ADD CONSTRAINT "council_requests_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_requests" ADD CONSTRAINT "council_requests_escrow_id_fkey" FOREIGN KEY ("escrow_id") REFERENCES "council_escrows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_contributions" ADD CONSTRAINT "council_contributions_request_id_fkey" FOREIGN KEY ("request_id") REFERENCES "council_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_contributions" ADD CONSTRAINT "council_contributions_custodian_identity_id_fkey" FOREIGN KEY ("custodian_identity_id") REFERENCES "identities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_reshare_sessions" ADD CONSTRAINT "council_reshare_sessions_source_roster_version_id_fkey" FOREIGN KEY ("source_roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_reshare_sessions" ADD CONSTRAINT "council_reshare_sessions_target_roster_version_id_fkey" FOREIGN KEY ("target_roster_version_id") REFERENCES "council_roster_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_reshare_keys" ADD CONSTRAINT "council_reshare_keys_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "council_reshare_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_subshares" ADD CONSTRAINT "council_subshares_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "council_reshare_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_subshares" ADD CONSTRAINT "council_subshares_escrow_id_fkey" FOREIGN KEY ("escrow_id") REFERENCES "council_escrows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_reshare_commitments" ADD CONSTRAINT "council_reshare_commitments_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "council_reshare_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "council_reshare_commitments" ADD CONSTRAINT "council_reshare_commitments_escrow_id_fkey" FOREIGN KEY ("escrow_id") REFERENCES "council_escrows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

