-- CreateTable
CREATE TABLE "auth_relays" (
    "state" TEXT NOT NULL,
    "code_challenge" TEXT NOT NULL,
    "relay_id" TEXT,
    "code" TEXT,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_relays_pkey" PRIMARY KEY ("state")
);

-- CreateIndex
CREATE UNIQUE INDEX "auth_relays_relay_id_key" ON "auth_relays"("relay_id");

-- CreateIndex
CREATE INDEX "auth_relays_expires_at_idx" ON "auth_relays"("expires_at");
