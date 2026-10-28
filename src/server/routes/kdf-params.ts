import { DEFAULT_KDF_PARAMS } from '@encryption/src/crypto/vault-unlock';

// KDF params are BOUNDED (not hard-pinned) on every keyring write: they must be at
// least the current standard (so no client can store a weak, cheap-to-brute-force
// vault) and no more than a sane maximum (so a stolen token can't store an
// absurd-cost vault that would DoS a later restore). Bounding rather than pinning
// lets the standard be RAISED over time for new vaults while OLDER vaults keep the
// (still-acceptable) params they were created with — restore uses each vault's OWN
// stored params (see /api/vault/meta -> kdf_variants), never a single constant.
const KDF_MAX_OPS = 10;
const KDF_MAX_MEM = 1024 * 1024 * 1024; // 1 GiB
export const kdfParamsAllowed = (ops: number, mem: number) =>
  ops >= DEFAULT_KDF_PARAMS.opsLimit && ops <= KDF_MAX_OPS && mem >= DEFAULT_KDF_PARAMS.memLimit && mem <= KDF_MAX_MEM;
