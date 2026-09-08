import { z } from 'zod';

import '@encryption/src/shared/zod-jitless';

// The BIP-39 wordlist language of the recovery phrase: which language the
// mnemonic words are drawn from, not the interface locale. Single source of
// truth for every `lang` field that crosses the vault post-message boundary,
// so the wire schema and the crypto-side type can never drift apart.
export const mnemonicLanguageSchema = z.enum(['french', 'english']);

export type MnemonicLanguage = z.infer<typeof mnemonicLanguageSchema>;
