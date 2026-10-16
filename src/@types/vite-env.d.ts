/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ALLOWED_ORIGINS?: string;
  readonly VITE_INTERFACE_ORIGIN?: string;
  readonly VITE_VAULT_URL?: string;
  /** Set to "false" to disable documentation pages on encryption */
  readonly VITE_DOCS_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
