import { defaultNamespace, resources } from '@encryption/src/i18n';

declare module 'i18next' {
  interface CustomTypeOptions {
    defaultNS: typeof defaultNamespace;
    resources: (typeof resources)['fr'];
  }
}
