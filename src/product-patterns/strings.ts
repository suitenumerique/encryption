// The texts of the share modal patterns, in the two interface languages. The
// design system's ShareModal brings its own ("N members", "Copy link", ...),
// in the locale its provider gets.

export type PatternLocale = 'en' | 'fr';

const en = {
  shareTitle: 'Share {{name}}',
  roleReader: 'Reader',
  roleEditor: 'Editor',
  roleAdministrator: 'Administrator',
  roleOwner: 'Owner',
  subtextReader: 'Can view only',
  subtextEditor: 'Can view and edit content',
  subtextAdministrator: 'Can edit and manage access',
  subtextOwner: 'Full control and can delete',
  pendingTitle: 'Action needed',
  pendingWaitingTitle: 'Waiting for access',
  pendingWaitingHint: 'Members who have not enabled encryption yet get access once they do.',
  pendingAccept: 'Accept',
  pendingAccepting: 'Accepting…',
  pendingWaitingChip: 'Waiting for encryption',
  pendingWaitingChipHint: 'Waiting for them to enable encryption',
  pendingWaitingAcceptanceChip: 'Waiting for acceptance',
  pendingWaitingAcceptanceChipHint: 'Encryption is enabled: someone who manages members still has to accept them',
  you: '{{name}} (you)',
  noKeysTitle: 'Encryption is not set up on this device',
  noKeysManager: 'Enable it here to invite people and accept pending members.',
  noKeysMember: 'Enable it here to open this item.',
  enableEncryption: 'Enable encryption',
  cancel: 'Cancel',
  inviteNeedsKeysTitle: 'Enable encryption to invite',
  inviteNeedsKeysText: "Inviting someone to an encrypted item needs encryption on this device: the item's key is shared from here.",
  inviteWithoutEncryptionTitle: 'Invite without encryption?',
  inviteWithoutEncryptionOne: 'This person has not enabled encryption yet. They will be added as pending and get access once they enable it.',
  inviteWithoutEncryptionOther: 'These people have not enabled encryption yet. They will be added as pending and get access once they enable it.',
};

export type PatternStringKey = keyof typeof en;

const fr: Record<PatternStringKey, string> = {
  shareTitle: 'Partager {{name}}',
  roleReader: 'Lecteur',
  roleEditor: 'Éditeur',
  roleAdministrator: 'Administrateur',
  roleOwner: 'Propriétaire',
  subtextReader: 'Peut voir uniquement',
  subtextEditor: 'Peut voir et modifier le contenu',
  subtextAdministrator: 'Peut gérer les accès',
  subtextOwner: 'Contrôle complet et peut supprimer',
  pendingTitle: 'Action requise',
  pendingWaitingTitle: "En attente d'accès",
  pendingWaitingHint: "Les membres qui n'ont pas encore activé le chiffrement auront accès dès qu'ils l'auront fait.",
  pendingAccept: 'Accepter',
  pendingAccepting: 'Acceptation…',
  pendingWaitingChip: 'En attente de chiffrement',
  pendingWaitingChipHint: "En attente de l'activation du chiffrement par cette personne",
  pendingWaitingAcceptanceChip: "En attente d'acceptation",
  pendingWaitingAcceptanceChipHint: "Le chiffrement est activé : une personne qui gère les membres doit encore l'accepter",
  you: '{{name}} (vous)',
  noKeysTitle: "Le chiffrement n'est pas configuré sur cet appareil",
  noKeysManager: 'Activez-le ici pour inviter des personnes et accepter les membres en attente.',
  noKeysMember: 'Activez-le ici pour ouvrir cet élément.',
  enableEncryption: 'Activer le chiffrement',
  cancel: 'Annuler',
  inviteNeedsKeysTitle: 'Activez le chiffrement pour inviter',
  inviteNeedsKeysText:
    "Inviter quelqu'un sur un élément chiffré nécessite le chiffrement sur cet appareil : la clé de l'élément est partagée depuis ici.",
  inviteWithoutEncryptionTitle: 'Inviter sans chiffrement ?',
  inviteWithoutEncryptionOne:
    "Cette personne n'a pas encore activé le chiffrement. Elle sera ajoutée en attente et aura accès dès qu'elle l'aura activé.",
  inviteWithoutEncryptionOther:
    "Ces personnes n'ont pas encore activé le chiffrement. Elles seront ajoutées en attente et auront accès dès qu'elles l'auront activé.",
};

const dictionaries: Record<PatternLocale, Record<PatternStringKey, string>> = { en, fr };

export type PatternTranslate = (key: PatternStringKey, values?: Record<string, string | number>) => string;

export function toPatternLocale(value: unknown): PatternLocale {
  return value === 'en' ? 'en' : 'fr';
}

export function createTranslate(locale: PatternLocale): PatternTranslate {
  return (key, values) => {
    let text = dictionaries[locale][key];

    for (const [name, value] of Object.entries(values ?? {})) {
      text = text.replaceAll(`{{${name}}}`, String(value));
    }

    return text;
  };
}
