// The products' own strings, copied from their i18n files so the patterns read
// exactly like the products: Docs keys its translations by the English text
// (src/frontend/apps/impress/src/i18n/translations.json), Drive by nested keys
// (src/frontend/apps/drive/src/features/i18n/translations.json).

export type PatternLocale = 'en' | 'fr';

const en = {
  // Docs: DocShareModal.tsx and its parts
  docsShareTitle: 'Share the document',
  docsCloseShare: 'Close the share modal',
  docsSearchPlaceholder: 'Type a name or email',
  docsSearchResults: 'Search results',
  docsDocumentOwner: 'Document owner',
  docsShareWithOther: 'Share with {{count}} users',
  docsPendingInvitations: 'Pending invitations',
  docsLinkSettings: 'Link settings',
  docsDocumentVisibility: 'Document visibility',
  docsCopyLink: 'Copy link',
  docsOk: 'OK',
  docsReachPrivate: 'Private',
  docsReachConnected: 'Connected',
  docsReachPublic: 'Public',
  docsReachPrivateDescription: 'Only invited people can access',
  docsRoleReader: 'Reader',
  docsRoleEditor: 'Editor',
  docsRoleAdministrator: 'Administrator',
  docsRoleOwner: 'Owner',
  docsHintMinLength: 'Type at least {{minLength}} characters to display user names',
  docsChooseEmail: 'Choose the email',
  docsNoResults: 'No results. Type a full email address to invite someone.',
  docsChooseUser: 'Choose a user',
  docsAdd: 'Add',
  docsVerifyIdentityOf: 'Verify the identity of {{name}}',
  docsNoEncryption: 'No encryption',
  docsNoEncryptionHint:
    'This person has not enabled encryption yet. They will be added as pending and get access once they enable it, the next time the document owner opens the document.',
  docsEncryptedInviteHint:
    'Invited people get access once they have signed up and enabled encryption, the next time the document owner opens the document.',
  docsWaitingForEncryption: 'Waiting for encryption',
  docsActionNeeded: 'Action needed',
  docsWaitingHint: 'Members who have not enabled encryption yet get access once they do.',
  docsAccept: 'Accept',
  docsAccepting: 'Accepting…',
  docsWaitingChipTitle: 'Waiting for them to enable encryption',
  docsNotOnboardedError: "This user still hasn't completed their encryption onboarding.",
  docsWrapFailedError: 'Failed to wrap the document key for this user.',
  docsEncryptionEnabled: 'Encryption enabled',
  docsEnableEncryption: 'Enable encryption',
  docsInvite: 'Invite',
  docsWaitingForAccess: 'Waiting for access',
  docsPendingNeedsSetup:
    'This document was encrypted before you enabled encryption, so its key could not be shared with you. Enable encryption on your account: you will get access the next time the document owner opens it.',
  docsPendingSetUp:
    'This document was encrypted before you enabled encryption, so its key could not be shared with you then. You will get access the next time the document owner opens it.',
  docsEncryptedDocument: 'Encrypted document',
  docsNeedsSetup: 'This document is encrypted. You must enable encryption on your account to access it.',
  docsNoKeyForYou: 'This encrypted document holds no key for you. Ask the document owner to add you to its members.',
  // Docs: ModalEncryptDoc.tsx
  docsEncryptDocument: 'Encrypt document',
  docsEncryptDescription:
    'The document and its attachments will be encrypted end-to-end. Only people you share it with will be able to access its contents.',
  docsEncrypt: 'Encrypt',
  docsCancel: 'Cancel',
  docsBlockerNoKeys: 'Enable encryption on your account to encrypt this document.',
  docsBlockerAntivirus: 'Some files are still being analyzed by the antivirus: wait for the analysis to finish',
  docsBlockerNotPrivate: 'Document must be set to private (currently {{reach}})',
  docsReachLowerPublic: 'public',
  docsReachLowerConnected: 'connected',
  docsPendingCollaboratorsOne:
    '{{count}} collaborator has not enabled encryption yet. They will be added as pending and get access once they enable it.',
  docsPendingCollaboratorsOther:
    '{{count}} collaborators have not enabled encryption yet. They will be added as pending and get access once they enable it.',

  // Drive: ItemShareModal.tsx and encryption/sharing/PendingEncryptionSection.tsx
  driveShareTitle: 'Share',
  driveVerifyIdentity: 'Verify identity',
  driveRoleReader: 'Reader',
  driveRoleEditor: 'Editor',
  driveRoleAdministrator: 'Administrator',
  driveRoleOwner: 'Owner',
  driveSubtextReader: 'Can view only',
  driveSubtextEditor: 'Can view and edit content',
  driveSubtextAdmin: 'Can edit and manage access',
  driveSubtextOwner: 'Full control and can delete',
  driveReachRestricted: 'Private',
  driveReachAuthenticated: 'Connected',
  driveReachPublic: 'Public',
  driveOnlyOwner: 'You cannot change your role as you are the only owner.',
  drivePendingTitle: 'Action needed',
  drivePendingWaitingHint: 'Members who have not enabled encryption yet get access once they do.',
  drivePendingAccept: 'Accept',
  drivePendingAccepting: 'Accepting…',
  drivePendingNoPublicKey: "This user still hasn't completed their encryption onboarding.",
  drivePendingEncryptionEnabled: 'Encryption enabled',
  drivePendingWaitingChip: 'Waiting for encryption',
  drivePendingWaitingChipHint: 'Waiting for them to enable encryption',
};

export type PatternStringKey = keyof typeof en;

const fr: Record<PatternStringKey, string> = {
  docsShareTitle: 'Partager le document',
  docsCloseShare: 'Fermer la fenêtre modale de partage',
  docsSearchPlaceholder: 'Tapez un nom ou un email',
  docsSearchResults: 'Résultats de la recherche',
  docsDocumentOwner: 'Propriétaire du document',
  docsShareWithOther: 'Partagé entre {{count}} utilisateurs',
  docsPendingInvitations: 'Invitations en attente',
  docsLinkSettings: 'Paramètres du lien',
  docsDocumentVisibility: 'Visibilité du document',
  docsCopyLink: 'Copier le lien',
  docsOk: 'OK',
  docsReachPrivate: 'Privé',
  docsReachConnected: 'Connecté',
  docsReachPublic: 'Public',
  docsReachPrivateDescription: 'Seules les personnes invitées peuvent accéder',
  docsRoleReader: 'Lecteur',
  docsRoleEditor: 'Éditeur',
  docsRoleAdministrator: 'Administrateur',
  docsRoleOwner: 'Propriétaire',
  docsHintMinLength: "Tapez au moins {{minLength}} caractères pour afficher les noms d'utilisateurs",
  docsChooseEmail: 'Choisissez le courriel',
  docsNoResults: "Aucun résultat. Tapez une adresse e-mail complète pour inviter quelqu'un(e).",
  docsChooseUser: 'Choisir un(e) utilisateur(trice)',
  docsAdd: 'Ajouter',
  docsVerifyIdentityOf: "Vérifier l'identité de {{name}}",
  docsNoEncryption: 'Pas de chiffrement',
  docsNoEncryptionHint:
    "Cette personne n'a pas encore activé le chiffrement. Elle sera ajoutée en attente et aura accès une fois le chiffrement activé, la prochaine fois que le propriétaire du document l'ouvrira.",
  docsEncryptedInviteHint:
    "Les personnes invitées auront accès une fois inscrites et leur chiffrement activé, la prochaine fois que le propriétaire du document l'ouvrira.",
  docsWaitingForEncryption: 'En attente de chiffrement',
  docsActionNeeded: 'Action requise',
  docsWaitingHint: "Les membres qui n'ont pas encore activé le chiffrement auront accès dès qu'ils l'auront fait.",
  docsAccept: 'Accepter',
  docsAccepting: 'Acceptation…',
  docsWaitingChipTitle: "En attente de l'activation du chiffrement par cette personne",
  docsNotOnboardedError: "Cette personne n'a pas encore terminé l'activation du chiffrement.",
  docsWrapFailedError: 'Impossible de chiffrer la clé du document pour cette personne.',
  docsEncryptionEnabled: 'Chiffrement activé',
  docsEnableEncryption: 'Activer le chiffrement',
  docsInvite: 'Inviter',
  docsWaitingForAccess: "En attente d'accès",
  docsPendingNeedsSetup:
    "Ce document a été chiffré avant que vous activiez le chiffrement, sa clé n'a donc pas pu vous être partagée. Activez le chiffrement sur votre compte : vous aurez accès la prochaine fois que le propriétaire du document l'ouvrira.",
  docsPendingSetUp:
    "Ce document a été chiffré avant que vous activiez le chiffrement, sa clé n'a donc pas pu vous être partagée à ce moment-là. Vous aurez accès la prochaine fois que le propriétaire du document l'ouvrira.",
  docsEncryptedDocument: 'Document chiffré',
  docsNeedsSetup: 'Ce document est chiffré. Vous devez activer le chiffrement sur votre compte pour y accéder.',
  docsNoKeyForYou: 'Ce document chiffré ne contient aucune clé pour vous. Demandez au propriétaire du document de vous ajouter à ses membres.',
  docsEncryptDocument: 'Chiffrer le document',
  docsEncryptDescription:
    'Le document et ses pièces jointes seront chiffrés de bout en bout. Seules les personnes avec qui vous le partagez pourront y accéder.',
  docsEncrypt: 'Chiffrer',
  docsCancel: 'Annuler',
  docsBlockerNoKeys: 'Activez le chiffrement sur votre compte pour chiffrer ce document.',
  docsBlockerAntivirus: "Des fichiers sont encore en cours d'analyse par l'antivirus : attendez la fin de l'analyse",
  docsBlockerNotPrivate: 'Le document doit être privé (actuellement {{reach}})',
  docsReachLowerPublic: 'public',
  docsReachLowerConnected: 'connecté',
  docsPendingCollaboratorsOne:
    "{{count}} personne n'a pas encore activé le chiffrement. Elle sera ajoutée en attente et aura accès dès qu'elle l'aura activé.",
  docsPendingCollaboratorsOther:
    "{{count}} personnes n'ont pas encore activé le chiffrement. Elles seront ajoutées en attente et auront accès dès qu'elles l'auront activé.",

  driveShareTitle: 'Partager',
  driveVerifyIdentity: "Vérifier l'identité",
  driveRoleReader: 'Lecteur',
  driveRoleEditor: 'Éditeur',
  driveRoleAdministrator: 'Administrateur',
  driveRoleOwner: 'Propriétaire',
  driveSubtextReader: 'Peut voir uniquement',
  driveSubtextEditor: 'Peut voir et modifier le contenu',
  driveSubtextAdmin: 'Peut gérer les accès',
  driveSubtextOwner: 'Contrôle complet et peut supprimer',
  driveReachRestricted: 'Privé',
  driveReachAuthenticated: 'Connecté',
  driveReachPublic: 'Public',
  driveOnlyOwner: 'Vous ne pouvez pas changer votre rôle car vous êtes le seul propriétaire.',
  drivePendingTitle: 'Action requise',
  drivePendingWaitingHint: "Les membres qui n'ont pas encore activé le chiffrement auront accès dès qu'ils l'auront fait.",
  drivePendingAccept: 'Accepter',
  drivePendingAccepting: 'Acceptation…',
  drivePendingNoPublicKey: "Cet utilisateur n'a pas encore terminé sa configuration du chiffrement.",
  drivePendingEncryptionEnabled: 'Chiffrement activé',
  drivePendingWaitingChip: 'En attente de chiffrement',
  drivePendingWaitingChipHint: "En attente de l'activation du chiffrement par cette personne",
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
