import { Document, Page, StyleSheet, Text, View } from '@react-pdf/renderer';

import i18n from '@encryption/src/i18n';
import { RECOVERY_KIT_FONT_FAMILY } from '@encryption/src/ui/documents/pdf-fonts';

// The printable Recovery Kit sheet as a real PDF (@react-pdf/renderer). It is the
// single source of truth for the printed backup: `RecoveryKitBackup` renders it
// to print, and the `Preview/Documents/RecoveryKit` story renders the SAME
// component in a PDF reader, so the preview is exactly what a user prints.
//
// @react-pdf renders in its own reconciler with no React context, so the
// `useTranslation` hook cannot reach the provider here. The i18n singleton with
// an explicit `{ lng }` is the context-free equivalent, so the copy stays in
// i18next like everywhere else instead of being pre-resolved and passed in.

const styles = StyleSheet.create({
  page: { fontFamily: RECOVERY_KIT_FONT_FAMILY, color: '#161616', fontSize: 11, padding: 48 },
  title: { fontSize: 18, fontWeight: 700, marginBottom: 10 },
  warning: {
    borderLeftWidth: 4,
    borderLeftColor: '#b34000',
    backgroundColor: '#ffe9e6',
    color: '#5a2200',
    fontSize: 10,
    padding: 10,
    marginBottom: 16,
  },
  label: { marginBottom: 12 },
  words: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    borderWidth: 1,
    borderColor: '#cccccc',
    backgroundColor: '#f9f9f9',
    borderRadius: 4,
    padding: 12,
  },
  word: { flexDirection: 'row', width: '33.33%', paddingVertical: 3 },
  num: { color: '#888888', width: 22, textAlign: 'right', marginRight: 6 },
  footer: {
    position: 'absolute',
    bottom: 24,
    left: 48,
    right: 48,
    flexDirection: 'row',
    justifyContent: 'space-between',
    fontSize: 8,
    color: '#999999',
  },
});

export function RecoveryKitDocument({ words, lang, domain }: { words: string[]; lang: string; domain: string }) {
  const title = i18n.t('onboarding.print_title', { lng: lang });
  const warning = i18n.t('onboarding.print_warning', { lng: lang });
  const label = i18n.t('onboarding.print_label', { lng: lang });
  const footer = i18n.t('onboarding.print_footer', { lng: lang, domain });

  return (
    <Document language={lang} title={title}>
      <Page size="A4" style={styles.page} wrap>
        <Text style={styles.title}>{title}</Text>
        <View style={styles.warning}>
          <Text>{warning}</Text>
        </View>
        <Text style={styles.label}>{label}</Text>
        <View style={styles.words}>
          {words.map((word, index) => (
            <View key={index} style={styles.word} wrap={false}>
              <Text style={styles.num}>{index + 1}.</Text>
              <Text>{word}</Text>
            </View>
          ))}
        </View>
        {/* `fixed` repeats the footer on every printed page, with a running page
            count: the footer a user would see on paper. */}
        <View style={styles.footer} fixed>
          <Text>{footer}</Text>
          <Text render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} />
        </View>
      </Page>
    </Document>
  );
}
