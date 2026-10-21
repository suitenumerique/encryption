import { ModalProvider } from '@gouvfr-lasuite/ui-components';
import type { Meta, StoryContext, StoryObj } from '@storybook/react';
import { within } from 'storybook/test';

import { generateMetaDefault } from '@encryption/.storybook/helpers';
import { PatternProvider } from '@encryption/src/product-patterns/PatternProvider';
import { type PatternState, states } from '@encryption/src/product-patterns/states';
import { createTranslate, toPatternLocale } from '@encryption/src/product-patterns/strings';

// The encryption states of the products' share dialogs (Docs and Drive), for
// the design of the generic flows on top of the design system's share modal.
// Each story is one state; "Overview" lays them all out on one page.

export default {
  title: 'Product patterns/Share modal',
  ...generateMetaDefault({}),
} as Meta;

type Story = StoryObj;

function localeOf(context: Pick<StoryContext, 'globals'>) {
  return toPatternLocale(context.globals.locale);
}

function stateStory(id: string): Story {
  const state: PatternState | undefined = states.find((candidate) => candidate.id === id);

  if (!state) {
    throw new Error(`No share modal state "${id}"`);
  }

  return {
    parameters: {
      docs: { description: { story: `**${state.name}**\n\n${state.description}\n\nProduct source: \`${state.source}\`` } },
    },
    render: (_args, context) => <PatternProvider locale={localeOf(context)}>{state.render()}</PatternProvider>,
    play: async ({ canvasElement, globals }) => {
      const t = createTranslate(toPatternLocale(globals.locale));
      // The modal is portaled next to the story root, and its menus to the page body.
      const body = within(canvasElement.ownerDocument.body);

      await state.check(body, t);
      await state.interact?.(body, t);
    },
  };
}

export const Overview: Story = {
  parameters: {
    docs: { description: { story: 'Every state side by side, each with the product file it mirrors.' } },
  },
  render: (_args, context) => (
    <PatternProvider locale={localeOf(context)}>
      <div className="pp-overview">
        {states.map((state) => (
          <section key={state.id} className="pp-overview__cell" data-testid={`overview-${state.id}`}>
            <h2 className="pp-overview__label">{state.name}</h2>
            <p className="pp-overview__source">{state.source}</p>
            {/* A provider per cell portals the cell's modal into the cell itself. */}
            <ModalProvider>{state.render()}</ModalProvider>
          </section>
        ))}
      </div>
    </PatternProvider>
  ),
  play: async ({ canvasElement, globals }) => {
    const t = createTranslate(toPatternLocale(globals.locale));
    const canvas = within(canvasElement);

    for (const state of states) {
      await state.check(within(await canvas.findByTestId(`overview-${state.id}`)), t);
    }
  },
};

// The same page in French whatever the toolbar says, so both dictionaries are
// rendered and asserted on every run.
export const OverviewFrench: Story = {
  ...Overview,
  globals: { locale: 'fr' },
};

export const DocsPlainDocument = stateStory('DocsPlainDocument');
export const DocsEncryptedDocument = stateStory('DocsEncryptedDocument');
export const DocsSearchPlainDocument = stateStory('DocsSearchPlainDocument');
export const DocsSearchEncryptedDocument = stateStory('DocsSearchEncryptedDocument');
export const DocsInviteByEmail = stateStory('DocsInviteByEmail');
export const DocsInviteSelection = stateStory('DocsInviteSelection');
export const DocsPendingEncryption = stateStory('DocsPendingEncryption');
export const DocsPendingReadOnly = stateStory('DocsPendingReadOnly');
export const DocsPendingAcceptProgress = stateStory('DocsPendingAcceptProgress');
export const DocsNoAccessNeedsSetup = stateStory('DocsNoAccessNeedsSetup');
export const DocsNoAccessNoKey = stateStory('DocsNoAccessNoKey');
export const DocsWaitingForAccessNeedsSetup = stateStory('DocsWaitingForAccessNeedsSetup');
export const DocsWaitingForAccess = stateStory('DocsWaitingForAccess');
export const DocsEncryptBlocked = stateStory('DocsEncryptBlocked');
export const DocsEncryptBlockedWithKeys = stateStory('DocsEncryptBlockedWithKeys');
export const DocsEncryptAnalyzingFiles = stateStory('DocsEncryptAnalyzingFiles');
export const DocsEncryptWithPendingCollaborators = stateStory('DocsEncryptWithPendingCollaborators');
export const DocsEncryptReady = stateStory('DocsEncryptReady');
export const DrivePlainItem = stateStory('DrivePlainItem');
export const DriveEncryptedVerifyIdentity = stateStory('DriveEncryptedVerifyIdentity');
export const DrivePendingEncryption = stateStory('DrivePendingEncryption');
export const DrivePendingViewerCannotAccept = stateStory('DrivePendingViewerCannotAccept');
export const DrivePendingAcceptProgress = stateStory('DrivePendingAcceptProgress');
