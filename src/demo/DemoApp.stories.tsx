import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { DemoApp } from '@encryption/src/demo/DemoApp';

type ComponentType = typeof DemoApp;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Demo/FakeProduct',
  component: DemoApp,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
      docs: {
        description: {
          component:
            'Full integration demo showing how a suite product uses the VaultClient SDK. Product operations (encrypt/decrypt) go through data.encryption, key management goes through encryption.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => {
  return <DemoApp />;
};

const DefaultStory = Template.bind({});
DefaultStory.parameters = {
  docs: {
    description: {
      story:
        'The demo page attempts to connect to the vault iframe at data.encryption.localhost:7200. In Storybook, the vault may not be running, so expect an initialization timeout. This story is best viewed with `npm run dev` running alongside.',
    },
  },
};

export const Default = prepareStory(DefaultStory);
