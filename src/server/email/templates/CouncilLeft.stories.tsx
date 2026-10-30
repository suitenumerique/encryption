import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilLeftEmail, subject } from '@encryption/src/server/email/templates/CouncilLeft';

type ComponentType = typeof CouncilLeftEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilLeft',
  component: CouncilLeftEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component: 'Email sent to a user who left their recovery council, so they learn of it if it was not them.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilLeftEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  council: 'Équipe sécurité DINUM',
  productUrl: 'http://localhost:7201',
};
DefaultStory.decorators = [WithEmailRenderer];
DefaultStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const Default = prepareStory(DefaultStory);

const ClientOverviewStory = Template.bind({});
ClientOverviewStory.args = { ...DefaultStory.args };
ClientOverviewStory.decorators = [WithEmailClientOverviewFactory(subject)];
ClientOverviewStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const ClientOverview = prepareStory(ClientOverviewStory);
