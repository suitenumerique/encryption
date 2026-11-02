import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilRecoveryCompletedEmail, subject } from '@encryption/src/server/email/templates/CouncilRecoveryCompleted';

type ComponentType = typeof CouncilRecoveryCompletedEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilRecoveryCompleted',
  component: CouncilRecoveryCompletedEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component: 'Email sent to the user once their vault was given back by their council and their new recovery phrase is in place.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilRecoveryCompletedEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  council: 'Équipe sécurité DINUM',
  contributors: 'Alice Martin, Claire Petit',
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
