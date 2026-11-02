import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilRecoveryCompletedCustodianEmail, subject } from '@encryption/src/server/email/templates/CouncilRecoveryCompletedCustodian';

type ComponentType = typeof CouncilRecoveryCompletedCustodianEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilRecoveryCompletedCustodian',
  component: CouncilRecoveryCompletedCustodianEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component: 'Email sent to the custodians of a council once a recovery they could take part in is completed.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilRecoveryCompletedCustodianEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  requester: 'Jean Dupont',
  council: 'Équipe sécurité DINUM',
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
