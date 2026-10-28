import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilRecoveryToApproveEmail, subject } from '@encryption/src/server/email/templates/CouncilRecoveryToApprove';

type ComponentType = typeof CouncilRecoveryToApproveEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilRecoveryToApprove',
  component: CouncilRecoveryToApproveEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component:
            'Email sent to the custodians of a council for a recovery: when the user asks (one of them must meet them first), then once a custodian met them (the others may approve remotely).',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilRecoveryToApproveEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  requester: 'Jean Dupont (jean.dupont@numerique.gouv.fr)',
  council: 'Équipe sécurité DINUM',
  step: 'approve',
  productUrl: 'http://localhost:7201',
};
DefaultStory.decorators = [WithEmailRenderer];
DefaultStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const Default = prepareStory(DefaultStory);

const MeetFirstStory = Template.bind({});
MeetFirstStory.args = { ...DefaultStory.args, step: 'meet' };
MeetFirstStory.decorators = [WithEmailRenderer];
MeetFirstStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const MeetFirst = prepareStory(MeetFirstStory);

const ClientOverviewStory = Template.bind({});
ClientOverviewStory.args = { ...DefaultStory.args };
ClientOverviewStory.decorators = [WithEmailClientOverviewFactory((locale) => subject(locale, 'approve'))];
ClientOverviewStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const ClientOverview = prepareStory(ClientOverviewStory);
