import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilRecoveryMeetingEmail, subject } from '@encryption/src/server/email/templates/CouncilRecoveryMeeting';

type ComponentType = typeof CouncilRecoveryMeetingEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilRecoveryMeeting',
  component: CouncilRecoveryMeetingEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component: 'Email sent to the user once remote approvals are in: they must now meet one of the listed custodians in person.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilRecoveryMeetingEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  council: 'Équipe sécurité DINUM',
  custodians: 'Claire Petit, David Moreau',
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
