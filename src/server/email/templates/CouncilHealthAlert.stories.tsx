import { Meta, StoryFn } from '@storybook/react';

import { WithEmailClientOverviewFactory } from '@encryption/.storybook/WithEmailClientOverviewFactory';
import { WithEmailRenderer } from '@encryption/.storybook/WithEmailRenderer';
import { commonEmailsParameters } from '@encryption/.storybook/email';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindEmailStructure } from '@encryption/.storybook/testing';
import { CouncilHealthAlertEmail, subject } from '@encryption/src/server/email/templates/CouncilHealthAlert';

type ComponentType = typeof CouncilHealthAlertEmail;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Emails/CouncilHealthAlert',
  component: CouncilHealthAlertEmail,
  ...generateMetaDefault({
    parameters: {
      ...commonEmailsParameters,
      docs: {
        description: {
          component:
            'Email sent to the custodians of a council when its health gets worse: no margin left (at risk), or people it can no longer help (lost).',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args, { globals }) => {
  return <CouncilHealthAlertEmail {...args} locale={(globals.locale as string) ?? 'en'} />;
};

const DefaultStory = Template.bind({});
DefaultStory.args = {
  council: 'Équipe sécurité DINUM',
  status: 'at-risk',
  lost: 0,
  absent: ['Bob Dupont'],
  inactive: ['Charlie Leroy'],
  teamReady: false,
  absenceDays: 90,
  productUrl: 'http://localhost:7201',
};
DefaultStory.decorators = [WithEmailRenderer];
DefaultStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const Default = prepareStory(DefaultStory);

const LostStory = Template.bind({});
LostStory.args = { ...DefaultStory.args, status: 'lost', lost: 3, absent: [], inactive: ['Bob Dupont', 'Charlie Leroy'], teamReady: false };
LostStory.decorators = [WithEmailRenderer];
LostStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const Lost = prepareStory(LostStory);

const BlockedStory = Template.bind({});
BlockedStory.args = { ...DefaultStory.args, status: 'blocked', lost: 0, absent: [], inactive: ['Bob Dupont'], teamReady: false };
BlockedStory.decorators = [WithEmailRenderer];
BlockedStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const Blocked = prepareStory(BlockedStory);

const ClientOverviewStory = Template.bind({});
ClientOverviewStory.args = { ...DefaultStory.args };
ClientOverviewStory.decorators = [WithEmailClientOverviewFactory((locale) => subject(locale, 'at-risk'))];
ClientOverviewStory.play = async ({ canvasElement }) => {
  await playFindEmailStructure(canvasElement);
};

export const ClientOverview = prepareStory(ClientOverviewStory);
