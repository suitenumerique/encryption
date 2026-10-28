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
          component: 'Email sent to every custodian of a council when one of its users asks for a recovery.',
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
