import { Decorator, Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from '@storybook/test';
import React, { useEffect, useRef } from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindAlert, playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import {
  handleGetApiVaultApprovalsByRequestId,
  handleGetApiVaultApprovalsPending,
  handlePostApiVaultApprovalsByRequestIdApprove,
  handlePostApiVaultApprovalsRequest,
} from '@encryption/src/ui/api/generated/msw.gen';
import { DeviceApproval } from '@encryption/src/ui/components/DeviceApproval';
import { sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof DeviceApproval;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/DeviceApproval',
  component: DeviceApproval,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <DeviceApproval {...args} />;

const baseArgs = {
  getToken: async () => 'mock-jwt-token',
  onClose: () => console.log('onClose'),
};

// A failing `getUserMedia` silently drops the component to the manual screen, so
// the camera is pinned rather than left to the machine opening Storybook.
function pinCamera(available: boolean): () => void {
  const previous = Object.getOwnPropertyDescriptor(navigator, 'mediaDevices');

  Object.defineProperty(navigator, 'mediaDevices', {
    configurable: true,
    value: {
      // Pending rather than resolved: no MediaStream to fabricate, and it is what
      // the scan screen looks like while the camera warms up.
      getUserMedia: available ? () => new Promise<MediaStream>(() => {}) : () => Promise.reject(new Error('NotFoundError')),
    },
  });

  return () => {
    if (previous) {
      Object.defineProperty(navigator, 'mediaDevices', previous);
    } else {
      Reflect.deleteProperty(navigator, 'mediaDevices');
    }
  };
}

function withCamera(available: boolean): Decorator {
  return function CameraDecorator(Story) {
    // Patched during render, so it is in place before the scanner's mount effect.
    const restore = useRef<(() => void) | null>(null);
    if (!restore.current) restore.current = pinCamera(available);

    useEffect(() => {
      return () => {
        restore.current?.();
        restore.current = null;
      };
    }, []);

    return <Story />;
  };
}

async function fillPairingCode(canvasElement: HTMLElement, digits: string) {
  const canvas = within(canvasElement);

  for (let group = 0; group * 5 < digits.length; group++) {
    await userEvent.type(await canvas.findByLabelText(`code group ${group + 1}`), digits.slice(group * 5, group * 5 + 5));
  }
}

const NewDeviceStory = Template.bind({});
NewDeviceStory.args = { ...baseArgs };
NewDeviceStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: false }),
  },
  msw: {
    handlers: [
      handlePostApiVaultApprovalsRequest({ body: { request_id: 'req-1', device_public_key: samplePublicKey.encryption_public_key } }),
      // 425 is the normal "still pending" poll outcome. The `{ body }` form only
      // types the 200, so a declared error needs the resolver form.
      handleGetApiVaultApprovalsByRequestId(() => Response.json({ code: 'vault_approval_not_ready' }, { status: 425 })),
    ],
  },
};

NewDeviceStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_start')));
  await within(canvasElement).findByAltText('pairing QR code');
};

export const NewDevice = prepareStory(NewDeviceStory);

const NewDeviceCodeRevealedStory = Template.bind({});
NewDeviceCodeRevealedStory.args = { ...baseArgs };
NewDeviceCodeRevealedStory.parameters = NewDeviceStory.parameters;
NewDeviceCodeRevealedStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_start')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.new_reveal_code')));
};

export const NewDeviceCodeRevealed = prepareStory(NewDeviceCodeRevealedStory);

const NewDeviceAdoptedStory = Template.bind({});
NewDeviceAdoptedStory.args = { ...baseArgs };
NewDeviceAdoptedStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: false }),
  },
  msw: {
    handlers: [
      handlePostApiVaultApprovalsRequest({ body: { request_id: 'req-1', device_public_key: samplePublicKey.encryption_public_key } }),
      handleGetApiVaultApprovalsByRequestId({
        body: { wrapped_device_bootstrap: samplePublicKey.key_binding_signature, device_public_key: samplePublicKey.encryption_public_key },
      }),
    ],
  },
};
// Reached by the 3s poll, so the default 1s wait would give up before the first tick.
NewDeviceAdoptedStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_start')));
  await playFindAlert(canvasElement, i18n.t('device_approval.new_success'), { timeout: 10000 });
};

export const NewDeviceAdopted = prepareStory(NewDeviceAdoptedStory);

const ErroredStory = Template.bind({});
ErroredStory.args = { ...baseArgs };
ErroredStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: false }),
    startDeviceApproval: async () => {
      throw new Error('The vault is unavailable.');
    },
  },
};
ErroredStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_start')));
  await playFindAlert(canvasElement, 'The vault is unavailable.');
};

export const Errored = prepareStory(ErroredStory);

const EnrolledDeviceStory = Template.bind({});
EnrolledDeviceStory.args = { ...baseArgs };
EnrolledDeviceStory.decorators = [withCamera(true)];
EnrolledDeviceStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: true }),
  },
};

export const EnrolledDevice = prepareStory(EnrolledDeviceStory);

const EnrolledDeviceManualEntryStory = Template.bind({});
EnrolledDeviceManualEntryStory.args = { ...baseArgs };
EnrolledDeviceManualEntryStory.decorators = [withCamera(true)];
EnrolledDeviceManualEntryStory.parameters = EnrolledDeviceStory.parameters;
EnrolledDeviceManualEntryStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.enter_code_instead')));
};

export const EnrolledDeviceManualEntry = prepareStory(EnrolledDeviceManualEntryStory);

const EnrolledDeviceNoCameraStory = Template.bind({});
EnrolledDeviceNoCameraStory.args = { ...baseArgs };
EnrolledDeviceNoCameraStory.decorators = [withCamera(false)];
EnrolledDeviceNoCameraStory.parameters = EnrolledDeviceStory.parameters;
// Reached by the camera rejecting, and distinct from ManualEntry by having no way back.
EnrolledDeviceNoCameraStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByLabelText('code group 1');
  expect(canvas.queryByRole('button', { name: i18n.t('device_approval.scan_instead') })).toBeNull();
};

export const EnrolledDeviceNoCamera = prepareStory(EnrolledDeviceNoCameraStory);

const EnrolledDeviceCodeMismatchStory = Template.bind({});
EnrolledDeviceCodeMismatchStory.args = { ...baseArgs };
EnrolledDeviceCodeMismatchStory.decorators = [withCamera(false)];
EnrolledDeviceCodeMismatchStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: true }),
    // A rejection for every pending request is what "no match" means.
    approveDevice: async () => {
      throw new Error('fingerprint mismatch');
    },
  },
  msw: {
    handlers: [
      handleGetApiVaultApprovalsPending({
        body: { approvals: [{ request_id: 'req-1', device_public_key: samplePublicKey.encryption_public_key }] },
      }),
    ],
  },
};
EnrolledDeviceCodeMismatchStory.play = async ({ canvasElement }) => {
  await fillPairingCode(canvasElement, sampleFingerprint);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_approve')));
  await playFindAlert(canvasElement, i18n.t('device_approval.code_no_match'));
};

export const EnrolledDeviceCodeMismatch = prepareStory(EnrolledDeviceCodeMismatchStory);

const EnrolledDeviceApprovedStory = Template.bind({});
EnrolledDeviceApprovedStory.args = { ...baseArgs };
EnrolledDeviceApprovedStory.decorators = [withCamera(false)];
EnrolledDeviceApprovedStory.parameters = {
  encryption: {
    hasKeys: async () => ({ hasKeys: true }),
  },
  msw: {
    handlers: [
      handleGetApiVaultApprovalsPending({
        body: { approvals: [{ request_id: 'req-1', device_public_key: samplePublicKey.encryption_public_key }] },
      }),
      handlePostApiVaultApprovalsByRequestIdApprove({ body: { approved: true } }),
    ],
  },
};
EnrolledDeviceApprovedStory.play = async ({ canvasElement }) => {
  await fillPairingCode(canvasElement, sampleFingerprint);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.btn_approve')));
  await playFindAlert(canvasElement, i18n.t('device_approval.approve_success'));
};

export const EnrolledDeviceApproved = prepareStory(EnrolledDeviceApprovedStory);
