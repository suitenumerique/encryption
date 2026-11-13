import { PartialStoryFn } from 'storybook/internal/types';

import { StorybookRendererLayout } from '@encryption/.storybook/StorybookRenderer';

export function WithEmailRenderer(Story: PartialStoryFn) {
  return (
    <StorybookRendererLayout>
      <Story />
    </StorybookRendererLayout>
  );
}
