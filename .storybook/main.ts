import type { StorybookConfig } from '@storybook/react-vite';
import path from 'path';
import remarkGfm from 'remark-gfm';

import { vendorMarianneFonts } from '../src/build/marianne-fonts';

const config: StorybookConfig = {
  stories: [path.resolve(__dirname, '../src/**/*.stories.@(js|ts|jsx|tsx)')],
  addons: [
    '@storybook/addon-a11y',
    {
      // The interface imports its documentation as MDX components with an MDX
      // provider (see src/ui/vite.config.ts), so Storybook's own MDX compiler
      // needs the same `providerImportSource` or <Alert>/<CodeBlock> used inside
      // a page render unstyled. Configured here rather than by adding a second
      // MDX plugin in viteFinal: addon-docs installs its plugin AFTER viteFinal
      // runs, so both would process the file and the second would fail.
      name: '@storybook/addon-docs',
      options: {
        mdxPluginOptions: {
          mdxCompileOptions: {
            providerImportSource: '@mdx-js/react',
            // Must mirror src/ui/vite.config.ts, otherwise the stories render
            // the documentation differently from production (tables as text).
            remarkPlugins: [remarkGfm],
          },
        },
      },
    },
    '@storybook/addon-essentials',
    '@storybook/addon-interactions',
    'storybook-dark-mode',
  ],
  staticDirs: [path.resolve(__dirname, 'public'), { from: path.resolve(__dirname, '../src/server/public-assets'), to: '/public-assets' }],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  core: {
    disableTelemetry: true,
  },
  viteFinal: async (config) => {
    config.resolve = config.resolve || {};
    config.resolve.alias = {
      ...(config.resolve.alias || {}),
      '@encryption': path.resolve(__dirname, '..'),
    };

    config.define = {
      ...(config.define || {}),
      'process.env.STORYBOOK_ENVIRONMENT': JSON.stringify('true'),
    };

    config.plugins = [...(config.plugins ?? []), vendorMarianneFonts()];

    return config;
  },
};

export default config;
