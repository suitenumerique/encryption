import { setProjectAnnotations } from '@storybook/react-vite';
import { beforeAll } from 'vitest';

import previewAnnotations from './.storybook/preview';

const project = setProjectAnnotations([previewAnnotations]);

beforeAll(project.beforeAll);
