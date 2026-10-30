declare module '*.mdx' {
  import type { ComponentType } from 'react';
  const Component: ComponentType;
  export default Component;
}

// architecture.md is imported as raw text and rendered at runtime (see
// src/ui/docs/internal/ArchitectureDoc), so the file stays plain markdown.
declare module '*.md?raw' {
  const content: string;

  export default content;
}
