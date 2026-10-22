// The Console Figma file, where the interface's screens are designed. A story
// passes the frames it implements as `parameters.design` and
// @storybook/addon-designs shows them in its "Design" tab, embedded from Figma:
// the viewer needs a Figma session with access to the file.
const CONSOLE_FILE = 'https://www.figma.com/design/FciuFnEEJ9dnlGCuYedcvo/Console';

/** One frame of the Console file, by the `node-id` of its URL (`4879-12693`). */
export function consoleFrame(nodeId: string, name?: string) {
  return { type: 'figma' as const, url: `${CONSOLE_FILE}?node-id=${nodeId}`, ...(name ? { name } : {}) };
}
