import { type ReactNode, createContext, useContext, useLayoutEffect, useState } from 'react';

export type InterfaceModalSize = 'small' | 'medium' | 'large';

const ModalSizeContext = createContext<((size: InterfaceModalSize | null) => void) | null>(null);

/**
 * The width of the modal App.tsx draws around the screens: 350px by default,
 * 450px or 526px while a mounted screen asks for it (a list, the 24-word phrase;
 * the settings home). Asked
 * from the screen itself, so a flow that moves between steps inside one route
 * gets the right width at every step.
 */
export function ModalSizeProvider({ children }: { children: (size: InterfaceModalSize) => ReactNode }) {
  const [requested, setRequested] = useState<InterfaceModalSize | null>(null);

  return <ModalSizeContext.Provider value={setRequested}>{children(requested ?? 'small')}</ModalSizeContext.Provider>;
}

/** Ask for `size` while mounted (and while `active`). Outside a provider it is a no-op. */
export function useModalSize(size: InterfaceModalSize, active = true): void {
  const setRequested = useContext(ModalSizeContext);

  // Before the paint, so the modal never shows one frame at the wrong width.
  useLayoutEffect(() => {
    if (!setRequested || !active) return;

    setRequested(size);

    return () => setRequested(null);
  }, [setRequested, size, active]);
}
