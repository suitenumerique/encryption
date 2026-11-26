import { ArgTypes, Controls, Description, PRIMARY_STORY, Primary, Stories, Subtitle, Title } from '@storybook/addon-docs/blocks';
import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

// Helper to get props type of a component
export type ComponentProps<F extends (props: any) => React.JSX.Element> = F extends (...args: infer A) => any ? Partial<A[0]> : never;

export interface StoryHelpers<ComponentType> {
  generateMetaDefault: (initialMeta: Meta<ComponentType>) => Meta<ComponentType>;
  prepareStory: <CT, ContextValueType extends MatchingContextValue<PossibleContextValueType>, PossibleContextValueType>(
    story: StoryFn<CT>,
    options?: StoryOptions<ContextValueType, PossibleContextValueType>
  ) => StoryFn<CT>;
}

export function StoryHelperFactory<ComponentType>(): StoryHelpers<ComponentType> {
  return {
    generateMetaDefault,
    prepareStory,
  };
}

export function generateMetaDefault<ComponentType>(initialMeta: Meta<ComponentType>): Meta<ComponentType> {
  const meta = initialMeta;

  // All exports that does not start with an uppercase should not be considered as a story
  if (!meta.includeStories) {
    meta.includeStories = /^[A-Z]/;
  }

  if (!meta.parameters) {
    meta.parameters = {};
  }

  if (!meta.parameters.docs) {
    meta.parameters.docs = {
      description: {
        page: () => {
          return (
            <>
              <Title />
              <Subtitle />
              <Description />
              <Primary />
              <ArgTypes of={PRIMARY_STORY} />
              <Controls of={PRIMARY_STORY} />
              <Stories />
            </>
          );
        },
      },
    };
  }

  return meta;
}

export type MatchingContextValue<PossibleContextValueType> = {
  [key in keyof PossibleContextValueType]: PossibleContextValueType[key] | StoryFn<PossibleContextValueType[key]>;
};

export interface ChildrenContext<ContextValueType extends MatchingContextValue<PossibleContextValueType>, PossibleContextValueType> {
  context: React.Context<PossibleContextValueType & object>;
  value: ContextValueType;
}

export interface StoryOptions<ContextValueType extends MatchingContextValue<PossibleContextValueType>, PossibleContextValueType> {
  layoutStory?: StoryFn<any>;
  childrenContext?: ChildrenContext<ContextValueType, PossibleContextValueType>;
}

export function prepareStory<ComponentType, ContextValueType extends MatchingContextValue<PossibleContextValueType>, PossibleContextValueType>(
  story: StoryFn<ComponentType>,
  options?: StoryOptions<ContextValueType, PossibleContextValueType>
): StoryFn<ComponentType> {
  if (!story.parameters) {
    story.parameters = {};
  }

  if (!story.decorators) {
    story.decorators = [];
  } else if (!Array.isArray(story.decorators)) {
    throw new Error('invalid property');
  }

  if (!story.parameters.docs) {
    story.parameters.docs = {};
  }

  let description = '';
  if (story.parameters.docs.description) {
    description = `${story.parameters.docs.description}\n`;
  }

  if (options?.layoutStory) {
    description += `\nThis story uses a mocked parent layout to give you more context.`;

    const layoutStory = options.layoutStory;
    const LayoutStory = layoutStory as any;

    story.decorators.push((Story) => {
      return (
        <LayoutStory {...layoutStory.args}>
          <Story />
        </LayoutStory>
      );
    });

    if (options.layoutStory.decorators) {
      if (!Array.isArray(options.layoutStory.decorators)) {
        throw new Error('invalid property');
      }

      story.decorators.push(...(options.layoutStory.decorators as any));
    }
  }

  if (options?.childrenContext) {
    description += `\nThis story uses mocked children components.`;

    const ChildrenContext = options.childrenContext.context;
    const safeValues = options.childrenContext.value as unknown as PossibleContextValueType & object;

    story.decorators.push((Story) => {
      return (
        <ChildrenContext.Provider value={safeValues}>
          <Story />
        </ChildrenContext.Provider>
      );
    });
  }

  story.parameters.docs.description = {
    story: description,
  };

  return story;
}
