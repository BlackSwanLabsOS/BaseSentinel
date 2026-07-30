/**
 * Structural Eliza types so this package typechecks without installing
 * `@elizaos/core` in the BaseSentinel monorepo. Consumers with real Eliza
 * pass this plugin into AgentRuntime — shapes match documented Action/Plugin.
 */
export type HandlerCallback = (response: {
  text?: string;
  content?: unknown;
  actions?: string[];
  error?: string;
}) => Promise<unknown>;

export interface ElizaMemory {
  content?: {
    text?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface ElizaAction {
  name: string;
  similes?: string[];
  description: string;
  examples?: Array<
    Array<{
      name: string;
      content: { text?: string; actions?: string[] };
    }>
  >;
  validate: (
    runtime: unknown,
    message: ElizaMemory,
    state?: unknown,
  ) => Promise<boolean>;
  handler: (
    runtime: unknown,
    message: ElizaMemory,
    state?: unknown,
    options?: Record<string, unknown>,
    callback?: HandlerCallback,
  ) => Promise<{
    success: boolean;
    text?: string;
    error?: string;
    data?: unknown;
  }>;
}

export interface ElizaPlugin {
  name: string;
  description: string;
  actions: ElizaAction[];
  providers?: unknown[];
  evaluators?: unknown[];
  services?: unknown[];
}
