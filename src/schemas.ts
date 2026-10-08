import { z } from "zod";

// Tolerant boundary schemas for `opencode session export` payloads.
// Unknown content parts are preserved as `unknown` + quarantine warning,
// never thrown away silently.

export const TokensSchema = z.object({
  input: z.number().optional(),
  output: z.number().optional(),
  reasoning: z.number().optional(),
  cache: z.object({ read: z.number().optional(), write: z.number().optional() }).catchall(z.unknown()).optional(),
}).catchall(z.unknown());

export const TimeSchema = z.object({
  created: z.number().optional(),
  completed: z.number().optional(),
  streamed: z.number().optional(),
  ran: z.number().optional(),
}).catchall(z.unknown());

const ToolStateSchema = z.object({
  status: z.string().optional(),
  input: z.unknown().optional(),
  output: z.unknown().optional(),
  content: z.unknown().optional(),
  error: z.unknown().optional(),
  metadata: z.unknown().optional(),
}).catchall(z.unknown());

const ToolContentSchema = z.object({
  type: z.literal("tool"),
  id: z.string().optional(),
  name: z.string().optional(),
  state: ToolStateSchema.optional(),
  time: TimeSchema.optional(),
  executed: z.unknown().optional(),
  providerState: z.unknown().optional(),
}).catchall(z.unknown());

const ReasoningContentSchema = z.object({
  type: z.literal("reasoning"),
  text: z.string().optional(),
  state: z.string().optional(),
  time: TimeSchema.optional(),
}).catchall(z.unknown());

const OtherContentSchema = z.object({ type: z.string() }).catchall(z.unknown());

const ContentSchema = z.union([ToolContentSchema, ReasoningContentSchema, OtherContentSchema]);

const AssistantMessageSchema = z.object({
  type: z.literal("assistant"),
  id: z.string().optional(),
  agent: z.string().optional(),
  model: z.unknown().optional(),
  content: z.array(ContentSchema).optional().default([]),
  tokens: TokensSchema.optional(),
  cost: z.number().optional(),
  finish: z.string().optional(),
  time: TimeSchema.optional(),
}).catchall(z.unknown());

const UserMessageSchema = z.object({
  type: z.literal("user"),
  id: z.string().optional(),
  text: z.string().optional(),
  time: TimeSchema.optional(),
}).catchall(z.unknown());

const MessageSchema = z.union([AssistantMessageSchema, UserMessageSchema, OtherContentSchema]);

export const SessionInfoSchema = z.object({
  id: z.string(),
  parentID: z.string().nullable().optional(),
  title: z.string().optional().default(""),
  agent: z.string().optional(),
  model: z.unknown().optional(),
  projectID: z.string().optional(),
  cost: z.number().optional(),
  tokens: TokensSchema.optional(),
  time: TimeSchema.optional(),
  location: z.unknown().optional(),
}).catchall(z.unknown());

export const SessionExportSchema = z.object({
  data: z.object({
    info: SessionInfoSchema,
    messages: z.array(MessageSchema).optional().default([]),
  }).catchall(z.unknown()),
}).catchall(z.unknown());

export type SessionExport = z.infer<typeof SessionExportSchema>;
export type SessionInfo = z.infer<typeof SessionInfoSchema>;
