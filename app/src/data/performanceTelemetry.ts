export type PerformanceKind =
  | "LLM Reasoning"
  | "RAG Retrieval"
  | "Embedding"
  | "Retry/Repair";

export type PerformanceStatus = "Healthy" | "Slow" | "Failed" | "Not Run";

export type GenerationParameterValue = string | number | boolean | string[] | null;
export type GenerationParameters = Record<string, GenerationParameterValue>;

export interface ObservedPerformanceConfiguration {
  provider: string | null;
  model: string | null;
  modelFamily: string | null;
  modelTag: string | null;
  parameterSize: string | null;
  generationParameters: GenerationParameters;
  callCount: number;
}

export interface PerformanceModelSummary {
  provider: string | null;
  model: string;
  modelFamily: string | null;
  modelTag: string | null;
  parameterSize: string | null;
  configured?: boolean;
  callCount: number;
  averageDurationMs: number | null;
  p95DurationMs: number | null;
  totalTokens: number;
  operationIds: string[];
}

export interface PerformanceTelemetryRecord {
  id: string;
  section: string;
  operation: string;
  kind: PerformanceKind;
  sourceFile: string;
  sourceFunction: string;
  callCount: number;
  successCount: number;
  failureCount: number;
  lastDurationMs: number | null;
  averageDurationMs: number | null;
  p95DurationMs: number | null;
  totalDurationMs: number;
  status: PerformanceStatus;
  lastRunAt: string | null;
  description: string;
  provider: string | null;
  model: string | null;
  modelFamily: string | null;
  modelTag: string | null;
  parameterSize: string | null;
  generationParameters: GenerationParameters;
  promptTokens: number | null;
  completionTokens: number | null;
  totalTokens: number | null;
  ollamaTotalDurationMs: number | null;
  ollamaLoadDurationMs: number | null;
  ollamaPromptEvalDurationMs: number | null;
  ollamaEvalDurationMs: number | null;
  doneReason: string | null;
  observedConfigurations: ObservedPerformanceConfiguration[];
}

export const PERFORMANCE_EXECUTION_POINT_TOTAL = 36;
