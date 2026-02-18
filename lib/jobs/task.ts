import { logger } from "./logger";
import { registerJobTags, setCurrentJobContext, updateProgress } from "./progress";
import { registerRun, updateRunStatus } from "./runs";

export type RunStatus =
  | "QUEUED"
  | "EXECUTING"
  | "COMPLETED"
  | "FAILED"
  | "CRASHED"
  | "CANCELED"
  | "SYSTEM_FAILURE";

interface TaskConfig<TPayload> {
  id: string;
  retry?: { maxAttempts: number };
  queue?: { concurrencyLimit: number };
  machine?: { preset: string };
  run: (payload: TPayload) => Promise<unknown>;
}

interface TriggerOptions {
  idempotencyKey?: string;
  tags?: string[];
  delay?: { until: Date } | string;
}

interface TaskHandle<TPayload> {
  id: string;
  trigger: (
    payload: TPayload,
    options?: TriggerOptions,
  ) => Promise<{ id: string }>;
  triggerAndWait: (
    payload: TPayload,
    options?: TriggerOptions,
  ) => Promise<unknown>;
  run: (payload: TPayload) => Promise<unknown>;
}

function generateJobId(): string {
  return `job_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

async function executeWithRetry<TPayload>(
  config: TaskConfig<TPayload>,
  payload: TPayload,
  jobId: string,
): Promise<unknown> {
  const maxAttempts = config.retry?.maxAttempts ?? 1;
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      setCurrentJobContext(jobId);
      const result = await config.run(payload);
      setCurrentJobContext(null);
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      logger.error(`Task ${config.id} failed (attempt ${attempt}/${maxAttempts})`, {
        jobId,
        error: lastError.message,
      });

      if (attempt < maxAttempts) {
        const delay = 1000 * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  setCurrentJobContext(null);
  throw lastError;
}

export function task<TPayload>(
  config: TaskConfig<TPayload>,
): TaskHandle<TPayload> {
  return {
    id: config.id,
    trigger: async (
      payload: TPayload,
      options?: TriggerOptions,
    ): Promise<{ id: string }> => {
      const jobId = generateJobId();
      const tags = options?.tags || [];
      const tagStr = tags.length > 0 ? ` [${tags.join(", ")}]` : "";

      if (tags.length > 0) {
        registerJobTags(jobId, tags);
      }
      registerRun(jobId, config.id, tags);

      logger.info(`Queuing task: ${config.id}${tagStr}`, { jobId });

      if (options?.delay && typeof options.delay === "object" && "until" in options.delay) {
        const delayMs = options.delay.until.getTime() - Date.now();
        if (delayMs > 0) {
          setTimeout(() => {
            updateRunStatus(jobId, "EXECUTING");
            executeWithRetry(config, payload, jobId)
              .then(() => updateRunStatus(jobId, "COMPLETED"))
              .catch((error) => {
                updateRunStatus(jobId, "FAILED");
                logger.error(`Delayed task ${config.id} failed`, {
                  jobId,
                  error: error instanceof Error ? error.message : String(error),
                });
              });
          }, delayMs);
          return { id: jobId };
        }
      }

      setImmediate(() => {
        updateRunStatus(jobId, "EXECUTING");
        executeWithRetry(config, payload, jobId)
          .then(() => updateRunStatus(jobId, "COMPLETED"))
          .catch((error) => {
            updateRunStatus(jobId, "FAILED");
            logger.error(`Background task ${config.id} failed`, {
              jobId,
              error: error instanceof Error ? error.message : String(error),
            });
          });
      });

      return { id: jobId };
    },
    triggerAndWait: async (
      payload: TPayload,
      options?: TriggerOptions,
    ): Promise<unknown> => {
      const jobId = generateJobId();
      logger.info(`Running task synchronously: ${config.id}`, { jobId });
      return executeWithRetry(config, payload, jobId);
    },
    run: config.run,
  };
}

export const metadata = {
  set: (key: string, value: unknown) => {
    if (key === "status" && value && typeof value === "object") {
      const { progress, text } = value as { progress: number; text: string };
      updateProgress({ progress, text });
    }
  },
};
