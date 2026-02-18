import { logger } from "./logger";

interface RunListOptions {
  taskIdentifier?: string[];
  tag?: string[];
  status?: string[];
  period?: string;
}

interface RunData {
  id: string;
  status: string;
  taskIdentifier: string;
}

interface RunListResult {
  data: RunData[];
}

type RunStatus = "QUEUED" | "EXECUTING" | "COMPLETED" | "FAILED";

const runStore = new Map<
  string,
  { id: string; status: RunStatus; taskIdentifier: string; tags: string[] }
>();

export function registerRun(
  jobId: string,
  taskId: string,
  tags: string[],
) {
  runStore.set(jobId, {
    id: jobId,
    status: "QUEUED",
    taskIdentifier: taskId,
    tags,
  });
}

export function updateRunStatus(jobId: string, status: RunStatus) {
  const run = runStore.get(jobId);
  if (run) {
    run.status = status;
  }
}

export const runs = {
  list: async (options: RunListOptions): Promise<RunListResult> => {
    const results: RunData[] = [];

    for (const run of runStore.values()) {
      if (options.tag && options.tag.length > 0) {
        const hasMatchingTag = options.tag.some((t) =>
          run.tags.some((rt) => rt === t || rt.includes(t) || t.includes(rt)),
        );
        if (!hasMatchingTag) continue;
      }

      if (
        options.taskIdentifier &&
        options.taskIdentifier.length > 0 &&
        !options.taskIdentifier.includes(run.taskIdentifier)
      ) {
        continue;
      }

      if (
        options.status &&
        options.status.length > 0 &&
        !options.status.includes(run.status)
      ) {
        continue;
      }

      results.push({
        id: run.id,
        status: run.status,
        taskIdentifier: run.taskIdentifier,
      });
    }

    return { data: results };
  },

  cancel: async (runId: string): Promise<void> => {
    const run = runStore.get(runId);
    if (run) {
      run.status = "FAILED";
      logger.info(`Run ${runId} cancelled`);
    } else {
      logger.debug(`runs.cancel called for unknown run ${runId}`);
    }
  },
};
