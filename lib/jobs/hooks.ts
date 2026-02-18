"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type RunStatus =
  | "QUEUED"
  | "EXECUTING"
  | "COMPLETED"
  | "FAILED"
  | "CRASHED"
  | "CANCELED"
  | "SYSTEM_FAILURE";

interface IDocumentProgressStatus {
  state: RunStatus;
  progress: number;
  text: string;
}

interface ProgressRun {
  id: string;
  status: RunStatus;
  metadata?: {
    status?: {
      progress: number;
      text: string;
    };
  };
}

export function useDocumentProgressStatus(
  documentVersionId: string,
  publicAccessToken: string | undefined,
) {
  const [status, setStatus] = useState<IDocumentProgressStatus>({
    state: "QUEUED",
    progress: 0,
    text: "Initializing...",
  });
  const [error, setError] = useState<Error | null>(null);
  const [run, setRun] = useState<ProgressRun | undefined>(undefined);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pollProgress = useCallback(async () => {
    if (!publicAccessToken || !documentVersionId) return;

    try {
      const response = await fetch(
        `/api/jobs/progress?tag=version:${documentVersionId}`,
        {
          headers: {
            Authorization: `Bearer ${publicAccessToken}`,
          },
        },
      );

      if (!response.ok) {
        if (response.status === 404) {
          return;
        }
        throw new Error("Failed to fetch progress");
      }

      const data = await response.json();

      if (data.status) {
        const newState: RunStatus =
          data.status.progress >= 100 ? "COMPLETED" : "EXECUTING";
        setStatus({
          state: newState,
          progress: data.status.progress,
          text: data.status.text,
        });

        const progressRun: ProgressRun = {
          id: data.jobId || documentVersionId,
          status: newState,
          metadata: { status: data.status },
        };
        setRun(progressRun);

        if (newState === "COMPLETED" && intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }
    } catch (err) {
      setError(
        err instanceof Error ? err : new Error("Failed to poll progress"),
      );
    }
  }, [documentVersionId, publicAccessToken]);

  useEffect(() => {
    if (!publicAccessToken || !documentVersionId) return;

    pollProgress();

    intervalRef.current = setInterval(pollProgress, 2000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [documentVersionId, publicAccessToken, pollProgress]);

  return { status, error, run };
}
