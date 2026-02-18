import { z } from "zod";

const ZDocumentProgressStatus = z.object({
  progress: z.number(),
  text: z.string(),
});

type TDocumentProgressStatus = z.infer<typeof ZDocumentProgressStatus>;

const ZDocumentProgressMetadata = z.object({
  status: ZDocumentProgressStatus,
});

const progressStore = new Map<string, TDocumentProgressStatus>();
const tagToJobMap = new Map<string, string>();
const jobToTagsMap = new Map<string, string[]>();

let currentJobId: string | null = null;

export function setCurrentJobContext(jobId: string | null) {
  currentJobId = jobId;
}

export function registerJobTags(jobId: string, tags: string[]) {
  jobToTagsMap.set(jobId, tags);
  for (const tag of tags) {
    tagToJobMap.set(tag, jobId);
  }
}

export function updateProgress(status: TDocumentProgressStatus) {
  if (currentJobId) {
    progressStore.set(currentJobId, status);
  }
}

export function updateProgressForJob(
  jobId: string,
  status: TDocumentProgressStatus,
) {
  progressStore.set(jobId, status);
}

export function getProgress(
  jobId: string,
): TDocumentProgressStatus | undefined {
  return progressStore.get(jobId);
}

export function getProgressByTag(
  tag: string,
): { jobId: string; status: TDocumentProgressStatus } | undefined {
  const jobId = tagToJobMap.get(tag);
  if (jobId) {
    const status = progressStore.get(jobId);
    if (status) {
      return { jobId, status };
    }
  }

  for (const [jid, tags] of jobToTagsMap.entries()) {
    if (tags.some((t) => t === tag || t.includes(tag) || tag.includes(t))) {
      const status = progressStore.get(jid);
      if (status) {
        return { jobId: jid, status };
      }
    }
  }

  return undefined;
}

export function clearProgress(jobId: string) {
  progressStore.delete(jobId);
  const tags = jobToTagsMap.get(jobId);
  if (tags) {
    for (const tag of tags) {
      tagToJobMap.delete(tag);
    }
    jobToTagsMap.delete(jobId);
  }
}

export function parseStatus(data: unknown): TDocumentProgressStatus {
  if (data && typeof data === "object" && "status" in data) {
    return ZDocumentProgressMetadata.parse(data).status;
  }
  return ZDocumentProgressStatus.parse(data);
}

export type { TDocumentProgressStatus };
