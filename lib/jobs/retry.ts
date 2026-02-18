import { logger } from "./logger";

interface RetryByStatus {
  [statusRange: string]: {
    strategy: "backoff";
    maxAttempts: number;
    factor: number;
    minTimeoutInMs: number;
    maxTimeoutInMs: number;
    randomize: boolean;
  };
}

interface RetryFetchOptions extends RequestInit {
  retry?: {
    byStatus?: RetryByStatus;
  };
}

function matchesStatusRange(status: number, range: string): boolean {
  if (range.includes("-")) {
    const [min, max] = range.split("-").map(Number);
    return status >= min && status <= max;
  }
  return status === Number(range);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const retry = {
  fetch: async (
    url: string | URL,
    options?: RetryFetchOptions,
  ): Promise<Response> => {
    const { retry: retryConfig, ...fetchOptions } = options || {};
    const byStatus = retryConfig?.byStatus || {};

    let lastResponse: Response | undefined;
    let lastError: Error | undefined;

    const maxOverallAttempts = 4;

    for (let attempt = 0; attempt < maxOverallAttempts; attempt++) {
      try {
        const response = await fetch(url.toString(), fetchOptions);

        let shouldRetry = false;
        let retryOptions:
          | RetryByStatus[string]
          | undefined;

        for (const [range, config] of Object.entries(byStatus)) {
          if (matchesStatusRange(response.status, range)) {
            shouldRetry = true;
            retryOptions = config;
            break;
          }
        }

        if (!shouldRetry || !retryOptions || attempt >= retryOptions.maxAttempts) {
          return response;
        }

        lastResponse = response;

        const baseDelay = Math.min(
          retryOptions.minTimeoutInMs * Math.pow(retryOptions.factor, attempt),
          retryOptions.maxTimeoutInMs,
        );
        const delay = retryOptions.randomize
          ? baseDelay * (0.5 + Math.random())
          : baseDelay;

        logger.warn(`Retrying fetch (attempt ${attempt + 1})`, {
          url: url.toString(),
          status: response.status,
          delay,
        });

        await sleep(delay);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < maxOverallAttempts - 1) {
          const delay = 1000 * Math.pow(2, attempt);
          logger.warn(`Fetch error, retrying (attempt ${attempt + 1})`, {
            url: url.toString(),
            error: lastError.message,
            delay,
          });
          await sleep(delay);
        }
      }
    }

    if (lastResponse) return lastResponse;
    throw lastError || new Error(`Failed to fetch ${url} after retries`);
  },
};
