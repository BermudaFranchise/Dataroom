const formatMeta = (meta?: Record<string, unknown>): string => {
  if (!meta || Object.keys(meta).length === 0) return "";
  try {
    return " " + JSON.stringify(meta);
  } catch {
    return "";
  }
};

export const logger = {
  info: (message: string, meta?: Record<string, unknown>) => {
    console.log(`[JOB:INFO] ${message}${formatMeta(meta)}`);
  },
  error: (message: string, meta?: Record<string, unknown>) => {
    console.error(`[JOB:ERROR] ${message}${formatMeta(meta)}`);
  },
  warn: (message: string, meta?: Record<string, unknown>) => {
    console.warn(`[JOB:WARN] ${message}${formatMeta(meta)}`);
  },
  debug: (message: string, meta?: Record<string, unknown>) => {
    if (process.env.NODE_ENV === "development") {
      console.log(`[JOB:DEBUG] ${message}${formatMeta(meta)}`);
    }
  },
};
