import Rollbar from 'rollbar';

const codeVersion = process.env.VERCEL_GIT_COMMIT_SHA || 
                    process.env.REPL_ID || 
                    'development';

// Safe stringify that handles circular references
function safeStringify(obj: unknown, maxDepth = 3): string {
  const seen = new WeakSet();
  return JSON.stringify(obj, (key, value) => {
    if (maxDepth <= 0) return '[max depth]';
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[circular]';
      }
      seen.add(value);
    }
    // Skip problematic properties that cause serialization issues
    if (key === 'data' && typeof value === 'object' && value !== null && 'user' in value) {
      return '[session data]';
    }
    return value;
  });
}

const baseConfig: Rollbar.Configuration = {
  captureUncaught: true,
  captureUnhandledRejections: true,
  environment: process.env.NODE_ENV || 'development',
  codeVersion,
  payload: {
    client: {
      javascript: {
        source_map_enabled: true,
        code_version: codeVersion,
        guess_uncaught_frames: true,
      },
    },
    server: {
      root: 'webpack://fundroom-ai/',
    },
  },
};

const clientToken = process.env.NEXT_PUBLIC_ROLLBAR_CLIENT_TOKEN;

export const clientConfig: Rollbar.Configuration = {
  accessToken: clientToken || 'disabled',
  enabled: !!clientToken,
  ...baseConfig,
  captureIp: 'anonymize',
  verbose: false,
  reportLevel: 'warning',
  // Disable telemetry completely to prevent circular reference and stack overflow issues
  autoInstrument: false, // Completely disable auto-instrumentation
  // Limit payload depth to prevent stack overflow during serialization
  maxItems: 10, // Only report first 10 errors per page load
  itemsPerMinute: 5, // Rate limit to prevent flood
  // Limit payload size to prevent stack overflow
  scrubFields: ['password', 'secret', 'token', 'accessToken', 'refreshToken', 'data.user', 'data', 'session'],
  // NOTE: Don't use scrubPaths for body.telemetry - it converts to string which breaks Rollbar API
  // Instead, we set telemetry to empty array in transform function
  // Transform payload to handle circular references (mutates in place, no return)
  transform: (payload: Record<string, unknown>) => {
    // Safely handle any remaining circular references in custom data
    if (payload.custom) {
      try {
        payload.custom = JSON.parse(safeStringify(payload.custom, 2));
      } catch {
        payload.custom = { error: 'Unable to serialize custom data' };
      }
    }
    // Set telemetry to empty array to prevent serialization issues
    // (scrubPaths converts to string "********" which breaks Rollbar API)
    if ((payload as any).body) {
      (payload as any).body.telemetry = [];
    }
  },
  // Early check to prevent processing problematic errors entirely
  checkIgnore: (_isUncaught: boolean, args: Rollbar.LogArgument[]) => {
    const message = args[0];
    if (typeof message === 'string') {
      const ignorePatterns = [
        'client token verification',
        'token verification',
        'initialized',
        'maximum call stack',
        'call stack size exceeded',
        'script error',
      ];
      return ignorePatterns.some(pattern => 
        message.toLowerCase().includes(pattern)
      );
    }
    // Ignore RangeError stack overflow errors - these are often caused by Rollbar itself
    if (message instanceof Error) {
      if (message.name === 'RangeError' || 
          message.message?.toLowerCase().includes('call stack')) {
        return true;
      }
    }
    return false;
  },
  // Wrap uncaught error handler to prevent Rollbar stack overflow
  onSendCallback: (_isUncaught: boolean, args: Rollbar.LogArgument[], _payload: unknown) => {
    // This runs before sending - we can abort if we detect circular ref issues
    try {
      const firstArg = args[0];
      if (firstArg instanceof Error && firstArg.name === 'RangeError') {
        return false; // Don't send
      }
    } catch {
      return false; // Don't send if checking causes error
    }
  },
};

const serverToken = process.env.ROLLBAR_POST_SERVER_ITEM_ACCESS_TOKEN || process.env.ROLLBAR_SERVER_TOKEN;

export const serverInstance = new Rollbar({
  accessToken: serverToken || 'disabled',
  enabled: !!serverToken,
  ...baseConfig,
  verbose: process.env.NODE_ENV === 'development',
});

export function setRollbarUser(user: { id: string; email?: string; username?: string }) {
  serverInstance.configure({
    payload: {
      person: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
    },
  });
}

export function clearRollbarUser() {
  serverInstance.configure({
    payload: {
      person: undefined,
    },
  });
}
