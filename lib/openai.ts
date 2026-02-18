import OpenAI from "openai";

const hasUserOpenAIKey = Boolean(process.env.OPENAI_API_KEY);
const hasReplitAI = Boolean(
  process.env.AI_INTEGRATIONS_OPENAI_API_KEY && 
  process.env.AI_INTEGRATIONS_OPENAI_BASE_URL
);

const primaryOpenAI = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || process.env.AI_INTEGRATIONS_OPENAI_API_KEY || "",
  baseURL: hasUserOpenAIKey ? undefined : process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

const fallbackOpenAI = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY || "",
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

function isQuotaOrRateLimitError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  
  const e = error as { status?: number; code?: string; message?: string; error?: { type?: string } };
  
  if (e.status === 429) return true;
  if (e.status === 503) return true;
  
  const rateLimitCodes = [
    "insufficient_quota",
    "rate_limit_exceeded",
    "tokens_exceeded",
    "requests_limit_reached",
    "billing_hard_limit_reached",
  ];
  if (e.code && rateLimitCodes.includes(e.code)) return true;
  
  const message = e.message?.toLowerCase() || "";
  const rateLimitKeywords = ["quota", "exceeded", "rate limit", "too many requests", "billing"];
  if (rateLimitKeywords.some(keyword => message.includes(keyword))) return true;
  
  if (e.error?.type === "insufficient_quota") return true;
  
  return false;
}

function logFallback(operation: string, error: unknown): void {
  const e = error as { status?: number; code?: string; message?: string };
  console.log(
    `[OpenAI Fallback] ${operation}: Primary failed (status=${e.status}, code=${e.code}), switching to Replit AI`
  );
}

export async function createChatCompletion(
  params: OpenAI.ChatCompletionCreateParamsNonStreaming
): Promise<OpenAI.ChatCompletion> {
  if (!hasUserOpenAIKey && hasReplitAI) {
    return await fallbackOpenAI.chat.completions.create(params);
  }
  
  try {
    return await primaryOpenAI.chat.completions.create(params);
  } catch (error) {
    if (isQuotaOrRateLimitError(error) && hasReplitAI) {
      logFallback("createChatCompletion", error);
      return await fallbackOpenAI.chat.completions.create(params);
    }
    throw error;
  }
}

export async function* createChatCompletionStream(
  params: OpenAI.ChatCompletionCreateParamsStreaming
): AsyncGenerator<OpenAI.ChatCompletionChunk> {
  if (!hasUserOpenAIKey && hasReplitAI) {
    const stream = await fallbackOpenAI.chat.completions.create(params);
    for await (const chunk of stream) {
      yield chunk;
    }
    return;
  }
  
  try {
    const stream = await primaryOpenAI.chat.completions.create(params);
    for await (const chunk of stream) {
      yield chunk;
    }
  } catch (error) {
    if (isQuotaOrRateLimitError(error) && hasReplitAI) {
      logFallback("createChatCompletionStream", error);
      const stream = await fallbackOpenAI.chat.completions.create(params);
      for await (const chunk of stream) {
        yield chunk;
      }
    } else {
      throw error;
    }
  }
}

export async function createEmbedding(
  params: OpenAI.EmbeddingCreateParams
): Promise<OpenAI.CreateEmbeddingResponse> {
  try {
    return await primaryOpenAI.embeddings.create(params);
  } catch (error) {
    if (isQuotaOrRateLimitError(error) && hasReplitAI) {
      logFallback("createEmbedding", error);
      return await fallbackOpenAI.embeddings.create(params);
    }
    throw error;
  }
}

export async function generateImage(
  params: OpenAI.ImageGenerateParams
): Promise<OpenAI.ImagesResponse> {
  if (!hasUserOpenAIKey && hasReplitAI) {
    const result = await fallbackOpenAI.images.generate(params);
    return result as OpenAI.ImagesResponse;
  }
  
  try {
    const result = await primaryOpenAI.images.generate(params);
    return result as OpenAI.ImagesResponse;
  } catch (error) {
    if (isQuotaOrRateLimitError(error) && hasReplitAI) {
      logFallback("generateImage", error);
      const fallbackResult = await fallbackOpenAI.images.generate(params);
      return fallbackResult as OpenAI.ImagesResponse;
    }
    throw error;
  }
}

export const openai = primaryOpenAI;
export { primaryOpenAI, fallbackOpenAI };
