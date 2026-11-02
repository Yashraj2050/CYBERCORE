import { apiClient } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";
import type { MessageAnalyzeRequest, MessageAnalyzeResult, MessageApiError } from "@/types/messages";

/**
 * Service for executing synchronous message phishing and social engineering evaluations.
 * Communicates with FastAPI endpoint: POST /api/v1/messages/analyze
 */
export const messagesService = {
  /**
   * Dispatches a message for heuristic pattern inspection.
   */
  async analyzeMessage(request: MessageAnalyzeRequest): Promise<MessageAnalyzeResult> {
    try {
      const response = await apiClient.post<MessageAnalyzeResult>("/messages/analyze", {
        message: request.message?.trim() || request.text?.trim() || "",
        source: request.source || "web",
      });
      return response.data;
    } catch (err) {
      throw this.classifyError(err);
    }
  },

  /**
   * Normalizes network, validation, and HTTP errors into structured user-facing representations.
   */
  classifyError(err: unknown): MessageApiError {
    // If already normalized, return directly
    if (
      typeof err === "object" &&
      err !== null &&
      "status" in err &&
      "message" in err &&
      ("isBlank" in err || "isTooLong" in err || "detail" in err)
    ) {
      return err as MessageApiError;
    }

    if (err instanceof ApiError || (typeof err === "object" && err !== null && "status" in err && "payload" in err)) {
      const apiErr = err as ApiError;
      const rawDetail =
        typeof apiErr.payload === "object" && apiErr.payload !== null && "detail" in apiErr.payload
          ? (apiErr.payload as { detail: unknown }).detail
          : apiErr.message;

      let detailString = typeof rawDetail === "string" ? rawDetail : JSON.stringify(rawDetail);

      const isBlank = apiErr.status === 400 && detailString.toLowerCase().includes("cannot be blank");
      const isTooLong =
        apiErr.status === 422 &&
        (detailString.toLowerCase().includes("10000") || detailString.toLowerCase().includes("string_too_long"));

      let cleanMessage = apiErr.message;
      if (isBlank) {
        cleanMessage = "Validation Error: Message content cannot be empty or purely whitespace.";
      } else if (isTooLong) {
        cleanMessage = "Payload Length Exceeded: Submitted message exceeds the 10,000 character analysis boundary.";
      } else if (apiErr.status === 429) {
        cleanMessage = "Rate Limit Reached: Analysis quota exceeded. Please stand by.";
      } else if (apiErr.status >= 500) {
        cleanMessage = "Engine Error: The heuristic analysis service encountered an internal exception.";
      }

      return {
        status: apiErr.status,
        message: cleanMessage,
        detail: detailString,
        isBlank,
        isTooLong,
      };
    }

    if (err instanceof Error) {
      const isTimeout = err.name === "AbortError" || err.message.toLowerCase().includes("timeout");
      return {
        status: isTimeout ? 408 : 0,
        message: isTimeout
          ? "Request Timed Out: Analysis service took longer than 30s to respond."
          : "Backend Bus Unavailable: Unable to connect to the FastAPI backend service.",
        isTimeout,
        detail: err.message,
      };
    }

    return {
      status: 0,
      message: "An unknown execution error occurred during message analysis.",
    };
  },
};

