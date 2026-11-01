import { apiClient } from "@/lib/api/client";
import type { ChatRequest, ChatResponse, SuggestionsResponse } from "@/types/ai";

/**
 * Service for interacting with CYBERCORE AI Cybersecurity Advisor.
 * Contract aligns with OpenAPI spec for /api/v1/ai.
 */
export const aiService = {
  /**
   * Retrieves recommended security inquiry prompts from the backend.
   * GET /api/v1/ai/suggestions
   */
  async getSuggestions(): Promise<SuggestionsResponse> {
    const response = await apiClient.get<SuggestionsResponse>("/ai/suggestions");
    return response.data;
  },

  /**
   * Submits a question or investigation prompt to the AI Cybersecurity Advisor.
   * POST /api/v1/ai/chat
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    const response = await apiClient.post<ChatResponse>("/ai/chat", request);
    return response.data;
  },
};

