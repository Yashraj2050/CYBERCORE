/**
 * AI Assistant Types matching OpenAPI contract for CYBERCORE.
 */

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ChatRequest {
  message: string;
  history?: ChatMessage[];
}

export interface ChatResponse {
  response: string;
  suggested_followups: string[];
}

export interface SuggestionsResponse {
  suggestions: string[];
}

