"use client";

import * as React from "react";
import {
  Bot,
  Send,
  Sparkles,
  RefreshCw,
  AlertOctagon,
  User,
  ArrowRight,
  RotateCcw,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { aiService } from "@/lib/api/services/ai";
import type { ChatMessage } from "@/types/ai";

interface MessageItem {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  followups?: string[];
  isError?: boolean;
}

export default function AssistantPage() {
  const [prompt, setPrompt] = React.useState("");
  const [messages, setMessages] = React.useState<MessageItem[]>([]);
  const [sending, setSending] = React.useState(false);

  // Suggestions state
  const [suggestions, setSuggestions] = React.useState<string[]>([]);
  const [loadingSuggestions, setLoadingSuggestions] = React.useState(true);
  const [suggestionsError, setSuggestionsError] = React.useState<string | null>(null);

  const messagesEndRef = React.useRef<HTMLDivElement>(null);
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);

  // Auto-scroll conversation to latest entry
  React.useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  // Load entry-point suggestions from backend
  const loadSuggestions = React.useCallback(async () => {
    setLoadingSuggestions(true);
    setSuggestionsError(null);
    try {
      const data = await aiService.getSuggestions();
      setSuggestions(data.suggestions || []);
    } catch (err) {
      setSuggestionsError(
        err instanceof Error ? err.message : "Failed to load suggestions from backend"
      );
    } finally {
      setLoadingSuggestions(false);
    }
  }, []);

  React.useEffect(() => {
    loadSuggestions();
  }, [loadSuggestions]);

  // Dispatch prompt to backend AI chat service
  const handleSendMessage = async (textToSend?: string) => {
    const messageContent = (textToSend ?? prompt).trim();
    if (!messageContent || messageContent.length < 2 || sending) return;

    const userMessage: MessageItem = {
      id: `user-${Date.now()}`,
      role: "user",
      content: messageContent,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    // Add user message to conversation and clear input immediately
    setMessages((prev) => [...prev, userMessage]);
    setPrompt("");
    setSending(true);

    try {
      // Build history payload matching ChatRequest contract
      const historyPayload: ChatMessage[] = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const res = await aiService.chat({
        message: messageContent,
        history: historyPayload,
      });

      const assistantMessage: MessageItem = {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        content: res.response,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        followups: res.suggested_followups || [],
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      const errorMsg =
        err instanceof Error ? err.message : "Failed to communicate with the AI Advisor API.";
      const failureMessage: MessageItem = {
        id: `err-${Date.now()}`,
        role: "assistant",
        content: `API Error: ${errorMsg}\n\nPlease verify that the CYBERCORE backend is running and reachable, and has AI keys configured.`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        isError: true,
      };
      setMessages((prev) => [...prev, failureMessage]);
    } finally {
      setSending(false);
    }
  };

  // Keyboard navigation: Enter sends, Shift+Enter adds newline
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (prompt.trim().length >= 2 && !sending) {
        handleSendMessage();
      }
    }
  };

  const handleClearChat = () => {
    setMessages([]);
    setPrompt("");
  };

  const handleSelectSuggestion = (suggestion: string) => {
    setPrompt(suggestion);
    textareaRef.current?.focus();
  };

  const hasMessages = messages.length > 0;
  const canSubmit = prompt.trim().length >= 2 && !sending;

  return (
    <PageContainer>
      <PageHeader
        editorialTag="AI CYBERSECURITY ADVISOR // ASSISTED REASONING"
        title="AI Assistant"
        description="Conversational security guidance, alert clarification, and incident containment recommendations powered by the CYBERCORE AI advisor."
        badge={
          <Badge variant="arctic" radius="xs" dot>
            READY
          </Badge>
        }
        actions={
          hasMessages ? (
            <Button
              variant="outline"
              size="sm"
              onClick={handleClearChat}
              disabled={sending}
              className="gap-1.5 text-xs font-mono text-cyber-text-dim hover:text-cyber-text-primary"
            >
              <RotateCcw className="h-3 w-3" />
              <span>NEW CONVERSATION</span>
            </Button>
          ) : undefined
        }
      />

      <div className="glass-panel border border-cyber-border rounded-xs flex flex-col min-h-[560px] justify-between p-4 sm:p-5 space-y-4 relative group">
        {/* Corner Monolithic Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />

        {/* Conversation Thread or Initial Guidance */}
        <div className="flex-1 overflow-y-auto pr-1 space-y-4 max-h-[500px]">
          {!hasMessages ? (
            <div className="space-y-6 max-w-2xl mx-auto py-6 sm:py-8 text-center">
              <div className="flex h-12 w-12 items-center justify-center border border-cyber-accent/40 bg-cyber-accent-subtle rounded-xs mx-auto">
                <Bot className="h-6 w-6 text-cyber-accent" />
              </div>

              <div className="space-y-2">
                <h2 className="text-sm font-mono font-bold tracking-monolithic text-cyber-text-primary uppercase">
                  CYBERCORE AI Cybersecurity Advisor
                </h2>
                <p className="text-xs text-cyber-text-secondary leading-relaxed font-sans">
                  Direct conversational access to triage guidance. Inquire about suspicious attack vectors, clarify investigation findings, or request incident mitigation best practices.
                </p>
              </div>

              {/* Dynamic Backend Suggestions */}
              <div className="space-y-2 pt-2 text-left">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-tactical text-cyber-text-dim block">
                    RECOMMENDED INQUIRY ENTRY POINTS:
                  </span>
                  <button
                    type="button"
                    onClick={loadSuggestions}
                    disabled={loadingSuggestions}
                    className="text-[10px] font-mono text-cyber-accent hover:underline flex items-center gap-1 uppercase"
                    aria-label="Refresh suggestions"
                  >
                    <RefreshCw className={`h-2.5 w-2.5 ${loadingSuggestions ? "animate-spin" : ""}`} />
                    <span>Refresh</span>
                  </button>
                </div>

                {loadingSuggestions ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {[1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className="h-12 bg-cyber-bg border border-cyber-border rounded-xs animate-pulse"
                      />
                    ))}
                  </div>
                ) : suggestionsError ? (
                  <div className="p-4 bg-cyber-threat-critical-bg border border-cyber-threat-critical-border rounded-xs text-center space-y-2">
                    <div className="flex items-center justify-center gap-2 text-xs font-mono text-cyber-threat-critical">
                      <AlertOctagon className="h-3.5 w-3.5" />
                      <span>SUGGESTIONS OFFLINE: {suggestionsError}</span>
                    </div>
                    <Button size="xs" variant="outline" onClick={loadSuggestions}>
                      Retry API Bus
                    </Button>
                  </div>
                ) : suggestions.length === 0 ? (
                  <div className="p-4 border border-cyber-border bg-cyber-bg rounded-xs text-center text-xs font-mono text-cyber-text-dim">
                    No recommended suggestions currently returned by the backend.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {suggestions.map((p, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleSelectSuggestion(p)}
                        className="p-2.5 bg-cyber-bg hover:bg-cyber-bg-surface border border-cyber-border hover:border-cyber-accent/40 rounded-xs text-[11px] font-mono text-cyber-text-secondary hover:text-cyber-text-primary text-left transition-colors flex items-start justify-between gap-2"
                      >
                        <span className="leading-snug">{p}</span>
                        <Sparkles className="h-3 w-3 text-cyber-accent shrink-0 mt-0.5" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-4 pt-2">
              {/* Session Status Header */}
              <div className="flex items-center justify-between border-b border-cyber-border/60 pb-2 text-[10px] font-mono text-cyber-text-dim">
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyber-threat-secure animate-pulse" />
                  ACTIVE CONSULTATION LOG
                </span>
                <span>{messages.length} TURNS RECORDED</span>
              </div>

              {/* Messages Flow */}
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex flex-col space-y-1.5 ${
                    msg.role === "user" ? "items-end" : "items-start"
                  }`}
                >
                  <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-text-dim px-1">
                    {msg.role === "user" ? (
                      <>
                        <span>{msg.timestamp}</span>
                        <span className="text-cyber-accent font-semibold">ANALYST</span>
                        <User className="h-3 w-3 text-cyber-accent" />
                      </>
                    ) : (
                      <>
                        <Bot className="h-3.5 w-3.5 text-cyber-accent" />
                        <span className="text-cyber-text-primary font-semibold">
                          CYBERCORE AI ADVISOR
                        </span>
                        <span>{msg.timestamp}</span>
                      </>
                    )}
                  </div>

                  <div
                    className={`max-w-2xl rounded-xs p-3.5 text-xs font-mono leading-relaxed whitespace-pre-wrap break-words ${
                      msg.role === "user"
                        ? "bg-cyber-bg-surface border border-cyber-accent/30 text-cyber-text-primary shadow-sm"
                        : msg.isError
                        ? "bg-cyber-threat-critical-bg border border-cyber-threat-critical-border text-cyber-threat-critical"
                        : "bg-cyber-bg border border-cyber-border text-cyber-text-secondary"
                    }`}
                  >
                    {msg.content}
                  </div>

                  {/* Assistant Suggested Follow-ups */}
                  {msg.role === "assistant" && msg.followups && msg.followups.length > 0 && (
                    <div className="space-y-1.5 pt-1 max-w-2xl">
                      <span className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
                        SUGGESTED FOLLOW-UPS:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {msg.followups.map((followup, idx) => (
                          <button
                            key={idx}
                            type="button"
                            disabled={sending}
                            onClick={() => handleSendMessage(followup)}
                            className="text-[11px] font-mono px-2.5 py-1 bg-cyber-bg hover:bg-cyber-bg-surface border border-cyber-border hover:border-cyber-accent/40 rounded-xs text-cyber-text-secondary hover:text-cyber-text-primary text-left transition-colors flex items-center gap-1.5 disabled:opacity-50"
                          >
                            <span>{followup}</span>
                            <ArrowRight className="h-2.5 w-2.5 text-cyber-accent shrink-0" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {/* Waiting Indicator */}
              {sending && (
                <div className="flex flex-col items-start space-y-1.5">
                  <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-text-dim px-1">
                    <Bot className="h-3.5 w-3.5 text-cyber-accent animate-spin" />
                    <span className="text-cyber-text-primary font-semibold">CYBERCORE AI ADVISOR</span>
                    <span>THINKING</span>
                  </div>
                  <div className="p-3 bg-cyber-bg border border-cyber-accent/30 rounded-xs flex items-center gap-2 text-xs font-mono text-cyber-accent">
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Analyzing inquiry and synthesizing advisory guidance...</span>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div className="border-t border-cyber-border/70 pt-3 space-y-2">
          <div className="relative flex items-center bg-cyber-bg border border-cyber-border rounded-xs focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent">
            <textarea
              ref={textareaRef}
              id="assistant-prompt-input"
              name="assistantPrompt"
              aria-label="Security inquiry prompt"
              rows={2}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={sending}
              placeholder="Ask the AI Advisor a security question, clarify an alert, or request guidance..."
              className="w-full bg-transparent px-3 py-2 pr-28 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none resize-none disabled:opacity-50"
            />
            <div className="absolute right-3 bottom-2.5 flex items-center gap-2">
              <Button
                variant="default"
                size="sm"
                disabled={!canSubmit}
                className="h-7 px-3 gap-1.5"
                onClick={() => handleSendMessage()}
              >
                {sending ? (
                  <>
                    <RefreshCw className="h-3 w-3 animate-spin" />
                    <span>TRANSMITTING...</span>
                  </>
                ) : (
                  <>
                    <span>TRANSMIT</span>
                    <Send className="h-3 w-3" />
                  </>
                )}
              </Button>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-[10px] font-mono text-cyber-text-dim gap-1 px-1">
            <span>BACKEND: POST /api/v1/ai/chat</span>
            <span>PRESS ENTER TO TRANSMIT // SHIFT+ENTER FOR NEWLINE</span>
          </div>

          <p className="text-[10px] text-cyber-text-dim leading-snug font-sans px-1">
            Advisory Notice: Guidance is provided for triage and informational purposes by the CYBERCORE AI module. Always verify findings against official enterprise security policies.
          </p>
        </div>
      </div>
    </PageContainer>
  );
}
