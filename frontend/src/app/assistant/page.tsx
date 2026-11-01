"use client";

import * as React from "react";
import {
  Bot,
  Send,
  Sparkles,
  RefreshCw,
  AlertOctagon,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { aiService } from "@/lib/api/services/ai";

export default function AssistantPage() {
  const [prompt, setPrompt] = React.useState("");
  const [suggestions, setSuggestions] = React.useState<string[]>([]);
  const [loadingSuggestions, setLoadingSuggestions] = React.useState(true);
  const [suggestionsError, setSuggestionsError] = React.useState<string | null>(null);

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
      />

      <div className="glass-panel border border-cyber-border rounded-xs flex flex-col min-h-[500px] justify-between p-5 space-y-6 relative group">
        {/* Corner Monolithic Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
        {/* Initial Empty / Guidance State */}
        <div className="space-y-6 max-w-2xl mx-auto py-8 text-center">
          <div className="flex h-12 w-12 items-center justify-center border border-cyber-accent/40 bg-cyber-accent-subtle rounded-xs mx-auto">
            <Bot className="h-6 w-6 text-cyber-accent" />
          </div>

          <div className="space-y-2">
            <h2 className="text-sm font-mono font-bold tracking-monolithic text-cyber-text-primary uppercase">
              CYBERCORE AI Cybersecurity Advisor
            </h2>
            <p className="text-xs text-cyber-text-secondary leading-relaxed font-sans">
              Direct conversational access to security guidance. Query common attack vectors, clarify suspicious alerts, or request standard incident containment best practices.
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
                    onClick={() => setPrompt(p)}
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

        {/* Input Bar */}
        <div className="border-t border-cyber-border/70 pt-4 space-y-2">
          <div className="relative flex items-center bg-cyber-bg border border-cyber-border rounded-xs focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent">
            <textarea
              id="assistant-prompt-input"
              name="assistantPrompt"
              aria-label="Security inquiry prompt"
              rows={2}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Ask the AI Advisor a security question, clarify an alert, or request guidance..."
              className="w-full bg-transparent px-3 py-2 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none resize-none"
            />
            <div className="absolute right-3 bottom-2.5 flex items-center gap-2">
              <Button
                variant="default"
                size="sm"
                disabled={!prompt.trim()}
                className="h-7 px-3 gap-1.5"
                onClick={() => {
                  alert(`Prompt queued for AI Assistant: ${prompt}`);
                  setPrompt("");
                }}
              >
                <span>TRANSMIT</span>
                <Send className="h-3 w-3" />
              </Button>
            </div>
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-cyber-text-dim px-1">
            <span>BACKEND: POST /api/v1/ai/chat</span>
            <span>PRESS ENTER OR CLICK TRANSMIT</span>
          </div>
        </div>
      </div>
    </PageContainer>
  );
}
