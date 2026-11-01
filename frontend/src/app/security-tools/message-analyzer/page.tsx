"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  MessageSquare,
  ChevronRight,
  Shield,
  Radio,
  Server,
  Lock,
  Radar,
  FileCode,
  Flame,
  UserX,
  AlertCircle,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { Badge } from "@/components/ui/badge";
import {
  MessageAnalyzerForm,
  MessageAnalysisResults,
  MessageAnalysisError,
} from "@/components/investigation/message-analyzer";
import { messagesService } from "@/lib/api/services/messages";
import type { MessageAnalyzeResult, MessageApiError } from "@/types/messages";

function MessageAnalyzerWorkstation() {
  const searchParams = useSearchParams();
  const queryParam = searchParams.get("query") || searchParams.get("text") || "";

  const [message, setMessage] = React.useState<string>(queryParam);
  const [status, setStatus] = React.useState<"idle" | "evaluating" | "success" | "error">("idle");
  const [analysisResult, setAnalysisResult] = React.useState<MessageAnalyzeResult | null>(null);
  const [analysisError, setAnalysisError] = React.useState<MessageApiError | null>(null);

  // Pre-populate message if passed via query, but DO NOT auto-submit (strict analyst confirmation)
  React.useEffect(() => {
    if (queryParam) {
      setMessage(queryParam);
    }
  }, [queryParam]);

  const executeAnalysis = React.useCallback(async (text: string) => {
    const cleanText = text.trim();
    if (!cleanText) return;

    setStatus("evaluating");
    setAnalysisError(null);

    try {
      const res = await messagesService.analyzeMessage({ message: cleanText, source: "web" });
      setAnalysisResult(res);
      setStatus("success");
    } catch (err) {
      const classified = messagesService.classifyError(err);
      setAnalysisError(classified);
      setStatus("error");
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeAnalysis(message);
  };

  const handleReset = () => {
    setMessage("");
    setStatus("idle");
    setAnalysisResult(null);
    setAnalysisError(null);
  };

  const handleSelectPreset = (presetText: string) => {
    setMessage(presetText);
    executeAnalysis(presetText);
  };

  return (
    <PageContainer>
      <div className="space-y-6">
        {/* Breadcrumbs */}
        <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider">
          <Link href="/" className="hover:text-cyber-accent transition-colors">
            CYBERCORE
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <Link href="/security-tools" className="hover:text-cyber-accent transition-colors">
            SECURITY TOOLS
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <span className="text-cyber-accent">MESSAGE PHISHING ANALYZER</span>
        </div>

        {/* Editorial Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-cyber-border pb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-none bg-cyber-accent" />
              <span className="text-[10px] font-mono uppercase tracking-tactical text-cyber-accent">
                INVESTIGATION MODULE // THREAT VECTOR 02
              </span>
            </div>
            <h1 className="font-mono text-2xl md:text-3xl font-bold tracking-tight text-cyber-text-primary">
              MESSAGE PHISHING ANALYZER
            </h1>
            <p className="text-xs md:text-sm font-mono text-cyber-text-secondary max-w-2xl">
              Deterministic pattern-based detection engine evaluating SMS, email, and notification texts
              for urgency tactics, OTP fraud, brand impersonation, and social engineering signals.
            </p>
          </div>

          {/* Engine Status Indicators */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Badge variant="arctic" className="text-[10px] gap-1.5 py-1">
              <Server className="h-3 w-3" /> FASTAPI /api/v1/messages/analyze
            </Badge>
            <Badge variant="default" className="text-[10px] gap-1.5 py-1">
              <Lock className="h-3 w-3 text-cyber-threat-secure" /> ZERO RETENTION
            </Badge>
          </div>
        </div>

        {/* Input Workstation */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 lg:p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-cyber-accent" />
              <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                COMMUNICATION PAYLOAD INSPECTOR
              </h2>
            </div>
            <span className="text-[10px] font-mono text-cyber-text-dim">
              SYNCHRONOUS HEURISTIC BUS // ~10-30MS
            </span>
          </div>

          <MessageAnalyzerForm
            message={message}
            onMessageChange={setMessage}
            onSubmit={handleSubmit}
            isLoading={status === "evaluating"}
            onReset={handleReset}
            onSelectPreset={handleSelectPreset}
          />
        </div>

        {/* State Renderers */}

        {/* 1. Evaluating State */}
        {status === "evaluating" && (
          <div className="border border-cyber-border-strong bg-cyber-bg-surface p-12 text-center space-y-6">
            <div className="relative mx-auto w-16 h-16 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-cyber-accent/30 animate-ping opacity-75" />
              <div className="absolute inset-2 rounded-full border border-cyber-accent/60 animate-pulse" />
              <div className="relative p-3 bg-cyber-bg-secondary border border-cyber-accent text-cyber-accent">
                <Radar className="h-7 w-7 animate-spin" />
              </div>
            </div>

            <div className="space-y-2 font-mono">
              <div className="text-[11px] text-cyber-accent uppercase tracking-tactical flex items-center justify-center gap-2">
                <Radio className="h-3 w-3 animate-pulse" />
                <span>EVALUATING HEURISTIC RULES</span>
              </div>
              <h3 className="text-base font-semibold text-cyber-text-primary">
                Querying FastAPI /messages/analyze Engine
              </h3>
              <p className="text-xs text-cyber-text-dim max-w-md mx-auto">
                Parsing regex libraries • Extracting URLs • Inspecting urgency triggers • Classifying impersonation
              </p>
            </div>
          </div>
        )}

        {/* 2. Error State */}
        {status === "error" && analysisError && (
          <MessageAnalysisError
            error={analysisError}
            onRetry={() => executeAnalysis(message)}
            onReset={handleReset}
          />
        )}

        {/* 3. Success State */}
        {status === "success" && analysisResult && (
          <MessageAnalysisResults result={analysisResult} />
        )}

        {/* 4. Idle State */}
        {status === "idle" && (
          <div className="space-y-6">
            {/* Capabilities Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-accent">
                  <FileCode className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    Pattern-Based Detection
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Evaluates messages against active regex pattern libraries targeting OTP theft, KYC expiry
                  threats, lottery rewards, courier customs fees, and investment scams.
                </p>
              </div>

              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-threat-high">
                  <Flame className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    Social Engineering Signals
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Extracts psychological pressure tactics including artificial urgency, fear induction, false
                  exclusivity, secrecy demands, and fraudulent reassurance signals.
                </p>
              </div>

              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-threat-critical">
                  <UserX className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    Entity Impersonation
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Identifies spoofing of major banking institutions (HDFC, SBI, ICICI), tax departments,
                  law enforcement authorities, and popular delivery couriers.
                </p>
              </div>
            </div>

            {/* Honest Heuristic Notice */}
            <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2 font-mono text-xs">
              <div className="flex items-center gap-2 text-cyber-accent font-semibold text-[10px] uppercase tracking-wider">
                <AlertCircle className="h-3.5 w-3.5" />
                <span>HONEST ENGINE PRINCIPLES & LIMITATIONS</span>
              </div>
              <p className="text-[11px] text-cyber-text-secondary leading-relaxed">
                CYBERCORE utilizes transparent, deterministic regex heuristics and pattern taxonomies. This analysis
                does not use black-box machine-learning classifiers. Heuristic rule systems can produce false
                positives on legitimate administrative warnings and false negatives on novel, spear-phishing campaigns.
                Always verify sensitive requests through verified, out-of-band communication channels.
              </p>
            </div>
          </div>
        )}
      </div>
    </PageContainer>
  );
}

export default function MessageAnalyzerPage() {
  return (
    <React.Suspense
      fallback={
        <PageContainer>
          <div className="p-12 text-center font-mono text-xs text-cyber-text-dim">
            Loading investigation module...
          </div>
        </PageContainer>
      }
    >
      <MessageAnalyzerWorkstation />
    </React.Suspense>
  );
}

