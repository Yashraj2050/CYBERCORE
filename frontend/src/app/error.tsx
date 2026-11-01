"use client";

import * as React from "react";
import Link from "next/link";
import { AlertOctagon, RotateCcw, Home } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  React.useEffect(() => {
    // Log unexpected client-side crash for diagnostics
    console.error("[CYBERCORE] Unhandled Application Exception:", error);
  }, [error]);

  return (
    <div className="flex-1 flex flex-col items-center justify-center p-6 min-h-[60vh]">
      <div className="w-full max-w-lg glass-panel border border-threat-critical/40 p-6 sm:p-8 space-y-6 text-center">
        {/* Tactical Error Header */}
        <div className="flex flex-col items-center space-y-3">
          <div className="w-12 h-12 rounded-sm bg-threat-critical/10 border border-threat-critical/30 flex items-center justify-center text-threat-critical">
            <AlertOctagon className="w-6 h-6 animate-pulse" />
          </div>
          <div className="space-y-1">
            <span className="text-[10px] font-mono tracking-widest uppercase text-threat-critical">
              {"// TELEMETRY RUNTIME EXCEPTION"}
            </span>
            <h2 className="text-xl font-bold tracking-tight text-cyber-text-primary font-mono">
              SYSTEM FAULT DETECTED
            </h2>
          </div>
        </div>

        {/* Diagnostic Output */}
        <div className="bg-cyber-bg-secondary border border-cyber-border p-3 text-left font-mono text-[11px] text-cyber-text-muted overflow-x-auto max-h-36">
          <p className="text-threat-critical font-semibold mb-1">
            {error.name || "Error"}: {error.message || "An unexpected error occurred during execution."}
          </p>
          {error.digest && (
            <p className="text-cyber-text-dim text-[10px] mt-1">
              DIGEST: {error.digest}
            </p>
          )}
        </div>

        {/* Recovery Action Controls */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Button
            onClick={() => reset()}
            className="w-full sm:w-auto h-9 px-4 text-xs font-mono font-semibold bg-cyber-accent text-cyber-text-inverse hover:bg-cyber-accent-hover flex items-center justify-center gap-2"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            RETRY EXECUTION
          </Button>

          <Link href="/" className="w-full sm:w-auto">
            <Button
              variant="outline"
              className="w-full h-9 px-4 text-xs font-mono border-cyber-border hover:bg-cyber-bg-surface-hover text-cyber-text-secondary flex items-center justify-center gap-2"
            >
              <Home className="w-3.5 h-3.5" />
              RETURN OVERVIEW
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
