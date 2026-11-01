"use client";

import * as React from "react";
import "./globals.css";
import { AlertOctagon, RotateCcw } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  React.useEffect(() => {
    console.error("[CYBERCORE] Critical Root Boundary Fault:", error);
  }, [error]);

  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-cyber-bg text-cyber-text-primary font-sans antialiased flex flex-col items-center justify-center p-6">
        <div className="w-full max-w-lg glass-panel border border-threat-critical/40 p-6 sm:p-8 space-y-6 text-center">
          <div className="flex flex-col items-center space-y-3">
            <div className="w-12 h-12 rounded-sm bg-threat-critical/10 border border-threat-critical/30 flex items-center justify-center text-threat-critical">
              <AlertOctagon className="w-6 h-6 animate-pulse" />
            </div>
            <div className="space-y-1">
              <span className="text-[10px] font-mono tracking-widest uppercase text-threat-critical">
                {"// CRITICAL APPLICATION CRASH"}
              </span>
              <h2 className="text-xl font-bold tracking-tight text-cyber-text-primary font-mono">
                ROOT KERNEL FAULT
              </h2>
            </div>
          </div>

          <div className="bg-cyber-bg-secondary border border-cyber-border p-3 text-left font-mono text-[11px] text-cyber-text-muted overflow-x-auto max-h-36">
            <p className="text-threat-critical font-semibold mb-1">
              {error.name || "CriticalError"}: {error.message || "An unrecoverable system exception occurred."}
            </p>
            {error.digest && (
              <p className="text-cyber-text-dim text-[10px] mt-1">
                DIGEST: {error.digest}
              </p>
            )}
          </div>

          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              onClick={() => reset()}
              type="button"
              className="h-9 px-4 text-xs font-mono font-semibold bg-cyber-accent text-cyber-text-inverse hover:bg-cyber-accent-hover flex items-center justify-center gap-2 rounded-sm cursor-pointer transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              RELOAD APPLICATION
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
