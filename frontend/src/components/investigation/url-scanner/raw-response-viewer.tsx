"use client";

import * as React from "react";
import { Code, Copy, Check, Download, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { UrlScanResult } from "@/types/scanner";

interface RawResponseViewerProps {
  scan: UrlScanResult;
}

export function RawResponseViewer({ scan }: RawResponseViewerProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const jsonString = React.useMemo(() => {
    return JSON.stringify(scan, null, 2);
  }, [scan]);

  const byteLength = React.useMemo(() => {
    return new Blob([jsonString]).size;
  }, [jsonString]);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = () => {
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan_${scan.scan_id || "telemetry"}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="glass-panel border border-cyber-border-strong rounded-xs relative group overflow-hidden">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />
      {/* Accordion Trigger */}
      <div className="flex items-center justify-between p-4 bg-cyber-bg-secondary border-b border-cyber-border">
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 text-left font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary hover:text-cyber-accent transition-colors"
        >
          <Code className="h-4 w-4 text-cyber-accent" />
          <span>RAW TELEMETRY / OPENAPI PAYLOAD</span>
          <span className="text-[10px] text-cyber-text-dim lowercase font-normal ml-2">
            ({byteLength} bytes)
          </span>
          {isOpen ? (
            <ChevronUp className="h-3.5 w-3.5 text-cyber-text-muted ml-1" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-cyber-text-muted ml-1" />
          )}
        </button>

        {isOpen && (
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={copyToClipboard}
              className="h-7 px-2.5 text-[10px] font-mono uppercase tracking-wider"
            >
              {copied ? (
                <>
                  <Check className="h-3 w-3 text-cyber-threat-secure mr-1" /> Copied
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3 mr-1" /> Copy JSON
                </>
              )}
            </Button>

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={downloadJson}
              className="h-7 px-2.5 text-[10px] font-mono uppercase tracking-wider"
            >
              <Download className="h-3 w-3 mr-1" /> Export
            </Button>
          </div>
        )}
      </div>

      {/* Expandable JSON Content */}
      {isOpen && (
        <div className="p-4 bg-cyber-bg">
          <pre className="max-h-96 overflow-x-auto overflow-y-auto p-4 bg-cyber-bg-secondary border border-cyber-border text-xs font-mono text-cyber-text-secondary leading-relaxed select-all">
            {jsonString}
          </pre>
        </div>
      )}
    </div>
  );
}

