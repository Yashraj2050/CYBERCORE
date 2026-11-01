"use client";

import * as React from "react";
import { Code, Copy, Check, Download, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";

interface IpDomainRawViewerProps {
  data: unknown;
  target: string;
}

export function IpDomainRawViewer({ data, target }: IpDomainRawViewerProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const jsonString = React.useMemo(() => {
    try {
      return JSON.stringify(data, null, 2);
    } catch {
      return "{}";
    }
  }, [data]);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const safeTarget = target.replace(/[^a-zA-Z0-9.-]/g, "_");
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeTarget}_intelligence.json`;
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
      <div className="flex items-center justify-between p-4 bg-cyber-bg-secondary border-b border-cyber-border">
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 text-xs font-mono font-semibold uppercase tracking-wider text-cyber-text-primary hover:text-cyber-accent transition-colors text-left"
        >
          <Code className="h-4 w-4 text-cyber-accent" />
          <span>TECHNICAL RAW PAYLOAD // JSON INSPECTION</span>
          {isOpen ? (
            <ChevronUp className="h-3.5 w-3.5 text-cyber-text-dim" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-cyber-text-dim" />
          )}
        </button>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleCopy}
            className="h-7 text-xs font-mono gap-1.5"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-cyber-threat-secure" />
                <span>COPIED</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                <span>COPY JSON</span>
              </>
            )}
          </Button>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleDownload}
            className="h-7 text-xs font-mono gap-1.5"
          >
            <Download className="h-3 w-3" />
            <span>DOWNLOAD</span>
          </Button>
        </div>
      </div>

      {isOpen && (
        <div className="p-4 bg-cyber-bg overflow-x-auto max-h-[500px]">
          <pre className="font-mono text-xs text-cyber-text-secondary leading-relaxed select-all">
            {jsonString}
          </pre>
        </div>
      )}
    </div>
  );
}

