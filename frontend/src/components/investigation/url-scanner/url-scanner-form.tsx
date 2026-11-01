"use client";

import * as React from "react";
import { Globe, Search, X, Loader2, ArrowRight, Shield, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface UrlScannerFormProps {
  url: string;
  onUrlChange: (url: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  onReset: () => void;
  onSelectPreset?: (presetUrl: string) => void;
}

const PRESET_TARGETS = [
  { label: "Cloudflare (1.1.1.1)", url: "https://1.1.1.1", type: "clean" },
  { label: "Google DNS (8.8.8.8)", url: "http://8.8.8.8", type: "clean" },
  { label: "SSRF Test (127.0.0.1)", url: "http://127.0.0.1", type: "ssrf" },
  { label: "SSRF Test (localhost)", url: "http://localhost:8000", type: "ssrf" },
];

export function UrlScannerForm({
  url,
  onUrlChange,
  onSubmit,
  isLoading,
  onReset,
  onSelectPreset,
}: UrlScannerFormProps) {
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const validateInput = (value: string): boolean => {
    const trimmed = value.trim();
    if (!trimmed) {
      setValidationError("Target URL or IP address is required.");
      return false;
    }

    if (trimmed.includes("://") && !trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setValidationError("Unsupported protocol. Only HTTP and HTTPS schemes are supported.");
      return false;
    }

    // Check basic URL format
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setValidationError("URL must include protocol scheme (http:// or https://).");
      return false;
    }

    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        setValidationError("Only HTTP and HTTPS protocols are permitted.");
        return false;
      }
      setValidationError(null);
      return true;
    } catch {
      setValidationError("Invalid URL format. Please provide a valid fully qualified domain or IP.");
      return false;
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    onUrlChange(val);
    if (validationError && val.trim()) {
      if (val.startsWith("http://") || val.startsWith("https://")) {
        setValidationError(null);
      }
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isLoading) return;

    let target = url.trim();
    // Only auto-prepend https:// if no protocol scheme exists at all
    if (target && !target.includes("://")) {
      target = `https://${target}`;
      onUrlChange(target);
    }

    if (!validateInput(target)) {
      return;
    }

    onSubmit(e);
  };

  const handleQuickProtocol = () => {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      onUrlChange(`https://${url.trim()}`);
      setValidationError(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Input Box */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex items-center rounded-none border border-cyber-border-strong bg-cyber-bg-secondary p-1 shadow-inner focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent/40 transition-all">
          <div className="flex items-center pl-3 pr-2 text-cyber-text-muted">
            <Globe className="h-4 w-4 shrink-0 text-cyber-accent" />
          </div>

          <input
            id="target-url-input"
            name="url"
            type="text"
            value={url}
            onChange={handleChange}
            placeholder="Enter target URL or IP (e.g. https://1.1.1.1 or https://example.com)..."
            disabled={isLoading}
            className="w-full bg-transparent px-2 py-2 text-xs md:text-sm font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none disabled:opacity-50"
            autoComplete="off"
            spellCheck="false"
          />

          <div className="flex items-center gap-1.5 pr-1">
            {url && !isLoading && (
              <button
                type="button"
                onClick={onReset}
                className="p-1.5 text-cyber-text-muted hover:text-cyber-text-primary hover:bg-cyber-bg-surface transition-colors"
                title="Clear input"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}

            <Button
              type="submit"
              variant="arctic"
              size="sm"
              disabled={isLoading || !url.trim()}
              className="gap-2 px-4 h-9 font-mono uppercase tracking-wider text-xs"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" />
                  <span>Scan Target</span>
                  <ArrowRight className="h-3.5 w-3.5 ml-0.5" />
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Validation warning */}
        {validationError && (
          <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-cyber-threat-high">
            <span>{validationError}</span>
            {!url.startsWith("http://") && !url.startsWith("https://") && url.trim().length > 0 && (
              <button
                type="button"
                onClick={handleQuickProtocol}
                className="underline hover:text-cyber-accent cursor-pointer ml-2"
              >
                Prepend https://
              </button>
            )}
          </div>
        )}
      </form>

      {/* Target Presets & Security Notice */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1 text-xs font-mono">
        {/* Preset quick buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center gap-1">
            <Sparkles className="h-3 w-3 text-cyber-accent" /> Test Targets:
          </span>
          {PRESET_TARGETS.map((preset) => (
            <button
              key={preset.url}
              type="button"
              disabled={isLoading}
              onClick={() => {
                if (onSelectPreset) {
                  onSelectPreset(preset.url);
                } else {
                  onUrlChange(preset.url);
                  setValidationError(null);
                }
              }}
              className="px-2 py-0.5 text-[10px] font-mono tracking-tight bg-cyber-bg-surface border border-cyber-border hover:border-cyber-accent/60 hover:text-cyber-accent text-cyber-text-secondary transition-colors"
            >
              {preset.label}
            </button>
          ))}
        </div>

        {/* SSRF & Defense note */}
        <div className="flex items-center gap-1.5 text-[10px] text-cyber-text-dim">
          <Shield className="h-3 w-3 text-cyber-accent/80" />
          <span>SSRF Filtering Active (RFC 1918 / Loopback Protected)</span>
        </div>
      </div>
    </div>
  );
}
