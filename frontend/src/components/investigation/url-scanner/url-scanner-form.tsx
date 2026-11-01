"use client";

import * as React from "react";
import { Globe, Search, X, Loader2, ArrowRight, Shield, Sparkles, Hash, Database } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ScanMode } from "@/types/scanner";

interface UrlScannerFormProps {
  url: string;
  onUrlChange: (url: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  onReset: () => void;
  onSelectPreset?: (presetUrl: string) => void;
  mode?: ScanMode;
  onModeChange?: (mode: ScanMode) => void;
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
  mode = "scan",
  onModeChange,
}: UrlScannerFormProps) {
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const validateInput = (value: string): boolean => {
    const trimmed = value.trim();
    if (!trimmed) {
      setValidationError(
        mode === "lookup_id"
          ? "Scan ID is required."
          : mode === "lookup_domain"
          ? "Domain name is required."
          : "Target URL or IP address is required."
      );
      return false;
    }

    if (mode === "lookup_id") {
      if (trimmed.length < 8) {
        setValidationError("Scan ID must be a valid identifier (e.g., UUID).");
        return false;
      }
      setValidationError(null);
      return true;
    }

    if (mode === "lookup_domain") {
      let clean = trimmed;
      if (clean.includes("://")) clean = clean.split("://")[1] || clean;
      if (clean.includes("/")) clean = clean.split("/")[0] || clean;
      if (!clean.includes(".")) {
        setValidationError("Please enter a valid domain name (e.g., example.com).");
        return false;
      }
      setValidationError(null);
      return true;
    }

    // Default URL validation mode
    if (trimmed.includes("://") && !trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setValidationError("Unsupported protocol. Only HTTP and HTTPS schemes are supported.");
      return false;
    }

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
      setValidationError(null);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isLoading) return;

    let target = url.trim();
    if (mode === "scan") {
      // Auto-prepend https:// if no protocol scheme exists at all
      if (target && !target.includes("://")) {
        target = `https://${target}`;
        onUrlChange(target);
      }
    } else if (mode === "lookup_domain") {
      // Strip scheme/path if user entered a full URL
      if (target.includes("://")) target = target.split("://")[1] || target;
      if (target.includes("/")) target = target.split("/")[0] || target;
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
      {/* Mode Switcher Tabs */}
      {onModeChange && (
        <div className="flex items-center gap-1 border-b border-cyber-border pb-2 text-xs font-mono">
          <button
            type="button"
            onClick={() => {
              onModeChange("scan");
              setValidationError(null);
            }}
            disabled={isLoading}
            className={`px-3 py-1 text-[11px] uppercase tracking-wider transition-colors border ${
              mode === "scan"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent-subtle"
                : "border-transparent text-cyber-text-dim hover:text-cyber-text-primary"
            }`}
          >
            <Globe className="h-3 w-3 inline mr-1.5" />
            LIVE URL SCAN
          </button>

          <button
            type="button"
            onClick={() => {
              onModeChange("lookup_id");
              setValidationError(null);
            }}
            disabled={isLoading}
            className={`px-3 py-1 text-[11px] uppercase tracking-wider transition-colors border ${
              mode === "lookup_id"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent-subtle"
                : "border-transparent text-cyber-text-dim hover:text-cyber-text-primary"
            }`}
          >
            <Hash className="h-3 w-3 inline mr-1.5" />
            LOOKUP BY SCAN ID
          </button>

          <button
            type="button"
            onClick={() => {
              onModeChange("lookup_domain");
              setValidationError(null);
            }}
            disabled={isLoading}
            className={`px-3 py-1 text-[11px] uppercase tracking-wider transition-colors border ${
              mode === "lookup_domain"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent-subtle"
                : "border-transparent text-cyber-text-dim hover:text-cyber-text-primary"
            }`}
          >
            <Database className="h-3 w-3 inline mr-1.5" />
            LOOKUP BY DOMAIN
          </button>
        </div>
      )}

      {/* Search Input Box */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex items-center rounded-none border border-cyber-border-strong bg-cyber-bg-secondary p-1 shadow-inner focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent/40 transition-all">
          <div className="flex items-center pl-3 pr-2 text-cyber-text-muted">
            {mode === "lookup_id" ? (
              <Hash className="h-4 w-4 shrink-0 text-cyber-accent" />
            ) : mode === "lookup_domain" ? (
              <Database className="h-4 w-4 shrink-0 text-cyber-accent" />
            ) : (
              <Globe className="h-4 w-4 shrink-0 text-cyber-accent" />
            )}
          </div>

          <input
            id="target-url-input"
            name="url"
            type="text"
            value={url}
            onChange={handleChange}
            placeholder={
              mode === "lookup_id"
                ? "Enter 36-char scan UUID (e.g. 97aa2ba2-19a8-47c0-83d8-b03ba6028689)..."
                : mode === "lookup_domain"
                ? "Enter domain name to retrieve cached scan (e.g. example.com)..."
                : "Enter target URL or IP (e.g. https://1.1.1.1 or https://example.com)..."
            }
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
                  <span>{mode === "scan" ? "Inspecting..." : "Retrieving..."}</span>
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" />
                  <span>
                    {mode === "lookup_id"
                      ? "Lookup ID"
                      : mode === "lookup_domain"
                      ? "Lookup Domain"
                      : "Scan Target"}
                  </span>
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
            {mode === "scan" && !url.startsWith("http://") && !url.startsWith("https://") && url.trim().length > 0 && (
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
        {mode === "scan" ? (
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
        ) : (
          <div className="text-[10px] text-cyber-text-dim">
            {mode === "lookup_id"
              ? "Queries FastAPI in-memory cache by UUID scan identifier."
              : "Queries FastAPI in-memory cache for latest recorded scan of domain."}
          </div>
        )}

        {/* SSRF & Defense note */}
        <div className="flex items-center gap-1.5 text-[10px] text-cyber-text-dim">
          <Shield className="h-3 w-3 text-cyber-accent/80" />
          <span>SSRF Filtering Active (RFC 1918 / Loopback Protected)</span>
        </div>
      </div>
    </div>
  );
}
