"use client";

import * as React from "react";
import {
  MessageSquare,
  Search,
  X,
  Loader2,
  ArrowRight,
  Shield,
  Sparkles,
  AlertTriangle,
  Lock,
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface MessageAnalyzerFormProps {
  message: string;
  onMessageChange: (val: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  onReset: () => void;
  onSelectPreset?: (presetText: string) => void;
}

const MAX_MESSAGE_LENGTH = 10000;

const PRESET_MESSAGES = [
  {
    label: "HDFC OTP Fraud",
    text: "URGENT: Your HDFC Bank account will be blocked today due to pending KYC update. Click https://hdfc-kyc-verify.com to update your details and share OTP immediately.",
    category: "critical",
  },
  {
    label: "Lottery Scam",
    text: "Congratulations! You have won $1,000,000 in our exclusive international lucky draw. To claim your prize reward, send your account details and wire transfer clearance fee today.",
    category: "scam",
  },
  {
    label: "Courier Parcel",
    text: "Your FedEx package parcel has been detained at customs clearance. Delivery fee pending. Tap link http://delivery-release-parcel.net to verify and pay $2.50 release fee right now.",
    category: "scam",
  },
  {
    label: "Benign Communication",
    text: "Hi team, please review the weekly project timeline briefing. Let me know if you have questions before our team sync tomorrow afternoon.",
    category: "clean",
  },
];

export function MessageAnalyzerForm({
  message,
  onMessageChange,
  onSubmit,
  isLoading,
  onReset,
  onSelectPreset,
}: MessageAnalyzerFormProps) {
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const charCount = message.length;
  const isOverLimit = charCount > MAX_MESSAGE_LENGTH;

  const validateInput = (text: string): boolean => {
    const trimmed = text.trim();
    if (!trimmed) {
      setValidationError("Message text is required. Please paste or enter message content.");
      return false;
    }
    if (text.length > MAX_MESSAGE_LENGTH) {
      setValidationError(`Message exceeds the maximum limit of ${MAX_MESSAGE_LENGTH.toLocaleString()} characters.`);
      return false;
    }
    setValidationError(null);
    return true;
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    onMessageChange(val);
    if (validationError && val.trim().length > 0 && val.length <= MAX_MESSAGE_LENGTH) {
      setValidationError(null);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isLoading) return;

    if (!validateInput(message)) {
      return;
    }

    onSubmit(e);
  };

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="relative rounded-none border border-cyber-border-strong bg-cyber-bg-secondary p-1 shadow-inner focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent/40 transition-all">
          {/* Top toolbar */}
          <div className="flex items-center justify-between border-b border-cyber-border px-3 py-2 text-xs font-mono text-cyber-text-dim">
            <div className="flex items-center gap-2">
              <MessageSquare className="h-3.5 w-3.5 text-cyber-accent" />
              <span className="uppercase text-[10px] tracking-wider text-cyber-text-secondary">
                RAW MESSAGE TELEMETRY INPUT
              </span>
            </div>

            <div className="flex items-center gap-3 text-[10px]">
              <span
                className={
                  isOverLimit
                    ? "text-cyber-threat-critical font-bold"
                    : charCount > 8000
                    ? "text-cyber-threat-high font-semibold"
                    : "text-cyber-text-dim"
                }
              >
                {charCount.toLocaleString()} / {MAX_MESSAGE_LENGTH.toLocaleString()} CHARS
              </span>
              {message && !isLoading && (
                <button
                  type="button"
                  onClick={onReset}
                  className="text-cyber-text-muted hover:text-cyber-text-primary p-0.5 transition-colors"
                  title="Clear input"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>

          {/* Textarea Input */}
          <textarea
            id="message-analysis-input"
            name="messageContent"
            rows={6}
            value={message}
            onChange={handleChange}
            disabled={isLoading}
            placeholder="Paste suspicious email text, SMS message, banking alert, OTP notification, or chat communication here..."
            className="w-full bg-transparent p-3 font-mono text-xs md:text-sm text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none resize-y min-h-[140px] leading-relaxed disabled:opacity-50"
            spellCheck="false"
          />

          {/* Bottom Action Footer */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-cyber-border p-2 bg-cyber-bg-tertiary/40">
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-cyber-text-dim">
              <Lock className="h-3 w-3 text-cyber-threat-secure" />
              <span>Zero-Retention: Raw text is evaluated in volatile memory and never stored</span>
            </div>

            <Button
              type="submit"
              variant="arctic"
              size="sm"
              disabled={isLoading || !message.trim() || isOverLimit}
              className="gap-2 px-5 h-9 font-mono uppercase tracking-wider text-xs ml-auto"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Evaluating Patterns...</span>
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" />
                  <span>Analyze Message</span>
                  <ArrowRight className="h-3.5 w-3.5 ml-0.5" />
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Validation warning */}
        {validationError && (
          <div className="flex items-center gap-2 text-[11px] font-mono text-cyber-threat-high">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>{validationError}</span>
          </div>
        )}
      </form>

      {/* Target Presets & Honest Engine Protocol */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center gap-1">
            <Sparkles className="h-3 w-3 text-cyber-accent" /> Sample Vectors:
          </span>
          {PRESET_MESSAGES.map((preset) => (
            <button
              key={preset.label}
              type="button"
              disabled={isLoading}
              onClick={() => {
                if (onSelectPreset) {
                  onSelectPreset(preset.text);
                } else {
                  onMessageChange(preset.text);
                  setValidationError(null);
                }
              }}
              className="px-2 py-0.5 text-[10px] font-mono tracking-tight bg-cyber-bg-surface border border-cyber-border hover:border-cyber-accent/60 hover:text-cyber-accent text-cyber-text-secondary transition-colors"
            >
              {preset.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 text-[10px] text-cyber-text-dim">
          <Shield className="h-3 w-3 text-cyber-accent/80" />
          <span>Deterministic Heuristic & Regex Rules Active</span>
        </div>
      </div>
    </div>
  );
}

