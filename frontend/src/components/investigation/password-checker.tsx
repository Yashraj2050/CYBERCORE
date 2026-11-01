"use client";

import * as React from "react";
import {
  Lock,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Search,
  CheckCircle,
  AlertOctagon,
  Eye,
  EyeOff,
  RotateCcw,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { securityToolsService } from "@/lib/api/services/security-tools";
import type { PasswordBreachResult } from "@/types/security-tools";

export function PasswordChecker() {
  const [password, setPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<PasswordBreachResult | null>(null);
  const [computedPrefix, setComputedPrefix] = React.useState<string | null>(null);

  // Computes SHA-1 hash client-side using Web Crypto API (zero external transmission)
  async function computeSha1Hex(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  const handleVerify = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanPassword = password.trim();
    if (!cleanPassword) {
      setResult({
        status: "INVALID_INPUT",
        prefix: "NONE",
        message: "Password Required",
        detail: "Please enter a password to verify against breach records. The raw password is never transmitted across the network.",
      });
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      // 1. Calculate SHA-1 entirely in local browser memory
      const fullHash = await computeSha1Hex(cleanPassword);
      const prefix = fullHash.slice(0, 5);
      const suffix = fullHash.slice(5);
      setComputedPrefix(prefix);

      // 2. Query backend using ONLY the 5-char prefix (k-anonymity)
      const res = await securityToolsService.checkPasswordBreach(prefix);

      if (res.status === "SERVICE_UNAVAILABLE") {
        setResult({
          status: "SERVICE_UNAVAILABLE",
          prefix,
          message: "HIBP Breach Database Unavailable",
          detail:
            "The upstream Have I Been Pwned service is unreachable (HTTP 503). This does NOT indicate your password is safe. Re-check when external connectivity is restored.",
        });
      } else if (res.status === "INVALID_INPUT") {
        setResult({
          status: "INVALID_INPUT",
          prefix,
          message: "Invalid Prefix Format",
          detail: res.message,
        });
      } else if (res.status === "ERROR") {
        setResult({
          status: "ERROR",
          prefix,
          message: "API Gateway Error",
          detail: res.message || "Failed to query the breach verification gateway. This does NOT indicate your password is safe.",
        });
      } else {
        // Parse returned multiline suffixes: backend returns { data: "SUFFIX:COUNT\r\n...", hash_prefix }
        if (!res.detail) {
          setResult({
            status: "ERROR",
            prefix,
            message: "Empty Gateway Response",
            detail: "The breach verification service returned an empty payload. This does NOT indicate your password is safe.",
          });
          return;
        }

        let isBreached = false;
        let count = 0;
        let totalSuffixesChecked = 0;

        try {
          const raw = JSON.parse(res.detail);
          const rawData =
            typeof raw === "object" && raw !== null && "data" in raw
              ? String((raw as { data: unknown }).data)
              : typeof raw === "string"
              ? raw
              : "";

          if (!rawData && typeof raw === "object" && raw !== null) {
            throw new Error("Missing breach data string in API response payload.");
          }

          // Split multiline data string into individual lines (\r\n or \n)
          const lines = rawData.split(/\r?\n/);
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const colonIndex = trimmed.indexOf(":");
            if (colonIndex === -1) continue;

            const lineSuffix = trimmed.slice(0, colonIndex).trim().toUpperCase();
            const countStr = trimmed.slice(colonIndex + 1).trim();
            totalSuffixesChecked++;

            if (lineSuffix === suffix) {
              isBreached = true;
              count = parseInt(countStr, 10) || 1;
              break;
            }
          }
        } catch {
          setResult({
            status: "ERROR",
            prefix,
            message: "Malformed Breach Response",
            detail: "Failed to parse credential breach signatures from gateway. This does NOT indicate your password is safe.",
          });
          return;
        }

        if (isBreached) {
          setResult({
            status: "BREACHED",
            prefix,
            matchCount: count,
            message: "Password Compromised in Known Data Breach",
            detail: `This cryptographic signature was identified ${count > 1 ? `${count.toLocaleString()} times ` : ""}in historical credential breach dumps. Do not use this password.`,
          });
        } else {
          setResult({
            status: "NOT FOUND IN BREACH CORPUS",
            prefix,
            message: "No Matching Record in Breach Corpus",
            detail:
              "No matching record was found in the checked breach corpus. This does not guarantee that the password has never been compromised.",
          });
        }
      }
    } catch (err) {
      setResult({
        status: "ERROR",
        prefix: computedPrefix || "UNKNOWN",
        message: "Verification Failed",
        detail: err instanceof Error ? err.message : "Client evaluation exception. This does NOT indicate your password is safe.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setPassword("");
    setResult(null);
    setComputedPrefix(null);
  };

  return (
    <div className="border border-cyber-border bg-cyber-bg-secondary p-5 rounded-xs space-y-4">
      <div className="flex items-center justify-between border-b border-cyber-border/60 pb-3">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-cyber-accent" />
          <h2 className="text-xs font-mono font-semibold tracking-tactical uppercase text-cyber-text-primary">
            Interactive Password Breach Verifier (k-Anonymity)
          </h2>
        </div>
        <Badge variant="monolithic" radius="xs">
          ZERO-KNOWLEDGE
        </Badge>
      </div>

      <p className="text-xs text-cyber-text-secondary leading-relaxed font-sans">
        Validate credentials against breach databases without disclosing the password. Only the first 5 characters of the SHA-1 hash leave your machine; the actual password never leaves the browser.
      </p>

      {/* Input Form */}
      <form onSubmit={handleVerify} className="space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative flex-1">
            <input
              id="password-verifier-input"
              name="passwordToVerify"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password to test (hashed client-side via SHA-1)..."
              className="w-full h-9 bg-cyber-bg border border-cyber-border rounded-xs px-3 pr-10 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none focus:border-cyber-accent"
              autoComplete="off"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-cyber-text-dim hover:text-cyber-text-secondary"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <Button
              type="submit"
              variant="default"
              size="sm"
              disabled={!password || loading}
              className="h-9 px-4 gap-1.5 shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>QUERYING...</span>
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" />
                  <span>VERIFY BREACH</span>
                </>
              )}
            </Button>

            {(password || result) && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleClear}
                disabled={loading}
                className="h-9 px-3 gap-1 shrink-0 text-cyber-text-dim hover:text-cyber-text-primary"
                title="Clear input and sensitive state"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">CLEAR</span>
              </Button>
            )}
          </div>
        </div>

        {computedPrefix && (
          <div className="text-[10px] font-mono text-cyber-text-dim flex items-center justify-between px-1">
            <span>CLIENT-CALCULATED PREFIX: <strong className="text-cyber-accent">{computedPrefix}</strong> (35 suffix chars retained in memory)</span>
            <span>TARGET: GET /api/v1/password/breached/{computedPrefix}</span>
          </div>
        )}
      </form>

      {/* 5 Distinct Result States */}
      {result && (
        <div
          className={`p-4 border rounded-xs space-y-2 text-xs font-mono transition-all ${
            result.status === "NOT FOUND IN BREACH CORPUS"
              ? "bg-cyber-threat-secure-bg border-cyber-threat-secure-border text-cyber-threat-secure"
              : result.status === "BREACHED"
              ? "bg-cyber-threat-critical-bg border-cyber-threat-critical-border text-cyber-threat-critical"
              : result.status === "SERVICE_UNAVAILABLE"
              ? "bg-amber-950/20 border-amber-600/40 text-amber-300"
              : result.status === "INVALID_INPUT"
              ? "bg-cyber-threat-medium-bg border-cyber-threat-medium-border text-cyber-threat-medium"
              : "bg-cyber-threat-critical-bg border-cyber-threat-critical-border text-cyber-threat-critical"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-semibold">
              {result.status === "NOT FOUND IN BREACH CORPUS" && (
                <CheckCircle className="h-4 w-4" />
              )}
              {result.status === "BREACHED" && <ShieldAlert className="h-4 w-4" />}
              {result.status === "SERVICE_UNAVAILABLE" && <AlertTriangle className="h-4 w-4" />}
              {result.status === "INVALID_INPUT" && <AlertOctagon className="h-4 w-4" />}
              {result.status === "ERROR" && <AlertOctagon className="h-4 w-4" />}
              <span>{result.message}</span>
            </div>

            <Badge
              variant={
                result.status === "NOT FOUND IN BREACH CORPUS"
                  ? "secure"
                  : result.status === "BREACHED"
                  ? "critical"
                  : result.status === "SERVICE_UNAVAILABLE"
                  ? "medium"
                  : result.status === "INVALID_INPUT"
                  ? "medium"
                  : "critical"
              }
              radius="xs"
            >
              STATUS: {result.status}
            </Badge>
          </div>

          <p className="text-[11px] leading-relaxed text-cyber-text-secondary font-sans">
            {result.detail}
          </p>

          {result.status === "SERVICE_UNAVAILABLE" && (
            <div className="p-2 bg-black/40 border border-amber-600/30 rounded-xs text-[10px] font-mono text-amber-200">
              <strong>CRITICAL NOTICE:</strong> HTTP 503 indicates the external breach API gateway was unreachable. This is an infrastructure availability timeout, NOT proof that the credential has never been compromised.
            </div>
          )}

          {result.status === "ERROR" && (
            <div className="p-2 bg-black/40 border border-cyber-threat-critical-border rounded-xs text-[10px] font-mono text-cyber-threat-critical">
              <strong>SECURITY NOTICE:</strong> Verification encountered a gateway or parsing failure. This failure is never treated as absence from the breach corpus. Re-test when the service responds normally.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
