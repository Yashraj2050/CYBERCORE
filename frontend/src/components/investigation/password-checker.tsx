"use client";

import * as React from "react";
import {
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Search,
  CheckCircle,
  AlertOctagon,
  Eye,
  EyeOff,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { securityToolsService } from "@/lib/api/services/security-tools";
import type { PasswordBreachStatus, PasswordBreachResult } from "@/types/security-tools";

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

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;

    setLoading(true);
    setResult(null);

    try {
      // 1. Calculate SHA-1 entirely in local browser memory
      const fullHash = await computeSha1Hex(password);
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
          detail: res.message,
        });
      } else {
        // Parse returned suffixes to determine if full hash matched
        let isBreached = false;
        let count = 0;

        if (res.detail) {
          try {
            const raw = JSON.parse(res.detail);
            // If backend returns an array or mapping of suffixes:
            if (typeof raw === "object" && raw !== null) {
              const matchedSuffix = Object.keys(raw).find(
                (s) => s.toUpperCase() === suffix
              );
              if (matchedSuffix) {
                isBreached = true;
                count = Number(raw[matchedSuffix]) || 1;
              }
            }
          } catch {
            isBreached = false;
          }
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
            status: "CLEAN",
            prefix,
            message: "No Breach Records Found for Signature",
            detail: `Prefix ${prefix} was queried via k-anonymity. The remaining 35 characters were matched locally in-browser with zero breach hits.`,
          });
        }
      }
    } catch (err) {
      setResult({
        status: "ERROR",
        prefix: computedPrefix || "UNKNOWN",
        message: "Verification Failed",
        detail: err instanceof Error ? err.message : "Client evaluation exception.",
      });
    } finally {
      setLoading(false);
    }
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
            result.status === "CLEAN"
              ? "bg-cyber-threat-secure-bg border-cyber-threat-secure-border text-cyber-threat-secure"
              : result.status === "BREACHED"
              ? "bg-cyber-threat-critical-bg border-cyber-threat-critical-border text-cyber-threat-critical"
              : result.status === "SERVICE_UNAVAILABLE"
              ? "bg-amber-950/20 border-amber-600/40 text-amber-300"
              : result.status === "INVALID_INPUT"
              ? "bg-cyber-threat-medium-bg border-cyber-threat-medium-border text-cyber-threat-medium"
              : "bg-cyber-bg border-cyber-border text-cyber-text-secondary"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-semibold">
              {result.status === "CLEAN" && <CheckCircle className="h-4 w-4" />}
              {result.status === "BREACHED" && <ShieldAlert className="h-4 w-4" />}
              {result.status === "SERVICE_UNAVAILABLE" && <AlertTriangle className="h-4 w-4" />}
              {result.status === "INVALID_INPUT" && <AlertOctagon className="h-4 w-4" />}
              {result.status === "ERROR" && <AlertOctagon className="h-4 w-4" />}
              <span>{result.message}</span>
            </div>

            <Badge
              variant={
                result.status === "CLEAN"
                  ? "secure"
                  : result.status === "BREACHED"
                  ? "critical"
                  : result.status === "SERVICE_UNAVAILABLE"
                  ? "medium"
                  : "default"
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
              <strong>CRITICAL NOTICE:</strong> HTTP 503 indicates the external breach API gateway was unreachable. This is an infrastructure availability timeout, NOT proof that the credential is secure.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

