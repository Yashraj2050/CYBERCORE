"use client";

import * as React from "react";
import {
  Hash,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Check,
  Copy,
  RotateCcw,
  Search,
  FileCode,
  Terminal,
  Activity,
  Info,
  Server,
  Lock,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { securityToolsService } from "@/lib/api/services/security-tools";
import type { HashCheckResponse, HashApiError, VirusTotalReputation } from "@/types/security-tools";

interface HashPreset {
  label: string;
  hash: string;
  algorithm: "MD5" | "SHA-1" | "SHA-256";
  filename?: string;
  description: string;
}

const HASH_PRESETS: HashPreset[] = [
  {
    label: "EICAR Standard AV Test (SHA-256)",
    hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    algorithm: "SHA-256",
    filename: "eicar.com.txt",
    description: "Industry-standard antivirus verification test vector (harmless string)",
  },
  {
    label: "Empty File Sentinel (MD5)",
    hash: "d41d8cd98f00b204e9800998ecf8427e",
    algorithm: "MD5",
    filename: "empty.bin",
    description: "Cryptographic null byte digest for MD5 verification",
  },
  {
    label: "Empty File Sentinel (SHA-1)",
    hash: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    algorithm: "SHA-1",
    filename: "empty.bin",
    description: "Cryptographic null byte digest for SHA-1 verification",
  },
  {
    label: "WannaCry Ransomware Dropper (SHA-256)",
    hash: "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    algorithm: "SHA-256",
    filename: "mssecsvc.exe",
    description: "Known WannaCry ransomware binary hash signature",
  },
];

export function HashChecker() {
  const [hashInput, setHashInput] = React.useState("");
  const [filenameInput, setFilenameInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<HashCheckResponse | null>(null);
  const [error, setError] = React.useState<HashApiError | null>(null);
  const [copiedKey, setCopiedKey] = React.useState<string | null>(null);

  // Real-time input detection
  const cleanInput = hashInput.trim().toLowerCase();
  const hexOnlyRegex = /^[0-9a-fA-F]*$/;
  const isHexOnly = hexOnlyRegex.test(hashInput.trim());

  let detectedAlgorithm: "MD5" | "SHA-1" | "SHA-256" | null = null;
  let validationMessage: string | null = null;
  let isValid = false;

  if (cleanInput.length === 0) {
    validationMessage = null;
  } else if (!isHexOnly) {
    validationMessage = "Invalid character detected: Hash must contain only hexadecimal characters (0-9, a-f).";
  } else if (cleanInput.length === 32) {
    detectedAlgorithm = "MD5";
    isValid = true;
  } else if (cleanInput.length === 40) {
    detectedAlgorithm = "SHA-1";
    isValid = true;
  } else if (cleanInput.length === 64) {
    detectedAlgorithm = "SHA-256";
    isValid = true;
  } else {
    validationMessage = `Unsupported hash length (${cleanInput.length} chars). Backend requires 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.`;
  }

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 2000);
  };

  const handleExecute = async (overrideHash?: string, overrideFilename?: string) => {
    const targetHash = (overrideHash ?? cleanInput).trim().toLowerCase();
    const targetFilename = (overrideFilename ?? filenameInput).trim();

    if (!targetHash) {
      setError({
        status: 400,
        title: "Missing Hash Input",
        message: "Please enter a cryptographic hash signature before submitting.",
        isInvalidFormat: true,
      });
      return;
    }

    // Client-side length & hex validation
    const targetHexOnly = /^[0-9a-fA-F]+$/.test(targetHash);
    if (!targetHexOnly || ![32, 40, 64].includes(targetHash.length)) {
      setError({
        status: 422,
        title: "Invalid Hash Format",
        message: "Hash must be a valid hexadecimal string of 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.",
        isInvalidFormat: true,
      });
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await securityToolsService.checkHash({
        hash_value: targetHash,
        filename: targetFilename.length > 0 ? targetFilename : null,
      });
      setResult(response);
    } catch (err) {
      const classified = securityToolsService.classifyHashError(err);
      setError(classified);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isValid && !loading) {
      handleExecute();
    }
  };

  const handleSelectPreset = (preset: HashPreset) => {
    setHashInput(preset.hash);
    setFilenameInput(preset.filename || "");
    setError(null);
    handleExecute(preset.hash, preset.filename);
  };

  const handleReset = () => {
    setHashInput("");
    setFilenameInput("");
    setResult(null);
    setError(null);
  };

  const getThreatBadgeVariant = (level: string) => {
    switch (level?.toUpperCase()) {
      case "CRITICAL":
        return "critical";
      case "HIGH":
        return "high";
      case "MEDIUM":
        return "medium";
      case "LOW":
        return "low";
      case "SAFE":
        return "secure";
      case "UNASSESSED":
        return "outline";
      default:
        return "default";
    }
  };

  const getRiskScoreColor = (score: number | null | undefined, level?: string) => {
    if (level === "UNASSESSED" || score === null || score === undefined) {
      return "text-cyber-text-dim border-cyber-border bg-cyber-bg-surface";
    }
    if (score >= 80) return "text-cyber-threat-critical border-cyber-threat-critical/40 bg-cyber-threat-critical/10";
    if (score >= 50) return "text-cyber-threat-high border-cyber-threat-high/40 bg-cyber-threat-high/10";
    if (score >= 20) return "text-cyber-threat-medium border-cyber-threat-medium/40 bg-cyber-threat-medium/10";
    if (score > 0) return "text-cyber-threat-low border-cyber-threat-low/40 bg-cyber-threat-low/10";
    return "text-cyber-threat-secure border-cyber-threat-secure/40 bg-cyber-threat-secure/10";
  };

  return (
    <div className="relative glass-panel border border-cyber-border rounded-xs p-6 sm:p-8 space-y-6 overflow-hidden">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

      {/* Header and Telemetry */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-cyber-border pb-5">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 bg-cyber-accent" />
            <span className="text-[10px] font-mono tracking-tactical text-cyber-accent uppercase font-medium">
              PRIVACY-PRESERVING SIGNATURE LOOKUP // FASTAPI BUS
            </span>
          </div>
          <h2 className="font-mono text-xl sm:text-2xl font-bold tracking-tight text-cyber-text-primary flex items-center gap-2.5">
            <Hash className="h-5 w-5 text-cyber-accent" />
            CRYPTOGRAPHIC HASH LOOKUP
          </h2>
          <p className="text-xs font-mono text-cyber-text-secondary max-w-2xl">
            Zero-knowledge file signature verification. Transmits only the cryptographic hash digest
            to the FastAPI engine—never raw file bytes. Supports MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <Badge variant="arctic" className="text-[10px] py-1 gap-1.5">
            <Server className="h-3 w-3" /> POST /api/v1/files/check-hash
          </Badge>
          <Badge variant="default" className="text-[10px] py-1 gap-1.5">
            <Lock className="h-3 w-3 text-cyber-threat-secure" /> ZERO FILE RETENTION
          </Badge>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label
              htmlFor="hash-input"
              className="text-xs font-mono font-medium text-cyber-text-primary uppercase tracking-wider flex items-center gap-2"
            >
              <span>Cryptographic Hash Signature</span>
              <span className="text-cyber-accent">*</span>
            </label>

            {/* Real-time Algorithm Detector */}
            {detectedAlgorithm ? (
              <Badge variant="secure" className="text-[10px] py-0.5 font-mono">
                ALGORITHM: {detectedAlgorithm} ({cleanInput.length} HEX)
              </Badge>
            ) : cleanInput.length > 0 ? (
              <Badge variant="outline" className="text-[10px] py-0.5 font-mono text-cyber-threat-high border-cyber-threat-high/40">
                LENGTH: {cleanInput.length} / 32, 40, 64
              </Badge>
            ) : (
              <span className="text-[10px] font-mono text-cyber-text-dim">
                AWAITING 32, 40, OR 64 HEX DIGEST
              </span>
            )}
          </div>

          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-cyber-text-dim">
              <Terminal className="h-4 w-4" />
            </div>
            <input
              id="hash-input"
              type="text"
              value={hashInput}
              onChange={(e) => {
                setHashInput(e.target.value);
                if (error) setError(null);
              }}
              placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
              disabled={loading}
              className="w-full bg-cyber-bg border border-cyber-border rounded-xs pl-10 pr-24 py-2.5 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim/60 focus:outline-none focus:border-cyber-accent transition-colors disabled:opacity-50"
            />
            {hashInput.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setHashInput("");
                  if (error) setError(null);
                }}
                disabled={loading}
                className="absolute inset-y-0 right-2 my-auto h-6 px-2 text-[10px] font-mono text-cyber-text-dim hover:text-cyber-text-primary bg-cyber-bg-surface border border-cyber-border rounded-xs transition-colors"
              >
                CLEAR
              </button>
            )}
          </div>

          {/* Validation Feedback */}
          {validationMessage && (
            <p className="text-[11px] font-mono text-cyber-threat-high flex items-center gap-1.5 pt-1">
              <AlertTriangle className="h-3 w-3 shrink-0" />
              <span>{validationMessage}</span>
            </p>
          )}
        </div>

        {/* Optional Filename Input */}
        <div className="space-y-2">
          <label
            htmlFor="filename-input"
            className="text-xs font-mono font-medium text-cyber-text-secondary uppercase tracking-wider flex items-center gap-2"
          >
            <span>Target Filename Reference</span>
            <span className="text-cyber-text-dim font-normal">(Optional context for heuristic engine)</span>
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-cyber-text-dim">
              <FileCode className="h-4 w-4" />
            </div>
            <input
              id="filename-input"
              type="text"
              value={filenameInput}
              onChange={(e) => setFilenameInput(e.target.value)}
              placeholder="e.g. suspicious_payload.exe, invoice.pdf"
              disabled={loading}
              className="w-full bg-cyber-bg border border-cyber-border rounded-xs pl-10 pr-4 py-2 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim/60 focus:outline-none focus:border-cyber-accent transition-colors disabled:opacity-50"
            />
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            <Button
              type="submit"
              disabled={!isValid || loading}
              className="h-9 px-5 text-xs font-mono gap-2"
            >
              {loading ? (
                <>
                  <Activity className="h-3.5 w-3.5 animate-spin" />
                  <span>INSPECTING SIGNATURE...</span>
                </>
              ) : (
                <>
                  <Search className="h-3.5 w-3.5" />
                  <span>EXECUTE HASH LOOKUP</span>
                </>
              )}
            </Button>

            {(result || error || hashInput) && (
              <Button
                type="button"
                variant="outline"
                onClick={handleReset}
                disabled={loading}
                className="h-9 px-3 text-xs font-mono gap-1.5"
              >
                <RotateCcw className="h-3 w-3" />
                <span>RESET</span>
              </Button>
            )}
          </div>

          <span className="text-[10px] font-mono text-cyber-text-dim">
            SUBMIT VIA [ENTER] // ENFORCES LOWERCASE HEX
          </span>
        </div>
      </form>

      {/* Preset Test Vectors */}
      <div className="space-y-2 border-t border-cyber-border/60 pt-4">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
            VERIFIED SIGNATURE TEST VECTORS
          </span>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            CLICK TO AUTOLOAD & VERIFY
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {HASH_PRESETS.map((preset) => (
            <button
              key={preset.hash}
              type="button"
              onClick={() => handleSelectPreset(preset)}
              disabled={loading}
              className="text-left p-2.5 bg-cyber-bg border border-cyber-border hover:border-cyber-accent/50 rounded-xs space-y-1 transition-all group disabled:opacity-50"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-medium text-cyber-text-primary group-hover:text-cyber-accent transition-colors truncate">
                  {preset.label}
                </span>
                <Badge variant="monolithic" className="text-[9px] shrink-0">
                  {preset.algorithm}
                </Badge>
              </div>
              <p className="font-mono text-[10px] text-cyber-text-dim truncate">
                {preset.hash}
              </p>
              <p className="text-[10px] text-cyber-text-secondary leading-tight font-sans">
                {preset.description}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Loading Indicator */}
      {loading && (
        <div className="p-6 border border-cyber-border bg-cyber-bg-surface/50 rounded-xs text-center space-y-3 animate-pulse">
          <Activity className="h-6 w-6 text-cyber-accent mx-auto animate-spin" />
          <div className="space-y-1">
            <p className="font-mono text-xs font-semibold text-cyber-text-primary uppercase tracking-wider">
              SCANNING CRYPTOGRAPHIC SIGNATURE AGAINST FASTAPI REPOSITORY
            </p>
            <p className="text-[11px] font-mono text-cyber-text-dim">
              Resolving hash heuristics and VirusTotal intelligence bus...
            </p>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="p-4 border border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs space-y-2">
          <div className="flex items-center gap-2 text-cyber-threat-critical">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              {error.title} {error.status > 0 && `(HTTP ${error.status})`}
            </span>
          </div>
          <p className="font-mono text-xs text-cyber-threat-critical/90">
            {error.message}
          </p>
          {error.detail && error.detail !== error.message && (
            <div className="p-2 bg-black/40 border border-cyber-threat-critical-border/40 rounded-xs text-[10px] font-mono text-cyber-threat-critical/80 break-all">
              RAW DETAIL: {error.detail}
            </div>
          )}
        </div>
      )}

      {/* Success Result Panel */}
      {result && !loading && (
        <div className="space-y-5 border-t border-cyber-border pt-5">
          {/* Top Verdict Banner */}
          <div className="p-4 bg-cyber-bg-surface border border-cyber-border rounded-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
                FASTAPI VERDICT EVALUATION
              </span>
              <div className="flex items-center gap-3">
                <Badge
                  variant={getThreatBadgeVariant(result.threat_level)}
                  className="text-xs px-2.5 py-1 font-mono font-bold uppercase"
                >
                  {result.threat_level}
                </Badge>
                <span className="font-mono text-xs text-cyber-text-secondary">
                  THREAT CLASSIFICATION
                </span>
              </div>
            </div>

            {/* Risk Score */}
            <div className="flex items-center gap-3">
              <div className="text-right">
                <span className="text-[10px] font-mono text-cyber-text-dim uppercase block">
                  AGGREGATE RISK SCORE
                </span>
                <span className="text-xs font-mono text-cyber-text-secondary">
                  SCALE: 0 (SAFE) - 100 (CRITICAL)
                </span>
              </div>
              <div
                className={`h-12 w-16 border rounded-xs flex items-center justify-center font-mono text-lg font-bold ${getRiskScoreColor(
                  result.risk_score,
                  result.threat_level
                )}`}
              >
                {result.risk_score !== null && result.risk_score !== undefined
                  ? result.risk_score
                  : "N/A"}
              </div>
            </div>
          </div>

          {/* Signature Metadata Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            {/* Hash Digest */}
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1.5 md:col-span-2">
              <div className="flex items-center justify-between text-cyber-text-dim text-[10px]">
                <span>CONFIRMED HASH SIGNATURE:</span>
                <button
                  type="button"
                  onClick={() => handleCopy(result.hash, "hash")}
                  className="flex items-center gap-1 text-cyber-accent hover:underline text-[10px]"
                >
                  {copiedKey === "hash" ? (
                    <>
                      <Check className="h-3 w-3 text-cyber-threat-secure" />
                      <span className="text-cyber-threat-secure">COPIED</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>COPY HASH</span>
                    </>
                  )}
                </button>
              </div>
              <div className="text-cyber-text-primary break-all select-all font-mono text-xs bg-cyber-bg-surface p-2 border border-cyber-border/40 rounded-xs">
                {result.hash}
              </div>
            </div>

            {/* Target Filename */}
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">
                ASSOCIATED FILENAME:
              </span>
              <span className="text-cyber-text-primary font-medium">
                {result.filename || "None provided (unnamed signature)"}
              </span>
            </div>

            {/* Detected Algorithm */}
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">
                VERIFIED ALGORITHM FORMAT:
              </span>
              <span className="text-cyber-accent font-medium">
                {result.hash.length === 32
                  ? "MD5 (128-bit / 32 hex)"
                  : result.hash.length === 40
                  ? "SHA-1 (160-bit / 40 hex)"
                  : result.hash.length === 64
                  ? "SHA-256 (256-bit / 64 hex)"
                  : `Custom Digest (${result.hash.length} hex)`}
              </span>
            </div>
          </div>

          {/* Heuristic Findings */}
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xs space-y-3">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-2">
              <span className="text-xs font-mono font-semibold uppercase text-cyber-text-primary flex items-center gap-2">
                <Shield className="h-3.5 w-3.5 text-cyber-accent" />
                ANALYSIS FINDINGS ({result.findings.length})
              </span>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                BACKEND HEURISTIC ENGINE
              </span>
            </div>

            {result.findings.length > 0 ? (
              <ul className="space-y-1.5">
                {result.findings.map((finding, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 text-xs font-mono text-cyber-text-secondary"
                  >
                    <span className="text-cyber-accent mt-0.5">•</span>
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs font-mono text-cyber-text-dim">
                No specific heuristic warnings or notes recorded.
              </p>
            )}
          </div>

          {/* VirusTotal Threat Intelligence */}
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xs space-y-3">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-2">
              <span className="text-xs font-mono font-semibold uppercase text-cyber-text-primary flex items-center gap-2">
                <Activity className="h-3.5 w-3.5 text-cyber-accent" />
                VIRUSTOTAL THREAT INTELLIGENCE
              </span>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                EXTERNAL REPUTATION BUS
              </span>
            </div>

            {result.vt_reputation && typeof result.vt_reputation === "object" ? (
              (result.vt_reputation as VirusTotalReputation).status === "unconfigured" ? (
                <div className="p-3 bg-cyber-bg-surface border border-cyber-threat-high/40 rounded-xs flex items-center gap-2.5 text-cyber-threat-high text-xs font-mono">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>
                    {(result.vt_reputation as VirusTotalReputation).message ||
                      "VirusTotal API key is not configured on this server. External threat intelligence unavailable."}
                  </span>
                </div>
              ) : (result.vt_reputation as VirusTotalReputation).status === "error" ||
                (result.vt_reputation as VirusTotalReputation).status === "timeout" ? (
                <div className="p-3 bg-cyber-bg-surface border border-cyber-threat-high/40 rounded-xs flex items-center gap-2.5 text-cyber-threat-high text-xs font-mono">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>
                    {(result.vt_reputation as VirusTotalReputation).message ||
                      "VirusTotal reputation query failed or timed out. External threat reputation unavailable."}
                  </span>
                </div>
              ) : (result.vt_reputation as VirusTotalReputation).status === "not_found" ? (
                <div className="p-3 bg-cyber-bg-surface border border-cyber-border rounded-xs flex items-center gap-2.5 text-cyber-text-secondary text-xs font-mono">
                  <Info className="h-4 w-4 shrink-0 text-cyber-accent" />
                  <span>
                    {(result.vt_reputation as VirusTotalReputation).message ||
                      "Hash signature not seen in the global VirusTotal database."}
                  </span>
                </div>
              ) : (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-xs">
                  <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border rounded-xs space-y-1">
                    <span className="text-[10px] text-cyber-text-dim block">MALICIOUS:</span>
                    <span className="text-cyber-threat-critical font-bold text-sm">
                      {Number((result.vt_reputation as VirusTotalReputation).malicious ?? 0)}
                    </span>
                  </div>
                  <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border rounded-xs space-y-1">
                    <span className="text-[10px] text-cyber-text-dim block">SUSPICIOUS:</span>
                    <span className="text-cyber-threat-high font-bold text-sm">
                      {Number((result.vt_reputation as VirusTotalReputation).suspicious ?? 0)}
                    </span>
                  </div>
                  <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border rounded-xs space-y-1">
                    <span className="text-[10px] text-cyber-text-dim block">HARMLESS / CLEAN:</span>
                    <span className="text-cyber-threat-secure font-bold text-sm">
                      {Number((result.vt_reputation as VirusTotalReputation).harmless ?? 0)}
                    </span>
                  </div>
                  <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border rounded-xs space-y-1">
                    <span className="text-[10px] text-cyber-text-dim block">TOTAL ENGINES:</span>
                    <span className="text-cyber-text-primary font-bold text-sm">
                      {Number((result.vt_reputation as VirusTotalReputation).total_engines ?? 0)}
                    </span>
                  </div>
                </div>
              )
            ) : (
              <div className="p-3 bg-cyber-bg-surface border border-cyber-border/70 rounded-xs flex items-center gap-2.5 text-cyber-text-dim text-xs font-mono">
                <Info className="h-4 w-4 shrink-0 text-cyber-accent" />
                <span>
                  VirusTotal API key not configured on server backend. External threat intelligence unavailable.
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
