"use client";

import * as React from "react";
import {
  UploadCloud,
  FileCode,
  FileWarning,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Check,
  Copy,
  RotateCcw,
  Activity,
  Info,
  Server,
  Lock,
  X,
  FileText,
  AlertOctagon,
  HardDrive,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { securityToolsService } from "@/lib/api/services/security-tools";
import type { FileAnalyzeResponse, FileApiError, VirusTotalReputation } from "@/types/security-tools";

// Maximum upload size: 25 Megabytes (matching FastAPI MAX_FILE_SIZE = 25 * 1024 * 1024)
const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function FileAnalyzer() {
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);
  const [isDragging, setIsDragging] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<FileAnalyzeResponse | null>(null);
  const [error, setError] = React.useState<FileApiError | null>(null);
  const [validationWarning, setValidationWarning] = React.useState<string | null>(null);
  const [copiedKey, setCopiedKey] = React.useState<string | null>(null);

  const fileInputRef = React.useRef<HTMLInputElement | null>(null);

  const validateAndStageFile = (file: File) => {
    setValidationWarning(null);
    setError(null);
    setResult(null);

    // 1. Non-empty check
    if (file.size === 0) {
      setValidationWarning("Selected file is empty (0 Bytes). Please select a file with valid binary content.");
      setSelectedFile(null);
      return;
    }

    // 2. Maximum size check (< 25MB)
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setValidationWarning(
        `File exceeds the 25 MB maximum upload limit (${formatBytes(file.size)}). Please select a smaller binary or document.`
      );
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file) {
        validateAndStageFile(file);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      if (file) {
        validateAndStageFile(file);
      }
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setValidationWarning(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 2000);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setValidationWarning("Please stage a file to analyze before executing.");
      return;
    }

    // Final pre-flight verification
    if (selectedFile.size === 0) {
      setError({
        status: 400,
        title: "Empty File Payload",
        message: "Cannot inspect an empty file. Select a file with content.",
        isEmpty: true,
      });
      return;
    }

    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      setError({
        status: 413,
        title: "Payload Too Large",
        message: `File size (${formatBytes(selectedFile.size)}) exceeds server limit of 25 MB.`,
        isTooLarge: true,
      });
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await securityToolsService.analyzeFile(selectedFile);
      setResult(data);
    } catch (err) {
      const classified = securityToolsService.classifyFileError(err);
      setError(classified);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setResult(null);
    setError(null);
    setValidationWarning(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Helper test vector: generate simulated test file in client memory (never persisted)
  const handleSimulateSpoofedFile = () => {
    // Windows MZ header bytes disguised as an image
    const mzBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]);
    const blob = new Blob([mzBytes], { type: "image/png" });
    const mockFile = new File([blob], "invoice_report_2026.png", { type: "image/png" });
    validateAndStageFile(mockFile);
  };

  const handleSimulateCleanFile = () => {
    const textContent = new TextEncoder().encode("CYBERCORE Local Inspection Test Payload - Harmless Text Document");
    const blob = new Blob([textContent], { type: "text/plain" });
    const mockFile = new File([blob], "defense_audit_sample.txt", { type: "text/plain" });
    validateAndStageFile(mockFile);
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
      default:
        return "default";
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return "text-cyber-threat-critical border-cyber-threat-critical/40 bg-cyber-threat-critical/10";
    if (score >= 50) return "text-cyber-threat-high border-cyber-threat-high/40 bg-cyber-threat-high/10";
    if (score >= 20) return "text-cyber-threat-medium border-cyber-threat-medium/40 bg-cyber-threat-medium/10";
    if (score > 0) return "text-cyber-threat-low border-cyber-threat-low/40 bg-cyber-threat-low/10";
    return "text-cyber-threat-secure border-cyber-threat-secure/40 bg-cyber-threat-secure/10";
  };

  return (
    <div className="relative glass-panel border border-cyber-border rounded-xs p-6 sm:p-8 space-y-6 overflow-hidden">
      {/* Monolithic Corner Markers */}
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
              BINARY STATIC ANALYSIS // DEEP HEURISTIC INSPECTOR
            </span>
          </div>
          <h2 className="font-mono text-xl sm:text-2xl font-bold tracking-tight text-cyber-text-primary flex items-center gap-2.5">
            <HardDrive className="h-5 w-5 text-cyber-accent" />
            FILE BINARY UPLOAD & ANALYSIS
          </h2>
          <p className="text-xs font-mono text-cyber-text-secondary max-w-2xl">
            Inspects uploaded binaries and documents for executable risk, magic bytes MIME mismatches,
            and disguised double extensions (e.g. .pdf.exe). Calculates MD5, SHA-1, and SHA-256 signatures.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <Badge variant="arctic" className="text-[10px] py-1 gap-1.5">
            <Server className="h-3 w-3" /> POST /api/v1/files/analyze
          </Badge>
          <Badge variant="default" className="text-[10px] py-1 gap-1.5">
            <Lock className="h-3 w-3 text-cyber-threat-secure" /> IN-MEMORY ONLY (MAX 25MB)
          </Badge>
        </div>
      </div>

      {/* Upload Zone / File Selection */}
      {!result && (
        <div className="space-y-4">
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileChange}
            disabled={loading}
            className="hidden"
          />

          {!selectedFile ? (
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xs p-8 text-center cursor-pointer transition-all duration-200 select-none ${
                isDragging
                  ? "border-cyber-accent bg-cyber-accent-subtle/40 scale-[1.01]"
                  : "border-cyber-border hover:border-cyber-accent/60 bg-cyber-bg/60 hover:bg-cyber-bg"
              }`}
            >
              <div className="max-w-md mx-auto space-y-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-xs border border-cyber-border bg-cyber-bg-surface mx-auto text-cyber-accent">
                  <UploadCloud className="h-6 w-6" />
                </div>
                <div className="space-y-1">
                  <p className="font-mono text-sm font-semibold text-cyber-text-primary uppercase tracking-wider">
                    DRAG & DROP BINARY OR DOCUMENT
                  </p>
                  <p className="text-xs font-mono text-cyber-text-secondary">
                    or click to browse local filesystem
                  </p>
                </div>
                <div className="flex items-center justify-center gap-3 pt-2 text-[10px] font-mono text-cyber-text-dim">
                  <span>MAX SIZE: 25 MB</span>
                  <span>•</span>
                  <span>ALL FILE TYPES ACCEPTED</span>
                  <span>•</span>
                  <span>ZERO PERSISTENCE</span>
                </div>
              </div>
            </div>
          ) : (
            /* Staged File Card */
            <div className="p-4 bg-cyber-bg border border-cyber-accent/50 rounded-xs space-y-4">
              <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center border border-cyber-accent/40 bg-cyber-accent-subtle rounded-xs text-cyber-accent">
                    <FileText className="h-5 w-5" />
                  </div>
                  <div>
                    <span className="font-mono text-xs font-semibold text-cyber-text-primary block truncate max-w-sm sm:max-w-md">
                      {selectedFile.name}
                    </span>
                    <span className="font-mono text-[10px] text-cyber-text-dim">
                      STAGED FOR FASTAPI BINARY INSPECTION
                    </span>
                  </div>
                </div>

                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleRemoveFile}
                  disabled={loading}
                  className="h-7 px-2 text-cyber-text-dim hover:text-cyber-threat-critical"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>

              {/* Pre-flight File Metadata */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
                <div className="p-2 bg-cyber-bg-surface border border-cyber-border rounded-xs">
                  <span className="text-cyber-text-dim block text-[10px]">FILE SIZE:</span>
                  <span className="text-cyber-text-primary font-semibold">
                    {formatBytes(selectedFile.size)}
                  </span>
                </div>
                <div className="p-2 bg-cyber-bg-surface border border-cyber-border rounded-xs">
                  <span className="text-cyber-text-dim block text-[10px]">DECLARED EXT:</span>
                  <span className="text-cyber-accent font-semibold">
                    {selectedFile.name.includes(".")
                      ? `.${selectedFile.name.split(".").pop()?.toLowerCase()}`
                      : "NONE"}
                  </span>
                </div>
                <div className="p-2 bg-cyber-bg-surface border border-cyber-border rounded-xs col-span-2">
                  <span className="text-cyber-text-dim block text-[10px]">CLIENT MIME TYPE:</span>
                  <span className="text-cyber-text-secondary truncate block">
                    {selectedFile.type || "application/octet-stream (unspecified)"}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    onClick={handleAnalyze}
                    disabled={loading}
                    className="h-9 px-5 text-xs font-mono gap-2"
                  >
                    {loading ? (
                      <>
                        <Activity className="h-3.5 w-3.5 animate-spin" />
                        <span>ANALYZING BINARY...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="h-3.5 w-3.5" />
                        <span>ANALYZE FILE</span>
                      </>
                    )}
                  </Button>

                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleRemoveFile}
                    disabled={loading}
                    className="h-9 px-3 text-xs font-mono"
                  >
                    REPLACE FILE
                  </Button>
                </div>

                <span className="text-[10px] font-mono text-cyber-text-dim">
                  MULTIPART/FORM-DATA // FIELD: file
                </span>
              </div>
            </div>
          )}

          {/* Validation Warning */}
          {validationWarning && (
            <p className="text-[11px] font-mono text-cyber-threat-high flex items-center gap-1.5 p-2.5 bg-cyber-threat-high-bg border border-cyber-threat-high-border rounded-xs">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              <span>{validationWarning}</span>
            </p>
          )}

          {/* Synthetic Test Vectors */}
          <div className="space-y-2 border-t border-cyber-border/60 pt-4">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
                SYNTHETIC IN-MEMORY TEST SAMPLES
              </span>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                CLIENT-GENERATED IN MEMORY
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={handleSimulateSpoofedFile}
                disabled={loading}
                className="text-left p-2.5 bg-cyber-bg border border-cyber-border hover:border-cyber-threat-critical/50 rounded-xs space-y-1 transition-all group disabled:opacity-50"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-medium text-cyber-text-primary group-hover:text-cyber-threat-critical transition-colors">
                    Spoofed Disguised Binary (.png.exe)
                  </span>
                  <Badge variant="critical" className="text-[9px]">
                    SPOOF TEST
                  </Badge>
                </div>
                <p className="text-[10px] text-cyber-text-secondary leading-tight font-sans">
                  Simulates a Windows executable with MZ magic bytes disguised under a .png image extension.
                </p>
              </button>

              <button
                type="button"
                onClick={handleSimulateCleanFile}
                disabled={loading}
                className="text-left p-2.5 bg-cyber-bg border border-cyber-border hover:border-cyber-accent/50 rounded-xs space-y-1 transition-all group disabled:opacity-50"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-medium text-cyber-text-primary group-hover:text-cyber-accent transition-colors">
                    Standard Text Document (.txt)
                  </span>
                  <Badge variant="secure" className="text-[9px]">
                    CLEAN TEST
                  </Badge>
                </div>
                <p className="text-[10px] text-cyber-text-secondary leading-tight font-sans">
                  Harmless plain text document to test normal hash calculation and benign heuristic verdict.
                </p>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Loading Animation */}
      {loading && (
        <div className="p-8 border border-cyber-border bg-cyber-bg-surface/50 rounded-xs text-center space-y-3 animate-pulse">
          <Activity className="h-7 w-7 text-cyber-accent mx-auto animate-spin" />
          <div className="space-y-1">
            <p className="font-mono text-xs font-semibold text-cyber-text-primary uppercase tracking-wider">
              TRANSMITTING FILE TO FASTAPI BINARY HEURISTIC ENGINE
            </p>
            <p className="text-[11px] font-mono text-cyber-text-dim">
              Sniffing magic bytes, detecting extension spoofing, computing MD5/SHA-1/SHA-256 signatures...
            </p>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="p-4 border border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-cyber-threat-critical">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider">
                {error.title} {error.status > 0 && `(HTTP ${error.status})`}
              </span>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleReset}
              className="h-6 text-[10px] font-mono"
            >
              DISMISS
            </Button>
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

      {/* Results Section */}
      {result && !loading && (
        <div className="space-y-5 border-t border-cyber-border pt-5">
          {/* Top Verdict Banner */}
          <div className="p-4 bg-cyber-bg-surface border border-cyber-border rounded-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
                FASTAPI BINARY ANALYSIS VERDICT
              </span>
              <div className="flex items-center gap-3">
                <Badge
                  variant={getThreatBadgeVariant(result.threat_level)}
                  className="text-xs px-2.5 py-1 font-mono font-bold uppercase"
                >
                  {result.threat_level}
                </Badge>
                <span className="font-mono text-xs text-cyber-text-secondary">
                  STATIC THREAT CLASSIFICATION
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
                  result.risk_score
                )}`}
              >
                {result.risk_score}
              </div>
            </div>
          </div>

          {/* Extension Spoofing Alert */}
          {result.is_spoofed_extension ? (
            <div className="p-4 border-2 border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs space-y-2">
              <div className="flex items-center gap-2 text-cyber-threat-critical">
                <AlertOctagon className="h-5 w-5 shrink-0" />
                <span className="font-mono text-xs font-bold uppercase tracking-wider">
                  SECURITY WARNING: DISGUISED EXTENSION SPOOFING DETECTED!
                </span>
              </div>
              <p className="text-xs font-mono text-cyber-threat-critical/95 leading-relaxed">
                The file presents a declared extension of{" "}
                <span className="font-bold underline">{result.declared_extension}</span>, but the underlying binary
                magic bytes reveal an actual MIME type of{" "}
                <span className="font-bold underline">{result.detected_mime}</span>. This pattern is strongly indicative of
                malware delivery or social engineering evasion.
              </p>
            </div>
          ) : (
            <div className="p-3 bg-cyber-threat-secure-bg border border-cyber-threat-secure-border rounded-xs flex items-center gap-2 text-cyber-threat-secure text-xs font-mono">
              <Check className="h-4 w-4 shrink-0" />
              <span>
                File extension ({result.declared_extension}) aligns with detected magic-byte MIME signature ({result.detected_mime}).
              </span>
            </div>
          )}

          {/* File Metadata Overview */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">ORIGINAL FILENAME:</span>
              <span className="text-cyber-text-primary font-semibold truncate block">
                {result.filename}
              </span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">VERIFIED FILE SIZE:</span>
              <span className="text-cyber-text-primary font-semibold">
                {formatBytes(result.file_size)}
              </span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">DECLARED EXTENSION:</span>
              <span className="text-cyber-accent font-semibold">
                {result.declared_extension || "NONE"}
              </span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-1">
              <span className="text-[10px] text-cyber-text-dim block">DETECTED MIME TYPE:</span>
              <span className="text-cyber-text-primary font-semibold truncate block">
                {result.detected_mime}
              </span>
            </div>
          </div>

          {/* Computed Cryptographic Signatures */}
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xs space-y-3">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-2">
              <span className="text-xs font-mono font-semibold uppercase text-cyber-text-primary flex items-center gap-2">
                <FileCode className="h-3.5 w-3.5 text-cyber-accent" />
                COMPUTED CRYPTOGRAPHIC SIGNATURES (SERVER-VERIFIED)
              </span>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                FASTAPI GENERATED
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              {/* MD5 */}
              <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border/60 rounded-xs space-y-1">
                <div className="flex items-center justify-between text-cyber-text-dim text-[10px]">
                  <span>MD5 (128-BIT / 32 HEX):</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(result.md5, "md5")}
                    className="flex items-center gap-1 text-cyber-accent hover:underline text-[10px]"
                  >
                    {copiedKey === "md5" ? (
                      <>
                        <Check className="h-3 w-3 text-cyber-threat-secure" />
                        <span className="text-cyber-threat-secure">COPIED</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>COPY</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="text-cyber-text-primary break-all select-all text-xs">
                  {result.md5}
                </div>
              </div>

              {/* SHA-1 */}
              <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border/60 rounded-xs space-y-1">
                <div className="flex items-center justify-between text-cyber-text-dim text-[10px]">
                  <span>SHA-1 (160-BIT / 40 HEX):</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(result.sha1, "sha1")}
                    className="flex items-center gap-1 text-cyber-accent hover:underline text-[10px]"
                  >
                    {copiedKey === "sha1" ? (
                      <>
                        <Check className="h-3 w-3 text-cyber-threat-secure" />
                        <span className="text-cyber-threat-secure">COPIED</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>COPY</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="text-cyber-text-primary break-all select-all text-xs">
                  {result.sha1}
                </div>
              </div>

              {/* SHA-256 */}
              <div className="p-2.5 bg-cyber-bg-surface border border-cyber-border/60 rounded-xs space-y-1">
                <div className="flex items-center justify-between text-cyber-text-dim text-[10px]">
                  <span>SHA-256 (256-BIT / 64 HEX):</span>
                  <button
                    type="button"
                    onClick={() => handleCopy(result.sha256, "sha256")}
                    className="flex items-center gap-1 text-cyber-accent hover:underline text-[10px]"
                  >
                    {copiedKey === "sha256" ? (
                      <>
                        <Check className="h-3 w-3 text-cyber-threat-secure" />
                        <span className="text-cyber-threat-secure">COPIED</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>COPY</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="text-cyber-text-primary break-all select-all text-xs">
                  {result.sha256}
                </div>
              </div>
            </div>
          </div>

          {/* Analysis Findings */}
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xs space-y-3">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-2">
              <span className="text-xs font-mono font-semibold uppercase text-cyber-text-primary flex items-center gap-2">
                <Shield className="h-3.5 w-3.5 text-cyber-accent" />
                STATIC ANALYSIS FINDINGS ({result.findings.length})
              </span>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                FASTAPI HEURISTICS
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
                No specific binary flags or malicious heuristics detected.
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
            ) : (
              <div className="p-3 bg-cyber-bg-surface border border-cyber-border/70 rounded-xs flex items-center gap-2.5 text-cyber-text-dim text-xs font-mono">
                <Info className="h-4 w-4 shrink-0 text-cyber-accent" />
                <span>
                  VirusTotal API key not configured on server backend. Showing local cryptographic heuristic findings only.
                </span>
              </div>
            )}
          </div>

          {/* Reset / Upload Another */}
          <div className="pt-2 flex items-center justify-between border-t border-cyber-border">
            <Button
              type="button"
              variant="monolithic"
              onClick={handleReset}
              className="h-9 px-4 text-xs font-mono gap-2"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>ANALYZE ANOTHER FILE</span>
            </Button>

            <span className="text-[10px] font-mono text-cyber-text-dim">
              ZERO PERSISTENCE // FILE BUFFER RELEASED FROM RAM
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
