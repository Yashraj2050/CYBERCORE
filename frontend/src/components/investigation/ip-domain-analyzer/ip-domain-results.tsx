"use client";

import * as React from "react";
import { IpInvestigationView } from "./ip-investigation-view";
import { DomainInvestigationView } from "./domain-investigation-view";
import type { IpDomainResult } from "@/types/ip-domain";

interface IpDomainResultsProps {
  result: IpDomainResult;
}

export function IpDomainResults({ result }: IpDomainResultsProps) {
  if (result.type === "ip") {
    return <IpInvestigationView result={result} />;
  }

  if (result.type === "domain") {
    return <DomainInvestigationView result={result} />;
  }

  return (
    <div className="p-6 bg-cyber-bg-secondary border border-cyber-border font-mono text-xs text-cyber-threat-high">
      Unrecognized entity response type: {(result as { type?: string }).type || "Unknown"}
    </div>
  );
}

