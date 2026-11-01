import Link from "next/link";
import { Compass, Home, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-6 min-h-[60vh]">
      <div className="w-full max-w-md glass-panel border border-cyber-border p-6 sm:p-8 space-y-6 text-center">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-12 h-12 rounded-sm bg-cyber-accent/10 border border-cyber-accent/30 flex items-center justify-center text-cyber-accent">
            <Compass className="w-6 h-6 animate-spin-slow" />
          </div>
          <div className="space-y-1">
            <span className="text-[10px] font-mono tracking-widest uppercase text-cyber-text-muted">
              {"// HTTP 404 // ROUTE_NOT_FOUND"}
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-cyber-text-primary font-mono">
              TARGET VECTOR UNREACHABLE
            </h1>
          </div>
        </div>

        <p className="text-xs text-cyber-text-muted leading-relaxed font-sans">
          The requested intelligence vector, tactical tool, or endpoint does not exist or has been relocated to an alternate address.
        </p>

        <div className="flex items-center justify-center gap-3 pt-2">
          <Link href="/">
            <Button
              className="h-9 px-4 text-xs font-mono font-semibold bg-cyber-accent text-cyber-text-inverse hover:bg-cyber-accent-hover flex items-center justify-center gap-2"
            >
              <Home className="w-3.5 h-3.5" />
              RETURN OVERVIEW
            </Button>
          </Link>
          <Link href="/security-tools">
            <Button
              variant="outline"
              className="h-9 px-4 text-xs font-mono border-cyber-border hover:bg-cyber-bg-surface-hover text-cyber-text-secondary flex items-center justify-center gap-2"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              SECURITY TOOLS
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
