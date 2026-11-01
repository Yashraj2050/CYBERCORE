"use client";

import * as React from "react";
import { TopNavigation } from "@/components/navigation/top-navigation";
import { MobileNavigation } from "@/components/navigation/mobile-navigation";
import { dashboardService } from "@/lib/api/services/dashboard";

interface AppHeaderProps {
  onOpenCommandMenu: () => void;
}

export function AppHeader({ onOpenCommandMenu }: AppHeaderProps) {
  const [systemStatus, setSystemStatus] = React.useState<string>("STANDBY");
  const [isBackendConnected, setIsBackendConnected] = React.useState<boolean>(false);

  // Poll or query backend telemetry on mount
  React.useEffect(() => {
    let mounted = true;
    async function checkHealth() {
      try {
        const stats = await dashboardService.getStats();
        if (mounted) {
          setSystemStatus(stats.system_status || "OPERATIONAL");
          setIsBackendConnected(true);
        }
      } catch {
        if (mounted) {
          setSystemStatus("STANDBY");
          setIsBackendConnected(false);
        }
      }
    }

    checkHealth();
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyber-border glass-subtle transition-colors duration-200">
      <div className="w-full px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        <div className="flex-1">
          <TopNavigation
            onOpenCommandMenu={onOpenCommandMenu}
            systemStatus={systemStatus}
            isBackendConnected={isBackendConnected}
          />
        </div>

        <MobileNavigation
          onOpenCommandMenu={onOpenCommandMenu}
          systemStatus={systemStatus}
          isBackendConnected={isBackendConnected}
        />
      </div>
    </header>
  );
}
