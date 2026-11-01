import * as React from "react";
import { cn } from "@/lib/utils";

export interface PageContainerProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export function PageContainer({
  children,
  className,
  ...props
}: PageContainerProps) {
  return (
    <div
      className={cn(
        "flex-1 w-full px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-6 md:space-y-8",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

