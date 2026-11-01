import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap text-xs font-mono uppercase tracking-tactical font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent focus-visible:ring-offset-1 focus-visible:ring-offset-cyber-bg disabled:pointer-events-none disabled:opacity-40 select-none",
  {
    variants: {
      variant: {
        default:
          "bg-cyber-accent text-cyber-bg font-semibold hover:bg-cyber-accent-hover shadow-subtle active:scale-[0.99]",
        monolithic:
          "bg-cyber-bg-secondary text-cyber-text-primary border border-cyber-border hover:border-cyber-border-strong hover:bg-cyber-bg-surface active:bg-cyber-bg-tertiary",
        arctic:
          "glass-subtle text-cyber-text-primary hover:border-cyber-accent/50 hover:text-white active:bg-cyber-bg-surface-elevated",
        outline:
          "border border-cyber-border text-cyber-text-secondary hover:text-cyber-text-primary hover:border-cyber-border-strong bg-transparent active:bg-cyber-bg-secondary/50",
        ghost:
          "text-cyber-text-secondary hover:text-cyber-text-primary hover:bg-cyber-bg-secondary active:bg-cyber-bg-surface",
        destructive:
          "bg-cyber-threat-critical-bg text-cyber-threat-critical border border-cyber-threat-critical-border hover:bg-cyber-threat-critical/20",
        secure:
          "bg-cyber-threat-secure-bg text-cyber-threat-secure border border-cyber-threat-secure-border hover:bg-cyber-threat-secure/20",
      },
      size: {
        xs: "h-6 px-2 text-[10px]",
        sm: "h-7 px-3 text-[11px]",
        default: "h-9 px-4 py-2",
        lg: "h-10 px-5 text-xs",
        icon: "h-9 w-9 p-0",
        "icon-sm": "h-7 w-7 p-0",
      },
      radius: {
        none: "rounded-none",
        xs: "rounded-xs",
        sm: "rounded-sm",
        default: "rounded-xs",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
      radius: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, radius, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, radius, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
