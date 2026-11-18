import React from 'react';
import { AlertTriangle, ShieldAlert, AlertCircle, Info, ShieldCheck } from 'lucide-react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const norm = severity?.toLowerCase() || 'informational';

  let colors = 'bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700';
  let Icon = Info;

  if (norm.includes('critical')) {
    colors = 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800 shadow-sm animate-pulse';
    Icon = ShieldAlert;
  } else if (norm.includes('high')) {
    colors = 'bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800 shadow-sm';
    Icon = AlertTriangle;
  } else if (norm.includes('medium')) {
    colors = 'bg-yellow-100 text-yellow-900 border-yellow-300 dark:bg-yellow-950/60 dark:text-yellow-300 dark:border-yellow-800';
    Icon = AlertCircle;
  } else if (norm.includes('low')) {
    colors = 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800';
    Icon = Info;
  } else if (norm.includes('clean') || norm.includes('confirmed')) {
    colors = 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800';
    Icon = ShieldCheck;
  }

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1 font-semibold',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-bold',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-md border uppercase tracking-wider font-mono ${colors} ${sizeClasses}`}
    >
      {showIcon && <Icon className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5 shrink-0'} />}
      <span>{severity || 'INFORMATIONAL'}</span>
    </span>
  );
};

