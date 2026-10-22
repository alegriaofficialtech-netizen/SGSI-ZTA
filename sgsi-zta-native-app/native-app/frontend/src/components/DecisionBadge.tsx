import React from 'react';
import { CheckCircle2, ShieldAlert, KeyRound } from 'lucide-react';
import type { Decision } from '../types/zeroTrust';

interface Props {
  decision: Decision;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const DecisionBadge: React.FC<Props> = ({ decision, size = 'md', showIcon = true }) => {
  const config = {
    ALLOW: {
      label: 'ALLOW',
      description: 'Acceso Permitido',
      className: 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40 hover:bg-emerald-900/60',
      icon: CheckCircle2,
      ariaLabel: 'Decisión: Permitido (ALLOW)',
    },
    DENY: {
      label: 'DENY',
      description: 'Acceso Denegado',
      className: 'bg-rose-950/80 text-rose-300 border-rose-500/40 hover:bg-rose-900/60',
      icon: ShieldAlert,
      ariaLabel: 'Decisión: Denegado (DENY)',
    },
    MFA_REQUIRED: {
      label: 'MFA REQUIRED',
      description: 'Segundo Factor Requerido',
      className: 'bg-amber-950/80 text-amber-300 border-amber-500/40 hover:bg-amber-900/60',
      icon: KeyRound,
      ariaLabel: 'Decisión: MFA Requerido (MFA_REQUIRED)',
    },
  }[decision];

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-base px-4 py-2 gap-2 font-bold tracking-wide',
  }[size];

  const iconSizes = {
    sm: 13,
    md: 15,
    lg: 20,
  }[size];

  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-full border shadow-sm transition-colors ${config.className} ${sizeClasses}`}
      role="status"
      aria-label={config.ariaLabel}
    >
      {showIcon && <Icon size={iconSizes} aria-hidden="true" />}
      <span>{config.label}</span>
    </span>
  );
};
