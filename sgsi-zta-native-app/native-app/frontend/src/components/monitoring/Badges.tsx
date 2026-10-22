import {
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCheck,
  FileX,
  Info,
  KeyRound,
  Lock,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import type { AlertStatus, EventType, Severity } from '../../types/monitoring';

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const sev = severity.toUpperCase();
  switch (sev) {
    case 'CRITICAL':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/50 text-rose-300 border border-rose-700/60"
          aria-label={`Severidad Crítica: ${sev}`}
        >
          <ShieldAlert size={13} className="text-rose-400" aria-hidden="true" />
          <span>CRITICAL</span>
        </span>
      );
    case 'HIGH':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/50 text-amber-300 border border-amber-700/60"
          aria-label={`Severidad Alta: ${sev}`}
        >
          <AlertTriangle size={13} className="text-amber-400" aria-hidden="true" />
          <span>HIGH</span>
        </span>
      );
    case 'MEDIUM':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-950/40 text-yellow-300 border border-yellow-700/50"
          aria-label={`Severidad Media: ${sev}`}
        >
          <AlertCircle size={13} className="text-yellow-400" aria-hidden="true" />
          <span>MEDIUM</span>
        </span>
      );
    case 'LOW':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-950/40 text-blue-300 border border-blue-700/50"
          aria-label={`Severidad Baja: ${sev}`}
        >
          <Info size={13} className="text-blue-400" aria-hidden="true" />
          <span>LOW</span>
        </span>
      );
    case 'INFO':
    default:
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700"
          aria-label={`Severidad Informativa: ${sev}`}
        >
          <Info size={13} className="text-slate-400" aria-hidden="true" />
          <span>INFO</span>
        </span>
      );
  }
}

export function AlertStatusBadge({ status }: { status: AlertStatus | string }) {
  const st = status.toUpperCase();
  switch (st) {
    case 'OPEN':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/50 text-rose-300 border border-rose-800/80"
          aria-label={`Estado Alerta: Abierta`}
        >
          <AlertOctagon size={13} className="text-rose-400" aria-hidden="true" />
          <span>OPEN</span>
        </span>
      );
    case 'ACKNOWLEDGED':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-950/50 text-sky-300 border border-sky-800/80"
          aria-label={`Estado Alerta: Reconocida`}
        >
          <Clock size={13} className="text-sky-400" aria-hidden="true" />
          <span>ACKNOWLEDGED</span>
        </span>
      );
    case 'RESOLVED':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/50 text-emerald-300 border border-emerald-800/80"
          aria-label={`Estado Alerta: Resuelta`}
        >
          <CheckCircle2 size={13} className="text-emerald-400" aria-hidden="true" />
          <span>RESOLVED</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300">
          <span>{status}</span>
        </span>
      );
  }
}

export function EventTypeBadge({ eventType }: { eventType: EventType | string }) {
  const typeMap: Record<string, { label: string; icon: typeof Shield }> = {
    AUTH_FAILURE: { label: 'Fallo Autenticación', icon: KeyRound },
    AUTH_SUCCESS: { label: 'Autenticación OK', icon: Lock },
    MFA_FAILURE: { label: 'Fallo MFA', icon: KeyRound },
    POLICY_DENY: { label: 'Denegación ZTA', icon: ShieldAlert },
    POLICY_MFA_REQUIRED: { label: 'MFA Requerido', icon: KeyRound },
    FILE_INTEGRITY_CHANGE: { label: 'Integridad (FIM)', icon: FileCheck },
    ASSET_CHANGE: { label: 'Cambio de Activo', icon: Shield },
    RISK_CHANGE: { label: 'Cambio de Riesgo', icon: AlertTriangle },
    SECURITY_CONFIGURATION_CHANGE: { label: 'Config Seguridad', icon: Shield },
  };

  const info = typeMap[eventType] || { label: eventType, icon: Shield };
  const IconComponent = info.icon;

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-medium bg-slate-800/90 text-slate-200 border border-slate-700/60"
      title={eventType}
    >
      <IconComponent size={12} className="text-blue-400" aria-hidden="true" />
      <span>{info.label}</span>
    </span>
  );
}

export function FimStatusBadge({ status }: { status: string }) {
  const st = status.toUpperCase();
  switch (st) {
    case 'NO_CHANGE':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/50 text-emerald-300 border border-emerald-800"
          aria-label="Estado FIM: Saludable sin cambios"
        >
          <CheckCircle2 size={13} className="text-emerald-400" aria-hidden="true" />
          <span>NO_CHANGE</span>
        </span>
      );
    case 'HASH_MISMATCH':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/50 text-rose-300 border border-rose-800 animate-pulse"
          aria-label="Estado FIM: Hash alterado"
        >
          <AlertTriangle size={13} className="text-rose-400" aria-hidden="true" />
          <span>HASH_MISMATCH</span>
        </span>
      );
    case 'FILE_MISSING':
      return (
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/50 text-amber-300 border border-amber-800"
          aria-label="Estado FIM: Archivo faltante"
        >
          <FileX size={13} className="text-amber-400" aria-hidden="true" />
          <span>FILE_MISSING</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
          <span>{status}</span>
        </span>
      );
  }
}
