import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { History, ArrowLeft, AlertCircle, Shield, Monitor, Box } from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { DecisionLog } from '../types/zeroTrust';
import { DecisionBadge } from '../components/DecisionBadge';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';

export const DecisionDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [decision, setDecision] = useState<DecisionLog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let active = true;
    zeroTrustApi
      .getDecision(id)
      .then((res) => {
        if (active) setDecision(res);
      })
      .catch(() => {
        if (active) setError('No se pudo encontrar la decisión solicitada.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [id]);

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-400">
        <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
        <p>Cargando auditoría de decisión...</p>
      </div>
    );
  }

  if (error || !decision) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg bg-rose-950/60 border border-rose-800 p-4 text-rose-200 text-sm flex items-center gap-2">
          <AlertCircle size={18} />
          <span>{error ?? 'Registro de decisión no encontrado.'}</span>
        </div>
        <Link to="/zero-trust/decisions" className="text-sm text-blue-400 hover:underline">
          Volver a Decisiones
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/zero-trust/decisions"
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
        >
          <ArrowLeft size={18} />
        </Link>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-slate-500">ID: {decision.id}</span>
            <span className="text-xs text-slate-500">·</span>
            <span className="text-xs text-slate-400">
              {new Date(decision.timestamp).toLocaleString('es-PE')}
            </span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1 flex items-center gap-2">
            <History className="text-blue-500" size={24} />
            Auditoría de Decisión Zero Trust
          </h1>
        </div>
      </div>

      {/* Main Decision Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-sm flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <span className="text-xs text-slate-400 uppercase font-semibold">Veredicto Emitido</span>
          <div className="mt-2">
            <DecisionBadge decision={decision.decision} size="lg" />
          </div>
        </div>
        <div className="sm:text-right">
          <span className="text-xs text-slate-400 block mb-1">Razón Oficial:</span>
          <ReasonCodeBadge code={decision.reason_code} showExplanation />
        </div>
      </div>

      {/* Context Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
        {/* Subject */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-sm font-semibold text-white border-b border-slate-800 pb-2 flex items-center gap-2">
            <Shield size={16} className="text-blue-400" />
            Sujeto y Autenticación
          </h2>
          <div className="space-y-2">
            <div>
              <span className="text-slate-500 block">Usuario:</span>
              <strong className="text-white text-sm font-mono">
                {decision.subject_username || 'No disponible'}
              </strong>
            </div>
            <div>
              <span className="text-slate-500 block">Roles Asignados:</span>
              <span className="font-mono text-blue-300">
                [
                {decision.subject_roles.length > 0
                  ? decision.subject_roles.join(', ')
                  : 'No disponible'}
                ]
              </span>
            </div>
            <div>
              <span className="text-slate-500 block">Segundo Factor (MFA):</span>
              <span
                className={`font-semibold ${
                  decision.subject_mfa_state ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {decision.subject_mfa_state ? 'Verificado en sesión' : 'No verificado'}
              </span>
            </div>
          </div>
        </div>

        {/* Target and Posture */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-sm font-semibold text-white border-b border-slate-800 pb-2 flex items-center gap-2">
            <Monitor size={16} className="text-cyan-400" />
            Dispositivo y Activo
          </h2>
          <div className="space-y-2">
            <div>
              <span className="text-slate-500 block">Dispositivo ID:</span>
              <strong className="text-slate-200 font-mono">
                {decision.device_id ?? 'No disponible'}
              </strong>
            </div>
            <div>
              <span className="text-slate-500 block">Nivel de Confianza:</span>
              <span className="font-mono text-white">{decision.device_trust}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Activo Hospitalario:</span>
              <span className="text-slate-200">
                {decision.asset_name
                  ? `${decision.asset_name} (${decision.asset_id})`
                  : 'No disponible'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block">Score de Riesgo Dinámico:</span>
              <span className="font-mono font-bold text-rose-400">
                {decision.effective_risk_score} / 100
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Target Resource & Matched Policy */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3 text-xs">
        <h2 className="text-sm font-semibold text-white border-b border-slate-800 pb-2 flex items-center gap-2">
          <Box size={16} className="text-purple-400" />
          Operación Evaluada
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <span className="text-slate-500 block">Recurso Objetivo:</span>
            <span className="font-mono text-sm text-cyan-300 font-bold">{decision.resource}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Acción Solicitada:</span>
            <span className="font-mono text-sm text-blue-300 font-bold">{decision.action}</span>
          </div>
          <div className="sm:col-span-2 pt-2 border-t border-slate-800">
            <span className="text-slate-500 block">Política Coincidente Aplicada:</span>
            {decision.policy_code ? (
              <span className="font-mono text-sm text-blue-400 font-bold">
                {decision.policy_code}
              </span>
            ) : (
              <span className="font-mono text-sm text-rose-400 font-semibold">
                DEFAULT_DENY (Acceso denegado por defecto sin regla explícita)
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
