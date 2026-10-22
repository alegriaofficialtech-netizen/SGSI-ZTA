import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Edit2,
  PowerOff,
  CheckCircle2,
  XCircle,
  KeyRound,
  History,
  AlertCircle,
} from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { Policy } from '../types/zeroTrust';
import { useAuth } from '../hooks/useAuth';

export const PolicyDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const isAdmin = user?.roles.includes('admin-ti');

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let active = true;
    zeroTrustApi
      .getPolicy(id)
      .then((res) => {
        if (active) setPolicy(res);
      })
      .catch(() => {
        if (active) setError('No se pudo cargar el detalle de la política.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [id]);

  const handleDisable = async () => {
    if (!policy) return;
    if (!window.confirm('¿Desea deshabilitar esta política?')) return;
    try {
      await zeroTrustApi.disablePolicy(policy.id);
      setPolicy({ ...policy, enabled: false });
    } catch {
      alert('Error al deshabilitar la política.');
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-400">
        <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
        <p>Cargando política...</p>
      </div>
    );
  }

  if (error || !policy) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg bg-rose-950/60 border border-rose-800 p-4 text-rose-200 text-sm flex items-center gap-2">
          <AlertCircle size={18} />
          <span>{error ?? 'Política no encontrada.'}</span>
        </div>
        <Link to="/zero-trust/policies" className="text-sm text-blue-400 hover:underline">
          Volver al listado
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link
            to="/zero-trust/policies"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <ArrowLeft size={18} />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-blue-400">{policy.code}</span>
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                  policy.effect === 'ALLOW'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'bg-rose-950 text-rose-400 border border-rose-800'
                }`}
              >
                {policy.effect}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white mt-1">{policy.name}</h1>
          </div>
        </div>

        {isAdmin && (
          <div className="flex items-center gap-2">
            <Link
              to={`/zero-trust/policies/${policy.id}/edit`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition"
            >
              <Edit2 size={14} /> Editar
            </Link>
            {policy.enabled && (
              <button
                onClick={() => void handleDisable()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 text-rose-400 border border-slate-700 hover:bg-slate-700 transition"
              >
                <PowerOff size={14} /> Deshabilitar
              </button>
            )}
          </div>
        )}
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2">
            Alcance de Autorización
          </h2>
          <div className="space-y-3 text-xs">
            <div>
              <span className="text-slate-400 block font-medium">Descripción:</span>
              <p className="text-slate-200 mt-1">{policy.description}</p>
            </div>
            <div className="grid grid-cols-2 gap-4 pt-2">
              <div>
                <span className="text-slate-400 block font-medium">Recurso:</span>
                <span className="font-mono text-sm text-cyan-300 font-semibold">
                  {policy.resource}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Acción:</span>
                <span className="font-mono text-sm text-blue-300 font-semibold">
                  {policy.action}
                </span>
              </div>
            </div>
            <div>
              <span className="text-slate-400 block font-medium mb-1.5">Roles Sujeto (RBAC):</span>
              <div className="flex flex-wrap gap-1.5">
                {policy.roles.map((r) => (
                  <span
                    key={r}
                    className="font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]"
                  >
                    {r}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2">
            Condiciones de Postura Zero Trust
          </h2>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div>
              <span className="text-slate-400 block font-medium">Exigencia MFA:</span>
              {policy.require_mfa ? (
                <span className="inline-flex items-center gap-1.5 text-amber-400 font-bold mt-1">
                  <KeyRound size={14} /> Obligatorio (TOTP RFC 6238)
                </span>
              ) : (
                <span className="text-slate-400 mt-1 inline-block">No requerido</span>
              )}
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Confianza de Dispositivo:</span>
              <span className="font-mono text-white font-semibold mt-1 inline-block">
                {policy.device_trust}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Prioridad de Evaluación:</span>
              <span className="font-mono text-white font-bold mt-1 inline-block">
                {policy.priority}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Umbral Máx. Riesgo:</span>
              <span className="font-mono text-rose-400 font-bold mt-1 inline-block">
                Score &le; {policy.max_risk_score}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Vigencia Máxima Sesión:</span>
              <span className="text-white mt-1 inline-block">
                {policy.session_max_age_minutes} minutos
              </span>
            </div>
            <div>
              <span className="text-slate-400 block font-medium">Estado en Motor:</span>
              <span
                className={`inline-flex items-center gap-1 font-semibold mt-1 ${
                  policy.enabled ? 'text-emerald-400' : 'text-slate-500'
                }`}
              >
                {policy.enabled ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                {policy.enabled ? 'Habilitada' : 'Deshabilitada'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Version History */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
        <h2 className="text-base font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
          <History size={18} className="text-slate-400" />
          Historial de Versiones y Auditoría
        </h2>
        {policy.history && policy.history.length > 0 ? (
          <div className="space-y-3">
            {policy.history.map((h) => (
              <div
                key={h.version}
                className="flex items-start justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs"
              >
                <div>
                  <div className="font-bold text-slate-200">
                    Versión {h.version} —{' '}
                    <span className="font-normal text-slate-400">{h.change_summary}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Autor: {h.updated_by}</div>
                </div>
                <span className="text-slate-500 font-mono text-[11px]">
                  {new Date(h.updated_at).toLocaleString('es-PE')}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-500">Versión 1 inicial activa.</p>
        )}
      </div>
    </div>
  );
};
