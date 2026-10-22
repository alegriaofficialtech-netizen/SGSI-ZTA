import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Check,
  Copy,
  FileCheck2,
  Fingerprint,
  RefreshCw,
  Scan,
  Shield,
} from 'lucide-react';
import { FimStatusBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { useAuth } from '../../hooks/useAuth';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { FimScanResult, FimTarget } from '../../types/monitoring';

export function FimDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const isAdmin = user?.roles.some((r) => r === 'admin-ti');

  const [target, setTarget] = useState<FimTarget | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<FimScanResult | null>(null);
  const [scanning, setScanning] = useState(false);

  // Re-baseline confirmation state
  const [showRebaselineConfirm, setShowRebaselineConfirm] = useState(false);
  const [rebaselining, setRebaselining] = useState(false);

  // Copy hash state
  const [copiedBaseline, setCopiedBaseline] = useState(false);
  const [copiedLast, setCopiedLast] = useState(false);

  async function loadTarget() {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.getFimTarget(id);
      setTarget(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al cargar detalle del objetivo FIM';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!id) return;
    let active = true;
    monitoringApi
      .getFimTarget(id)
      .then((res) => {
        if (active) {
          setTarget(res);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg =
            err instanceof Error ? err.message : 'Error al cargar detalle del objetivo FIM';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [id]);

  async function handleScan() {
    if (!id || !isAdmin) return;
    setScanning(true);
    setError(null);
    try {
      const res = await monitoringApi.scanFimTarget(id);
      setScanResult(res);
      void loadTarget();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al ejecutar escaneo';
      setError(msg);
    } finally {
      setScanning(false);
    }
  }

  async function handleConfirmRebaseline() {
    if (!id || !isAdmin) return;
    setRebaselining(true);
    setError(null);
    try {
      const updated = await monitoringApi.rebaselineFimTarget(id);
      setTarget(updated);
      setShowRebaselineConfirm(false);
      setScanResult(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al regenerar línea base';
      setError(msg);
    } finally {
      setRebaselining(false);
    }
  }

  function copyText(text: string, type: 'baseline' | 'last') {
    void navigator.clipboard.writeText(text);
    if (type === 'baseline') {
      setCopiedBaseline(true);
      setTimeout(() => setCopiedBaseline(false), 2000);
    } else {
      setCopiedLast(true);
      setTimeout(() => setCopiedLast(false), 2000);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/monitoring/fim"
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          aria-label="Volver a lista FIM"
        >
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Supervisión FIM</h1>
          <p className="text-xs text-slate-400 font-mono">Objetivo: {target?.target_code || id}</p>
        </div>
      </div>

      <MonitoringSubNav />

      {loading && (
        <div className="py-20 text-center text-slate-400">
          <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
          <p className="text-sm">Cargando objetivo FIM...</p>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-sm flex items-start gap-3"
        >
          <AlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {target && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Info */}
          <div className="lg:col-span-2 space-y-6">
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-blue-950/50 text-blue-400 border border-blue-800/60">
                    <FileCheck2 size={22} />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-white">{target.target_code}</h2>
                    <span className="text-xs text-slate-400 font-mono">
                      Ruta relativa: {target.relative_path}
                    </span>
                  </div>
                </div>
                {scanResult ? (
                  <FimStatusBadge status={scanResult.status} />
                ) : (
                  <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-medium">
                    {target.enabled ? 'Habilitado' : 'Inactivo'}
                  </span>
                )}
              </div>

              {/* Hash Comparison Box */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1 font-semibold">
                      <Fingerprint size={13} className="text-blue-400" />
                      Línea Base Oficial (SHA-256)
                    </span>
                    <button
                      onClick={() => copyText(target.baseline_sha256, 'baseline')}
                      className="text-slate-400 hover:text-white flex items-center gap-1 transition"
                      aria-label="Copiar hash de línea base"
                    >
                      {copiedBaseline ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedBaseline ? 'Copiado' : 'Copiar completo'}</span>
                    </button>
                  </div>
                  <code
                    data-testid="baseline-hash"
                    className="block p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 break-all"
                  >
                    {target.baseline_sha256}
                  </code>
                </div>

                {target.last_sha256 && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400 flex items-center gap-1 font-semibold">
                        <Fingerprint size={13} className="text-amber-400" />
                        Último Hash Calculado en Disco (SHA-256)
                      </span>
                      <button
                        onClick={() => copyText(target.last_sha256!, 'last')}
                        className="text-slate-400 hover:text-white flex items-center gap-1 transition"
                        aria-label="Copiar último hash calculado"
                      >
                        {copiedLast ? <Check size={12} /> : <Copy size={12} />}
                        <span>{copiedLast ? 'Copiado' : 'Copiar completo'}</span>
                      </button>
                    </div>
                    <code
                      data-testid="last-hash"
                      className={`block p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono break-all ${
                        target.last_sha256 === target.baseline_sha256
                          ? 'text-emerald-300'
                          : 'text-rose-400 font-bold'
                      }`}
                    >
                      {target.last_sha256}
                    </code>
                  </div>
                )}
              </div>

              {/* Actions for Admin */}
              {isAdmin && (
                <div className="pt-4 border-t border-slate-800 flex flex-wrap gap-3">
                  <button
                    onClick={() => void handleScan()}
                    disabled={scanning}
                    className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
                    aria-label="Escanear objetivo FIM ahora"
                  >
                    <Scan size={14} className={scanning ? 'animate-spin' : ''} />
                    <span>{scanning ? 'Escaneando...' : 'Escanear Ahora'}</span>
                  </button>

                  <button
                    onClick={() => setShowRebaselineConfirm(true)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-800/60 text-xs font-semibold flex items-center gap-1.5 transition"
                    aria-label="Aceptar Estado Actual como Línea Base"
                  >
                    <span>Aceptar Estado Actual como Línea Base</span>
                  </button>
                </div>
              )}
            </div>

            {/* Scan Result Details */}
            {scanResult && (
              <div
                role="status"
                className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3"
              >
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Detalle del Último Escaneo en Vivo
                </h3>
                <div className="space-y-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">Diagnóstico:</span>
                    <FimStatusBadge status={scanResult.status} />
                  </div>
                  <p className="text-slate-300 font-mono bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    {scanResult.message}
                  </p>
                  {scanResult.event_id && (
                    <div className="text-slate-300">
                      Evento de integridad:{' '}
                      <Link
                        to={`/monitoring/events/${scanResult.event_id}`}
                        className="text-blue-400 hover:underline font-mono"
                      >
                        {scanResult.event_id}
                      </Link>
                    </div>
                  )}
                  {scanResult.alert_id && (
                    <div className="text-rose-300">
                      Alerta generada:{' '}
                      <Link
                        to={`/monitoring/alerts/${scanResult.alert_id}`}
                        className="text-rose-400 hover:underline font-mono font-bold"
                      >
                        {scanResult.alert_id}
                      </Link>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Metadatos del Sandbox
              </h3>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Shield size={13} className="text-amber-400" /> Activo Relacionado
                  </span>
                  <strong className="text-white block">
                    {target.asset_id ? `ID #${target.asset_id}` : 'No vinculado'}
                  </strong>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Calendar size={13} className="text-slate-400" /> Última Verificación
                  </span>
                  <span className="text-slate-200 font-mono">
                    {dateLabel(target.last_checked_at)}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5">Fecha de Creación</span>
                  <span className="text-slate-200 font-mono">{dateLabel(target.created_at)}</span>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5">Última Actualización</span>
                  <span className="text-slate-200 font-mono">{dateLabel(target.updated_at)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {showRebaselineConfirm && (
        <div
          role="dialog"
          aria-labelledby="confirm-dialog-title"
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <AlertTriangle size={24} className="text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h2 id="confirm-dialog-title" className="text-base font-bold text-white">
                  Confirmar Nueva Línea Base
                </h2>
                <p className="text-xs text-slate-300 mt-2">
                  Esta acción acepta el estado actual como nueva línea base. No elimina el historial
                  anterior.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowRebaselineConfirm(false)}
                disabled={rebaselining}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmRebaseline()}
                disabled={rebaselining}
                className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs disabled:opacity-50 transition"
              >
                {rebaselining ? 'Procesando...' : 'Aceptar Nueva Línea Base'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
