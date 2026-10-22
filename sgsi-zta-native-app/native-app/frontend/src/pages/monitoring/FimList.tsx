import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  FileCheck2,
  Plus,
  RefreshCw,
  Scan,
} from 'lucide-react';
import { FimStatusBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { useAuth } from '../../hooks/useAuth';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { FimGlobalScanResponse, FimScanResult, FimTarget } from '../../types/monitoring';

export function FimList() {
  const { user } = useAuth();
  const isAdmin = user?.roles.some((r) => r === 'admin-ti');

  const [targets, setTargets] = useState<FimTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Scan state
  const [scanningGlobal, setScanningGlobal] = useState(false);
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [lastScanResult, setLastScanResult] = useState<FimScanResult | null>(null);
  const [globalScanResult, setGlobalScanResult] = useState<FimGlobalScanResponse | null>(null);

  // Re-baseline confirmation state
  const [rebaselineTarget, setRebaselineTarget] = useState<FimTarget | null>(null);
  const [rebaselining, setRebaselining] = useState(false);

  // Register Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [targetCode, setTargetCode] = useState('');
  const [relativePath, setRelativePath] = useState('');
  const [assetId, setAssetId] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  async function fetchTargets() {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.listFimTargets();
      setTargets(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al cargar objetivos FIM';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    monitoringApi
      .listFimTargets()
      .then((res) => {
        if (active) {
          setTargets(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al cargar objetivos FIM';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleScanTarget(target: FimTarget) {
    if (!isAdmin) return;
    setScanningId(target.id);
    setError(null);
    setGlobalScanResult(null);
    try {
      const result = await monitoringApi.scanFimTarget(target.id);
      setLastScanResult(result);
      void fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al escanear objetivo';
      setError(msg);
    } finally {
      setScanningId(null);
    }
  }

  async function handleScanAll() {
    if (!isAdmin) return;
    setScanningGlobal(true);
    setError(null);
    setLastScanResult(null);
    try {
      const result = await monitoringApi.scanAllFim();
      setGlobalScanResult(result);
      void fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al ejecutar barrido global FIM';
      setError(msg);
    } finally {
      setScanningGlobal(false);
    }
  }

  async function handleConfirmRebaseline() {
    if (!rebaselineTarget || !isAdmin) return;
    setRebaselining(true);
    setError(null);
    try {
      await monitoringApi.rebaselineFimTarget(rebaselineTarget.id);
      setRebaselineTarget(null);
      void fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al regenerar línea base';
      setError(msg);
    } finally {
      setRebaselining(false);
    }
  }

  async function handleCreateTarget(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin) return;
    setCreateSubmitting(true);
    setError(null);
    try {
      await monitoringApi.createFimTarget({
        target_code: targetCode.toUpperCase(),
        relative_path: relativePath,
        asset_id: assetId ? parseInt(assetId, 10) : null,
        enabled: true,
      });
      setShowCreateModal(false);
      setTargetCode('');
      setRelativePath('');
      setAssetId('');
      void fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al registrar archivo FIM';
      setError(msg);
    } finally {
      setCreateSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            File Integrity Monitoring (FIM)
          </h1>
          <p className="text-sm text-slate-400">
            Supervisión criptográfica de integridad SHA-256 sobre archivos sintéticos del
            laboratorio
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
          {isAdmin && (
            <>
              <button
                onClick={() => void handleScanAll()}
                disabled={scanningGlobal}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-50"
                aria-label="Escanear todos los objetivos"
              >
                <Scan size={14} className={scanningGlobal ? 'animate-spin' : ''} />
                <span>{scanningGlobal ? 'Escaneando...' : 'Escanear Todo'}</span>
              </button>
              <button
                onClick={() => setShowCreateModal(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition"
                aria-label="Registrar nuevo objetivo"
              >
                <Plus size={14} />
                <span>Nuevo Archivo</span>
              </button>
            </>
          )}
          <button
            onClick={() => void fetchTargets()}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            aria-label="Refrescar objetivos"
          >
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <MonitoringSubNav />

      {error && (
        <div
          role="alert"
          className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-sm flex items-start gap-3"
        >
          <AlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Global Scan Banner Result */}
      {globalScanResult && (
        <div
          role="status"
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-white flex items-center gap-1.5">
              <CheckCircle2 size={15} className="text-emerald-400" />
              Resultado de Barrido Global FIM
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              Total: {globalScanResult.scanned} / {globalScanResult.total_targets}
            </span>
          </div>
          <div className="flex flex-wrap gap-4 text-xs text-slate-300">
            <span>
              Sin cambios:{' '}
              <strong className="text-emerald-400 font-bold">{globalScanResult.unchanged}</strong>
            </span>
            <span>
              Alteraciones:{' '}
              <strong
                className={
                  globalScanResult.changed > 0
                    ? 'text-rose-400 font-bold'
                    : 'text-slate-400 font-normal'
                }
              >
                {globalScanResult.changed}
              </strong>
            </span>
            <span>
              Faltantes:{' '}
              <strong
                className={
                  globalScanResult.missing > 0
                    ? 'text-amber-400 font-bold'
                    : 'text-slate-400 font-normal'
                }
              >
                {globalScanResult.missing}
              </strong>
            </span>
          </div>
        </div>
      )}

      {/* Single Scan Result Banner */}
      {lastScanResult && (
        <div
          role="status"
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-white flex items-center gap-2">
              <span>Resultado Escaneo: {lastScanResult.target_code}</span>
              <FimStatusBadge status={lastScanResult.status} />
            </h2>
            <button
              onClick={() => setLastScanResult(null)}
              className="text-slate-400 hover:text-white text-xs"
            >
              Cerrar
            </button>
          </div>
          <p className="text-xs text-slate-300 font-mono">{lastScanResult.message}</p>
          {lastScanResult.alert_id && (
            <p className="text-xs text-rose-300">
              Alerta generada:{' '}
              <Link
                to={`/monitoring/alerts/${lastScanResult.alert_id}`}
                className="underline text-rose-400 hover:text-rose-200"
              >
                {lastScanResult.alert_id}
              </Link>
            </p>
          )}
        </div>
      )}

      {/* Targets Table */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
            Cargando objetivos FIM...
          </div>
        )}

        {!loading && targets.length === 0 && (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <FileCheck2 size={32} className="mx-auto text-slate-600" />
            <p className="font-medium text-sm">No hay archivos supervisados registrados</p>
          </div>
        )}

        {!loading && targets.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th scope="col" className="py-3 px-4">
                    Código
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Ruta Relativa
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Activo
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Línea Base (SHA-256)
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Última Revisión
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Estado
                  </th>
                  <th scope="col" className="py-3 px-4 text-right">
                    Acciones
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {targets.map((target) => (
                  <tr key={target.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-white whitespace-nowrap">
                      {target.target_code}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{target.relative_path}</td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {target.asset_id ? `#${target.asset_id}` : '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {target.baseline_sha256.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                      {dateLabel(target.last_checked_at)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {target.enabled ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <Check size={13} /> Activo
                        </span>
                      ) : (
                        <span className="text-slate-500 font-medium">Inactivo</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                      <Link
                        to={`/monitoring/fim/${target.id}`}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-400 font-medium transition"
                      >
                        Detalle
                      </Link>
                      {isAdmin && (
                        <>
                          <button
                            onClick={() => void handleScanTarget(target)}
                            disabled={scanningId === target.id}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 font-medium transition disabled:opacity-40"
                            aria-label={`Escanear ${target.target_code}`}
                          >
                            {scanningId === target.id ? 'Escaneando...' : 'Escanear'}
                          </button>
                          <button
                            onClick={() => setRebaselineTarget(target)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 font-medium transition"
                            aria-label={`Regenerar línea base ${target.target_code}`}
                          >
                            Re-Baseline
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Re-Baseline Confirmation Modal */}
      {rebaselineTarget && (
        <div
          role="dialog"
          aria-labelledby="rebaseline-modal-title"
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <AlertTriangle size={24} className="text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h2 id="rebaseline-modal-title" className="text-base font-bold text-white">
                  Confirmar Nueva Línea Base: {rebaselineTarget.target_code}
                </h2>
                <p className="text-xs text-slate-300 mt-2">
                  Esta acción acepta el estado actual como nueva línea base. No elimina el historial
                  anterior.
                </p>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  Archivo: {rebaselineTarget.relative_path}
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-4 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setRebaselineTarget(null)}
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
                {rebaselining ? 'Calculando Hash...' : 'Aceptar Nueva Línea Base'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Register New FIM Target Modal */}
      {showCreateModal && (
        <div
          role="dialog"
          aria-labelledby="create-fim-modal-title"
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h2
              id="create-fim-modal-title"
              className="text-base font-bold text-white flex items-center gap-2"
            >
              <FileCheck2 size={18} className="text-blue-400" />
              Registrar Archivo Supervisado (FIM)
            </h2>

            <form onSubmit={(e) => void handleCreateTarget(e)} className="space-y-4">
              <div>
                <label
                  htmlFor="create-target-code"
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  Código de Objetivo <span className="text-rose-400">*</span>
                </label>
                <input
                  id="create-target-code"
                  type="text"
                  placeholder="Ej: FIM-PATIENT-DEMO"
                  value={targetCode}
                  onChange={(e) => setTargetCode(e.target.value.toUpperCase())}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono placeholder:text-slate-600"
                />
              </div>

              <div>
                <label
                  htmlFor="create-target-path"
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  Ruta Relativa en monitoring-data <span className="text-rose-400">*</span>
                </label>
                <input
                  id="create-target-path"
                  type="text"
                  placeholder="Ej: patient-demo.json"
                  value={relativePath}
                  onChange={(e) => setRelativePath(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono placeholder:text-slate-600"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Solo rutas relativas dentro del sandbox autorizado.
                </span>
              </div>

              <div>
                <label
                  htmlFor="create-target-asset"
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  ID Activo Hospitalario (Opcional)
                </label>
                <input
                  id="create-target-asset"
                  type="number"
                  placeholder="Ej: 1"
                  value={assetId}
                  onChange={(e) => setAssetId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                >
                  {createSubmitting ? 'Registrando...' : 'Establecer Baseline y Guardar'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
