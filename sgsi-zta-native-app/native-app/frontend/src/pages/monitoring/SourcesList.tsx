import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Key,
  Plus,
  Power,
  RefreshCw,
  RotateCw,
  Server,
  ShieldAlert,
  X,
} from 'lucide-react';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { useAuth } from '../../hooks/useAuth';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { MonitoringSource, SourceType } from '../../types/monitoring';

export function SourcesList() {
  const { user } = useAuth();
  const isAdmin = user?.roles.some((r) => r === 'admin-ti');

  const [sources, setSources] = useState<MonitoringSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Create Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [sourceCode, setSourceCode] = useState('');
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState<SourceType>('HOST');
  const [assetId, setAssetId] = useState<string>('');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // One-time Key Modal state
  const [oneTimeKey, setOneTimeKey] = useState<{ code: string; key: string } | null>(null);
  const [copied, setCopied] = useState(false);

  // Rotate Key state
  const [rotatingId, setRotatingId] = useState<string | null>(null);

  async function fetchSources() {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.listSources();
      setSources(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al cargar fuentes de monitoreo';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    monitoringApi
      .listSources()
      .then((res) => {
        if (active) {
          setSources(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al cargar fuentes de monitoreo';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin) return;
    if (!sourceCode || sourceCode.length < 3 || sourceCode.length > 40) {
      setError('Código de fuente debe tener entre 3 y 40 caracteres.');
      return;
    }
    if (!name || name.trim().length === 0) {
      setError('El nombre de la fuente es requerido.');
      return;
    }

    setCreateSubmitting(true);
    setError(null);
    try {
      const created = await monitoringApi.createSource({
        source_code: sourceCode.toUpperCase(),
        name,
        source_type: sourceType,
        asset_id: assetId ? parseInt(assetId, 10) : null,
        enabled: true,
      });

      // Show one-time key in memory ONLY
      setOneTimeKey({ code: created.source_code, key: created.api_key });
      setShowCreateModal(false);
      setSourceCode('');
      setName('');
      setAssetId('');
      void fetchSources();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al registrar fuente';
      setError(msg);
    } finally {
      setCreateSubmitting(false);
    }
  }

  async function handleRotateKey(source: MonitoringSource) {
    if (!isAdmin) return;
    const ok = window.confirm(
      `¿Deseas rotar la clave de ${source.source_code}? La clave anterior quedará invalidada inmediatamente.`,
    );
    if (!ok) return;

    setRotatingId(source.id);
    setError(null);
    try {
      const rotated = await monitoringApi.rotateSourceKey(source.id);
      // Show new key in memory ONLY
      setOneTimeKey({ code: rotated.source_code, key: rotated.api_key });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al rotar clave';
      setError(msg);
    } finally {
      setRotatingId(null);
    }
  }

  async function handleToggleEnabled(source: MonitoringSource) {
    if (!isAdmin) return;
    try {
      const updated = await monitoringApi.updateSource(source.id, {
        enabled: !source.enabled,
      });
      setSources((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al modificar fuente';
      setError(msg);
    }
  }

  function copyKeyToClipboard() {
    if (!oneTimeKey) return;
    void navigator.clipboard.writeText(oneTimeKey.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Fuentes de Monitoreo</h1>
          <p className="text-sm text-slate-400">
            Sistemas, agentes e integraciones autenticadas mediante claves criptográficas Argon2id
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          {isAdmin && (
            <button
              onClick={() => {
                setShowCreateModal(true);
                setError(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition"
              aria-label="Registrar Fuente"
            >
              <Plus size={15} />
              <span>Registrar Fuente</span>
            </button>
          )}
          <button
            onClick={() => void fetchSources()}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            aria-label="Refrescar fuentes"
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

      {/* One-Time API Key Banner/Modal */}
      {oneTimeKey && (
        <div
          role="dialog"
          aria-labelledby="one-time-key-title"
          className="p-5 rounded-xl bg-amber-950/40 border border-amber-600/80 space-y-4 shadow-xl"
        >
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <ShieldAlert size={22} className="text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h2 id="one-time-key-title" className="text-sm font-bold text-amber-200">
                  Clave de Monitoreo Generada para {oneTimeKey.code}
                </h2>
                <p className="text-xs text-amber-300/90 mt-1">
                  <strong>Guarde esta clave ahora. No volverá a mostrarse.</strong> El servidor
                  almacena únicamente el hash Argon2id irreversible.
                </p>
              </div>
            </div>
            <button
              onClick={() => setOneTimeKey(null)}
              className="text-slate-400 hover:text-white transition"
              aria-label="Cerrar aviso de clave"
            >
              <X size={18} />
            </button>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              aria-label="Clave de API de un solo uso"
              data-testid="one-time-api-key"
              value={oneTimeKey.key}
              className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-amber-700/60 font-mono text-xs text-amber-100 select-all"
            />
            <button
              onClick={copyKeyToClipboard}
              className="px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition"
              aria-label="Copiar clave de API"
            >
              {copied ? <Check size={14} /> : <Copy size={14} />}
              <span>{copied ? 'Copiada' : 'Copiar'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Sources Table */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
            Cargando fuentes de monitoreo...
          </div>
        )}

        {!loading && sources.length === 0 && (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <Server size={32} className="mx-auto text-slate-600" />
            <p className="font-medium text-sm">No hay fuentes registradas</p>
          </div>
        )}

        {!loading && sources.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th scope="col" className="py-3 px-4">
                    Código
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Nombre
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Tipo
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Activo Vinculado
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Última Actividad
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Estado
                  </th>
                  {isAdmin && (
                    <th scope="col" className="py-3 px-4 text-right">
                      Acciones
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {sources.map((src) => (
                  <tr key={src.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-white whitespace-nowrap">
                      {src.source_code}
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">{src.name}</td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                        {src.source_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                      {src.asset_id ? `#${src.asset_id}` : '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                      {dateLabel(src.last_seen_at)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {src.enabled ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <Check size={13} /> Habilitada
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-500 font-medium">
                          <X size={13} /> Deshabilitada
                        </span>
                      )}
                    </td>
                    {isAdmin && (
                      <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                        {src.source_type !== 'FIM' && (
                          <button
                            onClick={() => void handleRotateKey(src)}
                            disabled={rotatingId === src.id}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 text-xs font-medium transition disabled:opacity-40"
                            title="Rotar clave de API"
                            aria-label={`Rotar clave para ${src.source_code}`}
                          >
                            <RotateCw
                              size={12}
                              className={rotatingId === src.id ? 'animate-spin' : ''}
                            />
                            <span>Rotar Clave</span>
                          </button>
                        )}
                        <button
                          onClick={() => void handleToggleEnabled(src)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                          title={src.enabled ? 'Deshabilitar fuente' : 'Habilitar fuente'}
                          aria-label={
                            src.enabled
                              ? `Deshabilitar fuente ${src.source_code}`
                              : `Habilitar fuente ${src.source_code}`
                          }
                        >
                          <Power
                            size={13}
                            className={src.enabled ? 'text-amber-400' : 'text-slate-600'}
                          />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Source Modal */}
      {showCreateModal && (
        <div
          role="dialog"
          aria-labelledby="create-source-modal-title"
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
        >
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2
                id="create-source-modal-title"
                className="text-base font-bold text-white flex items-center gap-2"
              >
                <Key size={18} className="text-blue-400" />
                Registrar Fuente de Monitoreo
              </h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
                aria-label="Cerrar modal"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={(e) => void handleCreate(e)} className="space-y-4">
              <div>
                <label
                  htmlFor="create-src-code"
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  Código de Fuente <span className="text-rose-400">*</span>
                </label>
                <input
                  id="create-src-code"
                  type="text"
                  placeholder="Ej: SRC-NATIVE-APACHE"
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value.toUpperCase())}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono placeholder:text-slate-600"
                />
                <span className="text-[11px] text-slate-500 mt-0.5 block">
                  3 a 40 caracteres alfanuméricos.
                </span>
              </div>

              <div>
                <label
                  htmlFor="create-src-name"
                  className="block text-xs font-semibold text-slate-300 mb-1"
                >
                  Nombre Descriptivo <span className="text-rose-400">*</span>
                </label>
                <input
                  id="create-src-name"
                  type="text"
                  placeholder="Ej: Agente Apache Hospital Central"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  maxLength={160}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder:text-slate-600"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label
                    htmlFor="create-src-type"
                    className="block text-xs font-semibold text-slate-300 mb-1"
                  >
                    Tipo de Fuente
                  </label>
                  <select
                    id="create-src-type"
                    value={sourceType}
                    onChange={(e) => setSourceType(e.target.value as SourceType)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white"
                  >
                    <option value="HOST">HOST</option>
                    <option value="NETWORK">NETWORK</option>
                    <option value="APPLICATION">APPLICATION</option>
                    <option value="DATABASE">DATABASE</option>
                    <option value="SECURITY_CONTROL">SECURITY_CONTROL</option>
                  </select>
                </div>

                <div>
                  <label
                    htmlFor="create-src-asset"
                    className="block text-xs font-semibold text-slate-300 mb-1"
                  >
                    ID Activo (Opcional)
                  </label>
                  <input
                    id="create-src-asset"
                    type="number"
                    placeholder="Ej: 1"
                    value={assetId}
                    onChange={(e) => setAssetId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
                  />
                </div>
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
                  {createSubmitting ? 'Registrando...' : 'Generar Clave y Crear'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
