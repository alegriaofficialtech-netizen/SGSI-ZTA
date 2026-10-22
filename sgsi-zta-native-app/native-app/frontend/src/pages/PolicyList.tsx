import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Plus,
  Search,
  Filter,
  Eye,
  Edit2,
  PowerOff,
  CheckCircle2,
  XCircle,
  AlertCircle,
  KeyRound,
} from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { Policy } from '../types/zeroTrust';
import { ZeroTrustSubNav } from '../components/ZeroTrustSubNav';
import { useAuth } from '../hooks/useAuth';

export const PolicyList: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const isAdmin = user?.roles.includes('admin-ti');

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [resourceFilter, setResourceFilter] = useState<string>('ALL');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [effectFilter, setEffectFilter] = useState<string>('ALL');
  const [enabledFilter, setEnabledFilter] = useState<string>('ALL');

  // Pagination
  const [page, setPage] = useState(1);
  const pageSize = 8;

  const fetchPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await zeroTrustApi.getPolicies();
      setPolicies(res.items);
    } catch {
      setError('Error al cargar las políticas de Zero Trust.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    zeroTrustApi
      .getPolicies()
      .then((res) => {
        if (active) setPolicies(res.items);
      })
      .catch(() => {
        if (active) setError('Error al cargar las políticas de Zero Trust.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleDisable = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('¿Está seguro de deshabilitar esta política de autorización?')) return;
    try {
      await zeroTrustApi.disablePolicy(id);
      await fetchPolicies();
    } catch {
      alert('Error al deshabilitar la política.');
    }
  };

  // Filter logic
  const filtered = policies.filter((p) => {
    if (search) {
      const s = search.toLowerCase();
      if (!p.code.toLowerCase().includes(s) && !p.name.toLowerCase().includes(s)) return false;
    }
    if (resourceFilter !== 'ALL' && p.resource !== resourceFilter) return false;
    if (actionFilter !== 'ALL' && p.action !== actionFilter) return false;
    if (effectFilter !== 'ALL' && p.effect !== effectFilter) return false;
    if (enabledFilter !== 'ALL') {
      const boolVal = enabledFilter === 'ENABLED';
      if (p.enabled !== boolVal) return false;
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / pageSize) || 1;
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="text-blue-500" size={26} />
            Políticas de Acceso Zero Trust
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Definición explícita de reglas de autorización, control RBAC y condiciones de postura.
          </p>
        </div>
        {isAdmin && (
          <Link
            to="/zero-trust/policies/new"
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition"
          >
            <Plus size={16} />
            Nueva Política
          </Link>
        )}
      </div>

      <ZeroTrustSubNav />

      {error && (
        <div className="rounded-lg bg-rose-950/60 border border-rose-800/80 p-4 text-rose-200 text-sm flex items-center gap-2">
          <AlertCircle size={18} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="relative">
            <Search size={16} className="absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Buscar por código o nombre..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <select
              value={resourceFilter}
              onChange={(e) => {
                setResourceFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por recurso"
            >
              <option value="ALL">Todos los Recursos</option>
              <option value="clinical-demo">clinical-demo</option>
              <option value="asset">asset</option>
              <option value="risk">risk</option>
              <option value="control">control</option>
              <option value="audit">audit</option>
              <option value="user-management">user-management</option>
            </select>
          </div>

          <div>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por acción"
            >
              <option value="ALL">Todas las Acciones</option>
              <option value="read">read</option>
              <option value="read_sensitive">read_sensitive</option>
              <option value="create">create</option>
              <option value="update">update</option>
              <option value="disable">disable</option>
              <option value="approve">approve</option>
              <option value="export">export</option>
            </select>
          </div>

          <div>
            <select
              value={effectFilter}
              onChange={(e) => {
                setEffectFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por efecto"
            >
              <option value="ALL">Todos los Efectos</option>
              <option value="ALLOW">ALLOW (Permitir)</option>
              <option value="DENY">DENY (Denegar)</option>
            </select>
          </div>

          <div>
            <select
              value={enabledFilter}
              onChange={(e) => {
                setEnabledFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por estado"
            >
              <option value="ALL">Todos los Estados</option>
              <option value="ENABLED">Activas</option>
              <option value="DISABLED">Deshabilitadas</option>
            </select>
          </div>
        </div>
      </div>

      {/* Policies Table (Desktop) / Cards (Mobile) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
            <p>Cargando políticas de autorización...</p>
          </div>
        ) : paginated.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <Filter size={32} className="mx-auto text-slate-600 mb-3" />
            <p className="text-base font-semibold text-slate-300">
              No existen políticas para los filtros seleccionados.
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Intente restablecer o modificar los criterios de búsqueda.
            </p>
          </div>
        ) : (
          <>
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300" role="table">
                <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Código</th>
                    <th className="px-4 py-3 font-semibold">Nombre</th>
                    <th className="px-4 py-3 font-semibold">Recurso / Acción</th>
                    <th className="px-4 py-3 font-semibold">Efecto</th>
                    <th className="px-4 py-3 font-semibold">MFA</th>
                    <th className="px-4 py-3 font-semibold">Prioridad</th>
                    <th className="px-4 py-3 font-semibold">Estado</th>
                    <th className="px-4 py-3 font-semibold text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {paginated.map((policy) => (
                    <tr
                      key={policy.id}
                      onClick={() => navigate(`/zero-trust/policies/${policy.id}`)}
                      className="hover:bg-slate-800/40 transition cursor-pointer"
                    >
                      <td className="px-4 py-3 font-mono font-bold text-blue-400">{policy.code}</td>
                      <td className="px-4 py-3">
                        <div className="font-semibold text-white">{policy.name}</div>
                        <div className="text-[11px] text-slate-400 line-clamp-1">
                          {policy.description}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-slate-300">{policy.resource}</span>
                        <span className="text-slate-500 mx-1">::</span>
                        <span className="font-mono text-cyan-400">{policy.action}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                            policy.effect === 'ALLOW'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-rose-950 text-rose-400 border border-rose-800'
                          }`}
                        >
                          {policy.effect}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {policy.require_mfa ? (
                          <span className="inline-flex items-center gap-1 text-amber-400 text-xs font-semibold">
                            <KeyRound size={13} /> Sí
                          </span>
                        ) : (
                          <span className="text-slate-500 text-xs">No</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-300">{policy.priority}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 text-xs ${
                            policy.enabled ? 'text-emerald-400' : 'text-slate-500'
                          }`}
                        >
                          {policy.enabled ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                          {policy.enabled ? 'Activa' : 'Deshabilitada'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <Link
                            to={`/zero-trust/policies/${policy.id}`}
                            title="Ver Detalle"
                            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
                          >
                            <Eye size={15} />
                          </Link>
                          {isAdmin && (
                            <>
                              <Link
                                to={`/zero-trust/policies/${policy.id}/edit`}
                                title="Editar"
                                className="p-1 rounded text-blue-400 hover:text-blue-300 hover:bg-slate-800"
                              >
                                <Edit2 size={15} />
                              </Link>
                              {policy.enabled && (
                                <button
                                  onClick={(e) => void handleDisable(policy.id, e)}
                                  title="Deshabilitar"
                                  className="p-1 rounded text-rose-400 hover:text-rose-300 hover:bg-slate-800"
                                >
                                  <PowerOff size={15} />
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards */}
            <div className="md:hidden divide-y divide-slate-800/80">
              {paginated.map((policy) => (
                <div
                  key={policy.id}
                  onClick={() => navigate(`/zero-trust/policies/${policy.id}`)}
                  className="p-4 space-y-2 hover:bg-slate-800/30 transition cursor-pointer"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="font-mono text-xs font-bold text-blue-400">
                        {policy.code}
                      </span>
                      <h3 className="text-sm font-semibold text-white">{policy.name}</h3>
                    </div>
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                        policy.effect === 'ALLOW'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}
                    >
                      {policy.effect}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{policy.description}</p>
                  <div className="flex flex-wrap gap-2 text-[11px] text-slate-400 pt-1">
                    <span className="bg-slate-800 px-2 py-0.5 rounded font-mono">
                      {policy.resource}::{policy.action}
                    </span>
                    {policy.require_mfa && (
                      <span className="bg-amber-950/80 text-amber-300 border border-amber-800/60 px-2 py-0.5 rounded flex items-center gap-1">
                        <KeyRound size={11} /> MFA Requerido
                      </span>
                    )}
                    <span className="bg-slate-800 px-2 py-0.5 rounded font-mono">
                      Prioridad: {policy.priority}
                    </span>
                  </div>
                  <div
                    className="flex items-center justify-between pt-2 border-t border-slate-800/40"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <span className="text-xs text-slate-400">
                      Estado:{' '}
                      <strong className={policy.enabled ? 'text-emerald-400' : 'text-slate-500'}>
                        {policy.enabled ? 'Activa' : 'Deshabilitada'}
                      </strong>
                    </span>
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/zero-trust/policies/${policy.id}`}
                        className="text-xs text-blue-400 hover:underline"
                      >
                        Ver
                      </Link>
                      {isAdmin && (
                        <Link
                          to={`/zero-trust/policies/${policy.id}/edit`}
                          className="text-xs text-cyan-400 hover:underline"
                        >
                          Editar
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Pagination controls */}
        {filtered.length > pageSize && (
          <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
            <span>
              Mostrando {Math.min(filtered.length, (page - 1) * pageSize + 1)} -{' '}
              {Math.min(filtered.length, page * pageSize)} de {filtered.length} políticas
            </span>
            <div className="flex gap-1.5">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Anterior
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Siguiente
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
