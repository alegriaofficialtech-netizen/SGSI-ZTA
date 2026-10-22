import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { History, Search, Filter, Eye, AlertCircle } from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { DecisionLog } from '../types/zeroTrust';
import { ZeroTrustSubNav } from '../components/ZeroTrustSubNav';
import { DecisionBadge } from '../components/DecisionBadge';

export const DecisionList: React.FC = () => {
  const navigate = useNavigate();
  const [decisions, setDecisions] = useState<DecisionLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [resourceFilter, setResourceFilter] = useState<string>('ALL');
  const [userSearch, setUserSearch] = useState('');

  // Pagination
  const [page, setPage] = useState(1);
  const pageSize = 8;

  useEffect(() => {
    let active = true;
    zeroTrustApi
      .getDecisions()
      .then((res) => {
        if (active) setDecisions(res.items);
      })
      .catch(() => {
        if (active) setError('No se pudo cargar el historial de decisiones.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const filtered = decisions.filter((d) => {
    if (decisionFilter !== 'ALL' && d.decision !== decisionFilter) return false;
    if (resourceFilter !== 'ALL' && d.resource !== resourceFilter) return false;
    if (userSearch) {
      const s = userSearch.toLowerCase();
      if (!d.subject_username.toLowerCase().includes(s)) return false;
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / pageSize) || 1;
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <History className="text-blue-500" size={26} />
          Pistas de Decisión y Auditoría Zero Trust
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Registro inmutable de todas las evaluaciones en tiempo real emitidas por el Policy
          Decision Point (PDP).
        </p>
      </div>

      <ZeroTrustSubNav />

      {error && (
        <div className="rounded-lg bg-rose-950/60 border border-rose-800 p-4 text-rose-200 text-sm flex items-center gap-2">
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Filters Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="relative">
            <Search size={16} className="absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Filtrar por usuario..."
              value={userSearch}
              onChange={(e) => {
                setUserSearch(e.target.value);
                setPage(1);
              }}
              className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <select
              value={decisionFilter}
              onChange={(e) => {
                setDecisionFilter(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              aria-label="Filtrar por decisión"
            >
              <option value="ALL">Todas las Decisiones</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DENY">DENY</option>
              <option value="MFA_REQUIRED">MFA_REQUIRED</option>
            </select>
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
        </div>
      </div>

      {/* Decisions Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-8 text-center text-slate-400 text-sm">
            <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
            <p>Cargando registros de auditoría...</p>
          </div>
        ) : paginated.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <Filter size={32} className="mx-auto text-slate-600 mb-3" />
            <p className="text-base font-semibold text-slate-300">
              No existen decisiones para los filtros seleccionados.
            </p>
            <p className="text-xs text-slate-500 mt-1">Pruebe ajustando los filtros de búsqueda.</p>
          </div>
        ) : (
          <>
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300" role="table">
                <thead className="bg-slate-950/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Fecha / Hora</th>
                    <th className="px-4 py-3 font-semibold">Usuario</th>
                    <th className="px-4 py-3 font-semibold">Recurso / Acción</th>
                    <th className="px-4 py-3 font-semibold">Activo</th>
                    <th className="px-4 py-3 font-semibold">Dispositivo</th>
                    <th className="px-4 py-3 font-semibold">Decisión</th>
                    <th className="px-4 py-3 font-semibold">Razón</th>
                    <th className="px-4 py-3 font-semibold">Política</th>
                    <th className="px-4 py-3 font-semibold text-right">Acción</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {paginated.map((dec) => (
                    <tr
                      key={dec.id}
                      onClick={() => navigate(`/zero-trust/decisions/${dec.id}`)}
                      className="hover:bg-slate-800/40 transition cursor-pointer"
                    >
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                        {new Date(dec.timestamp).toLocaleTimeString('es-PE', {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-semibold text-white">
                          {dec.subject_username || 'No disponible'}
                        </span>
                        <div className="text-[10px] text-slate-500 font-mono">
                          {dec.subject_roles.length > 0
                            ? dec.subject_roles.join(', ')
                            : 'No disponible'}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono">
                        <span className="text-slate-300">{dec.resource}</span>
                        <span className="text-slate-500 mx-1">::</span>
                        <span className="text-cyan-400">{dec.action}</span>
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                        {dec.asset_id ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                        {dec.device_id ?? '—'}
                      </td>
                      <td className="px-4 py-3">
                        <DecisionBadge decision={dec.decision} size="sm" />
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                        {dec.reason_code}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-blue-400">
                        {dec.policy_code ?? 'No disponible'}
                      </td>
                      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <Link
                          to={`/zero-trust/decisions/${dec.id}`}
                          title="Ver Detalle"
                          className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
                        >
                          <Eye size={15} />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards */}
            <div className="md:hidden divide-y divide-slate-800/80">
              {paginated.map((dec) => (
                <div
                  key={dec.id}
                  onClick={() => navigate(`/zero-trust/decisions/${dec.id}`)}
                  className="p-4 space-y-2 hover:bg-slate-800/30 transition cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">
                      {dec.subject_username || 'No disponible'}
                    </span>
                    <DecisionBadge decision={dec.decision} size="sm" />
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    {dec.resource} :: {dec.action}
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-800/40 pt-2">
                    <span>{new Date(dec.timestamp).toLocaleString('es-PE')}</span>
                    <span className="font-mono text-blue-400">
                      {dec.policy_code ?? 'No disponible'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Pagination */}
        {filtered.length > pageSize && (
          <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
            <span>
              Página {page} de {totalPages} ({filtered.length} eventos)
            </span>
            <div className="flex gap-1.5">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40"
              >
                Anterior
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40"
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
