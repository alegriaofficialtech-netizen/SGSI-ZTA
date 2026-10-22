import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Filter, RefreshCw, Search } from 'lucide-react';
import { AlertStatusBadge, SeverityBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { Alert, AlertStatus, Severity } from '../../types/monitoring';

export function AlertsList() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [status, setStatus] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [ruleCode, setRuleCode] = useState<string>('');

  async function fetchAlerts(targetPage = page) {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.listAlerts({
        page: targetPage,
        page_size: pageSize,
        status: status || undefined,
        severity: severity || undefined,
        rule: ruleCode || undefined,
      });
      setAlerts(res.items);
      setTotal(res.total);
      setPage(res.page);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al consultar alertas';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    monitoringApi
      .listAlerts({
        page: 1,
        page_size: pageSize,
        status: status || undefined,
        severity: severity || undefined,
        rule: ruleCode || undefined,
      })
      .then((res) => {
        if (active) {
          setAlerts(res.items);
          setTotal(res.total);
          setPage(res.page);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al consultar alertas';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [status, severity, ruleCode, pageSize]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Centro de Alertas</h1>
          <p className="text-sm text-slate-400">
            Alertas de seguridad generadas determinísticamente por reglas activas y deduplicación
          </p>
        </div>
        <button
          onClick={() => void fetchAlerts(page)}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition self-start sm:self-auto"
          aria-label="Refrescar alertas"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Refrescar</span>
        </button>
      </div>

      <MonitoringSubNav />

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
          <Filter size={14} className="text-blue-400" />
          <span>FILTROS DE ALERTAS</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label htmlFor="filter-alert-status" className="block text-xs text-slate-400 mb-1">
              Estado de Alerta
            </label>
            <select
              id="filter-alert-status"
              aria-label="Filtrar por estado"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
            >
              <option value="">Todos los estados</option>
              <option value="OPEN">OPEN (Abiertas)</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED (Reconocidas)</option>
              <option value="RESOLVED">RESOLVED (Resueltas)</option>
            </select>
          </div>

          <div>
            <label htmlFor="filter-alert-severity" className="block text-xs text-slate-400 mb-1">
              Severidad
            </label>
            <select
              id="filter-alert-severity"
              aria-label="Filtrar por severidad"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
            >
              <option value="">Todas las severidades</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>

          <div>
            <label htmlFor="filter-alert-rule" className="block text-xs text-slate-400 mb-1">
              Código de Regla
            </label>
            <input
              id="filter-alert-rule"
              aria-label="Buscar por código de regla"
              type="text"
              placeholder="Ej: RULE-FIM-HIGH"
              value={ruleCode}
              onChange={(e) => setRuleCode(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 placeholder:text-slate-600"
            />
          </div>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-sm"
        >
          {error}
        </div>
      )}

      {/* Alerts Table / Cards */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
            Cargando alertas...
          </div>
        )}

        {!loading && alerts.length === 0 && (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <Search size={32} className="mx-auto text-slate-600" />
            <p className="font-medium text-sm">No se encontraron alertas</p>
            <p className="text-xs text-slate-500">Prueba con otros criterios de búsqueda</p>
          </div>
        )}

        {!loading && alerts.length > 0 && (
          <>
            {/* Desktop Table View */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3 px-4">
                      Código
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Severidad
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Estado
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Título
                    </th>
                    <th scope="col" className="py-3 px-4 text-center">
                      Repeticiones
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Primera Vez
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Última Vez
                    </th>
                    <th scope="col" className="py-3 px-4 text-right">
                      Acción
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {alerts.map((alt) => (
                    <tr key={alt.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono font-medium text-white whitespace-nowrap">
                        {alt.alert_code}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={alt.severity as Severity} />
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <AlertStatusBadge status={alt.status as AlertStatus} />
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-200 max-w-sm truncate">
                        {alt.title}
                      </td>
                      <td className="py-3 px-4 text-center whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono font-bold text-xs">
                          {alt.occurrence_count}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                        {dateLabel(alt.first_seen_at)}
                      </td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                        {dateLabel(alt.last_seen_at)}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <Link
                          to={`/monitoring/alerts/${alt.id}`}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-400 font-medium transition"
                        >
                          Ver Detalle
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards View */}
            <div className="md:hidden divide-y divide-slate-800/80">
              {alerts.map((alt) => (
                <div key={alt.id} className="p-4 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-bold text-white text-xs">{alt.alert_code}</span>
                    <AlertStatusBadge status={alt.status as AlertStatus} />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-white">{alt.title}</h2>
                    <div className="mt-1 flex flex-wrap gap-2 items-center text-xs text-slate-400">
                      <SeverityBadge severity={alt.severity as Severity} />
                      <span>
                        Ocurrencias:{' '}
                        <strong className="text-slate-200">{alt.occurrence_count}</strong>
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Último evento: {dateLabel(alt.last_seen_at)}
                  </div>
                  <div className="pt-1">
                    <Link
                      to={`/monitoring/alerts/${alt.id}`}
                      className="block text-center py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 text-xs font-semibold transition"
                    >
                      Gestionar alerta
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Pagination Controls */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>
            Total: <strong className="text-slate-200">{total}</strong> alertas · Página{' '}
            <strong className="text-slate-200">{page}</strong> de{' '}
            <strong className="text-slate-200">{totalPages}</strong>
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void fetchAlerts(page - 1)}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition"
              aria-label="Página anterior"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => void fetchAlerts(page + 1)}
              disabled={page >= totalPages || loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition"
              aria-label="Página siguiente"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
