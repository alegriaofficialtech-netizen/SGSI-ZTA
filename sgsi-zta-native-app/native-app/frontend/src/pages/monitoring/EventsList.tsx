import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Filter, RefreshCw, Search } from 'lucide-react';
import { EventTypeBadge, SeverityBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type {
  EventType,
  MonitoringEventItem,
  MonitoringSource,
  Severity,
} from '../../types/monitoring';

export function EventsList() {
  const [events, setEvents] = useState<MonitoringEventItem[]>([]);
  const [sources, setSources] = useState<MonitoringSource[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [eventType, setEventType] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [sourceId, setSourceId] = useState<string>('');
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');

  useEffect(() => {
    let active = true;
    monitoringApi
      .listSources()
      .then((res) => {
        if (active) setSources(res);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    monitoringApi
      .listEvents({
        page: 1,
        page_size: pageSize,
        event_type: eventType || undefined,
        severity: severity || undefined,
        source_id: sourceId || undefined,
        date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
        date_to: dateTo ? new Date(dateTo).toISOString() : undefined,
      })
      .then((res) => {
        if (active) {
          setEvents(res.items);
          setTotal(res.total);
          setPage(res.page);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al consultar eventos';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [eventType, severity, sourceId, dateFrom, dateTo, pageSize]);

  async function fetchEvents(targetPage = page) {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.listEvents({
        page: targetPage,
        page_size: pageSize,
        event_type: eventType || undefined,
        severity: severity || undefined,
        source_id: sourceId || undefined,
        date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
        date_to: dateTo ? new Date(dateTo).toISOString() : undefined,
      });
      setEvents(res.items);
      setTotal(res.total);
      setPage(res.page);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al consultar eventos';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Eventos de Telemetría</h1>
          <p className="text-sm text-slate-400">
            Registro de eventos emitidos por fuentes autenticadas e integridad FIM
          </p>
        </div>
        <button
          onClick={() => void fetchEvents(page)}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition self-start sm:self-auto"
          aria-label="Refrescar eventos"
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
          <span>FILTROS DE AUDITORÍA</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          <div>
            <label htmlFor="filter-type" className="block text-xs text-slate-400 mb-1">
              Tipo de Evento
            </label>
            <select
              id="filter-type"
              aria-label="Filtrar por tipo de evento"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
            >
              <option value="">Todos los tipos</option>
              <option value="AUTH_FAILURE">AUTH_FAILURE</option>
              <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
              <option value="MFA_FAILURE">MFA_FAILURE</option>
              <option value="POLICY_DENY">POLICY_DENY</option>
              <option value="POLICY_MFA_REQUIRED">POLICY_MFA_REQUIRED</option>
              <option value="FILE_INTEGRITY_CHANGE">FILE_INTEGRITY_CHANGE</option>
              <option value="ASSET_CHANGE">ASSET_CHANGE</option>
              <option value="RISK_CHANGE">RISK_CHANGE</option>
              <option value="SECURITY_CONFIGURATION_CHANGE">SECURITY_CONFIGURATION_CHANGE</option>
            </select>
          </div>

          <div>
            <label htmlFor="filter-severity" className="block text-xs text-slate-400 mb-1">
              Severidad
            </label>
            <select
              id="filter-severity"
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
            <label htmlFor="filter-source" className="block text-xs text-slate-400 mb-1">
              Fuente Emisora
            </label>
            <select
              id="filter-source"
              aria-label="Filtrar por fuente emisora"
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
            >
              <option value="">Todas las fuentes</option>
              {sources.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.source_code} ({s.name})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="filter-date-from" className="block text-xs text-slate-400 mb-1">
              Desde
            </label>
            <input
              id="filter-date-from"
              aria-label="Fecha inicio"
              type="datetime-local"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
            />
          </div>

          <div>
            <label htmlFor="filter-date-to" className="block text-xs text-slate-400 mb-1">
              Hasta
            </label>
            <input
              id="filter-date-to"
              aria-label="Fecha fin"
              type="datetime-local"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
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

      {/* Events Table / Card Layout */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
            Cargando eventos...
          </div>
        )}

        {!loading && events.length === 0 && (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <Search size={32} className="mx-auto text-slate-600" />
            <p className="font-medium text-sm">No se encontraron eventos</p>
            <p className="text-xs text-slate-500">Prueba ajustando los filtros seleccionados</p>
          </div>
        )}

        {!loading && events.length > 0 && (
          <>
            {/* Desktop Table View */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3 px-4">
                      Fecha / Hora
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Tipo
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Severidad
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Fuente
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Activo
                    </th>
                    <th scope="col" className="py-3 px-4">
                      Título
                    </th>
                    <th scope="col" className="py-3 px-4 text-right">
                      Detalle
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {events.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                        {dateLabel(evt.occurred_at)}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <EventTypeBadge eventType={evt.event_type as EventType} />
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={evt.severity as Severity} />
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                        {evt.source_code}
                      </td>
                      <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                        {evt.asset_name || (evt.asset_id ? `#${evt.asset_id}` : '—')}
                      </td>
                      <td className="py-3 px-4 font-medium text-white max-w-xs truncate">
                        {evt.title}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <Link
                          to={`/monitoring/events/${evt.id}`}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-400 font-medium transition"
                        >
                          Ver
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards View */}
            <div className="md:hidden divide-y divide-slate-800/80">
              {events.map((evt) => (
                <div key={evt.id} className="p-4 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={evt.severity as Severity} />
                    <span className="text-xs text-slate-400 font-mono">
                      {dateLabel(evt.occurred_at)}
                    </span>
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-white">{evt.title}</h2>
                    <div className="mt-1 flex flex-wrap gap-2 items-center text-xs text-slate-400">
                      <EventTypeBadge eventType={evt.event_type as EventType} />
                      <span>
                        Fuente: <strong className="text-slate-200">{evt.source_code}</strong>
                      </span>
                      {evt.asset_name && (
                        <span>
                          Activo: <strong className="text-slate-200">{evt.asset_name}</strong>
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="pt-1">
                    <Link
                      to={`/monitoring/events/${evt.id}`}
                      className="block text-center py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 text-xs font-semibold transition"
                    >
                      Ver detalle completo
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
            Total: <strong className="text-slate-200">{total}</strong> eventos · Página{' '}
            <strong className="text-slate-200">{page}</strong> de{' '}
            <strong className="text-slate-200">{totalPages}</strong>
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void fetchEvents(page - 1)}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition"
              aria-label="Página anterior"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => void fetchEvents(page + 1)}
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
