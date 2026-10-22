import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Clock,
  Fingerprint,
  RefreshCw,
  Server,
  Shield,
} from 'lucide-react';
import { EventTypeBadge, SeverityBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { EventType, MonitoringEventDetail, Severity } from '../../types/monitoring';

export function EventDetail() {
  const { id } = useParams<{ id: string }>();
  const [event, setEvent] = useState<MonitoringEventDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadEvent() {
      if (!id) return;
      setLoading(true);
      setError(null);
      try {
        const res = await monitoringApi.getEvent(id);
        setEvent(res);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Error al cargar el detalle del evento';
        setError(msg);
      } finally {
        setLoading(false);
      }
    }
    void loadEvent();
  }, [id]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/monitoring/events"
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          aria-label="Volver a lista de eventos"
        >
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Detalle de Evento</h1>
          <p className="text-xs text-slate-400 font-mono">ID: {id}</p>
        </div>
      </div>

      <MonitoringSubNav />

      {loading && (
        <div className="py-20 text-center text-slate-400">
          <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
          <p className="text-sm">Cargando evento...</p>
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

      {event && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Info */}
          <div className="lg:col-span-2 space-y-6">
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={event.severity as Severity} />
                  <EventTypeBadge eventType={event.event_type as EventType} />
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  ID Externo: {event.source_event_id}
                </span>
              </div>

              <div>
                <h2 className="text-xl font-bold text-white mb-2">{event.title}</h2>
                <p className="text-sm text-slate-300 whitespace-pre-wrap bg-slate-950/60 p-3 rounded-lg border border-slate-800 font-mono">
                  {event.message}
                </p>
              </div>

              {/* Sanitized Payload Display */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield size={14} className="text-blue-400" />
                  Payload Sanitizado (Cero fuga de secretos)
                </h3>
                <pre
                  data-testid="event-payload"
                  className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 overflow-x-auto font-mono"
                >
                  {JSON.stringify(event.payload, null, 2)}
                </pre>
              </div>
            </div>
          </div>

          {/* Metadata Sidebar */}
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Metadatos Técnicos
              </h3>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Server size={13} className="text-blue-400" /> Fuente Emisora
                  </span>
                  <strong className="text-white font-mono block">{event.source_code}</strong>
                  <span className="text-slate-400">{event.source_name}</span>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Shield size={13} className="text-amber-400" /> Activo Relacionado
                  </span>
                  <strong className="text-white block">
                    {event.asset_name ||
                      (event.asset_id ? `ID #${event.asset_id}` : 'Sin activo vinculado')}
                  </strong>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Calendar size={13} className="text-slate-400" /> Ocurrido en
                  </span>
                  <span className="text-slate-200 font-mono">{dateLabel(event.occurred_at)}</span>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Clock size={13} className="text-slate-400" /> Ingerido en (Servidor)
                  </span>
                  <span className="text-slate-200 font-mono">{dateLabel(event.received_at)}</span>
                </div>

                <div className="pt-2 border-t border-slate-800">
                  <span className="text-slate-400 block mb-1 flex items-center gap-1">
                    <Fingerprint size={13} className="text-emerald-400" /> Huella SHA-256
                  </span>
                  <code className="block p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-300 break-all">
                    {event.fingerprint}
                  </code>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
