import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  Clock,
  Fingerprint,
  RefreshCw,
  Shield,
  ShieldAlert,
  User as UserIcon,
} from 'lucide-react';
import { AlertStatusBadge, SeverityBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { useAuth } from '../../hooks/useAuth';
import { dateLabel } from '../../services/api';
import { monitoringApi } from '../../services/monitoringApi';
import type { AlertDetail as AlertDetailType, AlertStatus, Severity } from '../../types/monitoring';

export function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const isAdmin = user?.roles.some((r) => r === 'admin-ti');

  const [alert, setAlert] = useState<AlertDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal / Comment form state
  const [activeAction, setActiveAction] = useState<'acknowledge' | 'resolve' | null>(null);
  const [comment, setComment] = useState('');

  useEffect(() => {
    if (!id) return;
    let active = true;
    monitoringApi
      .getAlert(id)
      .then((res) => {
        if (active) {
          setAlert(res);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg =
            err instanceof Error ? err.message : 'Error al cargar el detalle de la alerta';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [id]);

  async function handleAcknowledge() {
    if (!id) return;
    setActionLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await monitoringApi.acknowledgeAlert(id, comment);
      setAlert(updated);
      setSuccessMsg('Alerta reconocida correctamente.');
      setActiveAction(null);
      setComment('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al reconocer alerta';
      setError(msg);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleResolve() {
    if (!id) return;
    setActionLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await monitoringApi.resolveAlert(id, comment);
      setAlert(updated);
      setSuccessMsg('Alerta resuelta correctamente.');
      setActiveAction(null);
      setComment('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al resolver alerta';
      setError(msg);
    } finally {
      setActionLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/monitoring/alerts"
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          aria-label="Volver a lista de alertas"
        >
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Gestión de Alerta</h1>
          <p className="text-xs text-slate-400 font-mono">Código: {alert?.alert_code || id}</p>
        </div>
      </div>

      <MonitoringSubNav />

      {loading && (
        <div className="py-20 text-center text-slate-400">
          <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
          <p className="text-sm">Cargando alerta e historial...</p>
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

      {successMsg && (
        <div
          role="status"
          className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/80 text-emerald-300 text-sm flex items-start gap-3"
        >
          <CheckCircle2 size={18} className="text-emerald-400 shrink-0 mt-0.5" />
          <span>{successMsg}</span>
        </div>
      )}

      {alert && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Header Card */}
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={alert.severity as Severity} />
                  <AlertStatusBadge status={alert.status as AlertStatus} />
                </div>
                <div className="text-xs text-slate-400">
                  Ocurrencias dedup:{' '}
                  <span className="font-mono font-bold text-white text-sm">
                    {alert.occurrence_count}
                  </span>
                </div>
              </div>

              <div>
                <h2 className="text-xl font-bold text-white mb-2">{alert.title}</h2>
                <p className="text-sm text-slate-300 whitespace-pre-wrap bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  {alert.description}
                </p>
              </div>

              {/* Action Buttons (Strictly according to Alert Lifecycle) */}
              {isAdmin && alert.status !== 'RESOLVED' && (
                <div className="pt-4 border-t border-slate-800 space-y-3">
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Acciones de Ciclo de Vida (Admin-TI)
                  </h3>

                  {!activeAction && (
                    <div className="flex flex-wrap gap-3">
                      {alert.status === 'OPEN' && (
                        <button
                          onClick={() => {
                            setActiveAction('acknowledge');
                            setComment('');
                          }}
                          className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                          aria-label="Reconocer alerta"
                        >
                          <Clock size={15} />
                          <span>Reconocer alerta</span>
                        </button>
                      )}

                      {(alert.status === 'OPEN' || alert.status === 'ACKNOWLEDGED') && (
                        <button
                          onClick={() => {
                            setActiveAction('resolve');
                            setComment('');
                          }}
                          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                          aria-label="Resolver alerta"
                        >
                          <CheckCircle2 size={15} />
                          <span>Resolver alerta</span>
                        </button>
                      )}
                    </div>
                  )}

                  {/* Comment & Confirmation Form */}
                  {activeAction && (
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <strong className="text-xs text-white">
                          {activeAction === 'acknowledge'
                            ? 'Reconocer Incidente de Seguridad'
                            : 'Resolver Incidente de Seguridad'}
                        </strong>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {comment.length} / 1000 caracteres
                        </span>
                      </div>

                      <label htmlFor="action-comment" className="sr-only">
                        Comentario de auditoría (opcional)
                      </label>
                      <textarea
                        id="action-comment"
                        aria-label="Comentario de auditoría"
                        rows={3}
                        maxLength={1000}
                        placeholder="Comentario opcional justificativo para auditoría..."
                        value={comment}
                        onChange={(e) => setComment(e.target.value)}
                        className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                      />

                      <div className="flex items-center gap-2">
                        {activeAction === 'acknowledge' ? (
                          <button
                            onClick={() => void handleAcknowledge()}
                            disabled={actionLoading}
                            className="px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                          >
                            {actionLoading ? 'Procesando...' : 'Confirmar Reconocimiento'}
                          </button>
                        ) : (
                          <button
                            onClick={() => void handleResolve()}
                            disabled={actionLoading}
                            className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                          >
                            {actionLoading ? 'Procesando...' : 'Confirmar Resolución'}
                          </button>
                        )}
                        <button
                          onClick={() => setActiveAction(null)}
                          disabled={actionLoading}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
                        >
                          Cancelar
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!isAdmin && (
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center gap-2 text-xs text-slate-400">
                  <ShieldAlert size={16} className="text-amber-400" />
                  <span>
                    Solo lectura (Rol Auditor). No posee privilegios para transicionar el ciclo de
                    vida de la alerta.
                  </span>
                </div>
              )}

              {alert.status === 'RESOLVED' && (
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle2 size={16} className="text-emerald-400" />
                  <span>Alerta resuelta. Estado final e inmutable.</span>
                </div>
              )}
            </div>

            {/* Timeline Visual of AlertHistory */}
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Clock size={16} className="text-blue-400" />
                Historial de Ciclo de Vida (AlertHistory Inmutable)
              </h3>

              {alert.history.length === 0 ? (
                <p className="text-xs text-slate-500 italic">Sin transiciones registradas aún.</p>
              ) : (
                <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                  {alert.history.map((entry) => (
                    <div key={entry.id} className="relative space-y-1">
                      <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-blue-500 ring-4 ring-slate-900" />
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-semibold text-xs text-white">{entry.action}</span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {dateLabel(entry.created_at)}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 flex items-center gap-2">
                        <span>
                          Estado:{' '}
                          <span className="text-slate-300 font-medium">
                            {entry.previous_status || 'INICIAL'} → {entry.new_status}
                          </span>
                        </span>
                        {entry.actor_user_id && (
                          <span className="flex items-center gap-1 font-mono text-[11px] text-slate-400">
                            <UserIcon size={11} /> Usuario #{entry.actor_user_id}
                          </span>
                        )}
                      </div>
                      {entry.comment && (
                        <p className="text-xs text-slate-300 bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono">
                          &quot;{entry.comment}&quot;
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Sidebar Info */}
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Correlación & Trazabilidad
              </h3>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Shield size={13} className="text-blue-400" /> Evento de Origen
                  </span>
                  <Link
                    to={`/monitoring/events/${alert.event_id}`}
                    className="font-mono text-blue-400 hover:underline break-all block"
                  >
                    {alert.event_id}
                  </Link>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <ShieldAlert size={13} className="text-amber-400" /> Regla Disparadora
                  </span>
                  <Link
                    to={`/monitoring/rules/${alert.rule_id}`}
                    className="font-mono text-blue-400 hover:underline break-all block"
                  >
                    {alert.rule_id}
                  </Link>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5">Activo Hospitalario</span>
                  <strong className="text-white block">
                    {alert.asset_id ? `ID #${alert.asset_id}` : 'No especificado'}
                  </strong>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Calendar size={13} className="text-slate-400" /> Primera Detección
                  </span>
                  <span className="text-slate-200 font-mono">{dateLabel(alert.first_seen_at)}</span>
                </div>

                <div>
                  <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                    <Clock size={13} className="text-slate-400" /> Última Detección
                  </span>
                  <span className="text-slate-200 font-mono">{dateLabel(alert.last_seen_at)}</span>
                </div>

                {alert.acknowledged_at && (
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-slate-400 block mb-0.5">Reconocido Por / Fecha</span>
                    <span className="text-sky-300 font-medium block">
                      Usuario #{alert.acknowledged_by}
                    </span>
                    <span className="text-slate-400 font-mono text-[11px]">
                      {dateLabel(alert.acknowledged_at)}
                    </span>
                  </div>
                )}

                {alert.resolved_at && (
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-slate-400 block mb-0.5">Resuelto Por / Fecha</span>
                    <span className="text-emerald-300 font-medium block">
                      Usuario #{alert.resolved_by}
                    </span>
                    <span className="text-slate-400 font-mono text-[11px]">
                      {dateLabel(alert.resolved_at)}
                    </span>
                  </div>
                )}

                <div className="pt-2 border-t border-slate-800">
                  <span className="text-slate-400 block mb-1 flex items-center gap-1">
                    <Fingerprint size={13} className="text-emerald-400" /> Huella Alerta (SHA-256)
                  </span>
                  <code className="block p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-300 break-all font-mono">
                    {alert.fingerprint}
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
