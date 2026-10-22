import { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCheck2,
  Files,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { monitoringApi } from '../../services/monitoringApi';
import type { DashboardMetrics } from '../../types/monitoring';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#64748b',
};

export function MonitoringDashboard() {
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.getDashboardMetrics();
      setData(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al cargar métricas de monitoreo';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    monitoringApi
      .getDashboardMetrics()
      .then((res) => {
        if (active) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al cargar métricas de monitoreo';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Monitoreo de Seguridad & Alertas
          </h1>
          <p className="text-sm text-slate-400">
            Detección nativa de eventos, integridad de archivos y gestión determinista de alertas
          </p>
        </div>
        <button
          onClick={() => void loadData()}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition self-start sm:self-auto"
          aria-label="Actualizar métricas"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Actualizar</span>
        </button>
      </div>

      <MonitoringSubNav />

      {error && (
        <div
          role="alert"
          className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-sm flex items-start gap-3"
        >
          <AlertTriangle size={18} className="text-rose-400 shrink-0 mt-0.5" />
          <div>
            <strong className="block font-semibold">Error al obtener telemetría:</strong>
            <span>{error}</span>
          </div>
        </div>
      )}

      {loading && !data && (
        <div className="py-20 text-center text-slate-400 space-y-3">
          <RefreshCw size={28} className="animate-spin mx-auto text-blue-400" />
          <p className="text-sm font-medium">Cargando métricas de seguridad en tiempo real...</p>
        </div>
      )}

      {data && (
        <>
          {/* KPI Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Files size={13} className="text-blue-400" /> Eventos 24h
              </span>
              <p className="text-2xl font-bold text-white tracking-tight">{data.events_24h}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <AlertOctagon size={13} className="text-rose-400" /> Alertas Abiertas
              </span>
              <p className="text-2xl font-bold text-rose-400 tracking-tight">{data.alerts_open}</p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <Clock size={13} className="text-sky-400" /> Reconocidas
              </span>
              <p className="text-2xl font-bold text-sky-400 tracking-tight">
                {data.alerts_acknowledged}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                <CheckCircle2 size={13} className="text-emerald-400" /> Resueltas 24h
              </span>
              <p className="text-2xl font-bold text-emerald-400 tracking-tight">
                {data.alerts_resolved_24h}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 space-y-1">
              <span className="text-xs font-medium text-rose-300 flex items-center gap-1.5">
                <ShieldAlert size={13} className="text-rose-400" /> Críticas Abiertas
              </span>
              <p className="text-2xl font-bold text-rose-300 tracking-tight">
                {data.critical_open}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40 space-y-1">
              <span className="text-xs font-medium text-amber-300 flex items-center gap-1.5">
                <AlertTriangle size={13} className="text-amber-400" /> Altas Abiertas
              </span>
              <p className="text-2xl font-bold text-amber-300 tracking-tight">{data.high_open}</p>
            </div>
          </div>

          {/* FIM Status Bar */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-blue-950/50 text-blue-400 border border-blue-800/60">
                <FileCheck2 size={20} />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">
                  File Integrity Monitoring (FIM)
                </h2>
                <p className="text-xs text-slate-400">
                  Integridad de archivos sintéticos y hashes SHA-256
                </p>
              </div>
            </div>
            <div className="flex items-center gap-6 text-sm">
              <div>
                <span className="text-xs text-slate-400 block">Objetivos Monitoreados</span>
                <strong className="text-white font-medium">
                  {data.fim_targets_enabled} activos
                </strong>
              </div>
              <div>
                <span className="text-xs text-slate-400 block">Escaneos 24h</span>
                <strong className="text-white font-medium">{data.fim_scans_24h} ejecuciones</strong>
              </div>
              <div>
                <span className="text-xs text-slate-400 block">Cambios Detectados 24h</span>
                <strong
                  className={
                    data.fim_changes_24h > 0
                      ? 'text-rose-400 font-bold'
                      : 'text-emerald-400 font-medium'
                  }
                >
                  {data.fim_changes_24h} anomalías
                </strong>
              </div>
            </div>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Chart 1: Events by Hour */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Activity size={16} className="text-blue-400" />
                  Actividad de Eventos (Últimas 24 Horas)
                </h2>
                <p className="text-xs text-slate-400">Volumen horario de telemetría de seguridad</p>
              </div>
              <div className="h-60 w-full" data-testid="chart-events-by-hour">
                {data.events_by_hour.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Sin eventos registrados en las últimas 24 horas
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data.events_by_hour}>
                      <defs>
                        <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="hour" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="count"
                        stroke="#3b82f6"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#eventGrad)"
                        name="Eventos"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Chart 2: Alerts by Severity */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldAlert size={16} className="text-amber-400" />
                  Distribución de Alertas por Severidad
                </h2>
                <p className="text-xs text-slate-400">Clasificación acumulada de incidentes</p>
              </div>
              <div className="h-60 w-full" data-testid="chart-alerts-by-severity">
                {data.alerts_by_severity.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Sin alertas registradas
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.alerts_by_severity}>
                      <XAxis dataKey="severity" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                      />
                      <Bar dataKey="count" name="Alertas" radius={[4, 4, 0, 0]}>
                        {data.alerts_by_severity.map((entry) => (
                          <Cell
                            key={`cell-${entry.severity}`}
                            fill={SEVERITY_COLORS[entry.severity] || '#64748b'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Chart 3: Events by Type */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Files size={16} className="text-blue-400" />
                  Eventos por Tipo
                </h2>
                <p className="text-xs text-slate-400">
                  Frecuencia por categoría técnica de telemetría
                </p>
              </div>
              <div className="h-60 w-full" data-testid="chart-events-by-type">
                {data.events_by_type.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Sin eventos registrados
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.events_by_type} layout="vertical">
                      <XAxis
                        type="number"
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="event_type"
                        stroke="#64748b"
                        fontSize={10}
                        tickLine={false}
                        width={130}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                      />
                      <Bar dataKey="count" fill="#38bdf8" name="Eventos" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Chart 4: Top Affected Assets */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <AlertTriangle size={16} className="text-amber-400" />
                  Activos Más Afectados
                </h2>
                <p className="text-xs text-slate-400">
                  Activos hospitalarios con mayor correlación de incidentes
                </p>
              </div>
              <div className="h-60 w-full" data-testid="chart-top-affected-assets">
                {data.top_affected_assets.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Sin activos afectados en las últimas 24 horas
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.top_affected_assets} layout="vertical">
                      <XAxis
                        type="number"
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="asset_name"
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        width={130}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                        }}
                      />
                      <Bar dataKey="count" fill="#f59e0b" name="Incidentes" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
