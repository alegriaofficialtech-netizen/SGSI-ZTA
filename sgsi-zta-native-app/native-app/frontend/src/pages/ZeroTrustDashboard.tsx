import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  ShieldAlert,
  KeyRound,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area,
  CartesianGrid,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { ZeroTrustMetrics } from '../types/zeroTrust';
import { ZeroTrustSubNav } from '../components/ZeroTrustSubNav';

const PIE_COLORS = ['#10b981', '#f43f5e', '#f59e0b'];

export const ZeroTrustDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<ZeroTrustMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await zeroTrustApi.getDashboardMetrics();
      setMetrics(data);
    } catch {
      setError('No se pudieron cargar las métricas de Zero Trust. Reintente más tarde.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    zeroTrustApi
      .getDashboardMetrics()
      .then((data) => {
        if (active) setMetrics(data);
      })
      .catch(() => {
        if (active)
          setError('No se pudieron cargar las métricas de Zero Trust. Reintente más tarde.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="text-blue-500" size={26} />
            Zero Trust Architecture — Motor de Autorización
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Supervisión dinámica de decisiones, microsegmentación y postura de seguridad adaptativa.
          </p>
        </div>
        <button
          onClick={() => void fetchMetrics()}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Actualizar métricas
        </button>
      </div>

      <ZeroTrustSubNav />

      {error && (
        <div className="rounded-lg bg-rose-950/60 border border-rose-800/80 p-4 text-rose-200 text-sm flex items-center gap-3">
          <AlertTriangle size={18} className="shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-medium tracking-wider text-slate-400">
              Políticas Activas
            </span>
            <ShieldCheck size={18} className="text-blue-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {loading ? (
              <span className="inline-block w-12 h-7 bg-slate-800 animate-pulse rounded" />
            ) : (
              (metrics?.active_policies_count ?? 0)
            )}
          </div>
          <p className="mt-1 text-xs text-slate-500">Reglas evaluadas en tiempo de ejecución</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-medium tracking-wider text-slate-400">
              ALLOW (24h)
            </span>
            <CheckCircle2 size={18} className="text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">
            {loading ? (
              <span className="inline-block w-16 h-7 bg-slate-800 animate-pulse rounded" />
            ) : (
              (metrics?.allow_24h_count.toLocaleString() ?? 0)
            )}
          </div>
          <p className="mt-1 text-xs text-slate-500">Accesos autorizados por política</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-medium tracking-wider text-slate-400">
              DENY (24h)
            </span>
            <ShieldAlert size={18} className="text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">
            {loading ? (
              <span className="inline-block w-12 h-7 bg-slate-800 animate-pulse rounded" />
            ) : (
              (metrics?.deny_24h_count.toLocaleString() ?? 0)
            )}
          </div>
          <p className="mt-1 text-xs text-slate-500">Bloqueos de menor privilegio aplicados</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-medium tracking-wider text-slate-400">
              MFA REQUIRED (24h)
            </span>
            <KeyRound size={18} className="text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">
            {loading ? (
              <span className="inline-block w-12 h-7 bg-slate-800 animate-pulse rounded" />
            ) : (
              (metrics?.mfa_required_24h_count.toLocaleString() ?? 0)
            )}
          </div>
          <p className="mt-1 text-xs text-slate-500">Desafíos adaptativos de segundo factor</p>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
          <h2 className="text-base font-semibold text-white mb-1">
            Decisiones por Hora (Últimas 24h)
          </h2>
          <p className="text-xs text-slate-400 mb-4">
            Volumen cronológico de evaluaciones de acceso por tipo de decisión
          </p>
          <div className="h-64 w-full">
            {loading ? (
              <div className="h-full w-full bg-slate-800/40 animate-pulse rounded-lg" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={metrics?.decisions_by_hour ?? []}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="colorAllow" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorDeny" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="hour" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                    }}
                    labelStyle={{ color: '#e2e8f0', fontWeight: 600 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="allow"
                    name="ALLOW"
                    stroke="#10b981"
                    fillOpacity={1}
                    fill="url(#colorAllow)"
                  />
                  <Area
                    type="monotone"
                    dataKey="deny"
                    name="DENY"
                    stroke="#f43f5e"
                    fillOpacity={1}
                    fill="url(#colorDeny)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Donut Chart: Allow vs Deny vs MFA */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-white mb-1">Distribución de Decisiones</h2>
            <p className="text-xs text-slate-400 mb-4">Relación proporcional de resoluciones</p>
            <div className="h-52 w-full flex items-center justify-center">
              {loading ? (
                <div className="h-44 w-44 rounded-full bg-slate-800/40 animate-pulse" />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={metrics?.allow_vs_deny ?? []}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {(metrics?.allow_vs_deny ?? []).map((_, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                      }}
                      itemStyle={{ color: '#fff' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
          <div className="flex justify-around border-t border-slate-800 pt-3 text-xs">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> ALLOW
            </span>
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> DENY
            </span>
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> MFA
            </span>
          </div>
        </div>
      </div>

      {/* Top Denied Resources Bar Chart */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
        <h2 className="text-base font-semibold text-white mb-1">Top Recursos Denegados</h2>
        <p className="text-xs text-slate-400 mb-4">
          Identificación de objetivos con mayor índice de bloqueo preventivo por política
        </p>
        <div className="h-60 w-full">
          {loading ? (
            <div className="h-full w-full bg-slate-800/40 animate-pulse rounded-lg" />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={metrics?.top_denied_resources ?? []}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="resource"
                  stroke="#94a3b8"
                  fontSize={12}
                  width={130}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                  }}
                  labelStyle={{ color: '#e2e8f0', fontWeight: 600 }}
                />
                <Bar dataKey="count" name="Bloqueos" fill="#f43f5e" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
};
