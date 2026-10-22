import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, Check, Plus, Power, RefreshCw, X } from 'lucide-react';
import { EventTypeBadge, SeverityBadge } from '../../components/monitoring/Badges';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { useAuth } from '../../hooks/useAuth';
import { monitoringApi } from '../../services/monitoringApi';
import type { AlertRule, EventType, Severity } from '../../types/monitoring';

export function RulesList() {
  const { user } = useAuth();
  const isAdmin = user?.roles.some((r) => r === 'admin-ti');

  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggleLoading, setToggleLoading] = useState<string | null>(null);

  async function fetchRules() {
    setLoading(true);
    setError(null);
    try {
      const res = await monitoringApi.listRules();
      setRules(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al cargar reglas de alerta';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    monitoringApi
      .listRules()
      .then((res) => {
        if (active) {
          setRules(res);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          const msg = err instanceof Error ? err.message : 'Error al cargar reglas de alerta';
          setError(msg);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleToggle(rule: AlertRule) {
    if (!isAdmin) return;
    setToggleLoading(rule.id);
    setError(null);
    try {
      const updated = await monitoringApi.updateRule(rule.id, {
        enabled: !rule.enabled,
      });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al modificar regla';
      setError(msg);
    } finally {
      setToggleLoading(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Reglas de Detección de Alertas
          </h1>
          <p className="text-sm text-slate-400">
            Definición determinista para correlación de eventos y generación de incidentes
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          {isAdmin && (
            <Link
              to="/monitoring/rules/new"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition"
            >
              <Plus size={15} />
              <span>Nueva Regla</span>
            </Link>
          )}
          <button
            onClick={() => void fetchRules()}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            aria-label="Refrescar reglas"
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

      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
            Cargando reglas...
          </div>
        )}

        {!loading && rules.length === 0 && (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <Activity size={32} className="mx-auto text-slate-600" />
            <p className="font-medium text-sm">No hay reglas de alerta configuradas</p>
          </div>
        )}

        {!loading && rules.length > 0 && (
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
                    Tipo Evento
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Severidad Mínima
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Criticidad Activo
                  </th>
                  <th scope="col" className="py-3 px-4">
                    Cooldown (seg)
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
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-white whitespace-nowrap">
                      {rule.rule_code}
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">
                      <div>{rule.name}</div>
                      {rule.description && (
                        <span className="text-[11px] text-slate-500 truncate block max-w-xs">
                          {rule.description}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <EventTypeBadge eventType={rule.event_type as EventType} />
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={rule.minimum_severity as Severity} />
                    </td>
                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                      {rule.asset_criticality ? (
                        <span className="px-2 py-0.5 rounded bg-slate-800 font-mono text-[11px]">
                          {rule.asset_criticality}
                        </span>
                      ) : (
                        <span className="text-slate-500">Cualquiera</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                      {rule.cooldown_seconds}s
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {rule.enabled ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <Check size={13} /> Activa
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-500 font-medium">
                          <X size={13} /> Deshabilitada
                        </span>
                      )}
                    </td>
                    {isAdmin && (
                      <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                        <Link
                          to={`/monitoring/rules/${rule.id}`}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-400 font-medium transition"
                        >
                          Editar
                        </Link>
                        <button
                          onClick={() => void handleToggle(rule)}
                          disabled={toggleLoading === rule.id}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition disabled:opacity-40"
                          title={rule.enabled ? 'Deshabilitar regla' : 'Habilitar regla'}
                          aria-label={
                            rule.enabled
                              ? `Deshabilitar regla ${rule.rule_code}`
                              : `Habilitar regla ${rule.rule_code}`
                          }
                        >
                          <Power
                            size={13}
                            className={rule.enabled ? 'text-amber-400' : 'text-slate-600'}
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
    </div>
  );
}
