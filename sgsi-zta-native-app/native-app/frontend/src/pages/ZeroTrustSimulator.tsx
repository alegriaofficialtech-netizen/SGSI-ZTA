import React, { useState } from 'react';
import { PlayCircle, ShieldAlert, KeyRound, AlertTriangle, Sparkles } from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { SimulateRequest, SimulateResponse, Resource, Action } from '../types/zeroTrust';
import { ZeroTrustSubNav } from '../components/ZeroTrustSubNav';
import { DecisionBadge } from '../components/DecisionBadge';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';
import { useAuth } from '../hooks/useAuth';

const SYNTHETIC_SUBJECTS = [
  { id: 'usr-med-01', username: 'medico.demo', name: 'Dr. Alejandro Peña', roles: ['medico'] },
  { id: 'usr-adm-02', username: 'admision.demo', name: 'Carlos Ramos', roles: ['admision'] },
  {
    id: 'usr-enf-03',
    username: 'enfermeria.demo',
    name: 'Lic. Mariana Soto',
    roles: ['enfermeria'],
  },
  { id: 'usr-adm-00', username: 'admin.demo', name: 'Admin TI', roles: ['admin-ti'] },
  { id: 'usr-aud-04', username: 'auditor.demo', name: 'Auditor CISO', roles: ['auditor'] },
];

const SYNTHETIC_ASSETS = [
  { id: 'SRV-HIS-01', name: 'Servidor Central HIS (SRV-HIS-01)' },
  { id: 'PC-ADM-01', name: 'Estación de Admisión (PC-ADM-01)' },
  { id: 'LAP-MED-01', name: 'Laptop Médica Hospitalaria (LAP-MED-01)' },
];

const SYNTHETIC_DEVICES = [
  { id: 'LAP-MED-01', name: 'LAP-MED-01 (Trusted / EDR Active)' },
  { id: 'PC-ADM-01', name: 'PC-ADM-01 (Managed / Windows 11)' },
  { id: 'DEV-UNKNOWN-99', name: 'Dispositivo Externo No Confiable' },
];

export const ZeroTrustSimulator: React.FC = () => {
  const { user } = useAuth();
  const isAuthorized = user?.roles.some((r) => r === 'admin-ti' || r === 'auditor');

  const [form, setForm] = useState<SimulateRequest>({
    subject_user_id: 'usr-med-01',
    resource: 'clinical-demo',
    action: 'read_sensitive',
    asset_id: 'SRV-HIS-01',
    device_id: 'LAP-MED-01',
    assume_mfa: false,
  });

  const [evaluating, setEvaluating] = useState(false);
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isAuthorized) {
    return (
      <div className="space-y-6">
        <ZeroTrustSubNav />
        <div className="rounded-xl border border-rose-800 bg-rose-950/60 p-6 text-center text-rose-200">
          <ShieldAlert size={40} className="mx-auto text-rose-400 mb-3" />
          <h2 className="text-lg font-bold">Módulo Restringido</h2>
          <p className="text-sm mt-1 text-rose-300">
            El simulador de políticas Zero Trust está reservado exclusivamente para los roles{' '}
            <strong className="font-mono">admin-ti</strong> y{' '}
            <strong className="font-mono">auditor</strong>.
          </p>
        </div>
      </div>
    );
  }

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    setEvaluating(true);
    setError(null);
    try {
      const resp = await zeroTrustApi.simulateAccess(form);
      setResult(resp);
    } catch {
      setError('Error al ejecutar la simulación de autorización.');
    } finally {
      setEvaluating(false);
    }
  };

  const handleQuickPreset = (preset: 'medico-sensitive' | 'admision-sensitive' | 'admin-asset') => {
    if (preset === 'medico-sensitive') {
      setForm({
        subject_user_id: 'usr-med-01',
        resource: 'clinical-demo',
        action: 'read_sensitive',
        asset_id: 'SRV-HIS-01',
        device_id: 'LAP-MED-01',
        assume_mfa: false,
      });
    } else if (preset === 'admision-sensitive') {
      setForm({
        subject_user_id: 'usr-adm-02',
        resource: 'clinical-demo',
        action: 'read_sensitive',
        asset_id: 'SRV-HIS-01',
        device_id: 'PC-ADM-01',
        assume_mfa: false,
      });
    } else if (preset === 'admin-asset') {
      setForm({
        subject_user_id: 'usr-adm-00',
        resource: 'asset',
        action: 'create',
        asset_id: null,
        device_id: 'LAP-MED-01',
        assume_mfa: true,
      });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <PlayCircle className="text-blue-500" size={26} />
          Simulador de Políticas Zero Trust
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Entorno interactivo para ensayar y auditar la resolución del motor de políticas sin
          alterar el estado del sistema.
        </p>
      </div>

      <ZeroTrustSubNav />

      {/* Mandatory Academic Simulation Banner */}
      <div className="rounded-xl border border-amber-600/60 bg-amber-950/40 p-4 text-amber-200 text-xs flex items-center gap-3 shadow-sm">
        <AlertTriangle size={20} className="shrink-0 text-amber-400" />
        <div>
          <strong className="block text-sm font-bold text-amber-300 uppercase tracking-wide">
            SIMULACIÓN ACADÉMICA · NO REPRESENTA UN ACCESO REAL
          </strong>
          <span>
            Las evaluaciones generadas en esta pantalla se ejecutan sobre el sandbox de pruebas y no
            confieren acceso físico ni lógico a recursos reales.
          </span>
        </div>
      </div>

      {error && (
        <div className="rounded-lg bg-rose-950/60 border border-rose-800 p-4 text-rose-200 text-sm flex items-center gap-2">
          <ShieldAlert size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Preset Quick Actions */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400 font-medium">Escenarios frecuentes:</span>
        <button
          type="button"
          onClick={() => handleQuickPreset('medico-sensitive')}
          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
        >
          Médico $ ightarrow$ Historia Clínica (Sin MFA)
        </button>
        <button
          type="button"
          onClick={() => handleQuickPreset('admision-sensitive')}
          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
        >
          Admisión $ ightarrow$ Datos Clínicos Sensibles
        </button>
        <button
          type="button"
          onClick={() => handleQuickPreset('admin-asset')}
          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
        >
          Admin $ ightarrow$ Crear Activo Crítico (Con MFA)
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Simulator Form */}
        <form
          onSubmit={(e) => void handleEvaluate(e)}
          className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 shadow-sm"
        >
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2 flex items-center justify-between">
            <span>Parámetros de Evaluación</span>
            <span className="text-xs text-blue-400 font-mono">POST /simulate</span>
          </h2>

          <div>
            <label htmlFor="simSubject" className="block text-xs font-semibold text-slate-300 mb-1">
              Usuario Sintético Sujeto *
            </label>
            <select
              id="simSubject"
              value={form.subject_user_id}
              onChange={(e) => setForm({ ...form, subject_user_id: e.target.value })}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {SYNTHETIC_SUBJECTS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.username} — {s.name} ({s.roles.join(', ')})
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label
                htmlFor="simResource"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Recurso Objetivo *
              </label>
              <select
                id="simResource"
                value={form.resource}
                onChange={(e) => setForm({ ...form, resource: e.target.value as Resource })}
                className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="clinical-demo">clinical-demo</option>
                <option value="asset">asset</option>
                <option value="risk">risk</option>
                <option value="control">control</option>
                <option value="audit">audit</option>
                <option value="user-management">user-management</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="simAction"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Acción *
              </label>
              <select
                id="simAction"
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value as Action })}
                className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              >
                <option value="read">read</option>
                <option value="read_sensitive">read_sensitive</option>
                <option value="create">create</option>
                <option value="update">update</option>
                <option value="disable">disable</option>
                <option value="approve">approve</option>
                <option value="export">export</option>
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="simAsset" className="block text-xs font-semibold text-slate-300 mb-1">
              Activo Relacionado (Asset ID)
            </label>
            <select
              id="simAsset"
              value={form.asset_id ?? ''}
              onChange={(e) => setForm({ ...form, asset_id: e.target.value || null })}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">(Ninguno / Global)</option>
              {SYNTHETIC_ASSETS.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="simDevice" className="block text-xs font-semibold text-slate-300 mb-1">
              Dispositivo Origen (Device ID)
            </label>
            <select
              id="simDevice"
              value={form.device_id ?? ''}
              onChange={(e) => setForm({ ...form, device_id: e.target.value || null })}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">(Sin telemetría de dispositivo)</option>
              {SYNTHETIC_DEVICES.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
          </div>

          <div className="pt-2 border-t border-slate-800">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={form.assume_mfa}
                onChange={(e) => setForm({ ...form, assume_mfa: e.target.checked })}
                className="rounded bg-slate-950 border-slate-800 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <span className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                <KeyRound size={14} /> Assume MFA (Simular segundo factor completado)
              </span>
            </label>
          </div>

          <button
            type="submit"
            disabled={evaluating}
            className="w-full mt-4 flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-bold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-md transition disabled:opacity-50 tracking-wider"
          >
            <Sparkles size={16} />
            {evaluating ? 'EVALUANDO REGLAS...' : 'EVALUAR POLÍTICA'}
          </button>
        </form>

        {/* Simulator Results */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-md space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <span className="text-xs text-slate-400 uppercase font-semibold tracking-wider">
                    Resolución del Motor de Políticas
                  </span>
                  <div className="mt-2">
                    <DecisionBadge decision={result.decision} size="lg" />
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xs text-slate-500 block">ID de Evaluación</span>
                  <span className="font-mono text-xs text-slate-400">
                    {result.evaluation_id || 'No disponible'}
                  </span>
                </div>
              </div>

              {/* Reason Explanation */}
              <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="text-xs font-medium text-slate-400 block mb-1">
                  Razón de la Decisión:
                </span>
                <ReasonCodeBadge code={result.reason_code} showExplanation />
              </div>

              {/* Detailed Evaluation Context Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div className="rounded-lg bg-slate-950/50 border border-slate-800/80 p-3 space-y-2">
                  <span className="font-semibold text-slate-300 block border-b border-slate-800/80 pb-1">
                    Sujeto Evaluado
                  </span>
                  <div>
                    <span className="text-slate-500">Usuario:</span>{' '}
                    <strong className="text-white font-mono">
                      {result.user.username || 'No disponible'}
                    </strong>
                  </div>
                  <div>
                    <span className="text-slate-500">Roles:</span>{' '}
                    <span className="text-blue-300 font-mono">
                      [
                      {result.user.roles.length > 0
                        ? result.user.roles.join(', ')
                        : 'No disponible'}
                      ]
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Estado MFA:</span>{' '}
                    <strong
                      className={result.context.mfa_assumed ? 'text-emerald-400' : 'text-amber-400'}
                    >
                      {result.context.mfa_assumed ? 'Verificado' : 'No Presentado'}
                    </strong>
                  </div>
                </div>

                <div className="rounded-lg bg-slate-950/50 border border-slate-800/80 p-3 space-y-2">
                  <span className="font-semibold text-slate-300 block border-b border-slate-800/80 pb-1">
                    Postura y Contexto
                  </span>
                  <div>
                    <span className="text-slate-500">Confianza Dispositivo:</span>{' '}
                    <strong className="text-white font-mono">{result.context.device_trust}</strong>
                  </div>
                  <div>
                    <span className="text-slate-500">Score de Riesgo:</span>{' '}
                    <strong className="text-rose-400 font-mono">
                      {result.context.effective_risk_score}
                    </strong>{' '}
                    <span className="text-slate-500">({result.context.effective_risk_level})</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Activo Monitoreado:</span>{' '}
                    <span className="text-slate-300">{result.context.asset_name ?? 'N/A'}</span>
                  </div>
                </div>
              </div>

              {/* Matched Policy & Target */}
              <div className="rounded-lg bg-slate-950/50 border border-slate-800/80 p-3 text-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Política Coincidente (Matched Policy):</span>
                  <span className="font-mono font-bold text-blue-400">
                    {result.matched_policy ?? 'DEFAULT_DENY (Sin coincidencia)'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Objetivo Evaluado:</span>
                  <span className="font-mono text-cyan-300">
                    {result.resource} :: {result.action}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-slate-800 p-12 text-center text-slate-500">
              <PlayCircle size={40} className="mx-auto text-slate-700 mb-3" />
              <p className="text-base font-semibold text-slate-400">Simulador Listo</p>
              <p className="text-xs text-slate-600 mt-1 max-w-sm mx-auto">
                Seleccione el sujeto sintético, recurso y acción deseada para probar la resolución
                dinámica del motor Zero Trust.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
