import React, { useEffect, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Shield, ArrowLeft, Save, AlertCircle } from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import type { PolicyInput, Resource, Action, DeviceTrustLevel } from '../types/zeroTrust';
import { useAuth } from '../hooks/useAuth';

const AVAILABLE_RESOURCES: Resource[] = [
  'clinical-demo',
  'asset',
  'risk',
  'control',
  'audit',
  'user-management',
];

const AVAILABLE_ACTIONS: Action[] = [
  'read',
  'read_sensitive',
  'create',
  'update',
  'disable',
  'approve',
  'export',
];

const AVAILABLE_ROLES = [
  'admin-ti',
  'medico',
  'enfermeria',
  'admision',
  'laboratorio',
  'farmacia',
  'auditor',
];

export const PolicyForm: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const isEdit = Boolean(id);
  const navigate = useNavigate();
  const { user } = useAuth();
  const isAdmin = user?.roles.includes('admin-ti');

  const [form, setForm] = useState<PolicyInput>({
    code: '',
    name: '',
    description: '',
    resource: 'clinical-demo',
    action: 'read',
    roles: ['medico'],
    effect: 'ALLOW',
    priority: 10,
    require_mfa: false,
    max_risk_score: 50,
    device_trust: 'TRUSTED',
    session_max_age_minutes: 480,
    enabled: true,
  });

  const [loading, setLoading] = useState(isEdit);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) {
      alert('Solo el rol admin-ti tiene permisos para administrar políticas.');
      navigate('/zero-trust/policies');
      return;
    }

    if (isEdit && id) {
      void zeroTrustApi
        .getPolicy(id)
        .then((p) => {
          setForm({
            code: p.code,
            name: p.name,
            description: p.description,
            resource: p.resource,
            action: p.action,
            roles: p.roles,
            effect: p.effect,
            priority: p.priority,
            require_mfa: p.require_mfa,
            max_risk_score: p.max_risk_score,
            device_trust: p.device_trust,
            session_max_age_minutes: p.session_max_age_minutes,
            enabled: p.enabled,
          });
        })
        .catch(() => {
          setError('No se pudo cargar la política solicitada.');
        })
        .finally(() => setLoading(false));
    }
  }, [id, isEdit, isAdmin, navigate]);

  const handleRoleToggle = (role: string) => {
    setForm((prev) => {
      const exists = prev.roles.includes(role);
      const roles = exists ? prev.roles.filter((r) => r !== role) : [...prev.roles, role];
      return { ...prev, roles };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Strict frontend validation
    if (!form.code.trim() || !form.name.trim()) {
      setError('El código y el nombre de la política son obligatorios.');
      return;
    }
    if (!/^POL-[A-Z0-9_-]+$/.test(form.code.trim())) {
      setError(
        'El código debe seguir el formato estándar: ej. POL-CLIN-001 (mayúsculas y guiones).',
      );
      return;
    }
    if (form.roles.length === 0) {
      setError('Debe seleccionar al menos un rol aplicable.');
      return;
    }
    if (form.priority < 1 || form.priority > 100) {
      setError('La prioridad debe ser un valor entero entre 1 y 100.');
      return;
    }
    if (form.max_risk_score < 0 || form.max_risk_score > 100) {
      setError('El score máximo de riesgo debe estar entre 0 y 100.');
      return;
    }

    setSaving(true);
    try {
      if (isEdit && id) {
        await zeroTrustApi.updatePolicy(id, form);
      } else {
        await zeroTrustApi.createPolicy(form);
      }
      navigate('/zero-trust/policies');
    } catch {
      setError('Error al guardar la política. Verifique los datos e intente nuevamente.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-400">
        <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
        <p>Cargando formulario de política...</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/zero-trust/policies"
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
        >
          <ArrowLeft size={18} />
        </Link>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="text-blue-500" size={24} />
            {isEdit ? `Editar Política: ${form.code}` : 'Nueva Política de Acceso Zero Trust'}
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Configuración estructurada de controles de autorización sin código ejecutable ni JSON
            libre.
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-lg bg-rose-950/60 border border-rose-800/80 p-4 text-rose-200 text-sm flex items-center gap-2">
          <AlertCircle size={18} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-6">
        {/* Basic Metadata */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2">
            1. Metadatos de la Política
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="policyCode"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Código de Política *
              </label>
              <input
                id="policyCode"
                type="text"
                placeholder="POL-CLIN-001"
                value={form.code}
                onChange={(e) => setForm({ ...form, code: e.target.value.toUpperCase() })}
                disabled={isEdit}
                required
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono disabled:opacity-50"
              />
              <span className="text-[11px] text-slate-500">Identificador único inmutable</span>
            </div>

            <div>
              <label
                htmlFor="policyName"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Nombre Descriptivo *
              </label>
              <input
                id="policyName"
                type="text"
                placeholder="Control de Acceso a ..."
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label htmlFor="policyDesc" className="block text-xs font-semibold text-slate-300 mb-1">
              Descripción y Racional de Seguridad
            </label>
            <textarea
              id="policyDesc"
              rows={2}
              placeholder="Explique el propósito de la regla y requisitos de cumplimiento..."
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* Target and Roles */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2">
            2. Objetivo y Sujetos Autorizados
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="resourceSelect"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Recurso Objetivo (Resource) *
              </label>
              <select
                id="resourceSelect"
                value={form.resource}
                onChange={(e) => setForm({ ...form, resource: e.target.value as Resource })}
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              >
                {AVAILABLE_RESOURCES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="actionSelect"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Acción Solicitada (Action) *
              </label>
              <select
                id="actionSelect"
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value as Action })}
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              >
                {AVAILABLE_ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Roles Aplicables (RBAC Match) *
            </label>
            <div className="flex flex-wrap gap-2">
              {AVAILABLE_ROLES.map((role) => {
                const active = form.roles.includes(role);
                return (
                  <button
                    key={role}
                    type="button"
                    onClick={() => handleRoleToggle(role)}
                    className={`px-3 py-1 text-xs rounded-lg font-mono border transition ${
                      active
                        ? 'bg-blue-600/30 border-blue-500 text-blue-300 font-bold'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {active ? '✓ ' : ''}
                    {role}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Decision & Security Constraints */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <h2 className="text-base font-semibold text-white border-b border-slate-800 pb-2">
            3. Resolución y Condiciones Adaptativas Zero Trust
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label
                htmlFor="effectSelect"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Efecto de la Política *
              </label>
              <select
                id="effectSelect"
                value={form.effect}
                onChange={(e) => setForm({ ...form, effect: e.target.value as 'ALLOW' | 'DENY' })}
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500 font-semibold"
              >
                <option value="ALLOW">ALLOW (Permitir)</option>
                <option value="DENY">DENY (Denegar)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="priorityInput"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Prioridad de Evaluación (1–100) *
              </label>
              <input
                id="priorityInput"
                type="number"
                min={1}
                max={100}
                value={form.priority}
                onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value, 10) || 1 })}
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
              <span className="text-[11px] text-slate-500">Mayor valor = evaluada primero</span>
            </div>

            <div>
              <label
                htmlFor="deviceTrustSelect"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Confianza de Dispositivo *
              </label>
              <select
                id="deviceTrustSelect"
                value={form.device_trust}
                onChange={(e) =>
                  setForm({ ...form, device_trust: e.target.value as DeviceTrustLevel })
                }
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="TRUSTED">TRUSTED (Corporativo Verificado)</option>
                <option value="MANAGED">MANAGED (Gestionado / EDR)</option>
                <option value="ANY">ANY (Cualquiera)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div>
              <label
                htmlFor="riskScoreInput"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Umbral Máximo de Riesgo Permitido (0–100)
              </label>
              <input
                id="riskScoreInput"
                type="number"
                min={0}
                max={100}
                value={form.max_risk_score}
                onChange={(e) =>
                  setForm({ ...form, max_risk_score: parseInt(e.target.value, 10) || 0 })
                }
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
              <span className="text-[11px] text-slate-500">
                Scores mayores deniegan automáticamente
              </span>
            </div>

            <div>
              <label
                htmlFor="sessionAgeInput"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Vigencia Máxima de Sesión (minutos)
              </label>
              <input
                id="sessionAgeInput"
                type="number"
                min={5}
                max={1440}
                value={form.session_max_age_minutes}
                onChange={(e) =>
                  setForm({ ...form, session_max_age_minutes: parseInt(e.target.value, 10) || 60 })
                }
                className="w-full px-3 py-2 text-sm rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 pt-3 border-t border-slate-800">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={form.require_mfa}
                onChange={(e) => setForm({ ...form, require_mfa: e.target.checked })}
                className="rounded bg-slate-950 border-slate-800 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <span className="text-sm font-semibold text-amber-300 flex items-center gap-1.5">
                Exigir Segundo Factor Obligatorio (MFA / TOTP)
              </span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="rounded bg-slate-950 border-slate-800 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <span className="text-sm font-semibold text-slate-300">
                Política Habilitada (Activa en Engine)
              </span>
            </label>
          </div>
        </div>

        {/* Submit Actions */}
        <div className="flex items-center justify-end gap-3">
          <Link
            to="/zero-trust/policies"
            className="px-4 py-2 text-sm rounded-lg text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition"
          >
            Cancelar
          </Link>
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-5 py-2 text-sm font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition disabled:opacity-50"
          >
            <Save size={16} />
            {saving ? 'Guardando...' : isEdit ? 'Actualizar Política' : 'Crear Política'}
          </button>
        </div>
      </form>
    </div>
  );
};
