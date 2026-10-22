import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, RefreshCw, Save } from 'lucide-react';
import { MonitoringSubNav } from '../../components/monitoring/MonitoringSubNav';
import { monitoringApi } from '../../services/monitoringApi';
import type { EventType, Severity } from '../../types/monitoring';

export function RuleForm() {
  const { id } = useParams<{ id: string }>();
  const isEdit = Boolean(id);
  const navigate = useNavigate();

  const [ruleCode, setRuleCode] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [eventType, setEventType] = useState<EventType>('AUTH_FAILURE');
  const [minimumSeverity, setMinimumSeverity] = useState<Severity>('HIGH');
  const [assetCriticality, setAssetCriticality] = useState<string>('');
  const [cooldownSeconds, setCooldownSeconds] = useState(300);
  const [enabled, setEnabled] = useState(true);

  const [loading, setLoading] = useState(isEdit);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadRule() {
      if (!id) return;
      setLoading(true);
      setError(null);
      try {
        const r = await monitoringApi.getRule(id);
        setRuleCode(r.rule_code);
        setName(r.name);
        setDescription(r.description || '');
        setEventType(r.event_type);
        setMinimumSeverity(r.minimum_severity);
        setAssetCriticality(r.asset_criticality || '');
        setCooldownSeconds(r.cooldown_seconds);
        setEnabled(r.enabled);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Error al cargar regla';
        setError(msg);
      } finally {
        setLoading(false);
      }
    }
    void loadRule();
  }, [id]);

  function validate(): string | null {
    if (!isEdit) {
      if (!ruleCode || ruleCode.length < 3 || ruleCode.length > 40) {
        return 'Código de regla debe tener entre 3 y 40 caracteres.';
      }
      if (!/^[A-Za-z0-9_-]+$/.test(ruleCode)) {
        return 'Código de regla solo permite letras, números, guiones y guiones bajos.';
      }
    }
    if (!name || name.trim().length === 0 || name.length > 160) {
      return 'Nombre es requerido y debe tener máximo 160 caracteres.';
    }
    if (description.length > 2000) {
      return 'Descripción no puede exceder 2000 caracteres.';
    }
    if (cooldownSeconds < 0) {
      return 'Cooldown debe ser un valor positivo o cero.';
    }
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const valError = validate();
    if (valError) {
      setError(valError);
      return;
    }

    setSaving(true);
    setError(null);
    try {
      if (isEdit && id) {
        await monitoringApi.updateRule(id, {
          name,
          description,
          minimum_severity: minimumSeverity,
          asset_criticality: assetCriticality || null,
          cooldown_seconds: cooldownSeconds,
          enabled,
        });
      } else {
        await monitoringApi.createRule({
          rule_code: ruleCode,
          name,
          description,
          event_type: eventType,
          minimum_severity: minimumSeverity,
          asset_criticality: assetCriticality || null,
          cooldown_seconds: cooldownSeconds,
          enabled,
        });
      }
      navigate('/monitoring/rules');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al guardar la regla';
      setError(msg);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center gap-3">
        <Link
          to="/monitoring/rules"
          className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          aria-label="Volver a lista de reglas"
        >
          <ArrowLeft size={16} />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            {isEdit ? 'Editar Regla de Detección' : 'Nueva Regla de Detección'}
          </h1>
          <p className="text-sm text-slate-400">
            {isEdit
              ? `Modificación de parámetros para ${ruleCode}`
              : 'Configuración estructurada sin scripts ni sintaxis libre'}
          </p>
        </div>
      </div>

      <MonitoringSubNav />

      {loading && (
        <div className="py-20 text-center text-slate-400">
          <RefreshCw size={24} className="animate-spin mx-auto text-blue-400 mb-2" />
          <p className="text-sm">Cargando regla...</p>
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

      {!loading && (
        <form
          onSubmit={(e) => void handleSubmit(e)}
          className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="rule-code"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Código Único de Regla {!isEdit && <span className="text-rose-400">*</span>}
              </label>
              <input
                id="rule-code"
                type="text"
                disabled={isEdit}
                placeholder="Ej: RULE-FIM-CRITICAL"
                value={ruleCode}
                onChange={(e) => setRuleCode(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono placeholder:text-slate-600 disabled:opacity-50"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                3-40 caracteres alfanuméricos con guiones.
              </span>
            </div>

            <div>
              <label
                htmlFor="rule-name"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Nombre Descriptivo <span className="text-rose-400">*</span>
              </label>
              <input
                id="rule-name"
                type="text"
                placeholder="Ej: Detección de alteración en archivos críticos"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={160}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder:text-slate-600"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                Máximo 160 caracteres ({name.length}/160).
              </span>
            </div>
          </div>

          <div>
            <label
              htmlFor="rule-description"
              className="block text-xs font-semibold text-slate-300 mb-1"
            >
              Descripción de la Regla
            </label>
            <textarea
              id="rule-description"
              rows={3}
              placeholder="Explica qué condición de seguridad dispara esta alerta..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={2000}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder:text-slate-600"
            />
            <span className="text-[11px] text-slate-500 mt-1 block">
              Máximo 2000 caracteres ({description.length}/2000).
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-slate-800">
            <div>
              <label
                htmlFor="rule-event-type"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Tipo de Evento Disparador
              </label>
              <select
                id="rule-event-type"
                disabled={isEdit}
                value={eventType}
                onChange={(e) => setEventType(e.target.value as EventType)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white disabled:opacity-50"
              >
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
              <label
                htmlFor="rule-min-severity"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Severidad Mínima Requerida
              </label>
              <select
                id="rule-min-severity"
                value={minimumSeverity}
                onChange={(e) => setMinimumSeverity(e.target.value as Severity)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFO">INFO</option>
              </select>
              <span className="text-[11px] text-slate-500 mt-1 block">
                Orden: INFO &lt; LOW &lt; MEDIUM &lt; HIGH &lt; CRITICAL
              </span>
            </div>

            <div>
              <label
                htmlFor="rule-asset-criticality"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Criticidad Activo (Opcional)
              </label>
              <select
                id="rule-asset-criticality"
                value={assetCriticality}
                onChange={(e) => setAssetCriticality(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white"
              >
                <option value="">Cualquier criticidad</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800">
            <div>
              <label
                htmlFor="rule-cooldown"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Ventana Cooldown Deduplicación (Segundos)
              </label>
              <input
                id="rule-cooldown"
                type="number"
                min={0}
                value={cooldownSeconds}
                onChange={(e) => setCooldownSeconds(parseInt(e.target.value, 10) || 0)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                300s = 5 minutos. Eventos idénticos dentro de la ventana se deduplican.
              </span>
            </div>

            <div className="flex items-center gap-3 pt-4">
              <input
                id="rule-enabled"
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-0"
              />
              <label htmlFor="rule-enabled" className="text-xs text-slate-200 font-medium">
                Habilitar regla inmediatamente
              </label>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <Link
              to="/monitoring/rules"
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
            >
              Cancelar
            </Link>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
            >
              {saving ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  <span>Guardando...</span>
                </>
              ) : (
                <>
                  <Save size={14} />
                  <span>{isEdit ? 'Actualizar Regla' : 'Crear Regla'}</span>
                </>
              )}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
