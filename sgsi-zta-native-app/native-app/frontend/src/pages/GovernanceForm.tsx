import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Save } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api } from '../services/api';
import {
  categories,
  implementations,
  impactLabels,
  probabilityLabels,
  riskLabels,
  riskStates,
  treatments,
} from '../services/risks';
import { ErrorState, Loading } from '../components/Status';
import { GovernanceHeading, LevelBadge } from '../components/RiskUI';
import type {
  ControlData,
  ControlDraft,
  MatrixData,
  RiskData,
  RiskDraft,
  RiskOptions,
  ScenarioCatalog,
} from '../types/risks';

const emptyRisk: RiskDraft = {
  risk_code: '',
  title: '',
  description: '',
  asset_id: 0,
  threat_id: 0,
  vulnerability_id: 0,
  probability: 3,
  impact: 3,
  treatment: 'REDUCE',
  status: 'OPEN',
  owner_user_id: 0,
  review_due_at: null,
};
const emptyControl: ControlDraft = {
  control_code: '',
  name: '',
  description: '',
  category: 'IDENTITY',
  implementation_status: 'PLANNED',
  owner_user_id: 0,
  active: true,
};
type Draft = RiskDraft & ControlDraft;
export function GovernanceForm({ kind }: { kind: 'risks' | 'controls' }) {
  const { id } = useParams();
  const { user } = useAuth();
  const admin = !!user?.roles.includes('admin-ti');
  const navigate = useNavigate();
  const risks = kind === 'risks';
  const [data, setData] = useState<Draft>({ ...emptyRisk, ...emptyControl });
  const [options, setOptions] = useState<RiskOptions | null>(null);
  const [threats, setThreats] = useState<ScenarioCatalog[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<ScenarioCatalog[]>([]);
  const [matrix, setMatrix] = useState<MatrixData | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!admin) return;
    let active = true;
    Promise.all([
      api<RiskOptions>('/risks/options'),
      risks ? api<ScenarioCatalog[]>('/threats') : Promise.resolve([]),
      risks ? api<ScenarioCatalog[]>('/vulnerabilities') : Promise.resolve([]),
      risks ? api<MatrixData>('/risks/matrix') : Promise.resolve(null),
      id ? api<RiskData | ControlData>(`/${kind}/${id}`) : Promise.resolve(null),
    ])
      .then(([choices, t, v, m, row]) => {
        if (!active) return;
        setOptions(choices);
        setThreats(t);
        setVulnerabilities(v);
        setMatrix(m);
        if (row) {
          const values = { ...emptyRisk, ...emptyControl };
          for (const key of Object.keys(values) as (keyof Draft)[])
            if (key in row) Object.assign(values, { [key]: row[key as keyof typeof row] });
          setData(values);
        }
        setLoaded(true);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [admin, id, kind, risks]);
  function change<K extends keyof Draft>(key: K, value: Draft[K]) {
    setData((current) => ({ ...current, [key]: value }));
  }
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (
      !data.owner_user_id ||
      (risks && (!data.asset_id || !data.threat_id || !data.vulnerability_id))
    ) {
      setError('Selecciona las referencias obligatorias.');
      return;
    }
    setBusy(true);
    setError('');
    const template = risks ? emptyRisk : emptyControl;
    const body = Object.fromEntries(
      Object.keys(template)
        .filter((key) => !id || !['risk_code', 'control_code'].includes(key))
        .map((key) => [key, data[key as keyof Draft]]),
    );
    try {
      const row = await api<{ id: number }>(id ? `/${kind}/${id}` : `/${kind}`, {
        method: id ? 'PATCH' : 'POST',
        body: JSON.stringify(body),
      });
      navigate(`/${kind}/${row.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo guardar');
    } finally {
      setBusy(false);
    }
  }
  function select(
    key: keyof Draft,
    label: string,
    choices: { value: string; label: string }[],
    numeric = false,
    required = false,
  ) {
    return (
      <label key={key}>
        <span>
          {label}
          {required ? ' *' : ''}
        </span>
        <select
          aria-label={label}
          required={required}
          value={String(data[key] ?? '')}
          onChange={(e) =>
            change(key, (numeric ? Number(e.target.value) : e.target.value) as never)
          }
        >
          {required && <option value="0">Seleccionar…</option>}
          {choices.map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.label}
            </option>
          ))}
        </select>
      </label>
    );
  }
  const enumChoices = (values: string[]) =>
    values.map((value) => ({ value, label: riskLabels[value] }));
  if (!admin)
    return <ErrorState message="Solo admin-ti puede crear o editar riesgos y controles." />;
  if (!loaded || !options) return error ? <ErrorState message={error} /> : <Loading />;
  const preview = matrix?.cells.find(
    (cell) => cell.probability === data.probability && cell.impact === data.impact,
  );
  return (
    <>
      <Link className="back-link" to={id ? `/${kind}/${id}` : `/${kind}`}>
        ← Volver al {id ? 'detalle' : 'listado'}
      </Link>
      <GovernanceHeading
        title={
          risks ? (id ? 'Editar riesgo' : 'Nuevo riesgo') : id ? 'Editar control' : 'Nuevo control'
        }
        subtitle="Define un registro sintético y conserva su trazabilidad."
      />
      <form className="asset-form" onSubmit={submit}>
        <section className="panel asset-form-section">
          <div className="panel-heading">
            <div>
              <h2>01 · Identificación</h2>
              <p>* Campos obligatorios</p>
            </div>
          </div>
          <div className="asset-form-grid">
            <label>
              <span>Código *</span>
              <input
                aria-label="Código"
                value={risks ? data.risk_code : data.control_code}
                required
                disabled={!!id}
                pattern="[A-Z0-9]+(-[A-Z0-9]+)*"
                minLength={3}
                maxLength={40}
                placeholder={risks ? 'R-009' : 'CTRL-011'}
                onChange={(e) => change(risks ? 'risk_code' : 'control_code', e.target.value)}
              />
            </label>
            <label>
              <span>{risks ? 'Título' : 'Nombre'} *</span>
              <input
                aria-label={risks ? 'Título' : 'Nombre'}
                value={risks ? data.title : data.name}
                required
                minLength={2}
                maxLength={160}
                onChange={(e) => change(risks ? 'title' : 'name', e.target.value)}
              />
            </label>
            <label className="wide-field">
              <span>Descripción</span>
              <textarea
                aria-label="Descripción"
                maxLength={2000}
                rows={4}
                value={data.description}
                onChange={(e) => change('description', e.target.value)}
              />
            </label>
            {risks && (
              <>
                {select(
                  'asset_id',
                  'Activo',
                  options.assets.map((row) => ({
                    value: String(row.id),
                    label: `${row.asset_code} · ${row.name}`,
                  })),
                  true,
                  true,
                )}
                {select(
                  'threat_id',
                  'Amenaza',
                  threats
                    .filter((row) => row.active)
                    .map((row) => ({ value: String(row.id), label: row.name })),
                  true,
                  true,
                )}
                {select(
                  'vulnerability_id',
                  'Vulnerabilidad',
                  vulnerabilities
                    .filter((row) => row.active)
                    .map((row) => ({ value: String(row.id), label: row.name })),
                  true,
                  true,
                )}
              </>
            )}
            {select(
              'owner_user_id',
              'Responsable',
              options.owners.map((row) => ({ value: String(row.id), label: row.username })),
              true,
              true,
            )}
          </div>
        </section>
        <section className="panel asset-form-section">
          <div className="panel-heading">
            <div>
              <h2>02 · {risks ? 'Evaluación y tratamiento' : 'Implementación académica'}</h2>
              <p>
                {risks
                  ? 'La evaluación se calcula y valida en el servidor.'
                  : 'Los estados no representan certificación de cumplimiento.'}
              </p>
            </div>
          </div>
          <div className="asset-form-grid">
            {risks ? (
              <>
                {select(
                  'probability',
                  'Probabilidad',
                  probabilityLabels.map((label, n) => ({
                    value: String(n + 1),
                    label: `${n + 1} — ${label}`,
                  })),
                  true,
                )}
                {select(
                  'impact',
                  'Impacto',
                  impactLabels.map((label, n) => ({
                    value: String(n + 1),
                    label: `${n + 1} — ${label}`,
                  })),
                  true,
                )}
                {select('treatment', 'Tratamiento', enumChoices(treatments))}
                {select('status', 'Estado', enumChoices(riskStates))}
                <label>
                  <span>Fecha de revisión</span>
                  <input
                    aria-label="Fecha de revisión"
                    type="date"
                    value={data.review_due_at?.slice(0, 10) ?? ''}
                    onChange={(e) =>
                      change('review_due_at', e.target.value ? e.target.value + 'T00:00:00Z' : null)
                    }
                  />
                </label>
              </>
            ) : (
              <>
                {select('category', 'Categoría', enumChoices(categories))}
                {select('implementation_status', 'Implementación', enumChoices(implementations))}
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={data.active}
                    onChange={(e) => change('active', e.target.checked)}
                  />
                  Control activo
                </label>
              </>
            )}
          </div>
          {risks && preview && (
            <div
              className={`risk-preview risk-cell-${preview.level.toLowerCase()}`}
              role="status"
              aria-live="polite"
            >
              <div>
                <span className="eyebrow">EVALUACIÓN CALCULADA</span>
                <strong>Score: {preview.score} / 25</strong>
                <span>
                  Probabilidad {preview.probability} × Impacto {preview.impact}
                </span>
              </div>
              <LevelBadge value={preview.level} />
            </div>
          )}
        </section>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="asset-form-actions">
          <Link className="button secondary" to={`/${kind}`}>
            Cancelar
          </Link>
          <button className="button primary" disabled={busy}>
            <Save size={16} />
            {busy ? 'Guardando…' : risks ? 'Guardar riesgo' : 'Guardar control'}
          </button>
        </div>
      </form>
    </>
  );
}
