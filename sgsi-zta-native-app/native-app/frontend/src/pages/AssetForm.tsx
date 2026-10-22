import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Check, Info, Save } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api } from '../services/api';
import { ErrorState, Loading } from '../components/Status';
import { AssetBanner } from '../components/AssetUI';
import {
  assetLabels,
  classifications,
  criticalities,
  statuses,
  validateAssetDraft,
} from '../services/assets';
import type { AssetDetailData, AssetDraft, Catalog, Owner } from '../types/assets';

const empty: AssetDraft = {
  asset_code: '',
  name: '',
  description: '',
  asset_type_id: 0,
  department_id: 0,
  owner_user_id: 0,
  criticality: 'LOW',
  classification: 'INTERNAL',
  status: 'ACTIVE',
  monitoring_enabled: false,
  manufacturer: '',
  model: '',
  serial_number: '',
  hostname_demo: '',
  ip_address_demo: null,
  location_demo: '',
  notes: '',
};
export function AssetForm() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const admin = !!user?.roles.includes('admin-ti');
  const [data, setData] = useState<AssetDraft>(empty);
  const [types, setTypes] = useState<Catalog[]>([]);
  const [departments, setDepartments] = useState<Catalog[]>([]);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!admin) return;
    let active = true;
    Promise.all([
      api<Catalog[]>('/asset-types'),
      api<Catalog[]>('/departments'),
      api<Owner[]>('/assets/owners'),
      id ? api<AssetDetailData>(`/assets/${id}`) : Promise.resolve(null),
    ])
      .then(([typeList, departmentList, ownerList, asset]) => {
        if (!active) return;
        setTypes(typeList);
        setDepartments(departmentList);
        setOwners(ownerList);
        if (asset) {
          const draft = { ...empty };
          for (const key of Object.keys(empty) as (keyof AssetDraft)[])
            Object.assign(draft, { [key]: asset[key] });
          setData(draft);
        }
        setLoading(false);
      })
      .catch((e) => {
        if (active) setLoadError(e.message);
      });
    return () => {
      active = false;
    };
  }, [id, admin]);
  function change<K extends keyof AssetDraft>(key: K, value: AssetDraft[K]) {
    setData((current) => ({ ...current, [key]: value }));
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = validateAssetDraft(data);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError('');
    try {
      const body = {
        ...data,
        asset_code: data.asset_code.trim(),
        name: data.name.trim(),
        ip_address_demo: data.ip_address_demo?.trim() || null,
        monitoring_enabled: data.status === 'RETIRED' ? false : data.monitoring_enabled,
      };
      const result = await api<AssetDetailData>(id ? `/assets/${id}` : '/assets', {
        method: id ? 'PATCH' : 'POST',
        body: JSON.stringify(body),
      });
      navigate(`/assets/${result.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo guardar el activo');
    } finally {
      setBusy(false);
    }
  }
  function text(
    key:
      | 'asset_code'
      | 'name'
      | 'manufacturer'
      | 'model'
      | 'serial_number'
      | 'hostname_demo'
      | 'location_demo',
    label: string,
    max: number,
    placeholder = '',
    required = false,
  ) {
    return (
      <label key={key} htmlFor={`asset-${key}`}>
        {label}
        {required && ' *'}
        <input
          id={`asset-${key}`}
          value={data[key]}
          onChange={(e) => change(key, e.target.value)}
          maxLength={max}
          placeholder={placeholder}
          required={required}
          minLength={required ? (key === 'asset_code' ? 3 : 2) : undefined}
          pattern={key === 'asset_code' ? '[A-Z0-9]+(-[A-Z0-9]+)*' : undefined}
        />
      </label>
    );
  }
  if (!admin) return <ErrorState message="Solo admin-ti puede crear o editar activos." />;
  if (loadError) return <ErrorState message={loadError} />;
  if (loading) return <Loading />;
  return (
    <>
      <Link className="back-link" to={id ? `/assets/${id}` : '/assets'}>
        <ArrowLeft size={16} />
        Volver al {id ? 'detalle' : 'inventario'}
      </Link>
      <div className="page-heading">
        <div>
          <span className="eyebrow">GESTIÓN DE ACTIVOS</span>
          <h1>
            {id ? 'Editar activo' : 'Nuevo activo'}
            <span className="heading-dot">.</span>
          </h1>
          <p>
            {id
              ? 'Actualiza la información conservando la trazabilidad.'
              : 'Registra un activo sintético y asigna su clasificación.'}
          </p>
        </div>
        <span className="form-required-note">* Campos obligatorios</span>
      </div>
      <AssetBanner />
      <form className="asset-form" onSubmit={submit}>
        <section className="panel asset-form-section">
          <div className="panel-heading">
            <div>
              <h2>01 · Identificación</h2>
              <p>Datos generales del activo académico</p>
            </div>
            <Check size={18} />
          </div>
          <div className="asset-form-grid">
            {text('asset_code', 'Código', 40, 'EQP-DEMO-01', true)}
            {text('name', 'Nombre', 160, 'Equipo de demostración', true)}
            <label className="form-span-two" htmlFor="asset-description">
              Descripción
              <textarea
                id="asset-description"
                value={data.description}
                maxLength={2000}
                rows={3}
                onChange={(e) => change('description', e.target.value)}
              />
            </label>
            <label htmlFor="asset-type">
              Tipo *
              <select
                id="asset-type"
                value={data.asset_type_id}
                required
                onChange={(e) => change('asset_type_id', Number(e.target.value))}
              >
                <option value={0} disabled>
                  Seleccionar tipo
                </option>
                {types.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label htmlFor="asset-department">
              Área *
              <select
                id="asset-department"
                value={data.department_id}
                required
                onChange={(e) => change('department_id', Number(e.target.value))}
              >
                <option value={0} disabled>
                  Seleccionar área
                </option>
                {departments.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="form-span-two" htmlFor="asset-owner">
              Responsable *
              <select
                id="asset-owner"
                value={data.owner_user_id}
                required
                onChange={(e) => change('owner_user_id', Number(e.target.value))}
              >
                <option value={0} disabled>
                  Seleccionar usuario sintético
                </option>
                {!owners.some((owner) => owner.id === data.owner_user_id) &&
                  data.owner_user_id > 0 && (
                    <option value={data.owner_user_id} disabled>
                      Responsable desactivado · selecciona otro
                    </option>
                  )}
                {owners.map((owner) => (
                  <option key={owner.id} value={owner.id}>
                    {owner.display_name} · {owner.username}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </section>
        <section className="panel asset-form-section">
          <div className="panel-heading">
            <div>
              <h2>02 · Clasificación y estado</h2>
              <p>Prioridad de protección y ciclo de vida</p>
            </div>
          </div>
          <div className="asset-form-grid">
            {[
              ['criticality', 'Criticidad', criticalities],
              ['classification', 'Clasificación', classifications],
              ['status', 'Estado', statuses],
            ].map(([key, label, values]) => (
              <div key={String(key)}>
                <label htmlFor={`asset-${key}`}>{String(label)}</label>
                <select
                  id={`asset-${key}`}
                  value={String(data[key as keyof AssetDraft])}
                  onChange={(e) =>
                    setData((current) => ({ ...current, [String(key)]: e.target.value }))
                  }
                >
                  {(values as string[]).map((value) => (
                    <option key={value} value={value}>
                      {assetLabels[value]} · {value}
                    </option>
                  ))}
                </select>
              </div>
            ))}
            <div className="asset-monitor-setting">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={data.status !== 'RETIRED' && data.monitoring_enabled}
                  disabled={data.status === 'RETIRED'}
                  onChange={(e) => change('monitoring_enabled', e.target.checked)}
                />
                Monitoreo habilitado
              </label>
              <p>Marca de configuración. Eventos e integración: próxima fase M6.</p>
            </div>
          </div>
        </section>
        <section className="panel asset-form-section">
          <div className="panel-heading">
            <div>
              <h2>03 · Información técnica demo</h2>
              <p>Campos opcionales; utiliza únicamente datos sintéticos</p>
            </div>
            <Info size={19} />
          </div>
          <div className="asset-form-grid">
            {text('manufacturer', 'Fabricante', 100, 'Fabricante Demo')}
            {text('model', 'Modelo', 100, 'Modelo Demo')}
            {text('serial_number', 'Serial demo', 100, 'DEMO-0001')}
            {text('hostname_demo', 'Hostname demo', 120, 'eqp-demo')}
            <div>
              <label htmlFor="asset-ip">
                IP demo
                <input
                  id="asset-ip"
                  aria-describedby="asset-ip-help"
                  value={data.ip_address_demo ?? ''}
                  onChange={(e) => change('ip_address_demo', e.target.value)}
                  maxLength={45}
                  placeholder="192.0.2.20"
                />
              </label>
              <small className="field-help" id="asset-ip-help">
                Rangos documentales: 192.0.2.x, 198.51.100.x, 203.0.113.x
              </small>
            </div>
            {text('location_demo', 'Ubicación demo', 160, 'Sala Demo')}
            <label className="form-span-two" htmlFor="asset-notes">
              Notas
              <textarea
                id="asset-notes"
                rows={3}
                maxLength={2000}
                value={data.notes}
                onChange={(e) => change('notes', e.target.value)}
              />
            </label>
          </div>
        </section>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="asset-form-actions">
          <Link className="button secondary" to={id ? `/assets/${id}` : '/assets'}>
            Cancelar
          </Link>
          <button className="button primary" disabled={busy}>
            <Save size={17} />
            {busy ? 'Guardando…' : 'Guardar activo'}
          </button>
        </div>
      </form>
    </>
  );
}
