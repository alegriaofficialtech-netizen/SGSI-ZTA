import { assetLabels, criticalities, classifications, statuses } from '../services/assets';
import { useEffect, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  ArrowDownUp,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Plus,
  Search,
  SlidersHorizontal,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api } from '../services/api';
import { Badge, ErrorState, Loading } from '../components/Status';
import {
  AssetBanner,
  AssetMetrics,
  AssetStatusBadge,
  CriticalityBadge,
} from '../components/AssetUI';
import type { AssetPage, AssetSummary, Catalog } from '../types/assets';

export function Assets() {
  const { user } = useAuth();
  const allowed = !!user?.roles.some((role) => ['admin-ti', 'auditor'].includes(role));
  const admin = !!user?.roles.includes('admin-ti');
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get('search') ?? '');
  const [data, setData] = useState<AssetPage | null>(null);
  const [summary, setSummary] = useState<AssetSummary | null>(null);
  const [catalogs, setCatalogs] = useState<{ types: Catalog[]; departments: Catalog[] }>({
    types: [],
    departments: [],
  });
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(true);
  const query = params.toString();
  useEffect(() => {
    if (!allowed) return;
    let active = true;
    Promise.all([
      api<AssetSummary>('/assets/summary'),
      api<Catalog[]>('/asset-types'),
      api<Catalog[]>('/departments'),
    ])
      .then(([metrics, types, departments]) => {
        if (active) {
          setSummary(metrics);
          setCatalogs({ types, departments });
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [allowed, refresh]);
  useEffect(() => {
    if (!allowed) return;
    let active = true;
    api<AssetPage>(`/assets?${query}`)
      .then((result) => {
        if (active) {
          setData(result);
          setError('');
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    return () => {
      active = false;
    };
  }, [allowed, query, refresh]);
  function change(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    if (next.toString() === params.toString()) return;
    setBusy(true);
    setParams(next);
  }
  function submitSearch(event: FormEvent) {
    event.preventDefault();
    change('search', search.trim());
  }
  if (!allowed)
    return (
      <ErrorState message="El inventario está disponible para admin-ti y auditor. Tu rol operativo no tiene acceso a activos en M3." />
    );
  if (error) return <ErrorState message={error} retry={() => setRefresh(refresh + 1)} />;
  if (!data || !summary) return <Loading />;
  const filtered = [...params.keys()].some(
    (key) => !['page', 'page_size', 'sort_by', 'sort_order'].includes(key),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">GESTIÓN DE ACTIVOS</span>
          <h1>
            Inventario de Activos<span className="heading-dot">.</span>
          </h1>
          <p>Registro y clasificación de activos sintéticos del laboratorio SGSI-ZTA.</p>
        </div>
        {admin ? (
          <Link className="button primary" to="/assets/new">
            <Plus size={17} />
            Nuevo activo
          </Link>
        ) : (
          <Badge>Acceso de solo lectura</Badge>
        )}
      </div>
      <AssetBanner />
      <AssetMetrics data={summary} />
      <section className="panel asset-inventory">
        <div className="asset-toolbar">
          <form className="asset-search" onSubmit={submitSearch}>
            <div className="search-field">
              <Search size={17} />
              <input
                aria-label="Buscar activos"
                placeholder="Código, nombre o hostname…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
            <button className="button secondary" type="submit">
              Buscar
            </button>
          </form>
          <div className="asset-sort">
            <ArrowDownUp size={16} />
            <select
              aria-label="Ordenar activos"
              value={params.get('sort_by') ?? 'asset_code'}
              onChange={(e) => change('sort_by', e.target.value)}
            >
              {[
                ['asset_code', 'Código'],
                ['name', 'Nombre'],
                ['criticality', 'Criticidad'],
                ['status', 'Estado'],
                ['updated_at', 'Actualización'],
              ].map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <select
              aria-label="Dirección del orden"
              value={params.get('sort_order') ?? 'asc'}
              onChange={(e) => change('sort_order', e.target.value)}
            >
              <option value="asc">Ascendente</option>
              <option value="desc">Descendente</option>
            </select>
          </div>
        </div>
        <div className="asset-filters">
          <div className="filter-title">
            <SlidersHorizontal size={15} />
            Filtros
          </div>
          {[
            [
              'criticality',
              'Criticidad',
              criticalities.map((value) => ({ value, label: assetLabels[value] })),
            ],
            ['status', 'Estado', statuses.map((value) => ({ value, label: assetLabels[value] }))],
            [
              'asset_type',
              'Tipo',
              catalogs.types.map((row) => ({ value: String(row.id), label: row.name })),
            ],
            [
              'department',
              'Área',
              catalogs.departments.map((row) => ({ value: String(row.id), label: row.name })),
            ],
            [
              'classification',
              'Clasificación',
              classifications.map((value) => ({ value, label: assetLabels[value] })),
            ],
            [
              'monitoring_enabled',
              'Monitoreo',
              [
                { value: 'true', label: 'Habilitado' },
                { value: 'false', label: 'Sin monitoreo' },
              ],
            ],
          ].map(([key, label, options]) => (
            <label className="asset-filter" key={String(key)}>
              <span>{String(label)}</span>
              <select
                aria-label={`Filtrar por ${String(label).toLowerCase()}`}
                value={params.get(String(key)) ?? ''}
                onChange={(e) => change(String(key), e.target.value)}
              >
                <option value="">Todos</option>
                {(options as { value: string; label: string }[]).map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
          ))}
        </div>
        <div className="asset-result-bar">
          <span aria-live="polite">
            {busy ? 'Actualizando…' : `${data.total} activos encontrados`}
          </span>
          {filtered && (
            <button
              className="text-link"
              onClick={() => {
                setSearch('');
                setBusy(true);
                setParams({});
              }}
            >
              Limpiar filtros
            </button>
          )}
        </div>
        <div
          className="table-wrap asset-table-wrap"
          tabIndex={0}
          role="region"
          aria-label="Tabla de activos, desplazable horizontalmente"
          aria-busy={busy}
        >
          <table className="asset-table">
            <thead>
              <tr>
                {[
                  'Código',
                  'Activo',
                  'Tipo',
                  'Área',
                  'Criticidad',
                  'Clasificación',
                  'Estado',
                  'Monitoreo',
                  'Responsable',
                  'Acciones',
                ].map((label) => (
                  <th key={label}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <Link className="asset-code mono" to={`/assets/${asset.id}`}>
                      {asset.asset_code}
                    </Link>
                  </td>
                  <td>
                    <Link className="asset-name" to={`/assets/${asset.id}`}>
                      <strong>{asset.name}</strong>
                      <small>{asset.hostname_demo || 'Sin hostname demo'}</small>
                    </Link>
                  </td>
                  <td>{asset.asset_type.name}</td>
                  <td>{asset.department.name}</td>
                  <td>
                    <CriticalityBadge value={asset.criticality} />
                  </td>
                  <td>
                    <Badge>{assetLabels[asset.classification]}</Badge>
                  </td>
                  <td>
                    <AssetStatusBadge value={asset.status} />
                  </td>
                  <td>
                    <span className={`monitor-label ${asset.monitoring_enabled ? 'enabled' : ''}`}>
                      <i />
                      {asset.monitoring_enabled ? 'Habilitado' : 'Sin monitoreo'}
                    </span>
                  </td>
                  <td className="mono">{asset.owner.username}</td>
                  <td>
                    <Link
                      className="icon-button"
                      aria-label={`Ver ${asset.asset_code}`}
                      to={`/assets/${asset.id}`}
                    >
                      <ArrowRight size={17} />
                    </Link>
                  </td>
                </tr>
              ))}
              {!data.items.length && (
                <tr>
                  <td className="empty-cell" colSpan={10}>
                    No hay activos que coincidan con tu búsqueda.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="table-footer asset-pagination">
          <span>
            {data.items.length
              ? `${(data.page - 1) * data.page_size + 1}–${Math.min(data.page * data.page_size, data.total)} de ${data.total}`
              : `Sin resultados en esta página · ${data.total} en total`}
          </span>
          <div>
            <select
              aria-label="Activos por página"
              value={params.get('page_size') ?? '20'}
              onChange={(e) => change('page_size', e.target.value)}
            >
              {[10, 20, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size} / página
                </option>
              ))}
            </select>
            <button
              className="icon-button"
              aria-label="Página anterior"
              disabled={busy || data.page <= 1}
              onClick={() => change('page', String(data.page - 1))}
            >
              <ChevronLeft size={18} />
            </button>
            <span>
              Página {data.page} de {Math.max(1, data.pages)}
            </span>
            <button
              className="icon-button"
              aria-label="Página siguiente"
              disabled={busy || data.page >= data.pages}
              onClick={() => change('page', String(data.page + 1))}
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      </section>
      <p className="asset-count-note">
        Los indicadores representan todo el inventario, incluidos los retirados. Monitoreo indica
        configuración académica; la integración de eventos corresponde a M6.
      </p>
    </>
  );
}
