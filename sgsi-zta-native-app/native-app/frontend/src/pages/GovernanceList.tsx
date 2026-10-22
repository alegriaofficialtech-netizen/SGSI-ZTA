import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Plus, Search, ArrowRight, Grid3X3, ChevronLeft, ChevronRight } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useRemote } from '../hooks/useRemote';
import { Badge, ErrorState, Loading } from '../components/Status';
import {
  GovernanceHeading,
  GovernanceMetrics,
  LevelBadge,
  RiskStatusBadge,
} from '../components/RiskUI';
import {
  categories,
  implementations,
  levels,
  riskLabels,
  riskStates,
  treatments,
} from '../services/risks';
import type {
  ControlData,
  Page,
  RiskData,
  RiskOptions,
  RiskSummary,
  ScenarioCatalog,
} from '../types/risks';

export function GovernanceList({ kind }: { kind: 'risks' | 'controls' }) {
  const { user } = useAuth();
  const allowed = !!user?.roles.some((r) => ['admin-ti', 'auditor'].includes(r));
  const admin = !!user?.roles.includes('admin-ti');
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get('search') ?? '');
  const result = useRemote<Page<RiskData | ControlData>>(`/${kind}?${params}`, allowed);
  const stats = useRemote<RiskSummary>('/risks/summary', allowed);
  const options = useRemote<RiskOptions>('/risks/options', allowed);
  const threats = useRemote<ScenarioCatalog[]>('/threats', allowed && kind === 'risks');
  const vulnerabilities = useRemote<ScenarioCatalog[]>(
    '/vulnerabilities',
    allowed && kind === 'risks',
  );
  function change(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next);
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    change('search', search.trim());
  }
  if (!allowed) return <ErrorState message="Tu rol no tiene acceso a riesgos y controles en M4." />;
  if (result.error || stats.error || options.error || threats.error || vulnerabilities.error)
    return (
      <ErrorState
        message={
          result.error || stats.error || options.error || threats.error || vulnerabilities.error
        }
        retry={result.reload}
      />
    );
  if (!result.data || !stats.data || !options.data) return <Loading />;
  const data = result.data;
  const risks = kind === 'risks';
  const choices = (values: string[]) =>
    values.map((value) => ({ value, label: riskLabels[value] }));
  const ownerOptions = options.data.owners.map((row) => ({
    value: String(row.id),
    label: row.username,
  }));
  const filters = risks
    ? [
        {
          key: 'asset_id',
          name: 'Activo',
          options: options.data.assets.map((row) => ({
            value: String(row.id),
            label: row.asset_code,
          })),
        },
        { key: 'level', name: 'Nivel', options: choices(levels) },
        { key: 'status', name: 'Estado', options: choices(riskStates) },
        { key: 'treatment', name: 'Tratamiento', options: choices(treatments) },
        { key: 'owner', name: 'Responsable', options: ownerOptions },
        {
          key: 'threat',
          name: 'Amenaza',
          options: (threats.data ?? []).map((row) => ({ value: String(row.id), label: row.name })),
        },
        {
          key: 'vulnerability',
          name: 'Vulnerabilidad',
          options: (vulnerabilities.data ?? []).map((row) => ({
            value: String(row.id),
            label: row.name,
          })),
        },
      ]
    : [
        { key: 'category', name: 'Categoría', options: choices(categories) },
        { key: 'implementation_status', name: 'Implementación', options: choices(implementations) },
        { key: 'owner', name: 'Responsable', options: ownerOptions },
        {
          key: 'active',
          name: 'Vigencia',
          options: [
            { value: 'true', label: 'Activos' },
            { value: 'false', label: 'Deshabilitados' },
          ],
        },
      ];
  return (
    <>
      <GovernanceHeading
        title={risks ? 'Gestión de Riesgos' : 'Controles de Seguridad'}
        subtitle={
          risks
            ? 'Evalúa escenarios sintéticos y define su tratamiento.'
            : 'Gestiona medidas académicas y consulta su trazabilidad.'
        }
      >
        <div className="asset-actions">
          {risks && (
            <Link className="button secondary" to="/risks/matrix">
              <Grid3X3 size={16} />
              Matriz 5×5
            </Link>
          )}
          {admin ? (
            <Link className="button primary" to={`/${kind}/new`}>
              <Plus size={16} />
              {risks ? 'Nuevo riesgo' : 'Nuevo control'}
            </Link>
          ) : (
            <Badge>Acceso de solo lectura</Badge>
          )}
        </div>
      </GovernanceHeading>
      <GovernanceMetrics data={stats.data} controls={!risks} />
      <section className="panel asset-inventory">
        <div className="asset-toolbar">
          <form className="asset-search" onSubmit={submit}>
            <div className="search-field">
              <Search size={16} />
              <input
                aria-label={risks ? 'Buscar riesgos' : 'Buscar controles'}
                placeholder={risks ? 'Código, título, activo o amenaza…' : 'Código o nombre…'}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <button className="button secondary">Buscar</button>
          </form>
          <div className="asset-sort">
            <select
              aria-label="Ordenar registros"
              value={params.get('sort_by') ?? (risks ? 'risk_code' : 'control_code')}
              onChange={(e) => change('sort_by', e.target.value)}
            >
              {(risks
                ? ['risk_code', 'score', 'level', 'status', 'created_at', 'updated_at']
                : ['control_code', 'name', 'implementation_status', 'created_at', 'updated_at']
              ).map((field) => (
                <option key={field} value={field}>
                  {
                    {
                      risk_code: 'Código',
                      control_code: 'Código',
                      name: 'Nombre',
                      score: 'Score',
                      level: 'Nivel',
                      status: 'Estado',
                      implementation_status: 'Implementación',
                      created_at: 'Creación',
                      updated_at: 'Actualización',
                    }[field]
                  }
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
        <div className="asset-filters governance-filters">
          {filters.map((filter) => (
            <label className="asset-filter" key={filter.key}>
              <span>{filter.name}</span>
              <select
                aria-label={`Filtrar por ${filter.name.toLowerCase()}`}
                value={params.get(filter.key) ?? ''}
                onChange={(e) => change(filter.key, e.target.value)}
              >
                <option value="">Todos</option>
                {filter.options.map((option) => (
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
            {data.total} {risks ? 'riesgos' : 'controles'} encontrados
          </span>
          <button
            className="text-link"
            onClick={() => {
              setSearch('');
              setParams({});
            }}
          >
            Limpiar filtros
          </button>
        </div>
        <div
          className="table-wrap asset-table-wrap"
          tabIndex={0}
          role="region"
          aria-label={risks ? 'Tabla de riesgos' : 'Tabla de controles'}
        >
          <table className="governance-table">
            <thead>
              <tr>
                {(risks
                  ? [
                      'Código',
                      'Activo',
                      'Título',
                      'Amenaza',
                      'Probabilidad',
                      'Impacto',
                      'Score',
                      'Nivel',
                      'Tratamiento',
                      'Estado',
                      'Responsable',
                      'Acciones',
                    ]
                  : [
                      'Código',
                      'Nombre',
                      'Categoría',
                      'Implementación',
                      'Responsable',
                      'Riesgos relacionados',
                      'Vigencia',
                      'Acciones',
                    ]
                ).map((name) => (
                  <th key={name}>{name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((row) => (
                <tr key={row.id}>
                  {'risk_code' in row ? (
                    <>
                      <td>
                        <Link className="asset-code mono" to={`/risks/${row.id}`}>
                          {row.risk_code}
                        </Link>
                      </td>
                      <td>
                        <Link className="text-link" to={`/assets/${row.asset_id}`}>
                          {row.asset.asset_code}
                        </Link>
                      </td>
                      <td>{row.title}</td>
                      <td>{row.threat.name}</td>
                      <td>{row.probability}</td>
                      <td>{row.impact}</td>
                      <td>
                        <strong>{row.score}</strong> / 25
                      </td>
                      <td>
                        <LevelBadge value={row.level} />
                      </td>
                      <td>{riskLabels[row.treatment]}</td>
                      <td>
                        <RiskStatusBadge value={row.status} />
                      </td>
                      <td className="mono">{row.owner.username}</td>
                    </>
                  ) : (
                    <>
                      <td>
                        <Link className="asset-code mono" to={`/controls/${row.id}`}>
                          {row.control_code}
                        </Link>
                      </td>
                      <td>{row.name}</td>
                      <td>{riskLabels[row.category]}</td>
                      <td>
                        <RiskStatusBadge value={row.implementation_status} />
                      </td>
                      <td className="mono">{row.owner.username}</td>
                      <td>{row.risk_count}</td>
                      <td>
                        <Badge>{row.active ? 'Activo' : 'Deshabilitado'}</Badge>
                      </td>
                    </>
                  )}
                  <td>
                    <Link
                      className="icon-button"
                      aria-label={`Ver ${'risk_code' in row ? row.risk_code : row.control_code}`}
                      to={`/${kind}/${row.id}`}
                    >
                      <ArrowRight size={17} />
                    </Link>
                  </td>
                </tr>
              ))}
              {!data.items.length && (
                <tr>
                  <td colSpan={risks ? 12 : 8} className="empty-cell">
                    Sin resultados para estos filtros.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="table-footer asset-pagination">
          <span>
            {data.total} registros · Página {data.page} de {Math.max(1, data.pages)}
          </span>
          <div>
            <select
              aria-label="Registros por página"
              value={params.get('page_size') ?? '20'}
              onChange={(e) => change('page_size', e.target.value)}
            >
              {[10, 20, 50, 100].map((n) => (
                <option value={n} key={n}>
                  {n} / página
                </option>
              ))}
            </select>
            <button
              className="icon-button"
              aria-label="Página anterior"
              disabled={data.page <= 1}
              onClick={() => change('page', String(data.page - 1))}
            >
              <ChevronLeft size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Página siguiente"
              disabled={data.page >= data.pages}
              onClick={() => change('page', String(data.page + 1))}
            >
              <ChevronRight size={17} />
            </button>
          </div>
        </div>
      </section>
      <p className="asset-count-note">
        Incluye registros cerrados o deshabilitados. Los estados describen el laboratorio académico
        y no acreditan cumplimiento certificado.
      </p>
    </>
  );
}
