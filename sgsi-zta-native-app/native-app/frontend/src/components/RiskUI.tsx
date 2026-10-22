import { Link } from 'react-router-dom';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import { Badge } from './Status';
import { riskLabels } from '../services/risks';
import { dateLabel } from '../services/api';
import type { AuditEntry } from '../types';
import type { Level, RiskData, RiskSummary } from '../types/risks';

export function RiskBanner() {
  return (
    <div className="asset-lab-note">
      <ShieldAlert size={15} />
      <span>LABORATORIO ACADÉMICO · RIESGOS Y CONTROLES SINTÉTICOS</span>
    </div>
  );
}
export function LevelBadge({ value }: { value: Level }) {
  const tones = { LOW: 'green', MEDIUM: 'amber', HIGH: 'orange', CRITICAL: 'red' } as const;
  return <Badge tone={tones[value]}>{riskLabels[value]}</Badge>;
}
export function RiskStatusBadge({ value }: { value: string }) {
  return (
    <Badge
      tone={
        ['IMPLEMENTED', 'ACCEPTED'].includes(value)
          ? 'green'
          : ['PARTIAL', 'IN_TREATMENT'].includes(value)
            ? 'amber'
            : 'neutral'
      }
    >
      {riskLabels[value] ?? value}
    </Badge>
  );
}
export function GovernanceMetrics({
  data,
  controls = false,
}: {
  data: RiskSummary;
  controls?: boolean;
}) {
  const metrics = controls
    ? [
        ['Total controles', data.controls_total],
        ['Implementados', data.implemented],
        ['Parciales', data.partial],
        ['Planificados', data.planned],
      ]
    : [
        ['Total riesgos', data.total],
        ['Riesgos críticos', data.critical],
        ['Riesgos altos', data.high],
        ['En tratamiento', data.in_treatment],
        ['Cerrados', data.closed],
      ];
  return (
    <div className="metric-grid governance-metrics">
      {metrics.map(([name, value]) => (
        <section className="metric-card" key={name}>
          <div className="metric-top">
            <span>{name}</span>
            <ShieldAlert size={17} />
          </div>
          <strong className="metric-number">{value}</strong>
          <div className="metric-note">Escenarios académicos registrados</div>
        </section>
      ))}
    </div>
  );
}
export function RiskRows({ rows }: { rows: RiskData[] }) {
  return (
    <div
      className="table-wrap asset-table-wrap"
      tabIndex={0}
      role="region"
      aria-label="Riesgos relacionados"
    >
      <table>
        <thead>
          <tr>
            <th>Código</th>
            <th>Título</th>
            <th>Score</th>
            <th>Nivel</th>
            <th>Estado</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>
                <Link className="asset-code mono" to={`/risks/${row.id}`}>
                  {row.risk_code}
                </Link>
              </td>
              <td>{row.title}</td>
              <td>{row.score} / 25</td>
              <td>
                <LevelBadge value={row.level} />
              </td>
              <td>
                <RiskStatusBadge value={row.status} />
              </td>
            </tr>
          ))}
          {!rows.length && (
            <tr>
              <td colSpan={5} className="empty-cell">
                Sin riesgos relacionados.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
export function GovernanceHistory({ rows }: { rows: AuditEntry[] }) {
  return (
    <section className="panel asset-history">
      <div className="panel-heading">
        <div>
          <h2>Historial reciente</h2>
          <p>Últimos 50 cambios registrados</p>
        </div>
      </div>
      <ol>
        {rows.map((row) => {
          let detail: string;
          try {
            const d = JSON.parse(row.detail);
            detail =
              d.before !== undefined
                ? `${d.field}: ${riskLabels[d.before] ?? d.before} → ${riskLabels[d.after] ?? d.after}`
                : d.control_id
                  ? `Control #${d.control_id}`
                  : (d.fields?.join(', ') ?? '');
          } catch {
            detail = '';
          }
          return (
            <li key={row.id}>
              <span className="history-point" />
              <div>
                <strong>{row.action.replaceAll('_', ' ')}</strong>
                <p>{detail}</p>
                <small>
                  {row.username} · {dateLabel(row.timestamp)}
                </small>
              </div>
            </li>
          );
        })}
      </ol>
      {!rows.length && (
        <div className="history-empty">
          Seed académico inicial. Los cambios posteriores se registrarán aquí.
        </div>
      )}
    </section>
  );
}
export function GovernanceHeading({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children?: React.ReactNode;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">GESTIÓN DEL SGSI</span>
          <h1>
            {title}
            <span className="heading-dot">.</span>
          </h1>
          <p>{subtitle}</p>
        </div>
        {children}
      </div>
      <RiskBanner />
    </>
  );
}
export function BackLink({ to, label }: { to: string; label: string }) {
  return (
    <Link className="back-link" to={to}>
      <ArrowRight size={15} />
      {label}
    </Link>
  );
}
