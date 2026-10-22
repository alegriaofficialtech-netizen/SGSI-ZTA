import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Edit3, Plus, Unlink } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useRemote } from '../hooks/useRemote';
import { api, dateLabel } from '../services/api';
import { riskLabels, probabilityLabels, impactLabels } from '../services/risks';
import { Badge, ErrorState, Loading } from '../components/Status';
import {
  GovernanceHeading,
  GovernanceHistory,
  LevelBadge,
  RiskRows,
  RiskStatusBadge,
} from '../components/RiskUI';
import type { ControlData, ControlDetailData, RiskDetailData } from '../types/risks';

export function RiskDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const allowed = !!user?.roles.some((r) => ['admin-ti', 'auditor'].includes(r));
  const admin = !!user?.roles.includes('admin-ti');
  const result = useRemote<RiskDetailData>(`/risks/${id}`, allowed);
  const choices = useRemote<ControlData[]>('/controls/options', admin);
  const [controlId, setControlId] = useState('');
  const [relationship, setRelationship] = useState('PREVENTIVE');
  const [notes, setNotes] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function mutate(path: string, method: string, body?: unknown) {
    setBusy(true);
    setError('');
    try {
      await api(path, { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      setConfirm('');
      result.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo guardar el cambio');
    } finally {
      setBusy(false);
    }
  }
  if (!allowed) return <ErrorState message="Tu rol no tiene acceso a riesgos en M4." />;
  if (result.error) return <ErrorState message={result.error} retry={result.reload} />;
  if (!result.data) return <Loading />;
  const row = result.data;
  const linked = new Set(row.controls.map((link) => link.control_id));
  return (
    <>
      <Link className="back-link" to="/risks">
        ← Gestión de riesgos
      </Link>
      <GovernanceHeading title={row.risk_code} subtitle={row.title}>
        {admin ? (
          <div className="asset-actions">
            <Link className="button primary" to={`/risks/${row.id}/edit`}>
              <Edit3 size={16} />
              Editar riesgo
            </Link>
            {row.status !== 'CLOSED' && (
              <button className="button secondary" onClick={() => setConfirm('close')}>
                Cerrar riesgo
              </button>
            )}
          </div>
        ) : (
          <Badge>Solo lectura · auditor</Badge>
        )}
      </GovernanceHeading>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {confirm && (
        <div className="asset-confirm" role="alert">
          <div>
            <strong>{confirm === 'close' ? 'Cerrar riesgo' : 'Desasociar control'}</strong>
            <p>El registro y su auditoría se conservarán.</p>
          </div>
          <button className="button secondary" disabled={busy} onClick={() => setConfirm('')}>
            Cancelar
          </button>
          <button
            className="button danger"
            disabled={busy}
            onClick={() =>
              void mutate(
                confirm === 'close' ? `/risks/${id}/close` : `/risks/${id}/controls/${confirm}`,
                confirm === 'close' ? 'POST' : 'DELETE',
              )
            }
          >
            {busy ? 'Guardando…' : 'Confirmar'}
          </button>
        </div>
      )}
      <div className="asset-detail-grid">
        <section className="panel asset-information">
          <div className="panel-heading">
            <div>
              <h2>Evaluación del riesgo</h2>
              <p>Score calculado en el servidor</p>
            </div>
            <LevelBadge value={row.level} />
          </div>
          <div className={`risk-preview risk-cell-${row.level.toLowerCase()}`}>
            <strong>{row.score} / 25</strong>
            <RiskStatusBadge value={row.status} />
          </div>
          <p className="asset-description">{row.description || 'Sin descripción registrada.'}</p>
          <dl className="asset-definition">
            <div>
              <dt>Activo</dt>
              <dd>
                <Link className="text-link" to={`/assets/${row.asset_id}`}>
                  {row.asset.asset_code} · {row.asset.name}
                </Link>
              </dd>
            </div>
            {[
              ['Amenaza', row.threat.name],
              ['Vulnerabilidad', row.vulnerability.name],
              ['Probabilidad', `${row.probability} — ${probabilityLabels[row.probability - 1]}`],
              ['Impacto', `${row.impact} — ${impactLabels[row.impact - 1]}`],
              ['Tratamiento', riskLabels[row.treatment]],
              ['Responsable', row.owner.username],
              ['Identificado', dateLabel(row.identified_at)],
              ['Revisión', row.review_due_at ? dateLabel(row.review_due_at) : 'Sin fecha'],
              ['Cierre', row.closed_at ? dateLabel(row.closed_at) : 'Abierto'],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <GovernanceHistory rows={row.history} />
      </div>
      <section className="panel risk-linked-controls">
        <div className="panel-heading">
          <div>
            <h2>Controles asociados</h2>
            <p>Trazabilidad de las medidas académicas</p>
          </div>
          <Badge>{row.controls.length} asociados</Badge>
        </div>
        <div
          className="table-wrap asset-table-wrap"
          tabIndex={0}
          role="region"
          aria-label="Controles asociados"
        >
          <table>
            <thead>
              <tr>
                <th>Control</th>
                <th>Implementación</th>
                <th>Relación</th>
                <th>Notas</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {row.controls.map((link) => (
                <tr key={link.control_id}>
                  <td>
                    <Link className="asset-code" to={`/controls/${link.control_id}`}>
                      {link.control.control_code} · {link.control.name}
                    </Link>
                    {!link.control.active && <Badge>Deshabilitado</Badge>}
                  </td>
                  <td>
                    <RiskStatusBadge value={link.control.implementation_status} />
                  </td>
                  <td>{riskLabels[link.relationship_type]}</td>
                  <td>{link.notes || '—'}</td>
                  <td>
                    {admin && (
                      <button
                        className="icon-button"
                        aria-label={`Desasociar ${link.control.control_code}`}
                        disabled={busy}
                        onClick={() => setConfirm(String(link.control_id))}
                      >
                        <Unlink size={16} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {!row.controls.length && (
                <tr>
                  <td colSpan={5} className="empty-cell">
                    Sin controles asociados.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {admin && (
          <form
            className="risk-link-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (controlId)
                void mutate(`/risks/${id}/controls/${controlId}`, 'POST', {
                  relationship_type: relationship,
                  notes,
                });
            }}
          >
            <label>
              <span>Control para asociar</span>
              <select
                aria-label="Control para asociar"
                required
                value={controlId}
                onChange={(e) => setControlId(e.target.value)}
              >
                <option value="">Seleccionar control…</option>
                {(choices.data ?? [])
                  .filter((control) => !linked.has(control.id))
                  .map((control) => (
                    <option key={control.id} value={control.id}>
                      {control.control_code} · {control.name}
                    </option>
                  ))}
              </select>
            </label>
            <label>
              <span>Tipo de relación</span>
              <select
                aria-label="Tipo de relación"
                value={relationship}
                onChange={(e) => setRelationship(e.target.value)}
              >
                {['PREVENTIVE', 'DETECTIVE', 'CORRECTIVE'].map((value) => (
                  <option key={value} value={value}>
                    {riskLabels[value]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Notas de asociación</span>
              <input
                aria-label="Notas de asociación"
                value={notes}
                maxLength={1000}
                onChange={(e) => setNotes(e.target.value)}
              />
            </label>
            <button className="button primary" disabled={busy || !controlId}>
              <Plus size={15} />
              Asociar control
            </button>
            {choices.error && <p role="alert">{choices.error}</p>}
          </form>
        )}
      </section>
    </>
  );
}

export function ControlDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const allowed = !!user?.roles.some((r) => ['admin-ti', 'auditor'].includes(r));
  const admin = !!user?.roles.includes('admin-ti');
  const result = useRemote<ControlDetailData>(`/controls/${id}`, allowed);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function disable() {
    setBusy(true);
    try {
      await api(`/controls/${id}/disable`, { method: 'POST' });
      setConfirm(false);
      result.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo deshabilitar');
    } finally {
      setBusy(false);
    }
  }
  if (!allowed) return <ErrorState message="Tu rol no tiene acceso a controles en M4." />;
  if (result.error) return <ErrorState message={result.error} retry={result.reload} />;
  if (!result.data) return <Loading />;
  const row = result.data;
  return (
    <>
      <Link className="back-link" to="/controls">
        ← Controles de seguridad
      </Link>
      <GovernanceHeading title={row.control_code} subtitle={row.name}>
        {admin ? (
          <div className="asset-actions">
            <Link className="button primary" to={`/controls/${row.id}/edit`}>
              <Edit3 size={16} />
              Editar control
            </Link>
            {row.active && (
              <button className="button secondary" onClick={() => setConfirm(true)}>
                Deshabilitar control
              </button>
            )}
          </div>
        ) : (
          <Badge>Solo lectura · auditor</Badge>
        )}
      </GovernanceHeading>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {confirm && (
        <div className="asset-confirm" role="alert">
          <div>
            <strong>Deshabilitar {row.control_code}</strong>
            <p>Las relaciones históricas permanecerán visibles.</p>
          </div>
          <button className="button secondary" onClick={() => setConfirm(false)}>
            Cancelar
          </button>
          <button className="button danger" disabled={busy} onClick={() => void disable()}>
            Confirmar
          </button>
        </div>
      )}
      <div className="asset-detail-grid">
        <section className="panel asset-information">
          <div className="panel-heading">
            <div>
              <h2>Control académico</h2>
              <p>Descripción propia · Sin afirmación de certificación</p>
            </div>
            <RiskStatusBadge value={row.implementation_status} />
          </div>
          <p className="asset-description">{row.description}</p>
          <dl className="asset-definition">
            {[
              ['Categoría', riskLabels[row.category]],
              ['Responsable', row.owner.username],
              ['Vigencia', row.active ? 'Activo' : 'Deshabilitado'],
              ['Creado', dateLabel(row.created_at)],
              ['Actualizado', dateLabel(row.updated_at)],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <GovernanceHistory rows={row.history} />
      </div>
      <section className="panel matrix-selection">
        <div className="panel-heading">
          <div>
            <h2>Riesgos relacionados</h2>
            <p>{row.risk_count} relaciones vigentes</p>
          </div>
        </div>
        <RiskRows rows={row.risks} />
      </section>
    </>
  );
}
