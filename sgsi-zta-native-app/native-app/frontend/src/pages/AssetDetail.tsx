import { assetLabels } from '../services/assets';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Clock3, Edit3, Monitor, Shield, UserRound } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api, dateLabel } from '../services/api';
import { Badge, ErrorState, Loading } from '../components/Status';
import { AssetBanner, AssetStatusBadge, CriticalityBadge } from '../components/AssetUI';
import type { AssetDetailData } from '../types/assets';
import { useRemote } from '../hooks/useRemote';
import { RiskRows } from '../components/RiskUI';
import type { Page, RiskData } from '../types/risks';

const actions: Record<string, string> = {
  ASSET_CREATED: 'Creó el activo',
  ASSET_UPDATED: 'Actualizó el activo',
  ASSET_DISABLED: 'Retiró el activo',
  ASSET_OWNER_CHANGED: 'Cambió el responsable',
  ASSET_CRITICALITY_CHANGED: 'Cambió la criticidad',
  ASSET_CLASSIFICATION_CHANGED: 'Cambió la clasificación',
  ASSET_STATUS_CHANGED: 'Cambió el estado',
};
function historyChange(detail: string) {
  try {
    const item = JSON.parse(detail);
    return item.before !== undefined
      ? `${assetLabels[item.before] ?? item.before} → ${assetLabels[item.after] ?? item.after}`
      : (item.fields?.join(', ') ?? '');
  } catch {
    return '';
  }
}
export function AssetDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const [data, setData] = useState<AssetDetailData | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const admin = !!user?.roles.includes('admin-ti');
  const allowed = !!user?.roles.some((role) => ['admin-ti', 'auditor'].includes(role));
  const related = useRemote<Page<RiskData>>(`/risks?asset_id=${id}&page_size=100`, allowed);
  useEffect(() => {
    if (!allowed) return;
    let active = true;
    api<AssetDetailData>(`/assets/${id}`)
      .then((result) => {
        if (active) {
          setData(result);
          setError('');
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [id, refresh, allowed]);
  async function disable() {
    setBusy(true);
    try {
      await api(`/assets/${id}/disable`, { method: 'POST' });
      setConfirm(false);
      setRefresh(refresh + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo retirar');
    } finally {
      setBusy(false);
    }
  }
  if (!allowed) return <ErrorState message="Tu rol no tiene acceso al inventario en M3." />;
  if (error) return <ErrorState message={error} retry={() => setRefresh(refresh + 1)} />;
  if (!data) return <Loading />;
  return (
    <>
      <Link className="back-link" to="/assets">
        <ArrowLeft size={16} />
        Inventario de activos
      </Link>
      <div className="page-heading asset-detail-heading">
        <div>
          <span className="eyebrow mono">{data.asset_code}</span>
          <h1>{data.name}</h1>
          <div className="asset-heading-badges">
            <CriticalityBadge value={data.criticality} />
            <Badge>{assetLabels[data.classification]}</Badge>
            <AssetStatusBadge value={data.status} />
          </div>
        </div>
        {admin ? (
          <div className="asset-actions">
            <Link className="button primary" to={`/assets/${data.id}/edit`}>
              <Edit3 size={16} />
              Editar activo
            </Link>
            {data.status !== 'RETIRED' && (
              <button className="button secondary" onClick={() => setConfirm(true)}>
                Retirar
              </button>
            )}
          </div>
        ) : (
          <Badge>Solo lectura · auditor</Badge>
        )}
      </div>
      <AssetBanner />
      {data.status === 'RETIRED' && (
        <div className="scope-notice" role="status">
          Activo retirado el {dateLabel(data.disabled_at)}. Su registro e historial permanecen
          disponibles.
        </div>
      )}
      {confirm && (
        <div className="asset-confirm" role="alert">
          <div>
            <strong>Retirar {data.asset_code}</strong>
            <p>
              Se deshabilitará el monitoreo y se conservará todo el historial. Puedes reactivarlo
              desde edición.
            </p>
          </div>
          <button className="button secondary" disabled={busy} onClick={() => setConfirm(false)}>
            Cancelar
          </button>
          <button className="button danger" disabled={busy} onClick={() => void disable()}>
            {busy ? 'Retirando…' : 'Confirmar retiro'}
          </button>
        </div>
      )}
      <div className="asset-detail-grid">
        <section className="panel asset-information">
          <div className="panel-heading">
            <div>
              <h2>Información general</h2>
              <p>Identificación y clasificación del activo</p>
            </div>
            <Monitor size={20} />
          </div>
          <p className="asset-description">{data.description || 'Sin descripción registrada.'}</p>
          <dl className="asset-definition">
            {[
              ['Tipo', data.asset_type.name],
              ['Área', data.department.name],
              ['Responsable', data.owner.username],
              ['Monitoreo', data.monitoring_enabled ? 'Habilitado' : 'Sin monitoreo'],
              ['Hostname demo', data.hostname_demo],
              ['IP demo', data.ip_address_demo],
              ['Ubicación demo', data.location_demo],
              ['Fabricante', data.manufacturer],
              ['Modelo', data.model],
              ['Serial demo', data.serial_number],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value || 'No especificado'}</dd>
              </div>
            ))}
          </dl>
          {data.notes && (
            <div className="asset-notes">
              <h3>Notas</h3>
              <p>{data.notes}</p>
            </div>
          )}
          <div className="asset-record-meta">
            <Clock3 size={14} />
            <span>
              Creado {dateLabel(data.created_at)} · Actualizado {dateLabel(data.updated_at)}
            </span>
          </div>
        </section>
        <section className="panel asset-history">
          <div className="panel-heading">
            <div>
              <h2>Historial reciente</h2>
              <p>Últimos 30 eventos de este activo</p>
            </div>
            <UserRound size={19} />
          </div>
          <ol>
            {data.history.map((entry) => (
              <li key={entry.id}>
                <span className="history-point" />
                <div>
                  <strong>{actions[entry.action] ?? entry.action}</strong>
                  <p>{historyChange(entry.detail)}</p>
                  <small>
                    <span className="mono">{entry.username}</span> · {dateLabel(entry.timestamp)}
                  </small>
                </div>
              </li>
            ))}
          </ol>
          {!data.history.length && (
            <div className="history-empty">
              Registro inicial importado del dataset sintético. Los cambios operativos aparecerán
              aquí.
            </div>
          )}
        </section>
      </div>
      <div className="asset-future-grid">
        {[['Eventos', 'M6', Clock3]].map(([name, milestone, Icon]) => {
          const Symbol = Icon as typeof Shield;
          return (
            <section className="panel asset-future" key={String(name)}>
              <Symbol size={20} />
              <div>
                <h2>{String(name)}</h2>
                <p>Próxima fase {String(milestone)} · NOT_IMPLEMENTED</p>
              </div>
              <ArrowRight size={16} />
            </section>
          );
        })}
      </div>
      <section className="panel matrix-selection">
        <div className="panel-heading">
          <div>
            <h2>Riesgos relacionados</h2>
            <p>Escenarios vinculados a este activo</p>
          </div>
          <Link className="text-link" to={`/risks?asset_id=${id}`}>
            Ver todos →
          </Link>
        </div>
        {related.error ? (
          <ErrorState message={related.error} retry={related.reload} />
        ) : related.data ? (
          <RiskRows rows={related.data.items} />
        ) : (
          <Loading />
        )}
      </section>
    </>
  );
}
