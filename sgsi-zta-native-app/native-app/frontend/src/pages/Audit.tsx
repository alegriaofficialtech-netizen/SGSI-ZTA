import { useEffect, useState } from 'react';
import { FileCheck2, Search } from 'lucide-react';
import { api, dateLabel } from '../services/api';
import { Badge, ErrorState, Loading } from '../components/Status';
import type { AuditEntry } from '../types';

export function Audit() {
  const [data, setData] = useState<AuditEntry[] | null>(null);
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    api<AuditEntry[]>('/audit')
      .then((rows) => {
        if (active) {
          setData(rows);
          setError('');
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [refresh]);
  if (error) return <ErrorState message={error} retry={() => setRefresh(refresh + 1)} />;
  if (!data) return <Loading />;
  const rows = data.filter((row) =>
    `${row.action} ${row.username} ${row.resource} ${row.decision}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">TRAZABILIDAD DE ACCESO</span>
          <h1>
            Auditoría<span className="heading-dot">.</span>
          </h1>
          <p>Autenticación, autorización y cambios de identidad. Registros de solo lectura.</p>
        </div>
        <Badge tone="green">Auditoría M1</Badge>
      </div>
      <div className="info-strip">
        <FileCheck2 size={18} />
        <span>Últimos 100 registros. La retención y evidencias completas pertenecen a M7.</span>
      </div>
      <section className="panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Buscar registros"
              placeholder="Buscar evento, usuario o recurso…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button className="button secondary" onClick={() => setRefresh(refresh + 1)}>
            Actualizar
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID / FECHA</th>
                <th>USUARIO</th>
                <th>ACCIÓN</th>
                <th>RECURSO</th>
                <th>RESULTADO</th>
                <th>ORIGEN</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <small className="mono">EVT-{String(row.id).padStart(5, '0')}</small>
                    <div className="muted">{dateLabel(row.timestamp)}</div>
                  </td>
                  <td className="mono">{row.username}</td>
                  <td>{row.action.replaceAll('_', ' ')}</td>
                  <td>{row.resource}</td>
                  <td>
                    <Badge tone={row.decision === 'ALLOW' ? 'green' : 'red'}>{row.decision}</Badge>
                  </td>
                  <td className="mono muted">{row.ip}</td>
                </tr>
              ))}
              {!rows.length && (
                <tr>
                  <td className="empty-cell" colSpan={6}>
                    No hay registros para esta búsqueda.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
