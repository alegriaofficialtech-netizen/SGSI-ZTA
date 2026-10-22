import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useRemote } from '../hooks/useRemote';
import { ErrorState, Loading } from '../components/Status';
import { GovernanceHeading, RiskRows } from '../components/RiskUI';
import { riskLabels } from '../services/risks';
import type { MatrixData, MatrixCell, Page, RiskData } from '../types/risks';
export function RiskMatrix() {
  const { user } = useAuth();
  const allowed = !!user?.roles.some((r) => ['admin-ti', 'auditor'].includes(r));
  const [includeClosed, setIncludeClosed] = useState(false);
  const [selected, setSelected] = useState<MatrixCell | null>(null);
  const result = useRemote<MatrixData>(`/risks/matrix?include_closed=${includeClosed}`, allowed);
  const query = selected
    ? `/risks?probability=${selected.probability}&impact=${selected.impact}&exclude_closed=${!includeClosed}&page_size=100`
    : '';
  const rows = useRemote<Page<RiskData>>(query, allowed && !!selected);
  if (!allowed) return <ErrorState message="Tu rol no tiene acceso a la matriz de riesgos." />;
  if (result.error) return <ErrorState message={result.error} retry={result.reload} />;
  if (!result.data) return <Loading />;
  return (
    <>
      <GovernanceHeading
        title="Matriz de Riesgos 5×5"
        subtitle="Selecciona una celda para explorar sus escenarios. Evaluación provista por el backend."
      >
        <Link className="button secondary" to="/risks">
          Ver riesgos
        </Link>
      </GovernanceHeading>
      <section className="panel risk-matrix-panel">
        <div className="panel-heading">
          <div>
            <h2>Probabilidad × Impacto</h2>
            <p>
              {result.data.total} riesgos ·{' '}
              {includeClosed ? 'Incluye cerrados' : 'Excluye cerrados'}
            </p>
          </div>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeClosed}
              onChange={(e) => setIncludeClosed(e.target.checked)}
            />
            Incluir cerrados
          </label>
        </div>
        <div
          className="matrix-scroll"
          tabIndex={0}
          role="region"
          aria-label="Matriz 5 por 5, desplazable horizontalmente"
        >
          <div className="risk-matrix">
            <span className="matrix-corner">P / I</span>
            {[1, 2, 3, 4, 5].map((i) => (
              <strong className="matrix-axis" key={i}>
                Impacto {i}
              </strong>
            ))}
            {[5, 4, 3, 2, 1].map((p) => (
              <div className="matrix-row" key={p}>
                <strong className="matrix-axis">P {p}</strong>
                {result
                  .data!.cells.filter((cell) => cell.probability === p)
                  .map((cell) => (
                    <button
                      key={cell.impact}
                      className={`risk-cell risk-cell-${cell.level.toLowerCase()}`}
                      aria-pressed={selected?.probability === p && selected?.impact === cell.impact}
                      aria-label={`Probabilidad ${p}, impacto ${cell.impact}, score ${cell.score}, ${riskLabels[cell.level]}, ${cell.count} riesgos`}
                      title={`Probabilidad ${p} × Impacto ${cell.impact} · Score ${cell.score} · ${cell.level} · ${cell.count} riesgos`}
                      onClick={() => setSelected(cell)}
                    >
                      <strong>{cell.count}</strong>
                      <span>{riskLabels[cell.level]}</span>
                      <small>Score {cell.score}</small>
                    </button>
                  ))}
              </div>
            ))}
          </div>
        </div>
        <div className="risk-matrix-legend">
          {result.data.thresholds.map((threshold, n) => (
            <span className={`risk-cell-${threshold.level.toLowerCase()}`} key={threshold.level}>
              {riskLabels[threshold.level]} ·{' '}
              {n === 0 ? 1 : result.data!.thresholds[n - 1].maximum + 1}–{threshold.maximum}
            </span>
          ))}
        </div>
        <p className="asset-count-note">
          Cada celda representa una combinación exacta. Los niveles se derivan de score =
          probabilidad × impacto.
        </p>
      </section>
      {selected && (
        <section className="panel matrix-selection">
          <div className="panel-heading">
            <div>
              <h2>
                Probabilidad {selected.probability} · Impacto {selected.impact}
              </h2>
              <p>Escenarios de la celda seleccionada</p>
            </div>
            <Link className="text-link" to={query.replace('/risks?', '/risks?')}>
              Abrir listado filtrado
            </Link>
          </div>
          {rows.error ? (
            <ErrorState message={rows.error} />
          ) : rows.data ? (
            <RiskRows rows={rows.data.items} />
          ) : (
            <Loading />
          )}
        </section>
      )}
    </>
  );
}
