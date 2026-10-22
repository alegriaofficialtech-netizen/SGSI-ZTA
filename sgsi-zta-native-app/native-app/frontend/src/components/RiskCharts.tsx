import { Link } from 'react-router-dom';
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { riskLabels } from '../services/risks';
import type { Count, RiskSummary } from '../types/risks';
export function RiskCharts({ data }: { data: RiskSummary }) {
  return (
    <section className="asset-dashboard">
      <div className="asset-dashboard-heading">
        <div>
          <span className="eyebrow">RIESGOS Y CONTROLES</span>
          <h2>Gestión del SGSI</h2>
          <p>Registros académicos actuales · Incluye cerrados y deshabilitados</p>
        </div>
        <Link className="text-link" to="/risks/matrix">
          Explorar matriz →
        </Link>
      </div>
      <div className="metric-grid governance-metrics">
        {[
          ['Riesgos', data.total, '/risks'],
          ['Riesgos abiertos', data.open, '/risks?status=OPEN'],
          ['Riesgos críticos', data.critical, '/risks?level=CRITICAL'],
          ['Controles', data.controls_total, '/controls'],
          [
            'Controles implementados',
            data.implemented,
            '/controls?implementation_status=IMPLEMENTED',
          ],
        ].map(([label, value, to]) => (
          <section className="metric-card" key={label}>
            <Link className="text-link" to={String(to)}>
              {label}
            </Link>
            <strong className="metric-number">{value}</strong>
            <div className="metric-note">Datos de PostgreSQL</div>
          </section>
        ))}
      </div>
      <div className="asset-chart-grid">
        {[
          ['Riesgos por nivel', data.by_level],
          ['Riesgos por tratamiento', data.by_treatment],
          ['Controles por estado', data.controls_by_status],
        ].map(([title, rows]) => (
          <section className="panel" key={String(title)}>
            <div className="panel-heading">
              <h2>{String(title)}</h2>
            </div>
            <div className="asset-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={(rows as Count[]).map((row) => ({
                    ...row,
                    name: riskLabels[row.name] ?? row.name,
                  }))}
                  layout="vertical"
                  margin={{ left: 0, right: 20 }}
                >
                  <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={102}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11 }}
                  />
                  <Tooltip />
                  <Bar
                    dataKey="value"
                    name="Registros"
                    fill="#478a76"
                    barSize={16}
                    radius={[0, 4, 4, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="risk-chart-accessible" aria-label={String(title)}>
              {(rows as Count[]).map((row) => (
                <span key={row.name}>
                  {riskLabels[row.name] ?? row.name}: {row.value}
                </span>
              ))}
            </div>
          </section>
        ))}
      </div>
      <p className="asset-count-note">Alertas: próxima fase M6 · NOT_IMPLEMENTED</p>
    </section>
  );
}
