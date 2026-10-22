import { assetLabels } from '../services/assets';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AssetMetrics } from './AssetUI';
import { Badge } from './Status';
import type { AssetSummary } from '../types/assets';

export function AssetCharts({ data }: { data: AssetSummary }) {
  return (
    <section className="asset-dashboard">
      <div className="asset-dashboard-heading">
        <div>
          <span className="eyebrow">INVENTARIO DE INFORMACIÓN</span>
          <h2>Activos del laboratorio</h2>
          <p>Datos actuales de PostgreSQL · Incluye activos retirados</p>
        </div>
        <Link className="text-link" to="/assets">
          Ver inventario
          <ArrowRight size={16} />
        </Link>
      </div>
      <AssetMetrics data={data} />
      <div className="asset-state-strip">
        <strong>Por estado</strong>
        {data.by_status.map((item) => (
          <Badge key={item.name}>
            {assetLabels[item.name]} · {item.value}
          </Badge>
        ))}
      </div>
      <div className="asset-chart-grid">
        {[
          ['Por criticidad', data.by_criticality],
          ['Por tipo', data.by_type],
          ['Por área', data.by_department],
        ].map(([title, rows]) => (
          <section className="panel" key={String(title)}>
            <div className="panel-heading">
              <h2>Activos {String(title).toLowerCase()}</h2>
            </div>
            <div className="asset-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  layout="vertical"
                  data={(rows as { name: string; value: number }[]).map((item) => ({
                    ...item,
                    name: assetLabels[item.name] ?? item.name,
                  }))}
                  margin={{ top: 5, right: 25, left: 0, bottom: 5 }}
                >
                  <XAxis
                    type="number"
                    allowDecimals={false}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11 }}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={102}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fontSize: 11, fill: '#536b60' }}
                  />
                  <Tooltip
                    cursor={{ fill: '#f2f6f3' }}
                    contentStyle={{ borderRadius: 10, fontSize: 12 }}
                  />
                  <Bar
                    dataKey="value"
                    name="Activos"
                    radius={[0, 4, 4, 0]}
                    isAnimationActive={false}
                    barSize={15}
                  >
                    {(rows as { name: string }[]).map((item) => (
                      <Cell
                        key={item.name}
                        fill={
                          {
                            CRITICAL: '#c25b5b',
                            HIGH: '#d08744',
                            MEDIUM: '#d0ad59',
                            LOW: '#519b82',
                          }[item.name] ?? '#478a76'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>
        ))}
      </div>
    </section>
  );
}
