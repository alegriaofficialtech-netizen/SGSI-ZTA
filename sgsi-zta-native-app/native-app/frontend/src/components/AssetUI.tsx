import { Boxes, Eye, Flame, Radar, ShieldAlert } from 'lucide-react';
import { Badge } from './Status';
import { assetLabels } from '../services/assets';
import type { AssetStatus, AssetSummary, Criticality } from '../types/assets';

export function CriticalityBadge({ value }: { value: Criticality }) {
  const tone = { LOW: 'green', MEDIUM: 'amber', HIGH: 'orange', CRITICAL: 'red' } as const;
  return <Badge tone={tone[value]}>{assetLabels[value]}</Badge>;
}
export function AssetStatusBadge({ value }: { value: AssetStatus }) {
  return (
    <Badge tone={value === 'ACTIVE' ? 'green' : value === 'MAINTENANCE' ? 'amber' : 'neutral'}>
      {assetLabels[value]}
    </Badge>
  );
}
export function AssetBanner() {
  return (
    <div className="asset-lab-note">
      <ShieldAlert size={15} />
      <span>LABORATORIO ACADÉMICO · ACTIVOS COMPLETAMENTE SINTÉTICOS</span>
    </div>
  );
}
export function AssetMetrics({ data }: { data: AssetSummary }) {
  const metrics = [
    {
      name: 'Total activos',
      value: data.total,
      icon: Boxes,
      color: 'teal',
      note: 'Incluye activos retirados',
    },
    {
      name: 'Activos críticos',
      value: data.critical,
      icon: ShieldAlert,
      color: 'red',
      note: 'Clasificados como CRITICAL',
    },
    {
      name: 'Criticidad alta',
      value: data.high,
      icon: Flame,
      color: 'amber',
      note: 'Clasificados como HIGH',
    },
    {
      name: 'Monitoreados',
      value: data.monitored,
      icon: Radar,
      color: 'blue',
      note: 'Marcados para monitoreo',
    },
  ];
  return (
    <div className="metric-grid asset-metrics">
      {metrics.map(({ name, value, icon: Icon, color, note }) => (
        <section className="metric-card" key={name}>
          <div className="metric-top">
            <span>{name}</span>
            <span className={`metric-icon ${color}`}>
              <Icon size={19} />
            </span>
          </div>
          <strong className="metric-number">{value}</strong>
          <div className="metric-note">
            <Eye size={12} />
            {note}
          </div>
        </section>
      ))}
    </div>
  );
}
