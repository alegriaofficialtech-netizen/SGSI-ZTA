import { ShieldPlus } from 'lucide-react';

export function Brand({ light = false }: { light?: boolean }) {
  return (
    <div className={`brand ${light ? 'brand-light' : ''}`}>
      <span className="brand-mark">
        <ShieldPlus size={25} strokeWidth={1.8} />
      </span>
      <span>
        <strong>
          SGSI<span className="brand-dash">—</span>ZTA
        </strong>
        <small>HOSPITAL LAB</small>
      </span>
    </div>
  );
}
