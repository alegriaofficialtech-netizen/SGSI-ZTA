import { NavLink } from 'react-router-dom';
import { Activity, Bell, FileCheck2, Files, LayoutDashboard, Server } from 'lucide-react';

export function MonitoringSubNav() {
  const tabs = [
    { to: '/monitoring', label: 'Dashboard', icon: LayoutDashboard, end: true },
    { to: '/monitoring/events', label: 'Eventos', icon: Files },
    { to: '/monitoring/alerts', label: 'Alertas', icon: Bell },
    { to: '/monitoring/rules', label: 'Reglas', icon: Activity },
    { to: '/monitoring/sources', label: 'Fuentes', icon: Server },
    { to: '/monitoring/fim', label: 'FIM', icon: FileCheck2 },
  ];

  return (
    <nav
      className="flex items-center gap-1 border-b border-slate-800 pb-3 mb-6 overflow-x-auto"
      aria-label="Navegación de Monitoreo"
    >
      {tabs.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            `inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium transition ${
              isActive
                ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`
          }
        >
          <Icon size={16} aria-hidden="true" />
          <span>{label}</span>
        </NavLink>
      ))}
    </nav>
  );
}
