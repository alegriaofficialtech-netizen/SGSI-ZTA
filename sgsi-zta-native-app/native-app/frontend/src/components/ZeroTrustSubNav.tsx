import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Shield, PlayCircle, History } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export const ZeroTrustSubNav: React.FC = () => {
  const { user } = useAuth();
  const isAuditorOrAdmin = user?.roles.some((r) => r === 'admin-ti' || r === 'auditor');

  const links = [
    { to: '/zero-trust', label: 'Overview', icon: LayoutDashboard, end: true },
    { to: '/zero-trust/policies', label: 'Políticas', icon: Shield, end: false },
    ...(isAuditorOrAdmin
      ? [{ to: '/zero-trust/simulator', label: 'Simulador', icon: PlayCircle, end: false }]
      : []),
    { to: '/zero-trust/decisions', label: 'Decisiones', icon: History, end: false },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3 mb-6">
      {links.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            `inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
              isActive
                ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
            }`
          }
        >
          <Icon size={16} />
          <span>{label}</span>
        </NavLink>
      ))}
    </div>
  );
};
