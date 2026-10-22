import { useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  Activity,
  Bell,
  Boxes,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  FileCheck2,
  Files,
  HeartPulse,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { Brand } from '../components/Brand';
import { useAuth } from '../hooks/useAuth';

export function AppLayout() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const location = useLocation();

  const isPrivileged = user?.roles.some((r) => r === 'admin-ti' || r === 'auditor');

  const links = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/users', label: 'Usuarios', icon: Users },
    { to: '/assets', label: 'Activos', icon: Boxes },
    { to: '/risks', label: 'Riesgos', icon: Activity },
    { to: '/controls', label: 'Controles', icon: ClipboardCheck },
    ...(isPrivileged
      ? [
          {
            to: '/zero-trust',
            label: 'Zero Trust',
            icon: Shield,
            sublinks: [
              { to: '/zero-trust', label: 'Overview', end: true },
              { to: '/zero-trust/policies', label: 'Políticas' },
              { to: '/zero-trust/simulator', label: 'Simulador' },
              { to: '/zero-trust/decisions', label: 'Decisiones' },
            ],
          },
          {
            to: '/monitoring',
            label: 'Monitoreo',
            icon: Bell,
            sublinks: [
              { to: '/monitoring', label: 'Dashboard', end: true },
              { to: '/monitoring/events', label: 'Eventos' },
              { to: '/monitoring/alerts', label: 'Alertas' },
              { to: '/monitoring/rules', label: 'Reglas' },
              { to: '/monitoring/sources', label: 'Fuentes' },
              { to: '/monitoring/fim', label: 'FIM' },
            ],
          },
        ]
      : []),
    { to: '/clinical', label: 'Clinical Demo', icon: HeartPulse },
    { to: '/audit', label: 'Auditoría', icon: FileCheck2 },
    { to: '/evidence', label: 'Evidencias', icon: Files, later: true },
  ];

  const title =
    links.find((link) => location.pathname.startsWith(link.to))?.label ?? 'Configuración';

  async function signOut() {
    try {
      await logout();
    } catch {
      setError('No se pudo cerrar la sesión. Intenta nuevamente.');
    }
  }

  return (
    <div className="app-layout">
      {open && (
        <button
          className="sidebar-backdrop"
          aria-label="Cerrar menú"
          onClick={() => setOpen(false)}
        />
      )}
      <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}>
        <div className="sidebar-brand">
          <Brand light />
          <button className="mobile-close" aria-label="Cerrar menú" onClick={() => setOpen(false)}>
            <X size={20} />
          </button>
        </div>
        <div className="workspace-label">
          <span className="workspace-avatar">HL</span>
          <span>
            <strong>Hospital Lab</strong>
            <small>Workspace académico</small>
          </span>
          <ChevronRight size={15} />
        </div>
        <div className="nav-label">ESPACIO DE TRABAJO</div>
        <nav aria-label="Navegación principal">
          {links.map(({ to, label, icon: Icon, later, sublinks }) => (
            <div key={to} className="space-y-0.5">
              <NavLink
                to={to}
                onClick={() => setOpen(false)}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon size={19} strokeWidth={1.7} />
                <span>{label}</span>
                {later && (
                  <span className="nav-pending" title="Pendiente en una etapa futura">
                    ·
                  </span>
                )}
              </NavLink>

              {/* Sublinks dropdown if section route is active */}
              {sublinks && location.pathname.startsWith(to) && (
                <div className="pl-8 pr-2 py-1 space-y-0.5 border-l border-slate-800 ml-4">
                  {sublinks.map((sub) => (
                    <NavLink
                      key={sub.to}
                      to={sub.to}
                      end={sub.end}
                      onClick={() => setOpen(false)}
                      className={({ isActive }) =>
                        `block text-xs py-1 px-2 rounded font-medium transition ${
                          isActive
                            ? 'text-blue-400 font-bold bg-blue-950/40'
                            : 'text-slate-400 hover:text-slate-200'
                        }`
                      }
                    >
                      {sub.label}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <NavLink className="nav-link" to="/settings">
            <Settings size={19} />
            <span>Configuración</span>
          </NavLink>
          <div className="academic-mini">
            <CircleHelp size={17} />
            <span>
              Solo datos sintéticos<small>Entorno de demostración</small>
            </span>
          </div>
          <div className="sidebar-profile">
            <span className="profile-avatar">{user?.display_name.slice(0, 1)}</span>
            <span>
              <strong>{user?.display_name}</strong>
              <small>{user?.roles.join(', ')}</small>
            </span>
            <button title="Cerrar sesión" aria-label="Cerrar sesión" onClick={() => void signOut()}>
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="workspace-main">
        <header className="topbar">
          <div className="breadcrumb">
            <button className="menu-button" aria-label="Abrir menú" onClick={() => setOpen(true)}>
              <Menu size={22} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <span className="environment-pill">
              <span className="live-dot" /> ACADEMIC
            </span>
            <span className="topbar-avatar">{user?.display_name.slice(0, 1)}</span>
          </div>
        </header>
        <div className="academic-banner">
          <Shield size={14} />
          <span>Laboratorio académico · Todos los datos son sintéticos · No producción</span>
          <span className="stage-label">M0–M6</span>
        </div>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
