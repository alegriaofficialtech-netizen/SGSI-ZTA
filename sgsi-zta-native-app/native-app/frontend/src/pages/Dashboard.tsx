import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Clock3,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Users,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useAuth } from '../hooks/useAuth';
import { api, dateLabel } from '../services/api';
import { Badge, ErrorState, Loading } from '../components/Status';
import { AssetCharts } from '../components/AssetCharts';
import { RiskCharts } from '../components/RiskCharts';
import type { Overview } from '../types';

export function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    api<Overview>('/dashboard')
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
  }, [refresh]);
  if (error) return <ErrorState message={error} retry={() => setRefresh(refresh + 1)} />;
  if (!data) return <Loading />;
  const metrics = [
    {
      name: data.scope === 'global' ? 'Usuarios activos' : 'Mi cuenta activa',
      value: data.active_users,
      icon: Users,
      note: 'Identidades habilitadas',
      color: 'teal',
    },
    {
      name: 'Sesiones activas',
      value: data.active_sessions,
      icon: ShieldCheck,
      note: data.scope === 'global' ? 'En el laboratorio' : 'En mi cuenta',
      color: 'blue',
    },
    {
      name: 'MFA habilitado',
      value: data.mfa_enabled_users,
      icon: KeyRound,
      note: `${data.mfa_enabled_users} de ${data.active_users} identidades activas`,
      color: 'purple',
    },
    {
      name: 'Logins en 24 horas',
      value: data.logins_24h,
      icon: Activity,
      note: 'Accesos completados',
      color: 'amber',
    },
  ];
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">PANEL DE SEGURIDAD</span>
          <h1>
            Vista general<span className="heading-dot">.</span>
          </h1>
          <p>Bienvenido, {user?.display_name}. La actividad de tu laboratorio, en un solo lugar.</p>
        </div>
        <button className="button secondary" onClick={() => setRefresh(refresh + 1)}>
          <RefreshCw size={15} />
          Actualizar
        </button>
      </div>
      {data.scope === 'own' && (
        <div className="scope-notice">Estás viendo únicamente la actividad de tu cuenta.</div>
      )}
      <div className="metric-grid">
        {metrics.map(({ name, value, icon: Icon, note, color }) => (
          <section className="metric-card" key={name}>
            <div className="metric-top">
              <span>{name}</span>
              <span className={`metric-icon ${color}`}>
                <Icon size={19} />
              </span>
            </div>
            <strong className="metric-number">{value}</strong>
            <div className="metric-note">
              <span className="tiny-dot" />
              {note}
            </div>
          </section>
        ))}
      </div>
      <div className="dashboard-grid">
        <section className="panel activity-panel">
          <div className="panel-heading">
            <div>
              <h2>Actividad de acceso</h2>
              <p>Decisiones de autenticación y autorización</p>
            </div>
            <span className="period-label">
              <Clock3 size={14} /> Últimas 24 h
            </span>
          </div>
          <div className="chart-legend">
            <span>
              <i className="legend-green" />
              Permitido
            </span>
            <span>
              <i className="legend-red" />
              Denegado
            </span>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.activity} margin={{ top: 8, right: 14, left: -25, bottom: 4 }}>
                <defs>
                  <linearGradient id="allowFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3d9c82" stopOpacity={0.22} />
                    <stop offset="100%" stopColor="#3d9c82" stopOpacity={0.01} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="4 5" vertical={false} stroke="#e9eeeb" />
                <XAxis
                  dataKey="hour"
                  tickFormatter={(hour) =>
                    new Date(hour).toLocaleTimeString('es-PE', { hour: '2-digit' })
                  }
                  axisLine={false}
                  tickLine={false}
                  minTickGap={50}
                  tick={{ fill: '#8a9691', fontSize: 11 }}
                />
                <YAxis
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#8a9691', fontSize: 11 }}
                />
                <Tooltip
                  labelFormatter={(hour) => dateLabel(String(hour))}
                  contentStyle={{ border: '1px solid #e4e9e6', borderRadius: 12, fontSize: 12 }}
                />
                <Area
                  type="monotone"
                  dataKey="allow"
                  isAnimationActive={false}
                  name="Permitido"
                  stroke="#36947d"
                  strokeWidth={2.5}
                  fill="url(#allowFill)"
                />
                <Area
                  type="monotone"
                  dataKey="deny"
                  isAnimationActive={false}
                  name="Denegado"
                  stroke="#d28766"
                  strokeWidth={2}
                  fill="transparent"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-footer">
            Datos persistidos del laboratorio <span>UTC → hora de tu navegador</span>
          </div>
        </section>
        <section className="panel progress-panel">
          <div className="panel-heading">
            <div>
              <h2>Construcción del sistema</h2>
              <p>Alcance de esta versión</p>
            </div>
            <ArrowUpRight size={19} />
          </div>
          <div className="stage-step">
            <span className="step-icon">
              <ShieldCheck size={18} />
            </span>
            <div>
              <strong>Base de la aplicación</strong>
              <p>Frontend, API y base de datos</p>
            </div>
            <Badge tone="green">M0</Badge>
          </div>
          <div className="stage-step">
            <span className="step-icon">
              <KeyRound size={18} />
            </span>
            <div>
              <strong>Identidad y acceso</strong>
              <p>Usuarios, roles y sesiones</p>
            </div>
            <Badge tone="green">M1</Badge>
          </div>
          <div className="stage-step">
            <span className="step-icon">
              <LockIcon />
            </span>
            <div>
              <strong>MFA condicional</strong>
              <p>Autenticador y recuperación</p>
            </div>
            <Badge tone="green">M2</Badge>
          </div>
          <div className="stage-note">
            <span className="eyebrow">IDENTIDAD VERIFICADA</span>
            <p>Segundo factor obligatorio para médicos y administradores.</p>
            <Link to="/settings">
              Ver estado de mi cuenta <ArrowRight size={15} />
            </Link>
          </div>
        </section>
      </div>
      {data.assets && <AssetCharts data={data.assets} />}
      {data.risk_management && <RiskCharts data={data.risk_management} />}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Actividad reciente</h2>
            <p>Registro de las últimas operaciones</p>
          </div>
          {(user?.roles.includes('admin-ti') || user?.roles.includes('auditor')) && (
            <Link className="text-link" to="/audit">
              Ver registro <ArrowRight size={15} />
            </Link>
          )}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>EVENTO</th>
                <th>USUARIO</th>
                <th>RECURSO</th>
                <th>RESULTADO</th>
                <th>FECHA Y HORA</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_activity.map((row) => (
                <tr key={row.id}>
                  <td>
                    <div className="event-label">
                      <span className={`event-dot ${row.decision === 'DENY' ? 'denied' : ''}`} />
                      {row.action.replaceAll('_', ' ')}
                    </div>
                  </td>
                  <td className="mono">{row.username}</td>
                  <td>{row.resource}</td>
                  <td>
                    <Badge tone={row.decision === 'ALLOW' ? 'green' : 'red'}>
                      {row.decision === 'ALLOW' ? 'Permitido' : 'Denegado'}
                    </Badge>
                  </td>
                  <td className="muted">{dateLabel(row.timestamp)}</td>
                </tr>
              ))}
              {data.recent_activity.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty-cell">
                    Todavía no hay eventos registrados.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
      <footer className="page-footer">
        <span>SGSI-ZTA Hospital Lab · Propuesta académica</span>
        <span>Identidad propia · Datos sintéticos</span>
      </footer>
    </>
  );
}

function LockIcon() {
  return <KeyRound size={18} />;
}
