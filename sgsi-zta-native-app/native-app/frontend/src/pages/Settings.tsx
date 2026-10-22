import { useEffect, useState } from 'react';
import { Monitor, ShieldCheck } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api, dateLabel } from '../services/api';
import { Badge } from '../components/Status';
import type { SessionInfo } from '../types';
import { RecoverySettings } from '../components/RecoverySettings';

export function Settings() {
  const { user, logout } = useAuth();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    api<SessionInfo[]>('/auth/sessions')
      .then((rows) => {
        if (active) {
          setSessions(rows);
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
  async function revoke(id: string) {
    try {
      await api(`/auth/sessions/${id}`, { method: 'DELETE' });
      setRefresh(refresh + 1);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'No se pudo revocar la sesión');
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">MI ESPACIO</span>
          <h1>
            Configuración<span className="heading-dot">.</span>
          </h1>
          <p>Consulta tu identidad y controla tus sesiones.</p>
        </div>
      </div>
      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Mi cuenta</h2>
            <Badge tone="green">Activa</Badge>
          </div>
          <dl className="account-details">
            <dt>Nombre demo</dt>
            <dd>{user?.display_name}</dd>
            <dt>Usuario</dt>
            <dd className="mono">{user?.username}</dd>
            <dt>Área</dt>
            <dd>{user?.department}</dd>
            <dt>Roles</dt>
            <dd>{user?.roles.join(', ')}</dd>
            <dt>Autenticación</dt>
            <dd>{user?.mfa_enabled ? 'Contraseña y segundo factor' : 'Contraseña'}</dd>
            <dt>Segundo factor</dt>
            <dd>
              <Badge tone={user?.mfa_enabled ? 'green' : 'amber'}>
                {user?.mfa_enabled ? 'Autenticador activado' : 'Opcional · sin configurar'}
              </Badge>
            </dd>
          </dl>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Sesiones activas</h2>
            <ShieldCheck size={20} />
          </div>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          {sessions.map((session) => (
            <div className="session-row" key={session.id}>
              <Monitor size={23} />
              <div>
                <strong>{session.current ? 'Este navegador' : 'Otra sesión'}</strong>
                <p>Inicio: {dateLabel(session.created_at)}</p>
                <small>Expira: {dateLabel(session.expires_at)}</small>
              </div>
              <button
                className="button secondary small"
                onClick={() => {
                  if (session.current) {
                    void logout().catch((e) => setError(e.message));
                  } else {
                    void revoke(session.id);
                  }
                }}
              >
                {session.current ? 'Salir' : 'Revocar'}
              </button>
            </div>
          ))}
        </section>
      </div>
      {user?.mfa_enabled && <RecoverySettings />}
      <div className="scope-notice">
        Este laboratorio utiliza datos sintéticos. No representa protección operativa del hospital.
      </div>
    </>
  );
}
