import { useEffect, useState, type FormEvent } from 'react';
import { Check, MoreHorizontal, Plus, Search, Users as UsersIcon, X } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { api, dateLabel } from '../services/api';
import { Badge, ErrorState, Loading } from '../components/Status';
import type { User } from '../types';

interface RoleInfo {
  name: string;
  description: string;
  mfa_required: boolean;
}

export function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [roles, setRoles] = useState<RoleInfo[]>([]);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [editing, setEditing] = useState<User | 'new' | null>(null);
  const [toast, setToast] = useState('');
  const [refresh, setRefresh] = useState(0);
  const isAdmin = currentUser?.roles.includes('admin-ti');
  useEffect(() => {
    if (!isAdmin) return;
    let active = true;
    Promise.all([api<User[]>('/users'), api<RoleInfo[]>('/users/roles')])
      .then(([result, roleList]) => {
        if (active) {
          setUsers(result);
          setRoles(roleList);
          setError('');
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [refresh, isAdmin]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(''), 4500);
    return () => clearTimeout(timer);
  }, [toast]);
  if (!isAdmin)
    return (
      <ErrorState message="La gestión de usuarios está disponible para el rol admin-ti. Puedes consultar tu cuenta en Configuración." />
    );
  if (error) return <ErrorState message={error} retry={() => setRefresh(refresh + 1)} />;
  if (!users) return <Loading />;
  const filtered = users.filter(
    (row) =>
      `${row.username} ${row.display_name} ${row.department} ${row.roles.join(' ')}`
        .toLowerCase()
        .includes(search.toLowerCase()) &&
      (status === 'all' || row.is_active === (status === 'active')),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">IDENTIDAD Y ACCESO</span>
          <h1>
            Usuarios<span className="heading-dot">.</span>
          </h1>
          <p>Administra las identidades sintéticas y sus permisos.</p>
        </div>
        <button className="button primary" onClick={() => setEditing('new')}>
          <Plus size={17} />
          Nuevo usuario
        </button>
      </div>
      <div className="info-strip">
        <UsersIcon size={19} />
        <span>
          <strong>{users.length} identidades registradas</strong> ·{' '}
          {users.filter((row) => row.is_active).length} activas
        </span>
        <Badge tone="green">
          {users.filter((row) => row.mfa_enabled).length} con MFA habilitado
        </Badge>
      </div>
      <section className="panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Buscar usuarios"
              placeholder="Buscar por usuario, área o rol…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            aria-label="Filtrar por estado"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="all">Todos los estados</option>
            <option value="active">Activos</option>
            <option value="disabled">Desactivados</option>
          </select>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>USUARIO</th>
                <th>ÁREA</th>
                <th>ROL</th>
                <th>MFA</th>
                <th>ESTADO</th>
                <th>ÚLTIMO ACCESO</th>
                <th>
                  <span className="sr-only">Acciones</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.id}>
                  <td>
                    <div className="user-cell">
                      <span className="user-avatar">{row.display_name.slice(0, 1)}</span>
                      <span>
                        <strong>{row.display_name}</strong>
                        <small className="mono">{row.username}</small>
                      </span>
                    </div>
                  </td>
                  <td>{row.department}</td>
                  <td>
                    {row.roles.map((role) => (
                      <Badge key={role}>{role}</Badge>
                    ))}
                  </td>
                  <td>
                    <span className={row.mfa_required ? 'mfa-pending' : 'muted'}>
                      {row.mfa_enabled
                        ? 'Habilitado'
                        : row.mfa_required
                          ? 'Requerido · por configurar'
                          : 'Opcional'}
                    </span>
                  </td>
                  <td>
                    <Badge tone={row.is_active ? 'green' : 'neutral'}>
                      {row.is_active ? 'Activo' : 'Desactivado'}
                    </Badge>
                  </td>
                  <td className="muted">{dateLabel(row.last_login)}</td>
                  <td>
                    <button
                      className="icon-button"
                      aria-label={`Editar ${row.username}`}
                      onClick={() => setEditing(row)}
                    >
                      <MoreHorizontal size={20} />
                    </button>
                  </td>
                </tr>
              ))}
              {!filtered.length && (
                <tr>
                  <td className="empty-cell" colSpan={7}>
                    No se encontraron usuarios.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="table-footer">
          {filtered.length} de {users.length} usuarios{' '}
          <span>Las cuentas se desactivan conservando su historial.</span>
        </div>
      </section>
      {editing && (
        <UserModal
          user={editing}
          roles={roles}
          ownId={currentUser?.id}
          close={() => setEditing(null)}
          saved={() => {
            setEditing(null);
            setRefresh(refresh + 1);
            setToast('Usuario guardado. Los cambios quedaron registrados.');
          }}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={17} />
          {toast}
        </div>
      )}
    </>
  );
}

function UserModal({
  user,
  roles,
  ownId,
  close,
  saved,
}: {
  user: User | 'new';
  roles: RoleInfo[];
  ownId?: number;
  close: () => void;
  saved: () => void;
}) {
  const existing = user === 'new' ? null : user;
  const [username, setUsername] = useState(existing?.username ?? '');
  const [name, setName] = useState(existing?.display_name ?? '');
  const [department, setDepartment] = useState(existing?.department ?? '');
  const [password, setPassword] = useState('');
  const [selectedRoles, setSelectedRoles] = useState(existing?.roles ?? ['admision']);
  const [active, setActive] = useState(existing?.is_active ?? true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [close, busy]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = existing
        ? { display_name: name, department, roles: selectedRoles, is_active: active }
        : { username, display_name: name, department, password, roles: selectedRoles };
      await api(existing ? `/users/${existing.id}` : '/users', {
        method: existing ? 'PATCH' : 'POST',
        body: JSON.stringify(body),
      });
      setPassword('');
      saved();
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'No se pudo guardar');
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="user-modal-title">
        <div className="modal-heading">
          <div>
            <span className="eyebrow">CUENTA SINTÉTICA</span>
            <h2 id="user-modal-title">{existing ? 'Editar usuario' : 'Nuevo usuario'}</h2>
          </div>
          <button
            className="icon-button"
            aria-label="Cerrar formulario"
            onClick={close}
            disabled={busy}
          >
            <X size={20} />
          </button>
        </div>
        <form onSubmit={submit}>
          <label htmlFor="new-username">Usuario</label>
          <input
            id="new-username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={!!existing}
            pattern="[a-z0-9][a-z0-9._-]{2,79}"
            placeholder="usuario.demo"
            autoFocus
          />
          <label htmlFor="new-name">Nombre de demostración</label>
          <input
            id="new-name"
            required
            minLength={2}
            maxLength={120}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <label htmlFor="new-department">Área</label>
          <input
            id="new-department"
            required
            minLength={2}
            maxLength={80}
            value={department}
            onChange={(e) => setDepartment(e.target.value)}
          />
          {!existing && (
            <>
              <label htmlFor="new-password">Contraseña inicial</label>
              <input
                id="new-password"
                type="password"
                required
                minLength={14}
                maxLength={128}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
              <small className="field-help">
                Mínimo 14 caracteres: mayúscula, minúscula, número y símbolo.
              </small>
            </>
          )}
          <label>Roles asignados</label>
          <div className="role-options">
            {roles.map((role) => (
              <label className="checkbox-label" key={role.name}>
                <input
                  type="checkbox"
                  checked={selectedRoles.includes(role.name)}
                  disabled={existing?.id === ownId && role.name === 'admin-ti'}
                  onChange={(e) =>
                    setSelectedRoles(
                      e.target.checked
                        ? [...selectedRoles, role.name]
                        : selectedRoles.filter((name) => name !== role.name),
                    )
                  }
                />
                {role.name}
              </label>
            ))}
          </div>
          {existing && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={active}
                onChange={(e) => setActive(e.target.checked)}
                disabled={existing.id === ownId}
              />
              Cuenta activa
            </label>
          )}
          {existing && (
            <p className="field-help">Cambiar roles o desactivar la cuenta revoca sus sesiones.</p>
          )}
          {error && (
            <p role="alert" className="form-error">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <button className="button secondary" type="button" onClick={close} disabled={busy}>
              Cancelar
            </button>
            <button className="button primary" disabled={busy || !selectedRoles.length}>
              {busy ? 'Guardando…' : 'Guardar usuario'}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
