import { useState, type FormEvent } from 'react';
import { ArrowRight, Check, Eye, EyeOff, LockKeyhole, ShieldCheck } from 'lucide-react';
import { Navigate } from 'react-router-dom';
import { Brand } from '../components/Brand';
import { useAuth } from '../hooks/useAuth';

export function Login() {
  const { user, challenge, login, connectionError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (user) return <Navigate to="/dashboard" replace />;
  if (challenge) return <Navigate to={challenge.setup_required ? '/mfa/setup' : '/mfa'} replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(username, password, remember);
      setPassword('');
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'No se pudo iniciar sesión');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-layout">
      <section className="login-story">
        <Brand light />
        <div className="story-content">
          <span className="eyebrow light">
            <span className="live-dot" /> LABORATORIO ACADÉMICO · PIURA 2026
          </span>
          <h1>
            La seguridad empieza
            <br />
            con una identidad
            <br />
            <em>verificada.</em>
          </h1>
          <p>
            Un espacio para explorar la gestión de seguridad de la información y los principios de
            Zero Trust.
          </p>
          <div className="trust-graphic" aria-hidden="true">
            <div className="trust-orbit orbit-outer" />
            <div className="trust-orbit orbit-inner" />
            <div className="trust-core">
              <ShieldCheck size={54} strokeWidth={1.2} />
            </div>
            <span className="trust-node node-one">
              <Check size={15} /> Identidad
            </span>
            <span className="trust-node node-two">
              <LockKeyhole size={15} /> Sesión
            </span>
            <span className="trust-node node-three">
              <Check size={15} /> Autorización
            </span>
          </div>
        </div>
        <footer className="story-footer">
          PROPUESTA ACADÉMICA <span>DATOS 100% SINTÉTICOS</span>
        </footer>
      </section>
      <section className="login-form-side">
        <div className="login-top">
          <span className="badge badge-green">Native App · M0–M2</span>
        </div>
        <div className="login-card">
          <div className="login-lock">
            <LockKeyhole size={24} />
          </div>
          <span className="eyebrow">BIENVENIDO AL LABORATORIO</span>
          <h2>Inicia sesión</h2>
          <p className="muted">Accede con tu cuenta sintética asignada.</p>
          <form onSubmit={submit}>
            <label htmlFor="username">Usuario</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Ej. admin.demo"
              autoComplete="username"
              required
              maxLength={80}
            />
            <label htmlFor="password">Contraseña</label>
            <div className="password-field">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                maxLength={128}
              />
              <button
                type="button"
                aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
              />{' '}
              Recordarme en este equipo
            </label>
            {(error || connectionError) && (
              <p className="form-error" role="alert">
                {error || connectionError}
              </p>
            )}
            <button className="button primary login-submit" disabled={busy}>
              {busy ? 'Verificando…' : 'Entrar al laboratorio'}
              <ArrowRight size={18} />
            </button>
          </form>
          <div className="login-notice">
            <ShieldCheck size={18} />
            <p>
              Entorno de demostración. No contiene información de pacientes reales ni se conecta al
              hospital.
            </p>
          </div>
          <p className="mfa-notice">
            Las cuentas de médico y administrador requieren verificación en dos pasos.
          </p>
        </div>
        <footer className="login-footer">
          SGSI-ZTA Hospital Lab <span>Solo uso académico · No producción</span>
        </footer>
      </section>
    </main>
  );
}
