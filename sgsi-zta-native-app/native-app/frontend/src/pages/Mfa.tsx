import { useEffect, useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowRight, ShieldCheck, KeyRound } from 'lucide-react';
import { Brand } from '../components/Brand';
import { useAuth } from '../hooks/useAuth';
import { api } from '../services/api';

export function Mfa() {
  const { user, challenge, completeMfa, cancelMfa } = useAuth();
  const navigate = useNavigate();
  const [qr, setQr] = useState('');
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [codes, setCodes] = useState<string[]>([]);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const setup = !!challenge?.setup_required;
  useEffect(() => {
    let active = true;
    if (challenge?.setup_required) {
      api<{ qr_data_url: string }>('/auth/mfa/setup', {
        method: 'POST',
        body: JSON.stringify({ challenge_token: challenge.challenge_token }),
      })
        .then((result) => {
          if (active) setQr(result.qr_data_url);
        })
        .catch((problem) => {
          if (active) setError(problem.message);
        });
    }
    return () => {
      active = false;
    };
  }, [challenge]);

  if (user && !codes.length) return <Navigate to="/dashboard" replace />;
  if (!challenge && !codes.length) return <Navigate to="/login" replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const generated = await completeMfa(code, recovery);
      setQr('');
      setCode('');
      if (generated.length) setCodes(generated);
      else navigate('/dashboard', { replace: true });
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'No se pudo verificar el código');
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="mfa-layout">
      <div className="mfa-brand">
        <Brand light />
        <span>DATOS SINTÉTICOS · LABORATORIO ACADÉMICO</span>
      </div>
      <section className="mfa-card">
        <div className="login-lock">
          <ShieldCheck size={26} />
        </div>
        <span className="eyebrow">PROTEGE TU IDENTIDAD</span>
        <h1>
          {codes.length
            ? 'Guarda tus códigos de recuperación'
            : setup
              ? 'Configurar autenticación multifactor'
              : 'Verificación en dos pasos'}
        </h1>
        {codes.length ? (
          <>
            <p className="muted">
              Tu autenticador está activado. Cada código permite un único acceso si pierdes tu
              dispositivo. Estos códigos se muestran una sola vez.
            </p>
            <div className="recovery-codes">
              {codes.map((item) => (
                <code key={item}>{item}</code>
              ))}
            </div>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              He guardado mis códigos en un lugar seguro
            </label>
            <button
              className="button primary login-submit"
              disabled={!acknowledged}
              onClick={() => {
                setCodes([]);
                navigate('/dashboard', { replace: true });
              }}
            >
              Continuar al panel <ArrowRight size={18} />
            </button>
          </>
        ) : (
          <>
            {setup ? (
              <>
                <p className="muted">
                  Escanea este QR con Google Authenticator, Aegis o Microsoft Authenticator y
                  escribe el código de 6 dígitos.
                </p>
                <div className="mfa-qr">
                  {qr ? (
                    <img src={qr} alt="QR para configurar el autenticador" />
                  ) : (
                    <span>Preparando tu autenticador…</span>
                  )}
                </div>
              </>
            ) : (
              <p className="muted">
                {recovery
                  ? 'Usa uno de los códigos que guardaste al activar tu autenticador.'
                  : 'Abre tu aplicación de autenticación y escribe el código de 6 dígitos.'}
              </p>
            )}
            <form onSubmit={submit}>
              <label htmlFor="otp">
                {recovery ? 'Código de recuperación' : 'Código del autenticador'}
              </label>
              <input
                id="otp"
                className={recovery ? 'recovery-input' : 'otp-input'}
                type="text"
                inputMode={recovery ? 'text' : 'numeric'}
                autoComplete="one-time-code"
                value={code}
                onChange={(e) =>
                  setCode(recovery ? e.target.value : e.target.value.replace(/\D/g, '').slice(0, 6))
                }
                placeholder={recovery ? 'xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx' : '000000'}
                minLength={recovery ? 32 : 6}
                maxLength={recovery ? 35 : 6}
                required
                autoFocus
              />
              {error && (
                <p className="form-error" role="alert">
                  {error}
                </p>
              )}
              <button className="button primary login-submit" disabled={busy || (setup && !qr)}>
                {busy ? 'Verificando…' : setup ? 'Activar MFA' : 'Verificar'}{' '}
                <ArrowRight size={18} />
              </button>
            </form>
            {!setup && (
              <button
                className="text-link mfa-recovery"
                onClick={() => {
                  setRecovery(!recovery);
                  setCode('');
                  setError('');
                }}
              >
                <KeyRound size={16} />
                {recovery ? 'Usar mi autenticador' : 'Usar un código de recuperación'}
              </button>
            )}
            <p className="mfa-notice">Por tu seguridad, esta verificación vence en 5 minutos.</p>
            <Link className="text-link" to="/login" onClick={cancelMfa}>
              <ArrowLeft size={16} /> Volver al inicio de sesión
            </Link>
          </>
        )}
      </section>
      <footer className="mfa-footer">SGSI-ZTA Hospital Lab · Solo uso académico</footer>
    </main>
  );
}
