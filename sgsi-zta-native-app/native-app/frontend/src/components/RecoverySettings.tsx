import { useState, type FormEvent } from 'react';
import { api } from '../services/api';

export function RecoverySettings() {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function regenerate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const result = await api<{ recovery_codes: string[] }>('/auth/mfa/recovery/regenerate', {
        method: 'POST',
        body: JSON.stringify({ password, code }),
      });
      setCodes(result.recovery_codes);
      setPassword('');
      setCode('');
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'No se pudieron generar los códigos');
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel recovery-settings">
      <div className="panel-heading">
        <h2>Recuperación de cuenta</h2>
      </div>
      {codes.length ? (
        <>
          <p>
            Guarda estos códigos. Los anteriores han dejado de funcionar. Cada código permite un
            único acceso.
          </p>
          <div className="recovery-codes">
            {codes.map((item) => (
              <code key={item}>{item}</code>
            ))}
          </div>
          <button className="button secondary" onClick={() => setCodes([])}>
            He guardado mis códigos
          </button>
        </>
      ) : (
        <>
          <p className="muted">
            Genera nuevos códigos de recuperación con tu contraseña y un código nuevo del
            autenticador. Si acabas de acceder, espera a que cambie el código.
          </p>
          <form onSubmit={regenerate}>
            <label htmlFor="recovery-password">Confirma tu contraseña</label>
            <input
              id="recovery-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={128}
              required
            />
            <label htmlFor="recovery-totp">Código nuevo del autenticador</label>
            <input
              id="recovery-totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              minLength={6}
              maxLength={6}
              required
            />
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <button className="button secondary" disabled={busy}>
              {busy ? 'Generando…' : 'Regenerar códigos'}
            </button>
          </form>
        </>
      )}
    </section>
  );
}
