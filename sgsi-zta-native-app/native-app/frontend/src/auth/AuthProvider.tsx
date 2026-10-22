import { useEffect, useState, type ReactNode } from 'react';
import { api, ApiError, initializeCsrf } from '../services/api';
import type { User, MfaChallenge, AuthSuccess, LoginResult } from '../types';
import { AuthContext } from './context';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [connectionError, setConnectionError] = useState('');
  // Challenge stays only in memory, never in URLs or persistent browser storage.
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  useEffect(() => {
    let active = true;
    async function restore() {
      try {
        await initializeCsrf();
        let current: User;
        try {
          current = await api<User>('/auth/me');
        } catch (error) {
          if (!(error instanceof ApiError) || error.status !== 401) throw error;
          await api('/auth/refresh', { method: 'POST' });
          current = await api<User>('/auth/me');
        }
        if (active) setUser(current);
      } catch (error) {
        if (active && (!(error instanceof ApiError) || error.status !== 401)) {
          setConnectionError(
            'El servicio no está disponible. Verifica la conexión e intenta otra vez.',
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    void restore();
    const expire = () => setUser(null);
    window.addEventListener('sgsi:session-expired', expire);
    return () => {
      active = false;
      window.removeEventListener('sgsi:session-expired', expire);
    };
  }, []);

  async function login(username: string, password: string, remember: boolean) {
    await initializeCsrf();
    const result = await api<LoginResult>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, remember }),
    });
    if (result.status === 'AUTHENTICATED') {
      setUser(result.user);
      setChallenge(null);
    } else {
      setUser(null);
      setChallenge(result);
    }
    setConnectionError('');
    return result;
  }

  async function completeMfa(code: string, recovery: boolean) {
    if (!challenge) throw new Error('Inicia sesión de nuevo para verificar tu cuenta');
    const result = await api<AuthSuccess>('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ challenge_token: challenge.challenge_token, code, recovery }),
    });
    setUser(result.user);
    setChallenge(null);
    return result.recovery_codes ?? [];
  }

  async function logout() {
    await api('/auth/logout', { method: 'POST' });
    setUser(null);
    setChallenge(null);
    await initializeCsrf();
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        connectionError,
        challenge,
        login,
        logout,
        completeMfa,
        cancelMfa: () => setChallenge(null),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
