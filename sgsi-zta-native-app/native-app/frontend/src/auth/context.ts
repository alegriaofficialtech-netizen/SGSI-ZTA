import { createContext } from 'react';
import type { User, MfaChallenge, LoginResult } from '../types';

interface AuthState {
  user: User | null;
  loading: boolean;
  connectionError: string;
  challenge: MfaChallenge | null;
  login: (username: string, password: string, remember: boolean) => Promise<LoginResult>;
  completeMfa: (code: string, recovery: boolean) => Promise<string[]>;
  cancelMfa: () => void;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);
