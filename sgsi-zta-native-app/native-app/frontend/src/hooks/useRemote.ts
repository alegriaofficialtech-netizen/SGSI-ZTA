import { useEffect, useState } from 'react';
import { api } from '../services/api';
export function useRemote<T>(path: string, enabled = true) {
  const [snapshot, setSnapshot] = useState<{ path: string; value: T } | null>(null);
  const [failure, setFailure] = useState<{ path: string; message: string } | null>(null);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    api<T>(path)
      .then((value) => {
        if (active) {
          setSnapshot({ path, value });
          setFailure(null);
        }
      })
      .catch((e) => {
        if (active) setFailure({ path, message: e.message });
      });
    return () => {
      active = false;
    };
  }, [path, enabled, revision]);
  return {
    data: snapshot?.path === path ? snapshot.value : null,
    error: failure?.path === path ? failure.message : '',
    reload: () => setRevision((n) => n + 1),
  };
}
