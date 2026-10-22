import type { ReactNode } from 'react';

export function Badge({
  children,
  tone = 'neutral',
}: {
  children: ReactNode;
  tone?: 'neutral' | 'green' | 'amber' | 'red' | 'orange';
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function Loading() {
  return (
    <div className="loading-state">
      <span className="spinner" /> Cargando datos del laboratorio…
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="error-state" role="alert">
      <strong>No se pudieron cargar los datos</strong>
      <p>{message}</p>
      {retry && (
        <button className="button secondary" onClick={retry}>
          Volver a intentar
        </button>
      )}
    </div>
  );
}
