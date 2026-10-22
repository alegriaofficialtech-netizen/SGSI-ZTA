import { Link, useLocation } from 'react-router-dom';
import { ArrowLeft, Layers3 } from 'lucide-react';
import { Badge } from '../components/Status';

const modules: Record<string, { title: string; milestone: string; description: string }> = {
  assets: {
    title: 'Activos',
    milestone: 'M3',
    description: 'Inventario sintético, criticidad y responsables de los activos.',
  },
  risks: {
    title: 'Riesgos',
    milestone: 'M4',
    description: 'Evaluación de probabilidad e impacto y matriz de riesgos.',
  },
  controls: {
    title: 'Controles',
    milestone: 'M4',
    description: 'Controles académicos vinculados a riesgos y evidencias.',
  },
  policies: {
    title: 'Zero Trust',
    milestone: 'M5',
    description: 'Evaluación de políticas según identidad y contexto.',
  },
  alerts: {
    title: 'Alertas',
    milestone: 'M6',
    description: 'Detección y seguimiento de eventos de seguridad.',
  },
  events: {
    title: 'Eventos',
    milestone: 'M6',
    description: 'Monitoreo e integridad de archivos sintéticos.',
  },
  evidence: {
    title: 'Evidencias',
    milestone: 'M7',
    description: 'Evidencias verificables y trazabilidad de controles.',
  },
  clinical: {
    title: 'Clinical Demo',
    milestone: 'M5',
    description: 'Recursos completamente ficticios con decisiones de acceso Zero Trust.',
  },
};

export function PendingModule() {
  const location = useLocation();
  const module = modules[location.pathname.split('/')[1]];
  return (
    <div className="pending-module">
      <span className="pending-icon">
        <Layers3 size={34} strokeWidth={1.4} />
      </span>
      <Badge>{module?.milestone ?? 'Pendiente'} · Próxima fase · NOT_IMPLEMENTED</Badge>
      <h1>{module?.title ?? 'Página no encontrada'}</h1>
      <p>{module?.description ?? 'Esta ruta no está disponible.'}</p>
      <div className="pending-scope">
        La versión actual incluye identidad, MFA, activos, riesgos y controles (M0–M4). Este módulo
        se desarrollará en una etapa posterior.
      </div>
      <Link className="button primary" to="/dashboard">
        <ArrowLeft size={16} />
        Volver al dashboard
      </Link>
    </div>
  );
}
