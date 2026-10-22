export const riskLabels: Record<string, string> = {
  LOW: 'Bajo',
  MEDIUM: 'Medio',
  HIGH: 'Alto',
  CRITICAL: 'Crítico',
  OPEN: 'Abierto',
  IN_TREATMENT: 'En tratamiento',
  ACCEPTED: 'Aceptado',
  CLOSED: 'Cerrado',
  ACCEPT: 'Aceptar',
  AVOID: 'Evitar',
  REDUCE: 'Reducir',
  TRANSFER: 'Transferir',
  PLANNED: 'Planificado',
  PARTIAL: 'Parcial',
  IMPLEMENTED: 'Implementado',
  NOT_APPLICABLE: 'No aplica',
  PREVENTIVE: 'Preventivo',
  DETECTIVE: 'Detectivo',
  CORRECTIVE: 'Correctivo',
  ACCESS_CONTROL: 'Control de acceso',
  IDENTITY: 'Identidad',
  MONITORING: 'Monitoreo',
  ASSET_MANAGEMENT: 'Gestión de activos',
  BACKUP: 'Respaldos',
  AUDIT: 'Auditoría',
  CHANGE_MANAGEMENT: 'Gestión de cambios',
  NETWORK_SECURITY: 'Seguridad de red',
  GOVERNANCE: 'Gobernanza',
  INCIDENT_RESPONSE: 'Respuesta a incidentes',
};
export const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const riskStates = ['OPEN', 'IN_TREATMENT', 'ACCEPTED', 'CLOSED'];
export const treatments = ['ACCEPT', 'AVOID', 'REDUCE', 'TRANSFER'];
export const implementations = ['PLANNED', 'PARTIAL', 'IMPLEMENTED', 'NOT_APPLICABLE'];
export const categories = [
  'ACCESS_CONTROL',
  'IDENTITY',
  'MONITORING',
  'ASSET_MANAGEMENT',
  'BACKUP',
  'AUDIT',
  'CHANGE_MANAGEMENT',
  'NETWORK_SECURITY',
  'GOVERNANCE',
  'INCIDENT_RESPONSE',
];
export const probabilityLabels = ['Rara', 'Poco probable', 'Posible', 'Probable', 'Muy probable'];
export const impactLabels = ['Insignificante', 'Menor', 'Moderado', 'Mayor', 'Severo'];
