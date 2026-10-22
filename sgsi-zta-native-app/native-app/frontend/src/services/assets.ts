import type { AssetDraft, AssetStatus, Classification, Criticality } from '../types/assets';

export const criticalities: Criticality[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const classifications: Classification[] = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
];
export const statuses: AssetStatus[] = ['ACTIVE', 'INACTIVE', 'MAINTENANCE', 'RETIRED'];
export const assetLabels: Record<string, string> = {
  LOW: 'Baja',
  MEDIUM: 'Media',
  HIGH: 'Alta',
  CRITICAL: 'Crítica',
  PUBLIC: 'Pública',
  INTERNAL: 'Interna',
  CONFIDENTIAL: 'Confidencial',
  RESTRICTED: 'Restringida',
  ACTIVE: 'Activo',
  INACTIVE: 'Inactivo',
  MAINTENANCE: 'Mantenimiento',
  RETIRED: 'Retirado',
};
export function validateAssetDraft(data: AssetDraft): string {
  if (
    !/^[A-Z0-9]+(?:-[A-Z0-9]+)*$/.test(data.asset_code.trim()) ||
    data.asset_code.trim().length < 3
  )
    return 'Usa un código de al menos 3 caracteres con mayúsculas, números y guiones.';
  if (data.name.trim().length < 2) return 'El nombre debe tener al menos 2 caracteres.';
  if (!data.asset_type_id || !data.department_id || !data.owner_user_id)
    return 'Selecciona tipo, área y responsable.';
  if (data.ip_address_demo) {
    const parts = data.ip_address_demo.trim().split('.');
    if (
      parts.length !== 4 ||
      parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255) ||
      !['192.0.2', '198.51.100', '203.0.113'].includes(parts.slice(0, 3).join('.'))
    )
      return 'Usa una IP documental: 192.0.2.x, 198.51.100.x o 203.0.113.x';
  }
  if (data.hostname_demo && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(data.hostname_demo))
    return 'El hostname demo debe usar minúsculas, números, puntos o guiones.';
  return '';
}
