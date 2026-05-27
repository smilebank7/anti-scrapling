import type { PermissionsProbe } from '../types';

export async function collectPermissions(): Promise<PermissionsProbe> {
  const [notifications, midi, camera] = await Promise.all([
    queryPermission('notifications'),
    queryPermission('midi'),
    queryPermission('camera')
  ]);

  return {
    notifications_state: notifications,
    midi_state: midi,
    camera_state: camera
  };
}

async function queryPermission(name: string): Promise<string> {
  if (!navigator.permissions?.query) {
    return 'unsupported';
  }

  try {
    const status = await navigator.permissions.query({ name } as PermissionDescriptor);
    return status.state;
  } catch (error) {
    return error instanceof Error ? `error:${error.message}` : 'error';
  }
}
