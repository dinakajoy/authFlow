import { Service, Container } from 'typedi';

import { IPermission } from '../../api/permission/permission.interfaces';

import { PermissionRepository } from '../../repositories';

const permissionRepository = Container.get(PermissionRepository);

@Service()
export class PermissionService {
  public async getPermissions(): Promise<IPermission[]> {
    const permissions: IPermission[] = await permissionRepository.find();

    return permissions;
  }

  public async getPermissionsByRoles(
    assignableRoles?: string[] | null,
  ): Promise<IPermission[]> {
    const permissions = await permissionRepository.find({
      rolesAssignableTo: { $in: assignableRoles },
    });

    return permissions;
  }
}
