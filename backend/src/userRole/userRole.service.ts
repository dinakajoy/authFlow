import { Types } from 'mongoose';
import User from '../../api/user/user.model';
import UserRole from './userRole.model';
import {
  IUserRoleDocument,
  IUserRole,
} from './userRole.interfaces';
import {
  RoleTypes,
  STAFF_USERS_ROLES,
  EMPLOYEE_USER_ROLES_FOR_COUNT_LIMIT,
  NETWORK_USER_ROLES_COUNT_LIMIT,
  UserStatuses,
  UserRoles as UserRoleTypes,
  UserCategories,
  UserRoles,
  AccessPermissionTypes,
  INCUBATOR_USER_ROLES,
  FeatureFlagNames,
  CategoryTypes,
  UserVisibilityTypes,
  StartupVisibilityTypes,
} from '../../constants';
import {
  AssignedRolesNotDeletableError,
  DefaultRolesNotDeletableError,
  UserRoleNotFoundError,
  NotFoundError,
  ForbiddenError,
  UserRoleTypeNotCombinableError,
  DataError,
} from '../../graph/errors';
import { Redis, REDIS_KEYS } from '../redis';
import { IUser } from '../../api/user/user.interfaces';
import {
  UserRepository,
  IncubatorRepository,
  CategoryRepository,
} from '../../repositories';
import logger from '../../helpers/logging';
import { MenuItem, StartupMenuItem } from '../../resolver-types';
import type { Authorization } from '../../core/authorization';
import { featureIsActivated } from '../services.feature.flag';
import { toObjectId } from '../../config/mongoose';
import { ICategory } from '../../api/category/category.interfaces';
import { Modify } from '../../interfaces';
import { getIncubatorById } from '../incubators/getIncubatorById';

const userRepository = Container.get(UserRepository);
const incubatorRepository = Container.get(IncubatorRepository);
const categoryRepository = Container.get(CategoryRepository);
export interface PermissionInput {
  key: string;
  permissionCriteria: string;
}
export interface UserRoleInput {
  type?: UserRoleTypes[];
  label?: string;
  permissions?: [PermissionInput];
  userAccess?: {
    visibilitySettings?: AccessPermissionTypes;
    roles?: [Types.ObjectId] | [];
  };
  startupAccess?: {
    visibilitySettings?: AccessPermissionTypes;
  };
  description?: string;
}

@Service()
export class UserRoleService {
  public matchUserTypes(
    allowedRoleTypes: readonly UserRoleTypes[],
    userRole: Pick<IUserRole, 'type'>,
  ) {
    return userRole?.type?.some(roleType =>
      allowedRoleTypes.includes(roleType),
    );
  }

  public isOnlyFounder(userRole: Pick<IUserRole, 'type'>): boolean {
    return (
      this.matchUserTypes([UserRoleTypes.Cofounder], userRole) &&
      !this.matchUserTypes(STAFF_USERS_ROLES as UserRoleTypes[], userRole) &&
      !this.isEvaluator(userRole) &&
      !this.isNetwork(userRole)
    );
  }

  public isOnlyApplicant(userRole: Pick<IUserRole, 'type'>): boolean {
    return (
      this.matchUserTypes([UserRoleTypes.Applicant], userRole) &&
      !this.matchUserTypes(STAFF_USERS_ROLES as UserRoleTypes[], userRole) &&
      !this.isEvaluator(userRole) &&
      !this.isNetwork(userRole)
    );
  }

  public isSubAdmin(userRole: Pick<IUserRole, 'type'>): boolean {
    return (
      userRole.type.includes(UserRoleTypes.SubAdmin) &&
      !this.matchUserTypes(STAFF_USERS_ROLES as UserRoleTypes[], userRole)
    );
  }

  public isNetwork(userRole: Pick<IUserRole, 'type'>): boolean {
    return (
      this.matchUserTypes(
        [UserRoleTypes.Mentor, UserRoleTypes.Expert],
        userRole,
      ) &&
      !this.matchUserTypes(
        [...STAFF_USERS_ROLES, UserRoleTypes.SubAdmin],
        userRole,
      )
    );
  }

  public isEvaluator(userRole: Pick<IUserRole, 'type'>): boolean {
    return this.matchUserTypes([UserRoleTypes.Evaluator], userRole);
  }

  public isAdmin(userRole: Pick<IUserRole, 'type'>): boolean {
    return this.matchUserTypes(
      [UserRoleTypes.Admin, UserRoleTypes.AdminCoach],
      userRole,
    );
  }

  public isPaidUserRole(userRole: Pick<IUserRole, 'type'>): boolean {
    return this.matchUserTypes(
      [
        UserRoleTypes.Admin,
        UserRoleTypes.AdminCoach,
        UserRoleTypes.SubAdmin,
        UserRoleTypes.Coach,
        UserRoleTypes.Staff,
      ],
      userRole,
    );
  }

  public async currentUserIsSubAdmin(user: IUser): Promise<boolean> {
    const currentUserRole = await this.getUserRoleById(
      user.role as Types.ObjectId,
    );

    if (currentUserRole) {
      return this.isSubAdmin(currentUserRole);
    }
    logger.debug(`User role not found for user ${user._id}`);
    return false;
  }

  public async getRoleTypeByUserRoleId(userRoleId: Types.ObjectId) {
    const userRole = await this.getUserRoleById(userRoleId);

    if (userRole) {
      return this.roleToCategory(userRole);
    }
    return [];
  }

  public roleToCategory(
    userRole: IUserRoleDocument | IUserRole | { type: UserRoleTypes[] },
  ) {
    if (this.isPaidUserRole(userRole)) {
      return UserCategories.Employee;
    }
    if (this.isNetwork(userRole)) {
      return UserCategories.Network;
    }
    if (this.matchUserTypes([UserRoleTypes.Evaluator], userRole)) {
      return UserCategories.Evaluator;
    }

    return UserCategories.Other;
  }

  public roleHasPermission(
    permissions: string[] | string,
    userRole: IUserRole | IUserRoleDocument,
  ): boolean {
    if (permissions instanceof Array) {
      return [...(userRole.permissions || [])].some(permission =>
        permissions.includes(permission.key),
      );
    }
    return [...(userRole.permissions || [])].some(
      permission => permission.key === permissions,
    );
  }

  public async getUserRolesForApplicationDecision({
    incubatorId,
    categoryId,
  }: {
    incubatorId: string;
    categoryId: string;
  }): Promise<IUserRole[] | null> {
    const categoryType: ICategory | null = await categoryRepository.findById(
      categoryId,
      {
        type: 1,
      },
    );

    if (!categoryType) {
      throw new NotFoundError({ message: 'Category not found' });
    }

    if (categoryType.type === CategoryTypes.CommunityMember) {
      return this.getUserRoles({ incubatorId: toObjectId(incubatorId) });
    }

    return null;
  }

  public async updatesRoleMatter(
    incubator: IIncubator,
    newRoleId: Types.ObjectId,
    prevRoleId: Types.ObjectId | null,
  ): Promise<boolean> {
    if (prevRoleId !== null && newRoleId.toString() === prevRoleId.toString()) {
      return false;
    }

    const newRole = await this.getUserRoleById(newRoleId);

    if (!newRole) {
      throw new UserRoleNotFoundError();
    }

    if (prevRoleId) {
      const prevRole = await this.getUserRoleById(prevRoleId);
      if (!prevRole) {
        throw new UserRoleNotFoundError();
      }

      if (this.roleToCategory(prevRole) === UserCategories.Employee) {
        return false;
      }
    }
    if (this.roleToCategory(newRole) === UserCategories.Employee) {
      return true;
    }

    if (
      this.roleToCategory(newRole) === UserCategories.Evaluator &&
      incubator?.planInfo?.maxNbEvaluators > 0
    ) {
      return true;
    }

    if (
      this.roleToCategory(newRole) === UserCategories.Network &&
      incubator?.planInfo?.maxNbNetworks > 0
    ) {
      return true;
    }
    return false;
  }

  private userLimit = (
    incubator: Pick<IIncubator, 'planInfo'>,
    userCategory: UserCategories,
  ) => {
    switch (userCategory) {
      case UserCategories.Employee:
        return incubator?.planInfo?.employeeCountLimit ?? 0;
      case UserCategories.Network:
        return incubator?.planInfo?.maxNbNetworks ?? 0;
      case UserCategories.Evaluator:
        return incubator?.planInfo?.maxNbEvaluators ?? 0;
      default:
        return 0;
    }
  };

  private userTypeToCount = (userCategory: UserCategories) => {
    switch (userCategory) {
      case UserCategories.Employee:
        return EMPLOYEE_USER_ROLES_FOR_COUNT_LIMIT;
      case UserCategories.Network:
        return NETWORK_USER_ROLES_COUNT_LIMIT;
      case UserCategories.Evaluator:
        return [UserRoleTypes.Evaluator];
      default:
        return [];
    }
  };

  private async allowEditOfRole(
    prevRoleId: Types.ObjectId,
    updateRoleInput: UserRoleInput,
    incubator: IIncubator,
  ): Promise<boolean | Error> {
    // if no type is passed then allow edit as it does not have impact on plans
    if (updateRoleInput.type === undefined || updateRoleInput.type === null) {
      return true;
    }

    // if no user is assigned then allow edit as it does not have impact on plans
    const userCountOfRole = await userRepository.countDocuments({
      role: prevRoleId,
    });
    if (userCountOfRole === 0) {
      return true;
    }

    const prevUserRole = await this.getUserRoleById(prevRoleId);

    const differenceTypes = updateRoleInput.type.filter(
      userRoleType => !prevUserRole?.type?.includes(userRoleType),
    );

    // if there is no difference between previous user role types and new user role types then allow edit as it does not have impact on plans
    if (differenceTypes.length === 0) {
      return true;
    }

    // get the new type of the user role
    const newRoleCategory: UserCategories = this.roleToCategory({
      type: differenceTypes,
    });

    // see if there is sufficient limit in the plan to accommodate the number of users of the new type
    return this.canAddUserWithRole(incubator, userCountOfRole, newRoleCategory);
  }

  public async canAddUserWithRole(
    incubator: Pick<IIncubator, '_id' | 'planInfo'>,
    invitedUserCount: number,
    userType: UserCategories,
  ): Promise<boolean> {
    const limit = this.userLimit(incubator, userType);

    if (limit === 0 || invitedUserCount === 0 || userType === 'OTHER') {
      // incubator plan has unlimited users, pass check
      return true;
    }

    const userTypeToCountRoleIds = await this.getUserRolesIds({
      incubatorId: incubator._id,
      rolesTypesIncluded: this.userTypeToCount(userType) as UserRoleTypes[],
    });

    const currentUserCount: number = await userRepository.countDocuments({
      incubator: incubator._id,
      role: {
        $in: userTypeToCountRoleIds,
      },
      status: { $in: [UserStatuses.Active, UserStatuses.Pending] },
    });

    if (currentUserCount + invitedUserCount > limit) {
      return false;
    }
    return true;
  }

  public async roleSlugExist({
    incubator,
    roleSlug,
  }: {
    incubator: Types.ObjectId;
    roleSlug: string;
  }) {
    const userRole = await UserRole.findOne({ incubator, slug: roleSlug });

    return !!userRole;
  }

  public async getUserRoleBySlug({
    incubator,
    roleSlug,
  }: {
    incubator: Types.ObjectId;
    roleSlug: string;
  }): Promise<IUserRole | null> {
    const userRole = await UserRole.findOne({ incubator, slug: roleSlug });

    return userRole;
  }

  public async create({
    incubatorId,
    values,
  }: {
    incubatorId: Types.ObjectId;
    values: UserRoleInput;
  }): Promise<IUserRole | null> {
    const { permissions } = values;

    const slug = slugify(
      values.label?.toString().trim().toLowerCase() as string,
    );

    const types = values.type;

    if (
      (types?.includes(UserRoles.Applicant) ||
        types?.includes(UserRoles.Cofounder)) &&
      types.some(type => INCUBATOR_USER_ROLES.includes(type))
    ) {
      throw new UserRoleTypeNotCombinableError();
    }

    if (
      values.userAccess &&
      values.type?.some(type =>
        [UserRoles.Applicant, UserRoles.CommunityMember].includes(type),
      ) &&
      values.userAccess.visibilitySettings?.toString() ===
        UserVisibilityTypes.Assigned
    ) {
      throw new DataError({ message: 'Not allowed' });
    }
    if (
      values.startupAccess &&
      values.type?.some(type =>
        [
          UserRoles.Applicant,
          UserRoles.CommunityMember,
          UserRoles.Cofounder,
        ].includes(type),
      ) &&
      values.startupAccess.visibilitySettings?.toString() ===
        StartupVisibilityTypes.Assigned
    ) {
      throw new DataError({ message: 'Not allowed' });
    }

    const newUserRole = await UserRole.create({
      incubator: incubatorId,
      type: values.type,
      label: values.label,
      permissions,
      roleType: RoleTypes.Custom,
      description: values.description,
      userAccess: values.userAccess
        ? values.userAccess
        : {
            visibilitySettings: AccessPermissionTypes.NONE,
            roles: [],
          },
      startupAccess: values.startupAccess
        ? values.startupAccess
        : {
            visibilitySettings: AccessPermissionTypes.NONE,
          },
      slug,
    });

    const redisKeyAllUserRolesIncubator =
      REDIS_KEYS.USER_ROLES_FOR_INCUBATOR(incubatorId);
    const redisKeyUserRole = REDIS_KEYS.USER_ROLE(newUserRole._id);

    Redis.Instance.del(redisKeyAllUserRolesIncubator);
    Redis.Instance.setMaybeJson(redisKeyUserRole, newUserRole);

    return newUserRole;
  }

  public async update({
    userRoleId,
    incubatorId,
    values,
  }: {
    userRoleId: Types.ObjectId;
    incubatorId: Types.ObjectId;
    values: UserRoleInput;
  }): Promise<IUserRole> {
    const userRole: IUserRoleDocument | null = await UserRole.findById(
      userRoleId,
    );

    const incubator = await incubatorRepository.getById(incubatorId);

    if (!incubator) {
      throw new NotFoundError({ message: 'Incubator not found' });
    }

    if (!(await this.allowEditOfRole(userRoleId, values, incubator))) {
      throw new ForbiddenError({
        message:
          'Your plan does not allow to edit this role, as it would bring the number of user above your limit for this role category',
      });
    }

    let slug;
    if (values.label) {
      slug = slugify(values.label?.toString().trim().toLowerCase() as string);
    }

    if (
      values.userAccess &&
      values.type?.some(type =>
        [UserRoles.Applicant, UserRoles.CommunityMember].includes(type),
      ) &&
      values.userAccess.visibilitySettings?.toString() ===
        UserVisibilityTypes.Assigned
    ) {
      throw new DataError({ message: 'Not allowed' });
    }
    if (
      values.startupAccess &&
      values.type?.some(type =>
        [
          UserRoles.Applicant,
          UserRoles.CommunityMember,
          UserRoles.Cofounder,
        ].includes(type),
      ) &&
      values.startupAccess.visibilitySettings?.toString() ===
        StartupVisibilityTypes.Assigned
    ) {
      throw new DataError({ message: 'Not allowed' });
    }

    const update: Partial<IUserRoleDocument> = {
      ...(values.label && { label: values.label }),
      ...(values.type && { type: values.type }),
      ...(values.description && { description: values.description }),
      ...(values.permissions && { permissions: values.permissions }),
      ...(values.userAccess && { userAccess: values.userAccess }),
      ...(values.startupAccess && { startupAccess: values.startupAccess }),
      ...(slug && { slug }),
    };

    const updatedUserRole = await UserRole.findOneAndUpdate(
      { _id: userRole?._id, incubator: incubatorId },
      { $set: update },
      { new: true },
    );

    if (!updatedUserRole) {
      throw new UserRoleNotFoundError();
    }

    const redisKeyAllUserRolesIncubator =
      REDIS_KEYS.USER_ROLES_FOR_INCUBATOR(incubatorId);
    Redis.Instance.del(redisKeyAllUserRolesIncubator);

    const redisKeyUserRole = REDIS_KEYS.USER_ROLE(updatedUserRole._id);
    Redis.Instance.setMaybeJson(redisKeyUserRole, updatedUserRole);

    return updatedUserRole;
  }

  public async delete({
    userRoleId,
    incubatorId,
  }: {
    userRoleId: Types.ObjectId;
    incubatorId: Types.ObjectId;
  }): Promise<boolean> {
    const userRole: IUserRoleDocument | null = await UserRole.findOne({
      _id: userRoleId,
      incubator: incubatorId,
    });

    if (!userRole) {
      throw new UserRoleNotFoundError();
    }

    if (userRole.roleType === RoleTypes.Default) {
      throw new DefaultRolesNotDeletableError();
    }

    const usersAssignedToRole = await User.find({ role: userRole._id });

    if (usersAssignedToRole.length !== 0) {
      throw new AssignedRolesNotDeletableError();
    }

    await UserRole.findOneAndDelete({
      _id: userRoleId,
      incubator: incubatorId,
    });

    const redisKeyAllUserRolesIncubator =
      REDIS_KEYS.USER_ROLES_FOR_INCUBATOR(incubatorId);
    Redis.Instance.del(redisKeyAllUserRolesIncubator);

    const redisKeyUserRole = REDIS_KEYS.USER_ROLE(userRoleId);
    Redis.Instance.del(redisKeyUserRole);

    return true;
  }

  public async getSystemRoleByIncubator(incubatorId: Types.ObjectId) {
    const userRole = await UserRole.findOne({
      incubator: incubatorId,
      type: UserRoles.System,
    });

    return userRole;
  }

  public async getUserRoles({
    incubatorId,
    filter,
    fromCache = true,
  }: {
    incubatorId: Types.ObjectId;
    filter?: Partial<{
      _id?: Types.ObjectId[];
      label?: string | null;
      userRoleTypes?: UserRoleTypes[] | null;
      excludedUserRoleTypes?: UserRoleTypes[] | null;
      roleType?: RoleTypes;
    }>;
    fromCache?: boolean;
  }): Promise<IUserRole[]> {
    const query: {
      incubator: Types.ObjectId;
      _id?: { $in: Types.ObjectId[] };
      label?: { $regex: RegExp };
      type?: { $in: UserRoleTypes[]; $nin?: UserRoleTypes[] };
      roleType?: RoleTypes;
    } = {
      incubator: incubatorId,
    };

    if (filter?.label) {
      query.label = { $regex: new RegExp(filter.label, 'i') };
    }

    if (filter?.userRoleTypes && filter?.userRoleTypes.length) {
      if (
        filter?.excludedUserRoleTypes &&
        filter?.excludedUserRoleTypes.length
      ) {
        query.type = {
          $in: filter.userRoleTypes,
          $nin: filter.excludedUserRoleTypes,
        };
      } else {
        query.type = { $in: filter.userRoleTypes, $nin: [] };
      }
    }

    if (filter?.roleType && filter?.roleType.length) {
      query.roleType = filter.roleType;
    }

    if (filter?._id && filter?._id.length) {
      query._id = { $in: filter._id };
    }

    const redisKey = REDIS_KEYS.USER_ROLES_FOR_INCUBATOR(incubatorId);

    if (!filter && fromCache) {
      const redisUserRoles = await Redis.Instance.getMaybeJson(redisKey);

      if (redisUserRoles) {
        return redisUserRoles;
      }
    }

    const userRoles = await UserRole.find(query)
      .where('type')
      .ne(filter?.userRoleTypes?.includes(UserRoles.System) ? [] : ['system'])
      .collation({ locale: 'en' })
      .sort({ label: 1 })
      .exec();

    if (!filter) {
      Redis.Instance.setMaybeJson(redisKey, userRoles);
    }

    return userRoles;
  }

  public async getUserRolesCanInvite({
    incubatorId,
    userRoleTypes,
    userRole,
  }: {
    incubatorId: string;
    userRoleTypes?: UserRoleTypes[];
    userRole: IUserRole;
  }): Promise<IUserRole[]> {
    const userRoles = await this.getUserRoles({
      incubatorId: toObjectId(incubatorId),
      filter: { userRoleTypes },
    });

    if (this.isAdmin(userRole)) {
      return userRoles;
    }

    return userRoles.filter(role => {
      return !this.isAdmin(role);
    });
  }

  public async getUserRoleById(
    userRoleId: Types.ObjectId,
  ): Promise<IUserRole | null> {
    const redisKey = REDIS_KEYS.USER_ROLE(userRoleId);
    let userRole = await Redis.Instance.getMaybeJson(redisKey);

    if (!userRole || !userRole.type || !userRole.label) {
      userRole = await UserRole.findById(userRoleId).lean();
      Redis.Instance.setMaybeJson(redisKey, userRole);
    }

    return userRole;
  }

  public async getUserRoleByIds(
    userRoleIds: Types.ObjectId[],
  ): Promise<IUserRole[] | []> {
    const redisKeys = userRoleIds.map(userRoleId =>
      REDIS_KEYS.USER_ROLE(userRoleId),
    );
    const userRole = await Redis.Instance.getManyMaybeJson(redisKeys);
    let userRoleToFetch: IUserRole[] = [];

    if (userRole.notFound.length > 0) {
      // ? This removes `role:` key appended to the notfound Ids
      const notFoundRolesIds = userRole.notFound.map(roleKey =>
        roleKey.replace('role:', ''),
      );

      const userRolesFromDB: IUserRole[] = await UserRole.find({
        _id: { $in: notFoundRolesIds },
      }).lean();

      const mapUserRole: Record<string, IUserRole> = userRolesFromDB.reduce(
        (acc: Record<string, IUserRole>, userRoleFetched: IUserRole) => {
          acc[userRoleFetched._id.toString()] = userRoleFetched;
          return acc;
        },
        {} as Record<string, IUserRole>,
      );

      Redis.Instance.setManyMaybeJson(mapUserRole, REDIS_KEYS.USER_ROLE);
      userRoleToFetch = userRolesFromDB;
    }
    if (!userRole) {
      throw new UserRoleNotFoundError();
    }
    return [...userRole.found, ...userRoleToFetch];
  }

  public async findById({
    incubatorId,
    userRoleId,
  }: {
    incubatorId: Types.ObjectId;
    userRoleId: Types.ObjectId;
  }): Promise<IUserRoleDocument | null> {
    return UserRole.findOne({
      incubator: incubatorId,
      _id: userRoleId,
    }).lean();
  }

  public async getIncubatorRoles(
    incubatorId: Types.ObjectId,
  ): Promise<IUserRole[]> {
    if (!incubatorId) {
      throw new Error('Incubator id is required');
    }

    return UserRole.find({ incubator: incubatorId })
      .where('type')
      .ne(['system'])
      .collation({ locale: 'en' })
      .sort({ label: 1 })
      .exec();
  }

  public async getUserRolesIds({
    incubatorId,
    rolesTypesIncluded,
  }: {
    incubatorId: Types.ObjectId;
    rolesTypesIncluded: UserRoleTypes[];
  }): Promise<Types.ObjectId[]> {
    const userRoles = await this.getUserRoles({
      incubatorId,
    });

    return userRoles
      .filter(userRole => {
        return rolesTypesIncluded.some(role => userRole.type.includes(role));
      })
      .map(userRole => toObjectId(userRole._id));
  }

  public async getSystemRoleByIncubatorId(
    incubatorId: Types.ObjectId,
  ): Promise<IUserRole | null> {
    return UserRole.findOne({
      incubator: incubatorId,
      type: UserRoles.System,
    });
  }

  private async restrictedMenuItems(
    userRole: IUserRole,
    user: IUser,
    authorizer: Authorization,
    incubator: Modify<IIncubator, { _id: string }>,
    version: 1 | 2,
  ): Promise<
    Record<
      MenuItem,
      {
        access: boolean;
        incubatorFlag?: FeatureFlag | null;
      }
    >
  > {
    const userCategory: UserCategories = this.roleToCategory(userRole);
    const isAdmin: boolean = this.isAdmin(userRole);
    const isAllAdmins: boolean = this.matchUserTypes(
      [UserRoleTypes.Admin, UserRoleTypes.SubAdmin, UserRoleTypes.AdminCoach],
      userRole,
    );
    const isFounder: boolean = this.matchUserTypes(
      [UserRoleTypes.Cofounder],
      userRole,
    );

    const userHasStartup: boolean =
      user.startups && user.startups.filter(Boolean).length > 0;
    const isApplicant: boolean =
      this.matchUserTypes([UserRoleTypes.Applicant], userRole) &&
      !this.matchUserTypes([UserRoleTypes.Cofounder], userRole);

    const tagEditor = await authorizer.isAuthorized(
      'TAGS_EDITOR:VIEW',
      undefined,
      false,
    );
    const feedbackPageAccess =
      (await authorizer.isAuthorized(
        'FEEDBACK_REQUEST:VIEW',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'FEEDBACK_REQUEST:CREATE',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'FEEDBACK_REQUEST:EDIT',
        undefined,
        false,
      ));

    const canEditOrCreatedEvents =
      (await authorizer.isAuthorized('EVENT:CREATE', undefined, false)) ||
      (await authorizer.isAuthorized('EVENT:EDIT', undefined, false)) ||
      (await authorizer.isAuthorized('EVENT:DELETE', undefined, false));

    const canViewEmailSection =
      (await authorizer.isAuthorized(
        'EMAIL_REJECTION:CREATE',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'EMAIL_REJECTION:EDIT',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'EMAIL_BLUEPRINT:MANAGE',
        undefined,
        false,
      ));

    const canViewForms =
      (await authorizer.isAuthorized('FORM:EDIT', undefined, false)) ||
      (await authorizer.isAuthorized('FORM:CREATE', undefined, false));

    const evaluationParamsAccess =
      (await authorizer.isAuthorized(
        'EVALUATION_PARAMETER_EDITOR:VIEW',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'EVALUATION_PARAMETER_EDITOR:CREATE',
        undefined,
        false,
      )) ||
      (await authorizer.isAuthorized(
        'EVALUATION_PARAMETER_EDITOR:EDIT/DELETE',
        undefined,
        false,
      ));

    return {
      [MenuItem.SetupMenu]: {
        access: userCategory === UserCategories.Employee,
      },

      [MenuItem.ActivityFeed]: {
        access: userCategory === UserCategories.Employee,
        incubatorFlag: FeatureFlag.activityFeed,
      },
      [MenuItem.ApplicationsOverview]: {
        access: userCategory !== UserCategories.Other,
      },
      [MenuItem.ApplicationsDashboard]: {
        access: await authorizer.isAuthorized(
          'APPLICATION_DASHBOARD',
          undefined,
          false,
        ),
        incubatorFlag: FeatureFlag.applicationsDashboard,
      },
      [MenuItem.ApplicationsManager]: {
        access:
          (version === 1 && userCategory === UserCategories.Other) ||
          version === 2,
      },
      [MenuItem.Availability]: {
        access: userCategory !== UserCategories.Other,
      },
      [MenuItem.Calendar]: { access: !isApplicant },
      [MenuItem.Community]: {
        access: !isApplicant,
      },
      [MenuItem.Course]: {
        access: !isApplicant,
        incubatorFlag: FeatureFlag.course,
      },
      [MenuItem.IncubatorEvents]: {
        access: !isApplicant,
      },
      [MenuItem.StartupsPortfolio]: {
        access: userCategory !== UserCategories.Other,
        incubatorFlag: FeatureFlag.isIncubator,
      },
      [MenuItem.OrgSettingsSubMenu]: { access: isAdmin },
      [MenuItem.OrgUserRoleSettings]: {
        access: await authorizer.isAuthorized(
          'USER_ROLES:EDIT',
          undefined,
          false,
        ),
      },
      [MenuItem.OrgBrandingSettings]: { access: isAdmin },
      [MenuItem.OrgCustomDomain]: {
        access: isAdmin && Boolean(incubator.customDomain),
      },
      [MenuItem.OrgCurrentPlan]: { access: isAdmin },
      [MenuItem.OrgGeneralSettings]: { access: isAdmin },
      [MenuItem.OrgMentorMatching]: { access: isAdmin },
      [MenuItem.OrgMetricsCollection]: { access: isAdmin },
      [MenuItem.OrgPermissions]: { access: isAdmin },
      [MenuItem.OrgSeoSettings]: { access: isAdmin },
      [MenuItem.MyStartupSubMenu]: {
        access: isFounder && userHasStartup,
      },

      [MenuItem.SetupSubMenu]: {
        access:
          userCategory === UserCategories.Employee ||
          userCategory === UserCategories.Network,
      },
      [MenuItem.SetupArticles]: {
        access: await authorizer.isAuthorized(
          'ARTICLES:EDIT',
          undefined,
          false,
        ),
      },
      [MenuItem.SetupCustomFields]: {
        access: isAllAdmins,
        incubatorFlag: FeatureFlag.customFieldsEdit,
      },
      [MenuItem.SetupEmails]: { access: canViewEmailSection },
      [MenuItem.SetupEvaluationParams]: {
        access: await authorizer.isAuthorized(
          'EVALUATION_PARAMETER_EDITOR:VIEW',
          undefined,
          false,
        ),
        incubatorFlag: FeatureFlag.assessment,
      },
      [MenuItem.SetupFeedbackRequests]: {
        access: feedbackPageAccess,
        incubatorFlag: FeatureFlag.feedbackForms,
      },
      [MenuItem.SetupForms]: {
        access: canViewForms,
      },
      [MenuItem.SetupFunnels]: {
        access: await authorizer.isAuthorized(
          'FUNNELS:VIEW:LIST',
          undefined,
          false,
        ),
      },
      [MenuItem.SetupIndustries]: {
        access: await authorizer.isAuthorized(
          'INDUSTRIES:EDIT',
          undefined,
          false,
        ),
        incubatorFlag: FeatureFlag.editIndustries,
      },
      [MenuItem.SetupMentorsMgt]: { access: isAllAdmins },
      [MenuItem.SetupMetrics]: {
        access: await authorizer.isAuthorized(
          'METRICS/EDIT:VIEW',
          undefined,
          false,
        ),
      },
      [MenuItem.SetupMilestones]: {
        access: userCategory === UserCategories.Employee,
        incubatorFlag: FeatureFlag.milestones,
      },
      [MenuItem.SetupPrograms]: { access: isAllAdmins },
      [MenuItem.SetupStartupsMgt]: {
        access: userCategory === UserCategories.Employee,
      },
      [MenuItem.SetupTaxonomySubMenu]: {
        access: userCategory === UserCategories.Employee,
      },
      [MenuItem.SetupDataAssets]: {
        access:
          isAdmin && (await featureIsActivated(FeatureFlagNames.DataAssets)),
      },
      [MenuItem.StartupTags]: {
        access: tagEditor,
      },
      [MenuItem.MentorTags]: {
        access: isAllAdmins,
      },
      [MenuItem.UserTags]: {
        access: tagEditor,
      },
      [MenuItem.CommunityTags]: {
        access: tagEditor,
      },
      [MenuItem.ApplicationTags]: {
        access: userCategory === UserCategories.Employee,
      },
      [MenuItem.EventTags]: {
        access: tagEditor,
      },
      [MenuItem.FormsTags]: {
        access: tagEditor,
      },
      [MenuItem.OtherTags]: {
        access: tagEditor,
      },
      [MenuItem.UserSkills]: {
        access: userCategory === UserCategories.Employee,
      },
      [MenuItem.EvaluationCriteria]: {
        access: evaluationParamsAccess,
        incubatorFlag: FeatureFlag.editEvaluationCriteria,
      },
      [MenuItem.SetupUserMgt]: { access: isAllAdmins },
      [MenuItem.SetupCourses]: {
        access: await authorizer.isAuthorized(
          'COURSES:MANAGE',
          undefined,
          false,
        ),
        incubatorFlag: FeatureFlag.course,
      },
      [MenuItem.Profile]: { access: true },
      [MenuItem.UserSubMenu]: { access: true },
      [MenuItem.UserIntegration]: { access: !isApplicant },
      [MenuItem.UserAccountDelete]: { access: true },
      [MenuItem.UserCoachingPreferences]: {
        access: userCategory !== UserCategories.Other,
      },
      [MenuItem.UserSecurity]: {
        access: !incubator.featureFlags?.auth0,
      },
      [MenuItem.UserPreferences]: { access: true },
      [MenuItem.UserExport]: { access: true },
      [MenuItem.UserSubMenuSettings]: { access: true },
      [MenuItem.Tasks]: { access: !isApplicant },
      [MenuItem.Resources]: { access: true },
      [MenuItem.Support]: { access: true },
      [MenuItem.Documentation]: { access: true },
      [MenuItem.SupportRequest]: { access: true },
      [MenuItem.ChangeLog]: { access: false },
      [MenuItem.CalendarMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.EventsMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.GeneralMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.ApplicationsMenu]: { access: version !== 1 },
      [MenuItem.StartupsMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.CommunityMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.TrainingMenu]: {
        access: version !== 1 && !isApplicant,
        incubatorFlag: FeatureFlag.course,
      },
      [MenuItem.MyIncubatorEvents]: { access: version !== 1 && !isApplicant },
      [MenuItem.PlanningIncubatorEvents]: {
        access: version !== 1 && canEditOrCreatedEvents,
      },
      [MenuItem.UnpublishedIncubatorEvents]: {
        access: version !== 1 && canEditOrCreatedEvents,
      },
      [MenuItem.StartupAssignation]: { access: version !== 1 && isAllAdmins },
      [MenuItem.UserAssignation]: { access: version !== 1 && isAllAdmins },
      [MenuItem.EmailMenu]: {
        access: version !== 1 && canViewEmailSection,
      },
      [MenuItem.TaskMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.FeedbackMenu]: {
        access: version !== 1 && feedbackPageAccess,
        incubatorFlag: FeatureFlag.feedbackForms,
      },
      [MenuItem.FormsMenu]: {
        access: version !== 1 && canViewForms,
      },
      [MenuItem.ArticlesMenu]: {
        access:
          version !== 1 && isAdmin && userCategory === UserCategories.Employee,
      },
      [MenuItem.OrgSettingsMenu]: { access: version !== 1 && isAdmin },
      [MenuItem.ResourcesMenu]: { access: version !== 1 && !isApplicant },
      [MenuItem.UserTasks]: { access: version !== 1 && !isApplicant },
      [MenuItem.StartupTasks]: {
        access: version !== 1 && userCategory === UserCategories.Employee,
      },
      [MenuItem.EmailDesignTemplates]: {
        access: version !== 1 && isAdmin,
      },
      [MenuItem.EmailContentTemplates]: {
        access:
          version !== 1 &&
          (await authorizer.isAuthorized(
            'EMAIL_BLUEPRINT:MANAGE',
            undefined,
            false,
          )),
      },
      [MenuItem.GeneralMenuSection_1]: { access: version !== 1 },
      [MenuItem.GeneralMenuSection_2]: { access: version !== 1 },
      [MenuItem.GeneralMenuSection_3]: { access: version !== 1 },
      [MenuItem.CalendarMenuSection_1]: { access: version !== 1 },
      [MenuItem.CalendarMenuSection_2]: { access: version !== 1 },
      [MenuItem.EmailMenuSection_1]: { access: version !== 1 },
      [MenuItem.StartupsMenuSection_1]: { access: version !== 1 },
      [MenuItem.StartupsMenuSection_2]: { access: version !== 1 },
      [MenuItem.StartupsMenuSection_3]: { access: version !== 1 },
      [MenuItem.StartupsMenuSection_4]: { access: version !== 1 },
      [MenuItem.CommunityMenuSection_1]: { access: version !== 1 },
      [MenuItem.CommunityMenuSection_2]: { access: version !== 1 },
      [MenuItem.TrainingMenuSection_1]: { access: version !== 1 },
      [MenuItem.TrainingMenuSection_2]: { access: version !== 1 },
      [MenuItem.ResourcesMenuSection_1]: { access: version !== 1 },
      [MenuItem.ResourcesMenuSection_2]: { access: version !== 1 },
      [MenuItem.EventsMenuSection_1]: { access: version !== 1 },
      [MenuItem.TaskMenuSection_1]: { access: version !== 1 },
      [MenuItem.FeedbackMenuSection_1]: { access: version !== 1 },
      [MenuItem.FeedbackMenuSection_2]: { access: version !== 1 },
      [MenuItem.FormsMenuSection_1]: { access: version !== 1 },
      [MenuItem.ArticlesMenuSection_1]: { access: version !== 1 },
      [MenuItem.ArticlesMenuSection_2]: { access: version !== 1 },
      [MenuItem.ApplicationsMenuSection_1]: { access: version !== 1 },
      [MenuItem.ApplicationsMenuSection_2]: { access: version !== 1 },
      [MenuItem.ApplicationsMenuSection_3]: { access: version !== 1 },
      [MenuItem.OrgSettingsMenuSection_1]: { access: version !== 1 },
      [MenuItem.OrgSettingsMenuSection_2]: { access: version !== 1 },
      [MenuItem.OrgSettingsMenuSection_3]: { access: version !== 1 },
      [MenuItem.OrgSettingsMenuSection_4]: { access: version !== 1 },
      [MenuItem.OrgSettingsMenuSection_5]: { access: version !== 1 },
      [MenuItem.UserSubMenuSection_1]: { access: version !== 1 },
      [MenuItem.UserSubMenuSection_2]: { access: version !== 1 },
    };
  }

  private async restrictedMenuItemsForStartup(
    userRole: IUserRole,
    startupId: Types.ObjectId,
    authorizer: Authorization,
  ): Promise<
    Record<
      StartupMenuItem,
      {
        access: boolean;
        incubatorFlag?: FeatureFlag | null;
      }
    >
  > {
    const isApplicant =
      this.matchUserTypes([UserRoleTypes.Applicant], userRole) &&
      !this.matchUserTypes([UserRoleTypes.Cofounder], userRole);

    const startupMilestoneAccess =
      (await authorizer.isAuthorized(
        'STARTUP_MILESTONE:CREATE',
        [{ key: 'startupId', value: String(startupId) }],
        false,
      )) ||
      (await authorizer.isAuthorized(
        'STARTUP_MILESTONE:EDIT',
        [{ key: 'startupId', value: String(startupId) }],
        false,
      ));

    const canViewFeedback =
      (await authorizer.isAuthorized(
        'FEEDBACK_REQUEST:VIEW',
        [{ key: 'startupId', value: String(startupId) || '' }],
        false,
      )) ||
      (await authorizer.isAuthorized(
        'FEEDBACK_ANSWER:VIEW',
        [{ key: 'startupId', value: String(startupId) || '' }],
        false,
      ));

    return {
      [StartupMenuItem.StartupActivities]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupAnalytics]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupCompanyInfo]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupExport]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupFeedback]: {
        access: canViewFeedback,
        incubatorFlag: FeatureFlag.feedbackForms,
      },
      [StartupMenuItem.StartupMilestones]: {
        access: startupMilestoneAccess,
        incubatorFlag: FeatureFlag.milestones,
      },
      [StartupMenuItem.StartupTasks]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupAssessment]: {
        access: !isApplicant,
        incubatorFlag: FeatureFlag.assessment,
      },
      [StartupMenuItem.StartupDocuments]: {
        access: !isApplicant,
      },
      [StartupMenuItem.StartupApplications]: {
        access: !isApplicant,
      },
    };
  }

  private childrenParentRelationship: (
    version: 1 | 2,
    menu: 'SIDEBAR' | 'SITEMAP',
  ) => Map<MenuItem, MenuItem[]> = (
    version: 1 | 2,
    menu: 'SIDEBAR' | 'SITEMAP',
  ) => {
    switch (version) {
      case 1:
        return this.childrenParentRelationshipV1;
      case 2:
        if (menu === 'SIDEBAR') {
          return this.childrenParentRelationshipV2;
        }
        if (menu === 'SITEMAP') {
          return this.sitemap;
        }
        throw new Error('Invalid menu for version 2');
      default:
        throw new Error('Invalid version');
    }
  };

  private sitemap: Map<MenuItem, MenuItem[]> = new Map([
    [MenuItem.CalendarMenuSection_1, [MenuItem.CalendarMenu]],
    [MenuItem.CalendarMenuSection_2, [MenuItem.CalendarMenu]],

    [MenuItem.Calendar, [MenuItem.CalendarMenuSection_1]],
    [MenuItem.Availability, [MenuItem.CalendarMenuSection_1]],
    [
      MenuItem.UserCoachingPreferences,
      [MenuItem.CalendarMenuSection_2, MenuItem.UserSubMenuSection_2],
    ],

    [MenuItem.EmailMenuSection_1, [MenuItem.EmailMenu]],
    [MenuItem.EmailDesignTemplates, [MenuItem.EmailMenuSection_1]],
    [MenuItem.EmailContentTemplates, [MenuItem.EmailMenuSection_1]],

    [MenuItem.StartupsMenuSection_1, [MenuItem.StartupsMenu]],
    [MenuItem.StartupsMenuSection_2, [MenuItem.StartupsMenu]],
    [MenuItem.StartupsMenuSection_3, [MenuItem.StartupsMenu]],
    [MenuItem.StartupsMenuSection_4, [MenuItem.StartupsMenu]],

    [MenuItem.StartupsPortfolio, [MenuItem.StartupsMenuSection_1]],

    [MenuItem.StartupAssignation, [MenuItem.StartupsMenuSection_2]],
    [
      MenuItem.SetupMentorsMgt,
      [MenuItem.StartupsMenuSection_2, MenuItem.CommunityMenuSection_2],
    ],

    [MenuItem.SetupPrograms, [MenuItem.StartupsMenuSection_2]],
    [MenuItem.SetupEvaluationParams, [MenuItem.StartupsMenuSection_2]],
    [MenuItem.SetupMetrics, [MenuItem.StartupsMenuSection_2]],
    [MenuItem.SetupMilestones, [MenuItem.StartupsMenuSection_2]],
    [MenuItem.SetupStartupsMgt, [MenuItem.StartupsMenuSection_3]],
    [MenuItem.SetupCustomFields, [MenuItem.StartupsMenuSection_3]],

    [MenuItem.ApplicationsMenuSection_1, [MenuItem.ApplicationsMenu]],
    [MenuItem.ApplicationsMenuSection_2, [MenuItem.ApplicationsMenu]],
    [MenuItem.ApplicationsMenuSection_3, [MenuItem.ApplicationsMenu]],

    [MenuItem.ApplicationsManager, [MenuItem.ApplicationsMenuSection_1]],
    [MenuItem.ApplicationsOverview, [MenuItem.ApplicationsMenuSection_2]],
    [MenuItem.ApplicationsDashboard, [MenuItem.ApplicationsMenuSection_2]],
    [MenuItem.SetupFunnels, [MenuItem.ApplicationsMenuSection_2]],

    [
      MenuItem.SetupForms,
      [
        MenuItem.ApplicationsMenuSection_3,
        MenuItem.FormsMenuSection_1,
        MenuItem.FeedbackMenuSection_2,
      ],
    ],
    [
      MenuItem.SetupEmails,
      [
        MenuItem.ApplicationsMenuSection_3,
        MenuItem.StartupsMenuSection_4,
        MenuItem.EmailMenuSection_1,
      ],
    ],

    [
      MenuItem.SetupFeedbackRequests,
      [MenuItem.StartupsMenuSection_4, MenuItem.FeedbackMenuSection_1],
    ],

    [MenuItem.CommunityMenuSection_1, [MenuItem.CommunityMenu]],
    [MenuItem.CommunityMenuSection_2, [MenuItem.CommunityMenu]],
    [MenuItem.Community, [MenuItem.CommunityMenuSection_1]],
    [
      MenuItem.SetupUserMgt,
      [MenuItem.CommunityMenuSection_1, MenuItem.OrgSettingsMenuSection_3],
    ],
    [MenuItem.UserAssignation, [MenuItem.CommunityMenuSection_2]],

    [MenuItem.TrainingMenuSection_1, [MenuItem.TrainingMenu]],
    [MenuItem.TrainingMenuSection_2, [MenuItem.TrainingMenu]],

    [
      MenuItem.Course,
      [MenuItem.TrainingMenuSection_1, MenuItem.ArticlesMenuSection_2],
    ],
    [MenuItem.SetupCourses, [MenuItem.TrainingMenuSection_2]],
    [
      MenuItem.SetupArticles,
      [
        MenuItem.TrainingMenuSection_2,
        MenuItem.ResourcesMenuSection_2,
        MenuItem.ArticlesMenuSection_1,
      ],
    ],

    [MenuItem.ResourcesMenuSection_1, [MenuItem.ResourcesMenu]],
    [MenuItem.ResourcesMenuSection_2, [MenuItem.ResourcesMenu]],

    [
      MenuItem.Resources,
      [MenuItem.ResourcesMenuSection_1, MenuItem.ArticlesMenuSection_2],
    ],

    [MenuItem.EventsMenuSection_1, [MenuItem.EventsMenu]],
    [MenuItem.IncubatorEvents, [MenuItem.EventsMenuSection_1]],
    [MenuItem.MyIncubatorEvents, [MenuItem.EventsMenuSection_1]],
    [MenuItem.PlanningIncubatorEvents, [MenuItem.EventsMenuSection_1]],
    [MenuItem.UnpublishedIncubatorEvents, [MenuItem.EventsMenuSection_1]],

    [MenuItem.TaskMenuSection_1, [MenuItem.TaskMenu]],
    [MenuItem.Tasks, [MenuItem.TaskMenuSection_1]],
    [MenuItem.UserTasks, [MenuItem.TaskMenuSection_1]],
    [MenuItem.StartupTasks, [MenuItem.TaskMenuSection_1]],

    [MenuItem.FeedbackMenuSection_1, [MenuItem.FeedbackMenu]],
    [MenuItem.FeedbackMenuSection_2, [MenuItem.FeedbackMenu]],

    [MenuItem.FormsMenuSection_1, [MenuItem.FormsMenu]],

    [MenuItem.ArticlesMenuSection_1, [MenuItem.ArticlesMenu]],
    [MenuItem.ArticlesMenuSection_2, [MenuItem.ArticlesMenu]],

    [MenuItem.OrgSettingsMenuSection_1, [MenuItem.OrgSettingsMenu]],
    [MenuItem.OrgSettingsMenuSection_2, [MenuItem.OrgSettingsMenu]],
    [MenuItem.OrgSettingsMenuSection_3, [MenuItem.OrgSettingsMenu]],
    [MenuItem.OrgSettingsMenuSection_4, [MenuItem.OrgSettingsMenu]],
    [MenuItem.OrgSettingsMenuSection_5, [MenuItem.OrgSettingsMenu]],

    [MenuItem.OrgGeneralSettings, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgCustomDomain, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgMentorMatching, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgBrandingSettings, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgMetricsCollection, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgPermissions, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgSeoSettings, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgUserRoleSettings, [MenuItem.OrgSettingsMenuSection_1]],
    [MenuItem.OrgCurrentPlan, [MenuItem.OrgSettingsMenuSection_2]],
    [MenuItem.SetupTaxonomySubMenu, [MenuItem.OrgSettingsMenuSection_4]],
    [MenuItem.SetupIndustries, [MenuItem.OrgSettingsMenuSection_4]],
    [MenuItem.ActivityFeed, [MenuItem.OrgSettingsMenuSection_5]],

    [MenuItem.UserSubMenuSection_1, [MenuItem.UserSubMenu]],
    [MenuItem.UserSubMenuSection_2, [MenuItem.UserSubMenu]],
    [MenuItem.UserPreferences, [MenuItem.UserSubMenuSection_1]],
    [MenuItem.UserSecurity, [MenuItem.UserSubMenuSection_1]],
    [MenuItem.UserIntegration, [MenuItem.UserSubMenuSection_1]],
    [MenuItem.UserAccountDelete, [MenuItem.UserSubMenuSection_1]],

    [MenuItem.UserTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.EventTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.FormsTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.MentorTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.StartupTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.CommunityTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.ApplicationTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.OtherTags, [MenuItem.SetupTaxonomySubMenu]],
  ]);

  private childrenParentRelationshipV1: Map<MenuItem, MenuItem[]> = new Map([
    [MenuItem.OrgCustomDomain, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgBrandingSettings, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgCurrentPlan, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgGeneralSettings, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgMentorMatching, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgMetricsCollection, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgPermissions, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgSeoSettings, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.OrgUserRoleSettings, [MenuItem.OrgSettingsSubMenu]],
    [MenuItem.SetupArticles, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupCustomFields, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupEmails, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupEvaluationParams, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupFeedbackRequests, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupForms, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupFunnels, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupIndustries, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.SetupMentorsMgt, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupMetrics, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupMilestones, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupPrograms, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupStartupsMgt, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupTaxonomySubMenu, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupDataAssets, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupCourses, [MenuItem.SetupSubMenu]],
    [MenuItem.SetupUserMgt, [MenuItem.SetupSubMenu]],
    [MenuItem.Profile, [MenuItem.UserSubMenu]],
    [MenuItem.Availability, [MenuItem.UserSubMenu]],
    [MenuItem.Calendar, [MenuItem.UserSubMenu]],
    [MenuItem.UserSubMenuSettings, [MenuItem.UserSubMenu]],
    [MenuItem.UserExport, [MenuItem.UserSubMenu]],
    [MenuItem.UserIntegration, [MenuItem.UserSubMenuSettings]],
    [MenuItem.UserAccountDelete, [MenuItem.UserSubMenuSettings]],
    [MenuItem.UserCoachingPreferences, [MenuItem.UserSubMenuSettings]],
    [MenuItem.UserSecurity, [MenuItem.UserSubMenuSettings]],
    [MenuItem.UserPreferences, [MenuItem.UserSubMenuSettings]],
    [MenuItem.StartupTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.MentorTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.UserTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.CommunityTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.ApplicationTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.EventTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.FormsTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.OtherTags, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.UserSkills, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.EvaluationCriteria, [MenuItem.SetupTaxonomySubMenu]],
    [MenuItem.Documentation, [MenuItem.Support]],
    [MenuItem.SupportRequest, [MenuItem.Support]],
    [MenuItem.ChangeLog, [MenuItem.Support]],
  ]);

  private childrenParentRelationshipV2: Map<MenuItem, MenuItem[]> = new Map([
    [MenuItem.Profile, [MenuItem.GeneralMenuSection_1]],
    [MenuItem.ActivityFeed, [MenuItem.GeneralMenuSection_1]],
    [MenuItem.Tasks, [MenuItem.GeneralMenuSection_1]],
    [MenuItem.SetupFunnels, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupCourses, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupForms, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupFeedbackRequests, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupCustomFields, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupEmails, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.SetupTaxonomySubMenu, [MenuItem.GeneralMenuSection_2]],
    [MenuItem.OrgGeneralSettings, [MenuItem.GeneralMenuSection_3]],
  ]);

  public async getMenuItemForUserRole({
    incubatorId,
    userRole,
    user,
    authorizer,
    version,
    menu,
  }: {
    incubatorId: Types.ObjectId;
    userRole: IUserRole;
    user: IUser;
    authorizer;
    version: 1 | 2;
    menu: 'SIDEBAR' | 'SITEMAP';
  }): Promise<
    {
      name: MenuItem;
      locked: boolean; // feature flag
      subMenu: {
        name: MenuItem;
        locked: boolean;
      }[];
    }[]
  > {
    const incubator = await getIncubatorById(incubatorId, {
      cache: true,
    });
    if (!incubator) {
      throw new NotFoundError({ message: 'Incubator not found' });
    }

    const menuConfig = await this.restrictedMenuItems(
      userRole,
      user,
      authorizer,
      incubator,
      version,
    );

    const childrenParentRelationship = this.childrenParentRelationship(
      version,
      menu,
    );

    logger.debug('restrictedMenuItemsForStartup:: menuConfig', menuConfig);

    const incubatorFeatureFlags = incubator.featureFlags;
    if (!incubatorFeatureFlags) {
      throw new NotFoundError({ message: 'Incubator feature flags not found' });
    }

    const parentOfChildIsAccessible = item => {
      const parents: MenuItem[] | undefined =
        childrenParentRelationship.get(item);
      return !parents || parents.some(parent => menuConfig[parent].access);
    };

    const filteredMenuItems: MenuItem[] = Object.values(MenuItem).filter(
      mItem => menuConfig[mItem].access && parentOfChildIsAccessible(mItem),
    );

    const allChildren: Set<MenuItem> = new Set(
      [...childrenParentRelationship.keys()].filter(child =>
        filteredMenuItems.includes(child),
      ),
    );
    const childrenOfParent = (parent: MenuItem): MenuItem[] =>
      Array.from(allChildren).filter(mItem =>
        childrenParentRelationship.get(mItem)?.includes(parent),
      );

    const isLocked = (item: MenuItem): boolean => {
      const featureFlag = menuConfig[item].incubatorFlag;
      if (featureFlag) {
        return !incubatorFeatureFlags[featureFlag];
      }
      return false;
    };

    function buildItemOrSubMenu(
      parent: MenuItem,
    ): { name: MenuItem; locked: boolean }[] {
      return childrenOfParent(parent).map(children => ({
        name: children,
        locked: isLocked(children),
        subMenu: buildItemOrSubMenu(children),
      }));
    }

    const parents: Set<MenuItem> = new Set(
      [...childrenParentRelationship.values()]
        .flat()
        .filter(parent => filteredMenuItems.includes(parent)),
    );

    let onlyTopLevelMenuItems: MenuItem[];

    switch (version) {
      case 1:
        onlyTopLevelMenuItems = filteredMenuItems.filter(
          menuItem => !childrenParentRelationship.has(menuItem),
        );
        break;
      case 2:
      default:
        onlyTopLevelMenuItems = Array.from(parents).filter(
          menuItem => !childrenParentRelationship.has(menuItem),
        );
    }

    const topLevelMenu: {
      subMenu:
        | {
            name: MenuItem;
            locked: boolean;
          }[];
      name: MenuItem;
      locked: boolean;
    }[] = onlyTopLevelMenuItems.map(tpLevel => ({
      name: tpLevel,
      locked: isLocked(tpLevel),
      subMenu: buildItemOrSubMenu(tpLevel),
    }));

    return topLevelMenu;
  }

  public async getStartupMenuItemForUserRole({
    incubatorId,
    userRole,
    startupId,
    authorizer,
  }: {
    incubatorId: Types.ObjectId;
    userRole: IUserRole;
    startupId: Types.ObjectId;
    authorizer: Authorization;
  }): Promise<
    {
      name: StartupMenuItem;
      locked: boolean;
    }[]
  > {
    const menuConfig = await this.restrictedMenuItemsForStartup(
      userRole,
      startupId,
      authorizer,
    );

    const incubator = await incubatorRepository.getById(incubatorId);
    if (!incubator) {
      throw new NotFoundError({ message: 'Incubator not found' });
    }

    const incubatorFeatureFlags = incubator.featureFlags;
    if (!incubatorFeatureFlags) {
      throw new NotFoundError({ message: 'Incubator feature flags not found' });
    }

    const filteredMenuItems: StartupMenuItem[] = Object.values(
      StartupMenuItem,
    ).filter(mItem => menuConfig[mItem].access);

    const isLocked = (item: StartupMenuItem): boolean => {
      const featureFlag = menuConfig[item].incubatorFlag;
      if (featureFlag) {
        return !incubatorFeatureFlags[featureFlag];
      }
      return false;
    };

    return filteredMenuItems.map(tpLevel => ({
      name: tpLevel,
      locked: isLocked(tpLevel),
    }));
  }
}
