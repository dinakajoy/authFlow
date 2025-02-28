import mongoose, { Types } from 'mongoose';
import { Container } from 'typedi';
import logger from '../helpers/logging';
import EmailContent from '../api/emailContent/email.content.model';
import { IUser } from '../api/user/user.interfaces';
import { IUserRole } from '../api/userRole/userRole.interfaces';
import { ICategory } from '../api/category/category.interfaces';
import { IIncubatorEvent } from '../api/incubatorEvent/incubator.event.interfaces';

import {
  UserRoles,
  IncubatorEventTypes,
  PermissionCriteriaTypes,
  AccessPermissionTypes,
} from '../constants';

import {
  UserRepository,
  StartupRepository,
  IncubatorRepository,
  IncubatorEventRepository,
  CategoryRepository,
  CoachingSessionRepository,
  ProgramRepository,
  ApplicationRepository,
  NoteRepository,
} from '../repositories';

import { ForbiddenError, PermissionError } from '../graph/errors';

import { UserService } from '../services/users';

import { isUserAssignedAsCategoryAdmin } from '../services/applications/helpers/isUserAssignedAsCategoryAdmin';
import { hasCategoryPermission } from '../services/services.category';
import { UserRoleService } from '../services/userRole/userRole.service';
import {
  isUserAssignedToStartup,
  userIsCofounderOfStartup,
} from '../services/users/helpers/isUserAssignedToStartup';
import { AssignedStartupsService, StartupService } from '../services/startups';

import { StartupProcessor } from '../graph/startup/processors';
import * as TaskService from '../services/services.task';
import { IIncubator } from '../api/incubator/incubator.interfaces';
import { IncubatorEventPermission } from '../services/incubatorEvents/services.incubator.event.permission';
import { isFormCreator } from '../services/forms/services.form';
import { LearningManagementSystemService } from '../services/lms/lms.service';
import { CourseTeamRole } from '../api/lms/course.interface';

import * as FormAssignmentServices from '../services/services.form.assignment';
import * as FormSubmissionRequestService from '../services/services.form.submission.request';
import { FormProcessor } from '../graph/form/processors';
import { Modify } from '../interfaces';
import { IApplication } from '../api/application/application.interfaces';
import { toObjectId } from '../config/mongoose';
import { StartupPermissions } from '../resolver-types';
import { IncubatorService } from '../services/incubators';

const userRepository = Container.get(UserRepository);
const userRoleService = Container.get(UserRoleService);
const incubatorRepository = Container.get(IncubatorRepository);
const startupRepository = Container.get(StartupRepository);
const incubatorEventRepository = Container.get(IncubatorEventRepository);
const incubatorEventPermission = Container.get(IncubatorEventPermission);
const categoryRepository = Container.get(CategoryRepository);
const coachingSessionRepository = Container.get(CoachingSessionRepository);
const courseRepository = Container.get(LearningManagementSystemService);
const programRepository = Container.get(ProgramRepository);
const applicationRepository = Container.get(ApplicationRepository);
const noteRepository = Container.get(NoteRepository);
export class Authorization {
  private currentUser: Pick<
    Modify<IUser, { _id: string | Types.ObjectId }>,
    '_id' | 'incubator' | 'startups' | 'assignedStartups' | 'role'
  >;

  private role: Modify<IUserRole, { _id: string | Types.ObjectId }>;

  private incubatorId: Types.ObjectId;

  constructor(
    incubatorId?: Types.ObjectId,
    currentUser?: Pick<
      Modify<IUser, { _id: string | Types.ObjectId }>,
      '_id' | 'incubator' | 'startups' | 'assignedStartups' | 'role'
    >,
    role?: Modify<IUserRole, { _id: string | Types.ObjectId }>,
  ) {
    if (currentUser) {
      this.currentUser = currentUser;
    }

    if (role) {
      this.role = role;
    }

    if (incubatorId) {
      this.incubatorId = incubatorId;
    }
  }

  private roleTypeMatch(allowedUsedRoles: UserRoles[]) {
    return allowedUsedRoles.some(allowedRole =>
      this.role.type.includes(allowedRole),
    );
  }

  public findUserPermission(permission: string) {
    return this.role.permissions.find(
      userPermission => userPermission.key === permission,
    );
  }

  private categoryPermission(
    funnel: Pick<ICategory, 'people' | 'admin'>,
  ): boolean {
    if (!this.currentUser) {
      throw new Error(
        'Requires Authenticated to have current user and does not',
      );
    }
    return (
      (funnel.people.some(
        userId => String(userId) === String(this.currentUser._id),
      ) ||
        (funnel.admin &&
          funnel.admin?.some(
            userId => String(userId) === String(this.currentUser._id),
          ))) ??
      false
    );
  }

  public checkApplicationBasedPermission = async (
    funnelId: string | Types.ObjectId,
  ): Promise<boolean> => {
    const funnel: ICategory | null = await categoryRepository.findById(
      funnelId,
    );

    if (!funnel) {
      logger.error(`Funnel not found for id ${funnelId}`);
      return false;
    }

    return this.categoryPermission(funnel);
  };

  private checkStartupBasedPermission = async (
    permission: string,
    startupId: string,
  ): Promise<boolean> => {
    if (!startupId) {
      return false;
    }

    if (
      this.findUserPermission(permission)?.permissionCriteria ===
      PermissionCriteriaTypes.ALL
    ) {
      return true;
    }

    if (
      this.findUserPermission(permission)?.permissionCriteria ===
      PermissionCriteriaTypes.ASSIGNED
    ) {
      return this.hasStartupAccess(startupId);
    }

    return false;
  };

  private evaluatePermissionCriteria = (
    permission: string,
    hasStartupAccess: boolean,
  ): boolean => {
    if (
      this.findUserPermission(permission)?.permissionCriteria ===
      PermissionCriteriaTypes.ALL
    ) {
      return true;
    }

    // TODO: Change this to has an assigned permission
    if (permission === 'STARTUP_FILE:VIEW') {
      return hasStartupAccess;
    }

    if (
      this.findUserPermission(permission)?.permissionCriteria ===
      PermissionCriteriaTypes.ASSIGNED
    ) {
      return hasStartupAccess;
    }
    return false;
  };

  public async startupPermissions(
    startupId: string,
  ): Promise<StartupPermissions> {
    const permissionsObject: StartupPermissions = {};

    const startupAssignationPermission = {
      viewFile: 'STARTUP_FILE:VIEW',
      viewTags: 'TAGS:STARTUP:VIEW',
      addTags: 'TAG:STARTUP:ADD',
      removeTags: 'TAG:STARTUP:REMOVE',
      viewIndustries: 'INDUSTRIES:VIEW',
      addIndustries: 'INDUSTRIES:STARTUP:ADD',
      removeIndustries: 'INDUSTRIES:STARTUP:REMOVE',
      editStartupName: 'STARTUP/NAME:EDIT',
      editStartupConnections: 'STARTUP/ASSIGNATION_MEMBERS:EDIT',
      createMilestonesPlan: 'STARTUP_MILESTONE:CREATE',
      editMilestonesPlan: 'MILESTONE:MANAGE',
      viewFeedbackRequests: 'FEEDBACK_ANSWER:VIEW',
      deleteStartups: 'STARTUP:DELETE',
      exportCoachingSession: 'COACHING_SESSION:EXPORT',
      deleteCoachingSession: 'COACHING_SESSION:DELETE',
    };

    const userIsAssignedToStartup = await this.hasStartupAccess(startupId);

    for (const [permissionValue, permissionKey] of Object.entries(
      startupAssignationPermission,
    )) {
      permissionsObject[permissionValue] = this.evaluatePermissionCriteria(
        permissionKey,
        userIsAssignedToStartup,
      );
    }

    return permissionsObject;
  }

  private hasStartupAccess = async (startupId: string): Promise<boolean> => {
    const startup = await startupRepository.getById(toObjectId(startupId));

    if (!startup) {
      logger.error(`Startup not found for id ${startupId}`);
      return false;
    }

    return (
      userIsCofounderOfStartup(this.currentUser, startup) ||
      isUserAssignedToStartup(this.currentUser, startup)
    );
  };

  private hasCofounderAccess = async (startupId: Types.ObjectId) => {
    const startup = await startupRepository.getById(startupId);

    if (!startup) {
      logger.error(`Startup not found for id ${startupId}`);
      return false;
    }

    return userIsCofounderOfStartup(this.currentUser, startup);
  };

  private hasFeedbackRequestAccess = async (
    feedbackRequestId: string | Types.ObjectId,
  ) => {
    const feedbackRequest =
      await FormSubmissionRequestService.getFormSubmissionRequest(
        this.currentUser,
        feedbackRequestId,
      );

    if (!feedbackRequest) {
      logger.error(`Feedback request not found for id ${feedbackRequestId}`);
      return false;
    }

    return (
      userRoleService.isPaidUserRole(this.role) &&
      String(feedbackRequest.createdBy) === String(this.currentUser._id)
    );
  };

  public isPermissionCriteriaAll(permission: string | string[]): boolean {
    if (Array.isArray(permission)) {
      return permission.some(p => {
        const userPermission = this.findUserPermission(p);
        return (
          userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL
        );
      });
    }

    if (typeof permission === 'string') {
      const userPermission = this.findUserPermission(permission);
      return userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL;
    }

    return false;
  }

  public isPermissionCriteriaAssigned(permission: string | string[]): boolean {
    if (Array.isArray(permission)) {
      return (
        !permission.some(p => {
          const userPermission = this.findUserPermission(p);
          return (
            userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL
          );
        }) &&
        permission.some(p => {
          const userPermission = this.findUserPermission(p);
          return (
            userPermission?.permissionCriteria ===
            PermissionCriteriaTypes.ASSIGNED
          );
        })
      );
    }

    if (typeof permission === 'string') {
      const userPermission = this.findUserPermission(permission);
      return (
        userPermission?.permissionCriteria === PermissionCriteriaTypes.ASSIGNED
      );
    }

    return false;
  }

  public async checkAuthorization(
    permission,
    data?: {
      key: string;
      value: string;
    }[],
  ) {
    const values: {
      startupId?: string;
      userId?: string | Types.ObjectId;
      funnelId?: string | Types.ObjectId;
      formId?: string | Types.ObjectId;
      taskId?: string | Types.ObjectId;
      incubatorId?: string | Types.ObjectId;
      eventId?: string | Types.ObjectId;
      coachingSessionId?: string | Types.ObjectId;
      courseId?: string | Types.ObjectId;
      evaluationAssignmentId?: string | Types.ObjectId;
      feedbackRequestId?: string | Types.ObjectId;
      feedbackRequestRecipientId?: string | Types.ObjectId;
      isAssigned?: string;
      applicationId?: string | Types.ObjectId;
      rejectionEmailId?: string | Types.ObjectId;
      noteId?: string;
    } =
      data?.reduce((acc, item) => ({ ...acc, [item.key]: item.value }), {}) ??
      {};

    const userPermission = await this.findUserPermission(permission);

    if (userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL) {
      return true;
    }

    switch (permission) {
      case 'APPLICATION_OVERVIEW/BATCH/ACTION_CTAS:VIEW': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (!values.funnelId) {
            logger.error(
              `Missing funnelId criteria for ${permission} permission`,
            );
            return false;
          }
          const category: ICategory | null = await categoryRepository.findById(
            values.funnelId,
          );

          if (category === null) {
            logger.error(
              `Category not found for id ${values.funnelId} in permission ${permission}`,
            );
            return false;
          }

          return isUserAssignedAsCategoryAdmin({
            category,
            userId: this.currentUser._id as Types.ObjectId,
          });
        }

        return false;
      }

      case 'AVAILABILITY:EDIT': {
        if (String(this.currentUser._id) === String(values.userId)) {
          return true;
        }

        return false;
      }

      case 'FUNNEL:DELETE':
      case 'FUNNEL:EDIT': {
        if (userRoleService.isPaidUserRole(this.role)) {
          if (!values.funnelId) {
            logger.error(
              `Missing funnelId criteria for ${permission} permission`,
            );
            return false;
          }

          return hasCategoryPermission(
            this.currentUser,
            String(values.funnelId),
          );
        }
        return false;
      }

      case 'FUNNELS:VIEW:LIST': {
        return userRoleService.isPaidUserRole(this.role);
      }

      case 'STARTUP_FILE:VIEW': {
        // Checks if the current user is a cofounder of the startup
        const { startups } = this.currentUser;
        if (startups?.some(s => String(s) === String(values?.startupId))) {
          return true;
        }

        // Checks if the current user is a connection to the startup
        const { assignedStartups } = this.currentUser;
        if (
          (assignedStartups || []).some(
            s => String(s) === String(values?.startupId),
          )
        ) {
          return true;
        }

        // Checks if current user is assigned to the startup
        if (values.startupId) {
          const ids = await StartupProcessor.getAllAssignedAdmin(
            values.startupId,
          );

          if (ids.some(id => String(id) === String(this.currentUser._id))) {
            return true;
          }
        }

        return false;
      }

      case 'USER_PROFILE/SOCIAL_MEDIA:VIEW': {
        /**
         * If current user is staff, coach, admin&coach or admin, then they can see the social media info of all profiles
         * If current user is cofounder/community member then they can see only the contact information of those profile where they are assigned
         */
        const profileUser = await userRepository.findOne({
          _id: values.userId,
          incubator: this.incubatorId,
        });

        if (!profileUser) {
          throw new Error('User not found');
        }
        const profileUserRole = await userRoleService.getUserRoleById(
          profileUser?.role,
        );

        if (!profileUserRole) {
          throw new Error('User role not found');
        }

        // If user is an assigned admin to a startup, they can see user's profile
        const subAdminStartups = this.currentUser.startups || [];
        const ids = await Promise.all(
          subAdminStartups.map(startupId =>
            StartupProcessor.getAllAssignedAdmin(startupId),
          ),
        );

        const currentUserStartupsIds = (
          (this.currentUser.startups as Types.ObjectId[]) || []
        ).map(String);
        const profileUserAssignedStartupsIds = (
          profileUser.assignedStartups || []
        ).map(String);

        if (
          ids?.flat().includes(profileUser._id.toString()) ||
          currentUserStartupsIds.some(value =>
            profileUserAssignedStartupsIds.includes(value),
          )
        ) {
          return true;
        }

        if (
          currentUserStartupsIds.some(value =>
            profileUserAssignedStartupsIds.includes(value),
          )
        ) {
          return true;
        }

        return false;
      }

      case 'PROFILE/BOOK_MEETING_CTA:VIEW': {
        /**
         * Current user can only see the schedule meeting button if its role is
         * cofounder/community member and the target user profile is:
         * - any staff, coach, admin&coach or admin
         * - expert/mentor if the expert/mentor is assigned to the cofounder's startup
         */
        if (
          !this.role.type.includes(UserRoles.Cofounder) &&
          !this.role.type.includes(UserRoles.CommunityMember)
        ) {
          return false;
        }

        if (!userPermission) {
          return false;
        }

        if (!values.userId) {
          logger.error(`
            Missing userId criteria for ${permission} permission
          `);
          return false;
        }

        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          const profileUser = await userRepository.findById(
            new Types.ObjectId(values.userId),
          );
          if (this.role.type.includes(UserRoles.SubAdmin)) {
            const subAdminStartups = this.currentUser.startups || [];
            const ids = await Promise.all(
              subAdminStartups.map(startupId =>
                StartupProcessor.getAllAssignedAdmin(startupId),
              ),
            );

            const currentUserStartupsIds = (
              (this.currentUser.startups as Types.ObjectId[]) || []
            ).map(String);
            const profileUserAssignedStartupsIds = (
              profileUser?.assignedStartups || []
            ).map(String);

            return (
              ids?.flat().includes(this.role._id.toString()) ||
              currentUserStartupsIds.some(value =>
                profileUserAssignedStartupsIds.includes(value),
              )
            );
          }

          if (this.roleTypeMatch([UserRoles.Expert, UserRoles.Mentor])) {
            const currentUserStartupsIds = (
              (this.currentUser.startups as Types.ObjectId[]) || []
            ).map(String);
            const profileUserAssignedStartupsIds = (
              profileUser?.assignedStartups || []
            ).map(String);

            return currentUserStartupsIds.some(value =>
              profileUserAssignedStartupsIds.includes(value),
            );
          }
        }

        return false;
      }

      case 'FORM:EDIT': {
        if (values.formId) {
          if (
            await isFormCreator(this.currentUser._id, String(values?.formId))
          ) {
            return true;
          }
        }

        return false;
      }

      case 'APPLICATION_DASHBOARD':
      case 'APPLICATION_FLOW:EDIT':
      case 'APPLICATION_FLOW:VIEW': {
        if (values.funnelId && userRoleService.isPaidUserRole(this.role)) {
          return this.checkApplicationBasedPermission(values.funnelId);
        }
        return false;
      }

      case 'APPLICATION/DECIDE_ROUND:VIEW': {
        if (
          userPermission?.permissionCriteria ===
            PermissionCriteriaTypes.ASSIGNED &&
          values.funnelId &&
          userRoleService.isPaidUserRole(this.role)
        ) {
          return this.checkApplicationBasedPermission(values.funnelId);
        }
        return false;
      }
      case 'APPLICATION:DELETE': {
        if (values.applicationId) {
          const incubator = await IncubatorService.getIncubatorById(
            this.incubatorId,
            { cache: true },
          );

          if (!incubator) {
            return false;
          }

          if (incubator.allowUserSelfDelete) {
            const application = await applicationRepository.findById(
              toObjectId(values.applicationId),
            );

            if (!application) {
              return false;
            }

            return (
              String(this.currentUser._id) === String(application.createdBy)
            );
          }
        }
        if (
          userPermission?.permissionCriteria ===
            PermissionCriteriaTypes.ASSIGNED &&
          values.funnelId &&
          userRoleService.isPaidUserRole(this.role)
        ) {
          return this.checkApplicationBasedPermission(values.funnelId);
        }
        return false;
      }

      case 'TASK/TASK:DELETE': {
        if (!values.taskId) {
          logger.error(`Missing taskId criteria for ${permission}`);
          return false;
        }

        return TaskService.isUserAuthorizedToDeleteTask(
          this.currentUser,
          this.role,
          values.taskId,
        );
      }

      case 'STARTUP/NAME:EDIT': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          let startup;
          if (values.startupId) {
            startup = await startupRepository.getById(
              new Types.ObjectId(values.startupId),
            );

            const { startups } = this.currentUser;

            if (!startup) {
              logger.error(
                `Startup not found for id ${values.startupId} in ${permission} permission`,
              );
              return false;
            }

            if (startups.map(s => String(s)).includes(String(startup._id))) {
              return true;
            }

            // Checks if user is a connection to the startup
            const { assignedStartups } = this.currentUser;

            return (assignedStartups || [])
              .map(s => String(s))
              .includes(String(startup._id));
          }
        }

        return false;
      }

      case 'STARTUP:DELETE': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (values.startupId) {
            const startup = await startupRepository.getById(
              toObjectId(values.startupId),
            );

            if (!startup) {
              logger.error(
                `Startup not found for id ${values.startupId} in ${permission} permission`,
              );
              return false;
            }

            return StartupService.hasStartupDeletePermission(
              {
                _id: toObjectId(this.currentUser._id),
                startups: this.currentUser.startups,
              },
              this.role,
              startup,
            );
          }

          return false;
        }
        logger.error(`Missing startupId criteria for ${permission} permission`);
        return false;
      }

      case 'INDUSTRIES:STARTUP:ADD':
      case 'INDUSTRIES:STARTUP:REMOVE':
      case 'TAG:STARTUP:REMOVE':
      case 'TAG:STARTUP:ADD':
      case 'STARTUP/ASSIGNATION_MEMBERS:EDIT': {
        return this.checkStartupBasedPermission(
          permission,
          values.startupId ? values.startupId : '',
        );
      }

      case 'TAGS:STARTUP:VIEW':
      case 'STARTUP:INDUSTRY:VIEW': {
        const tagPermission = await this.findUserPermission(permission);
        if (
          !values.startupId &&
          values.isAssigned &&
          tagPermission?.permissionCriteria === PermissionCriteriaTypes.ASSIGNED
        ) {
          return true;
        }
        return this.checkStartupBasedPermission(
          permission,
          values.startupId ? values.startupId : '',
        );
      }

      case 'USER:EDIT': {
        if (String(this.currentUser._id) === String(values.userId)) {
          return true;
        }

        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          const targetUser = await userRepository.findOne({
            _id: values.userId,
            incubator: this.incubatorId,
          });

          if (!targetUser) {
            logger.error(
              `User not found for id ${values.userId} in ${permission} permission`,
            );
            return false;
          }
          const targetUserStartupIds = targetUser?.startups || [];

          if (targetUserStartupIds.length > 0) {
            const assignedStartupIdsForCurrentUser =
              await AssignedStartupsService.getAssignedStartupsIdsForUser(
                this.currentUser,
              );

            if (
              targetUserStartupIds
                .map(String)
                .some(userStartup =>
                  assignedStartupIdsForCurrentUser
                    .map(String)
                    .includes(userStartup),
                )
            ) {
              return true;
            }
          }
        }

        return false;
      }

      case 'EVENT:CREATE': {
        const incubator = await incubatorRepository.getById(this.incubatorId);

        if (
          incubator?.usersEventPermission.some(
            user => String(user) === String(this.currentUser._id),
          )
        ) {
          return true;
        }

        const subadminAssignations =
          await UserService.getAssignedCategoriesProgramsIdsForSubadmin(
            this.incubatorId,
            this.currentUser._id,
          );

        if (subadminAssignations?.programs.length === 0) {
          return false;
        }
        return true;
      }

      case 'EVENT:DELETE':
      case 'EVENT:EDIT': {
        if (!values.eventId) {
          logger.error(`Missing eventId criteria for ${permission}`);
          return false;
        }

        // current user is the creator therefore has edit access
        const event: IIncubatorEvent | null =
          await incubatorEventRepository.getById(
            new mongoose.Types.ObjectId(values.eventId),
          );

        if (!event) {
          logger.error(
            `Event not found for id ${values.eventId} in ${permission} permission`,
          );
          return false;
        }

        if (String(event.createdBy) === String(this.currentUser._id)) {
          return true;
        }

        // user has direct access to edit this event
        if (
          incubatorEventPermission.hasEventSpecificPermission(
            event,
            this.currentUser,
          )
        ) {
          return true;
        }

        // if it is a one on one and the host is the current user
        if (
          [
            IncubatorEventTypes.OneOnOneGeneral,
            IncubatorEventTypes.OneOnOneSpecific,
          ].includes(event.eventType) &&
          event.hosts?.length > 0 &&
          event.hosts.map(String).includes(this.currentUser._id.toString())
        ) {
          return true;
        }

        const incubator: Pick<IIncubator, 'usersEventPermission'> | null =
          await incubatorRepository.getById(this.incubatorId);

        if (!incubator) {
          logger.error(
            `incubator not found for id ${this.incubatorId} in ${permission} permission`,
          );
          return false;
        }

        // That user has edit access to all events of this incubator
        if (
          incubatorEventPermission.hasUserSpecificPermission(
            incubator,
            this.currentUser,
          )
        ) {
          return true;
        }

        return false;
      }

      case 'STARTUP_MILESTONE:EDIT':
      case 'STARTUP_MILESTONE:CREATE': {
        /**
         * Cofounder roles are not assigned this permission, so
         * should allow them to create startup milestones without this permissions
         */
        if (!userPermission) {
          if (values.startupId) {
            return this.hasCofounderAccess(values.startupId);
          }
        }

        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (values.startupId) {
            return this.checkStartupBasedPermission(
              permission,
              values.startupId,
            );
          }
        }

        return false;
      }

      case 'COURSES:MANAGE': {
        /**
         * Return true for the following cases:
         * User is creator of course
         * User is part of the course team
         */
        if (userRoleService.isPaidUserRole(this.role)) {
          if (!values.courseId) {
            const coursesWithCurrentUserAsTeamMember =
              await courseRepository.findCourse({
                team: {
                  $elemMatch: {
                    user: this.currentUser._id,
                  },
                },
              });

            const coursesCreatedByCurrentUser =
              await courseRepository.findCourse({
                createdBy: this.currentUser._id,
              });

            if (
              coursesWithCurrentUserAsTeamMember.length > 0 ||
              coursesCreatedByCurrentUser.length > 0
            ) {
              return true;
            }
          }

          const course = await courseRepository.findCourseById({
            courseId: String(values.courseId),
            incubatorId: this.incubatorId,
          });

          if (!course) {
            logger.error(
              `Course not found for id ${values.courseId} in ${permission} permission`,
            );
            return false;
          }

          if (String(course.createdBy) === String(this.currentUser._id)) {
            return true;
          }

          if (
            course.team.some(
              teamMember =>
                String(teamMember.user) === String(this.currentUser._id) &&
                teamMember.role === CourseTeamRole.ADMIN,
            )
          ) {
            return true;
          }
        }
        return false;
      }

      case 'COACHING_SESSION:DELETE': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (values.coachingSessionId) {
            const coachingSession = await coachingSessionRepository.findById(
              values.coachingSessionId,
            );

            if (!coachingSession) {
              logger.error(
                `Coaching session not found for id ${values.coachingSessionId} in ${permission} permission`,
              );
              return false;
            }

            if (
              String(coachingSession.sessionStartedBy) ===
              String(this.currentUser._id)
            ) {
              return true;
            }

            if (
              coachingSession.coachs?.some(
                coach => String(coach) === String(this.currentUser._id),
              )
            ) {
              return true;
            }
          }
        }

        return false;
      }

      case 'COACHING_SESSION:EXPORT': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (userRoleService.isPaidUserRole(this.role)) {
            /**
             * If exporting all coaching sessions in a startup by clicking
             * "Export Coaching Sessions" button in startup page
             */
            if (values.startupId) {
              return this.hasStartupAccess(values.startupId);
            }
          }

          /**
           * If exporting a single coaching session
           */
          if (values.coachingSessionId) {
            const coachingSession = await coachingSessionRepository.findById(
              values.coachingSessionId,
            );

            if (!coachingSession) {
              logger.error(
                `Coaching session not found for id ${values.coachingSessionId} in ${permission} permission`,
              );
              return false;
            }

            if (
              String(coachingSession.sessionStartedBy) ===
              String(this.currentUser._id)
            ) {
              return true;
            }

            if (
              coachingSession.coachs?.some(
                coach => String(coach) === String(this.currentUser._id),
              )
            ) {
              return true;
            }
          }
        }

        return false;
      }

      case 'FEEDBACK_REQUEST:CREATE': {
        // Checks case where request is created from startup profile
        if (values.startupId) {
          return this.hasStartupAccess(values.startupId);
        }

        return false;
      }

      case 'FEEDBACK_REQUEST:EDIT': {
        if (
          values.startupId &&
          (await this.hasStartupAccess(values.startupId))
        ) {
          return true;
        }

        if (
          values.feedbackRequestId &&
          (await this.hasFeedbackRequestAccess(values.feedbackRequestId))
        ) {
          return true;
        }

        return false;
      }

      case 'FEEDBACK_REQUEST:VIEW': {
        // Checks case where request is created from startup profile
        if (values.startupId) {
          if (await this.hasStartupAccess(values.startupId)) {
            return true;
          }

          return false;
        }

        if (
          values.feedbackRequestId &&
          (await this.hasFeedbackRequestAccess(values.feedbackRequestId))
        ) {
          return true;
        }

        /**
         * Checks case where requests are fetched from feedback request
         * list (formSubmissionRequestsPaginated)
         */
        if (!values.feedbackRequestId) {
          const feedbackRequestWithCurrentUserAsCreator =
            await FormSubmissionRequestService.findFormSubmissionRequests({
              createdBy: this.currentUser._id,
            });

          if (
            userRoleService.isPaidUserRole(this.role) &&
            feedbackRequestWithCurrentUserAsCreator.length > 0
          ) {
            return true;
          }

          // Should view list of request if user has permission to view requests or create/edit requests
          if (await this.isAuthorized('FEEDBACK_REQUEST:CREATE', [], false)) {
            return true;
          }
          if (await this.isAuthorized('FEEDBACK_REQUEST:EDIT', [], false)) {
            return true;
          }
        }

        return false;
      }

      case 'FEEDBACK_ANSWER:VIEW': {
        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (values.feedbackRequestRecipientId) {
            const feedbackRequestRecipient =
              await FormSubmissionRequestService.getFormSubmissionRequestRecipient(
                {
                  incubatorId: this.incubatorId,
                  recipientId: toObjectId(values.feedbackRequestRecipientId),
                },
              );

            if (feedbackRequestRecipient && feedbackRequestRecipient.startup) {
              return this.hasStartupAccess(
                feedbackRequestRecipient?.startup?.toString() || '',
              );
            }
            return false;
          }

          // Checks case where request is created from startup profile
          if (values.startupId) {
            return this.hasStartupAccess(values.startupId);
          }

          // If current user is the creator of the feedback request
          if (
            values.feedbackRequestId &&
            (await this.hasFeedbackRequestAccess(values.feedbackRequestId))
          ) {
            return true;
          }
        }

        return false;
      }

      case 'TAGS:USER:VIEW':
      case 'INDUSTRIES:VIEW':
      case 'USER:INDUSTRY:VIEW': {
        if (values.userId) {
          return String(this.currentUser._id) === String(values.userId);
        }
        return Boolean(this.findUserPermission(permission));
      }

      case 'APPLICATION/DOWNLOAD_APPLICATION_CTA:VIEW': {
        if (values.applicationId) {
          const application = await applicationRepository.findById(
            values.applicationId,
          );
          if (!application) {
            return false;
          }
          return String(this.currentUser._id) === String(application.createdBy);
        }

        return Boolean(this.findUserPermission(permission));
      }

      case 'EVALUATION_PARAMETER_EDITOR:CREATE': {
        // keep here as for EVALUATION_PARAMETER_EDITOR:VIEW it bypasses the primary all check
        if (
          userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL
        ) {
          return true;
        }

        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          const programsUserIsAssignedTo =
            await programRepository.findByUserAssigned(this.currentUser._id);

          if (programsUserIsAssignedTo.length > 0) {
            return true;
          }
        }

        return false;
      }

      case 'EVALUATION_PARAMETER_EDITOR:EDIT/DELETE': {
        // keep here as for EVALUATION_PARAMETER_EDITOR:VIEW it bypasses the primary all check
        if (
          userPermission?.permissionCriteria === PermissionCriteriaTypes.ALL
        ) {
          return true;
        }

        if (
          userPermission?.permissionCriteria ===
          PermissionCriteriaTypes.ASSIGNED
        ) {
          if (values.evaluationAssignmentId) {
            const evaluationAssignment =
              await FormProcessor.resolveEvaluationAssignment(
                String(values.evaluationAssignmentId),
              );

            if (!evaluationAssignment) {
              logger.error(
                `Evaluation assignment not found for id ${values.evaluationAssignmentId}`,
              );
              return false;
            }

            if (
              !evaluationAssignment.programs ||
              evaluationAssignment.programs.length === 0
            ) {
              return false;
            }

            if (
              await FormAssignmentServices.validateUserIsAssignedToSelectedPrograms(
                this.currentUser._id,
                evaluationAssignment.programs || [],
              )
            ) {
              return true;
            }
          }
        }

        return false;
      }

      case 'EVALUATION_PARAMETER_EDITOR:VIEW': {
        if (this.findUserPermission(permission)) {
          return true;
        }

        const shouldAllowIfUserCanCreateOrEditAssignation =
          (await this.isAuthorized(
            'EVALUATION_PARAMETER_EDITOR:CREATE',
            [],
            false,
          )) ||
          (await this.isAuthorized(
            'EVALUATION_PARAMETER_EDITOR:EDIT/DELETE',
            [],
            false,
          ));

        if (shouldAllowIfUserCanCreateOrEditAssignation) {
          return true;
        }

        return false;
      }

      case 'EMAIL_REJECTION:EDIT': {
        if (values.rejectionEmailId) {
          const email = await EmailContent.findById(values.rejectionEmailId);

          if (!email) {
            throw new Error('Rejection email not found');
          }

          if (String(email?.createdBy) === String(this.currentUser._id)) {
            return true;
          }

          if (email.applicantCategory) {
            const funnel = await categoryRepository.findById(
              email.applicantCategory,
            );
            if (funnel && this.categoryPermission(funnel)) {
              return true;
            }
          }
        }

        return Boolean(this.findUserPermission(permission));
      }
      case 'APPLICATION_DRAFT:ACCESS': {
        if (!values.applicationId && !values.funnelId) {
          return false;
        }

        let funnel;

        if (values.applicationId) {
          const application: Modify<
            IApplication,
            { category: ICategory }
          > | null = await applicationRepository
            .findById(values.applicationId)
            .populate('category');

          if (!application) {
            return false;
          }
          if (String(application.createdBy) === String(this.currentUser._id)) {
            // if crated By is the current user
            return true;
          }

          funnel = application.category;
        }

        if (!values.funnelId) {
          return false;
        }

        funnel = funnel || (await categoryRepository.findById(values.funnelId));

        if (!funnel) {
          return false;
        }

        if (this.categoryPermission(funnel)) {
          return true;
        }
        return false;
      }
      case 'NOTE_SINGLE:DELETE': {
        if (values.noteId) {
          const note = await noteRepository.findById(values.noteId, {
            _id: 1,
            createdBy: 1,
          });

          if (!note) {
            throw new Error('Note not found');
          }

          if (String(note?.createdBy) === String(this.currentUser._id)) {
            return true;
          }
        }

        return Boolean(this.findUserPermission(permission));
      }
      case 'NOTE_THREAD:DELETE':
      case 'FORM:CREATE':
      case 'METRICS/EDIT:VIEW':
      case 'FUNNEL:CREATE':
      case 'USER:INVITE':
      case 'SAVED_VIEWS:READ':
      case 'COURSE:CREATE':
      case 'USER_ROLES:EDIT':
      case 'ARTICLES:EDIT':
      case 'CHAT:USER_ACCESS:EDIT':
      case 'CHAT:LIMIT:READ':
      case 'EMAIL_BLUEPRINT:MANAGE':
      case 'INDUSTRIES:CREATE':
      case 'INDUSTRIES:EDIT':
      case 'APPLICATION_OVERVIEW/FILTERS:VIEW':
      case 'TIMELINE/EMAIL_THREAD_META:VIEW':
      case 'APPLICATION_OVERVIEW/QUEUE_BAR:VIEW':
      case 'TIMELINE/CREATE_PRIVATE_COMMENT:VIEW':
      case 'APPLICATION_ALL:VIEW':
      case 'TAGS_EDITOR:VIEW':
      case 'TAGS_EDITOR:EDIT':
      case 'TAGS_EDITOR:CREATE':
      case 'TAGS:APPLICATION:VIEW':
      case 'EMAIL_REJECTION:CREATE': {
        return Boolean(this.findUserPermission(permission));
      }

      case 'STARTUP:ACCESS:VISIBILITY': {
        return (
          this.role.startupAccess.visibilitySettings !==
          AccessPermissionTypes.NONE
        );
      }

      default:
        if (!userPermission) {
          return false;
        }
        throw new PermissionError({
          message: `Wrong Permission, ${permission}`,
        });
    }
  }

  public async isAuthorized(
    permission,
    data?: {
      key: string;
      value: string;
    }[],
    outcomeThrows = true,
  ) {
    const authorized = await this.checkAuthorization(permission, data);

    if (!authorized && outcomeThrows) {
      throw new ForbiddenError({
        message: `You are not authorized to execute ${permission}`,
      });
    }

    return authorized;
  }
}
