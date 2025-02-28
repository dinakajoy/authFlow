import mongoose, { FilterQuery, PipelineStage, Types } from 'mongoose';
import sanitize from 'mongo-sanitize';
import { nanoid } from 'nanoid';
import defaults from 'lodash/defaults';
import values from 'lodash/values';
import isEmpty from 'lodash/isEmpty';
import { Container } from 'typedi';
import difference from 'lodash/difference';
import { createHmac } from 'node:crypto';
import jwt from 'jsonwebtoken';

import superagent, { Response } from 'superagent';
import { DateTime } from 'luxon';
import config from '../../config/environment';
import { Redis, REDIS_KEYS } from '../redis';
import User from '../../api/user/user.model';
import Startup from '../../api/startup/startup.model';
import Program from '../../api/program/program.model';

import { signToken } from '../../auth/auth.service';
import { EmailService } from '../emails';
import { IUserDocument, IUser } from '../../api/user/user.interfaces';
import {
  UserRoles,
  STAFF_USERS_ROLES,
  AUTH_PROVIDERS,
  UserStatuses,
  GOOGLE_AUTH_URL,
  RoleTypes,
  EMPLOYEE_USER_ROLES_FOR_COUNT_LIMIT,
  FormTypes,
} from '../../constants';
import logger from '../../helpers/logging';
import Category from '../../api/category/category.model';
import Application from '../../api/application/application.model';
import { IStartup } from '../../api/startup/startup.interfaces';
import {
  assignStartupTasksToNewCofounder,
  assignProfileCompletionAutomatedTaskToUser,
} from '../services.task';
import { getDaysInSeconds, getHoursInSeconds } from '../../helpers/utils/utils';

import BackendError from '../errors/backend-error';
import {
  IApiCredentials,
  IIncubator,
} from '../../api/incubator/incubator.interfaces';
import { ErrorMetadata } from '../../ErrorMetadata';
import { IntegrationError, NotFoundError } from '../../graph/errors';
import { ApplicationStatus } from '../applications/constants';
import { AggregatedUserModel } from '../../types/global';
import { applicationHasSubAdminAccess } from '../applications/helpers/applicationHasSubAdminAccess';
import { UserRepository } from '../../repositories/user.repository';
import { UserRoleService } from '../userRole/userRole.service';
import UserIntegration from '../../core/userIntegrations/userIntegration';
import { getAuth0UserById } from '../../auth/auth0.service';
import { Modify } from '../../interfaces';
import {
  IUserRole,
  IUserRoleDocument,
} from '../../api/userRole/userRole.interfaces';
import { addUserToStartupCofounders } from '../../api/openRoutes/zapierImport/user/createUser';
import {
  MappedSubmission,
  getIndustries,
  getProgramsForUser,
  getTagsForUser,
  handleAddOrReplaceOperation,
  submissionsMapper,
  submittedQuestionsAreValidForLatestForm,
} from '../../api/openRoutes/zapierImport/utils';
import { FormService } from '../forms';
import { ProfileFieldsService } from '../profile';
import { IForm } from '../../api/form/form.interfaces';
import { UserProcessor } from '../../graph/user/processors';
import { toObjectId } from '../../config/mongoose';
import * as UserBatchProcessingLockService from './batch.processing.lock';
import * as UserBatchProcessingPubSubHandler from './batch.processing.pubsub.handler';
import { CreateJobArgument } from '../queue/v2/utils';
import { JobQueue } from '../queue/v2/queues';
import { IncubatorService } from '../incubators';
import { UserOnboardingFlowService } from './userOnboardingFlow.service';
import { ICoachingSession } from '../../api/coachingSession/coachingSession.interfaces';
import { ProgramRepository } from '../../repositories';
import { IProgram } from '../../api/program/program.interfaces';
import { IFormAnswer } from '../../api/form/form.answer.interfaces';

const redisClient = Redis.Instance.getClient();
const userRepository = Container.get(UserRepository);
const userRoleService = Container.get(UserRoleService);
const userIntegration = Container.get(UserIntegration);
const userOnboardingFlowService = Container.get(UserOnboardingFlowService);
const programRepository = Container.get(ProgramRepository);

const agent = superagent.agent();

const setupRedis = async (selectedUserIds, batchOperationId, currentUser) => {
  await redisClient
    .multi()
    .setex(
      REDIS_KEYS.getUserBatchOperationTotalCount(batchOperationId),
      getHoursInSeconds(1),
      selectedUserIds.length,
    )
    .setex(
      REDIS_KEYS.getUserBatchOperationSucceededCount(batchOperationId),
      getDaysInSeconds(1),
      0,
    )
    .setex(
      REDIS_KEYS.getUserBatchOperationFailedCount(batchOperationId),
      getDaysInSeconds(1),
      0,
    )
    .exec();

  await UserBatchProcessingLockService.setIsBatchProcessingForUsers(
    selectedUserIds,
    {
      operationId: batchOperationId,
      operationRequestDate: new Date(),
      operationRequester: currentUser._id as Types.ObjectId,
    },
  );
};

export async function getUserById(
  userId: Types.ObjectId,
  currentUser?: IUser,
): Promise<IUserDocument | null> {
  const criteria: {
    _id: Types.ObjectId;
    status?: {
      $in: UserStatuses[];
    };
  } = {
    _id: userId,
  };

  // without current user it will return only status authorized in user repository
  if (currentUser) {
    const currentUserRole: IUserRoleDocument | IUserRole | null =
      await userRoleService.getUserRoleById(currentUser.role as Types.ObjectId);
    if (
      currentUserRole &&
      userRoleService.matchUserTypes(STAFF_USERS_ROLES, currentUserRole)
    ) {
      criteria.status = {
        $in: values(UserStatuses).filter(
          userStatus => userStatus !== UserStatuses.Deleted,
        ),
      };
    }
  }
  return userRepository.findOne(criteria, '-salt -password');
}

export function getGoogleTokenFromAuthCode(
  authCode,
  redirectUri,
  credentials: IApiCredentials,
) {
  return agent
    .post(`${GOOGLE_AUTH_URL}/token`)
    .send({
      alt: 'json',
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: redirectUri,
    })
    .set('Content-Type', 'application/x-www-form-urlencoded')
    .withCredentials()
    .catch(err => {
      const { response } = err;
      if (response?.status === 400 && response.text) {
        const { error: errorCode } = JSON.parse(response.text);
        if (errorCode === 'invalid_grant') {
          logger.error('processGoogleAuthForLogin::invalid_grant', {
            response,
          });
          throw new BackendError(
            'Grant is invalid or expired, Please try again',
            ErrorMetadata.Authentication.code,
          );
        }

        if (errorCode === 'access_denied') {
          logger.error('processGoogleAuthForLogin::access_denied', {
            response,
          });
          throw new BackendError(
            'You have not granted permission for login action. Please allow access to continue',
            ErrorMetadata.Authentication.code,
          );
        }
      }

      logger.info('getGoogleTokenFromAuthCode:: ', err);
      throw err;
    });
}

export function validateToken(idToken) {
  return agent.get(`${GOOGLE_AUTH_URL}/tokeninfo`).query({
    id_token: idToken,
  });
}

export function buildQueryFromFilters(
  incubatorId,
  {
    name = '',
    roles,
    status = '',
    statuses,
    assignedStartups = 0,
    tags,
    industries,
    programs,
    startups,
    applicants,
    coachingSession,
    userIdToExclude,
    chatFeature,
  }: {
    name?: string;
    roles?: Types.ObjectId[];
    status?: string;
    statuses?: string[];
    assignedStartups?: number;
    tags?: string[];
    industries?: string[];
    programs?: string[];
    applicants?: Types.ObjectId[];
    startups?: Types.ObjectId[];
    coachingSession?: Modify<ICoachingSession, { startup: IStartup }>;
    userIdToExclude?: Types.ObjectId;
    chatFeature?: boolean;
  },
) {
  const q: {
    incubator: Types.ObjectId;
    status?: string | object;
    role?: object;
    startups?: { $in: Types.ObjectId[] };
    applicants?: { $in: Types.ObjectId[] };
    $or?: unknown[];
    $and?: unknown[];
    tags?: object;
    industries?: object;
    programs?: object;
    createdAt?: object;
    assignedStartups?: object;
    $expr?: object;
    chatFeature?: unknown;
  } = { incubator: toObjectId(incubatorId) };
  // deprecated:
  if (status && status !== '') {
    q.status = { $in: status.split(',') };
  }

  const startupsOrApplicants: unknown[] = [];
  const fullNameOrEmailOrExpertisesName: (
    | { fullName: { $regex: string; $options: 'i' } }
    | { email: { $regex: string; $options: 'i' } }
    | { 'expertises.name': { $regex: string; $options: 'i' } }
  )[] = [];

  if (name && name !== '') {
    fullNameOrEmailOrExpertisesName.push(
      { fullName: { $regex: name, $options: 'i' } },
      { email: { $regex: name, $options: 'i' } },
      { 'expertises.name': { $regex: `^${name}`, $options: 'i' } },
    );
  }

  if (startups) {
    startupsOrApplicants.push({
      startups: { $in: startups },
    });
  }

  if (applicants) {
    startupsOrApplicants.push({ _id: { $in: applicants } });
  }

  if (startupsOrApplicants.length && !fullNameOrEmailOrExpertisesName.length) {
    q.$or = startupsOrApplicants;
  }

  if (!startupsOrApplicants.length && fullNameOrEmailOrExpertisesName.length) {
    q.$or = fullNameOrEmailOrExpertisesName;
  }

  if (startupsOrApplicants.length && fullNameOrEmailOrExpertisesName.length) {
    q.$and = [
      {
        $or: fullNameOrEmailOrExpertisesName,
      },
      {
        $or: startupsOrApplicants,
      },
    ];
  }

  if (tags && tags.length > 0) {
    q.tags = { $in: tags.map((tag: string) => new Types.ObjectId(tag)) };
  }

  if (industries && industries.length > 0) {
    q.industries = {
      $in: industries.map((industry: string) => new Types.ObjectId(industry)),
    };
  }

  if (programs && programs.length > 0) {
    q.programs = {
      $in: programs.map((program: string) => new Types.ObjectId(program)),
    };
  }

  // filter by number of startups assigned to mentors/experts
  switch (assignedStartups) {
    case 1:
      q.createdAt = { $gte: DateTime.utc().minus({ month: 1 }).toJSDate() };
      break;
    case 2:
      q.assignedStartups = { $size: 0 };
      break;
    case 3:
      q.assignedStartups = { $size: 1 };
      break;
    case 4:
      q.assignedStartups = { $size: 2 };
      break;
    case 5:
      q.$expr = { $gt: [{ $size: '$assignedStartups' }, 2] };
      break;
    case 6:
      q.status = UserStatuses.Unactive;
      break;
    default:
      break;
  }

  if (statuses && statuses.length > 0) {
    q.status = { $in: statuses };
  }
  if (tags && tags.length > 0) {
    q.tags = { $in: tags.map((tag: string) => new Types.ObjectId(tag)) };
  }
  if (roles && roles.length > 0) {
    q.role = { $in: roles.map(roleId => new Types.ObjectId(roleId)) };
  }

  if (coachingSession) {
    /**
     * All user in a coaching session can get to select these:
     * INCUBATOR ROLES + founder of the same startup or user to be couched
     */
    const users: Types.ObjectId[] = [];
    if (coachingSession.user) {
      users.push(coachingSession.user);
    } else if (coachingSession.startup.people) {
      users.push(...coachingSession.startup.people);
    }

    q.$or = [
      {
        _id: { $in: users },
      },
      {
        role: q.role,
      },
    ];
    delete q.role;
  }

  if (userIdToExclude) {
    const excludeApplicationCreator = {
      _id: { $ne: userIdToExclude },
    };

    q.$and = q.$and
      ? [...q.$and, excludeApplicationCreator]
      : [excludeApplicationCreator];
  }

  if (chatFeature === true) {
    q.chatFeature = true;
  } else if (chatFeature === false) {
    q.$or = [
      {
        chatFeature: { $exists: false },
      },
      {
        chatFeature: false,
      },
    ];
  }

  return q;
}

export function getUserCountMatchingQuery(q) {
  return User.countDocuments(q);
}

export function aggregatePaginatedFetch(
  currentUserRole: IUserRoleDocument | IUserRole,
  q,
  { page, pageSize, inApplicationFunnelId },
  sortOpt,
) {
  const skip = pageSize * page;

  const pipelinedAggregate: PipelineStage[] = [
    {
      $lookup: {
        from: 'expertise',
        localField: '_id',
        foreignField: 'user',
        as: 'expertises',
      },
    },
    {
      $addFields: {
        fullName: {
          $concat: ['$firstName', ' ', '$lastName'],
        },
      },
    },
    {
      $match: { ...q, deletedAt: { $exists: false } },
    },
  ];

  if (inApplicationFunnelId) {
    // only applicants in the same funnel
    pipelinedAggregate.push(
      {
        $lookup: {
          from: 'applications',
          let: { owner: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$createdBy', '$$owner'] },
                    { $ne: ['$status', 'draft'] },
                    { $eq: ['$category', inApplicationFunnelId] },
                  ],
                },
              },
            },
          ],
          as: 'inFunnel',
        },
      },
      {
        $addFields: {
          // if is applicant, must be in funnel
          includeInResults: {
            $cond: {
              if: { $eq: ['$role', 'applicant'] },
              then: { $ne: [{ $size: '$inFunnel' }, 0] },
              else: true,
            },
          },
        },
      },
      {
        $match: {
          // remove applicants outside of funnel
          includeInResults: true,
        },
      },
    );
  }

  pipelinedAggregate.push(
    { $sort: sortOpt },
    {
      $project: {
        salt: 0,
        password: 0,
        resetPasswordToken: 0,
        adminValidationToken: 0,
        validationToken: 0,
        ...(!userRoleService.matchUserTypes(
          EMPLOYEE_USER_ROLES_FOR_COUNT_LIMIT,
          currentUserRole,
        ) && {
          email: 0,
          phone: 0,
          remoteAuth: 0,
          api: 0,
          country: 0,
          gender: 0,
          birthday: 0,
          info: 0,
          provider: 0,
          facebook: 0,
          adminValidated: 0,
          countryOrigin: 0,
          countryOfResidence: 0,
          tempEmail: 0,
          invitedBy: 0,
          workStatus: 0,
          neomaFields: 0,
          locations: 0,
          lastSeenNotifications: 0,
          answersLastUpdatedAt: 0,
          externalImport: 0,
          isLead: 0,
          setPasswordRequiredOnConversionFromLead: 0,
        }),
      },
    },
    {
      $facet: {
        metadata: [{ $count: 'total' }],
        results: [{ $skip: skip }, { $limit: pageSize }],
      },
    },
    {
      $project: {
        filteredCount: { $arrayElemAt: ['$metadata.total', 0] },
        results: 1,
      },
    },
  );

  return User.aggregate(pipelinedAggregate).collation({
    locale: 'en',
  });
}

export function getUniqueLocations(locationsPassed) {
  //  created this variable to avoid eslint warnings (shouldn't change param variables)
  let locations = locationsPassed;
  //  Extract the location names of the sent locations
  //  (which are the new location and the previous locations attributed to that user)
  //  and then push them to a set to get unique names
  const locationsSet = new Set(
    locations.map(locationObj => {
      return locationObj.location;
    }),
  );
  locations = Array.from(locationsSet);
  //  we want the data to be saved in the format of [ {location:locationString} ]
  // example: [{location:"office"}, {location:"office2"}....]
  // so after we made sure that we got unique locations on our hand, we convert them to the correct format
  locations = locations.map(locationString => {
    return { location: locationString };
  });
  return locations;
}

export async function createUser(
  user: IUser,
  incubatorId: string | Types.ObjectId,
  validated = false,
  provider = 'local',
) {
  const userRole = await userRoleService.getUserRoleById(user.role);

  if (!userRole) {
    logger.error('role not found');
    throw new NotFoundError({ message: 'User role not found' });
  }

  const onboardingFlow =
    await userOnboardingFlowService.prepareUserOnboardingFlow({
      incubatorId: String(incubatorId),
      userRole,
    });

  const userObj: Partial<IUser> = {
    ...user,
    provider,
    status: UserStatuses.Active,
    validated,
    ...(onboardingFlow && {
      onboardingFlow,
    }),
  };

  const newUser = await new User(userObj).save();

  try {
    await userIntegration.create(newUser, incubatorId);
  } catch (err) {
    logger.error('creation of user in postgres error: ', err);
    await User.deleteOne({ _id: newUser._id });
    throw new IntegrationError({
      message: `The creation of user ${user.email} failed`,
    });
  }

  return newUser;
}

export type UsersParams = {
  email: string;
  firstName: string;
  lastName: string;
  role: Types.ObjectId;
  externalImport?: boolean;
};

export async function createInvitedUsers(
  users: UsersParams[],
  requester: Pick<IUser, '_id' | 'startups' | 'role'>,
  requesterUserRole: Pick<IUserRole, 'type'>,
  incubator: Pick<
    IIncubator,
    | '_id'
    | 'name'
    | 'dateFormatForTransactionalEmails'
    | 'featureFlags'
    | 'slug'
    | 'domainUrl'
    | 'customDomain'
    | 'generalEmail'
    | 'active'
    | 'planInfo'
    | 'timezone'
    | 'timeDisplayPreference'
    | 'defaultLanguage'
  >,
  opts?: { reInvite?: boolean; lead?: boolean; preActivate?: boolean },
) {
  const usersIds: {
    userId: Types.ObjectId;
    newlyCreated: boolean;
  }[] = [];

  const userFailed: {
    email: string;
    userId: Types.ObjectId | string;
  }[] = [];

  const options = defaults(opts, {
    reInvite: true,
    lead: false,
    preActivate: false,
  });

  await Promise.all(
    users.map(async user => {
      const alreadyInvited = await userRepository
        .findOne({
          incubator: incubator._id,
          email: user.email,
        })
        .lean();
      if (alreadyInvited) {
        const alreadyInvitedUserRole: IUserRole | null =
          await userRoleService.getUserRoleById(
            alreadyInvited.role as Types.ObjectId,
          );

        if (!alreadyInvitedUserRole) {
          logger.error('requester role not found');
          throw new NotFoundError({ message: 'User role not found' });
        }

        if (
          userRoleService.matchUserTypes(
            [UserRoles.Applicant, UserRoles.CommunityMember],
            alreadyInvitedUserRole,
          )
        ) {
          // role "applicant" will throw out an error
          const founderUserRole: IUserRole[] =
            await userRoleService.getUserRoles({
              incubatorId: incubator._id,
              filter: {
                userRoleTypes: [UserRoles.Cofounder],
                roleType: RoleTypes.Default,
              },
            });
          if (!founderUserRole || founderUserRole.length !== 1) {
            throw new Error('Founder role is not found');
          }

          alreadyInvited.role = founderUserRole[0]._id;
        }
        usersIds.push({ userId: alreadyInvited._id, newlyCreated: false });
        if (options.reInvite === true) {
          await User.updateOne(
            {
              email: user.email,
            },
            { invitedAt: new Date().toISOString() },
            { upsert: true },
          );
          await EmailService.Instance.sendInvitationEmail(
            incubator,
            alreadyInvited,
            requester,
          );
        }
        return;
      }
      const role = await userRoleService.getUserRoleById(user.role);
      if (!role) {
        logger.error('role not found');
        throw new NotFoundError({ message: 'User role not found' });
      }

      const onboardingFlow =
        await userOnboardingFlowService.prepareUserOnboardingFlow({
          incubatorId: String(incubator._id),
          userRole: role,
        });

      const newUser = await new User({
        provider: 'local',
        email: user.email,
        password: nanoid(),
        resetPasswordToken: nanoid(),
        firstName: user.firstName,
        lastName: user.lastName,
        role: role._id,
        incubator: incubator._id,
        invitedBy: requester._id as Types.ObjectId,
        invitedAt: new Date().toISOString(),
        timezone: incubator.timezone ?? 'Etc/UTC',
        timeDisplayPreference: incubator.timeDisplayPreference,
        externalImport: !!user.externalImport,
        startups: requester.startups ?? [],
        language: incubator.defaultLanguage ?? 'en',
        isLead: !!options.lead,
        setPasswordRequiredOnConversionFromLead: options.lead,
        status: options.preActivate === true ? 'active' : 'pending',
        ...(onboardingFlow && {
          onboardingFlow,
        }),
      }).save();

      logger.info(
        `user ${user.email} with _id${newUser._id} created in mongo. Now about to create in PG`,
      );
      try {
        await userIntegration.create(newUser, incubator._id);
      } catch (err) {
        logger.error('creation of user in postgres error:', err);
        await User.deleteOne({ _id: newUser._id });
        userFailed.push({
          userId: newUser._id,
          email: user.email,
        });
        logger.error(
          `user ${user.email} creation failed and was reverted`,
          err,
        );
        return;
      }
      logger.info(`user ${user.email} created in postgres`);

      usersIds.push({ userId: newUser._id, newlyCreated: true });

      if (
        userRoleService.isSubAdmin(requesterUserRole) &&
        userRoleService.isNetwork(role)
      ) {
        const assignedProgram: IProgram[] =
          await programRepository.findByUserAssigned(requester._id, { _id: 1 });

        if (assignedProgram.length > 0) {
          await programRepository.updateMany(
            { _id: { $in: assignedProgram.map(p => p._id) } },
            {
              $addToSet: {
                connectedNetworkUsers: newUser._id,
              },
            },
          );
        }
      }

      if (!options.lead) {
        await EmailService.Instance.sendInvitationEmail(
          incubator,
          newUser,
          requester,
        );
      }
    }),
  );

  return {
    usersIds,
    userFailed,
  };
}

export async function createUserFromInvitation(
  params: UsersParams | UsersParams[],
  requester: Pick<IUser, '_id' | 'startups' | 'role'>,
  requesterUserRole: Pick<IUserRole, 'type'>,
  incubator: Pick<
    IIncubator,
    | '_id'
    | 'name'
    | 'dateFormatForTransactionalEmails'
    | 'featureFlags'
    | 'slug'
    | 'domainUrl'
    | 'customDomain'
    | 'generalEmail'
    | 'active'
    | 'planInfo'
    | 'timezone'
    | 'timeDisplayPreference'
    | 'defaultLanguage'
  >,
  opts?: { reInvite?: boolean; lead?: boolean; preActivate?: boolean },
): Promise<
  {
    userId: Types.ObjectId;
    newlyCreated: boolean;
  }[]
> {
  if (isEmpty(params)) return [];
  const users = Array.isArray(params) ? params : [params];
  let targetedStartup: IStartup | null = null;
  if (requester?.startups?.[0]) {
    if (
      (userRoleService.isOnlyFounder(requesterUserRole) &&
        Array.isArray(requester.startups) &&
        requester.startups.length > 0) ||
      /**
       * handle staff going to startup profile and inviting a cofounder directly
       * (startup id is still passed in requested.startups)
       */
      userRoleService.isPaidUserRole(requesterUserRole)
    ) {
      targetedStartup = await Startup.findById(requester.startups[0]);
      if (!targetedStartup) {
        throw new Error(
          `Startup with id ${requester.startups[0]} is not found`,
        );
      }
      if (!targetedStartup?.people) {
        throw new Error(`people of ${targetedStartup._id} is undefined`);
      }
    } else {
      logger.error('createUserFromInvitation::', { requester, params });
      throw new Error(
        'You do not have permission to invite this user to this startup',
      );
    }
  }

  const { usersIds, userFailed } = await createInvitedUsers(
    users,
    requester,
    requesterUserRole,
    incubator,
    opts,
  );

  if (userFailed.length > 0) {
    throw new IntegrationError({
      message: `user ${userFailed
        .map(u => u.email)
        .join(', ')} creation failed and was reverted`,
    });
  }

  if (requester?.startups?.[0]) {
    // add users to startup.people
    await Startup.findOneAndUpdate(
      { _id: requester.startups[0] },
      {
        $addToSet: {
          people: {
            $each: usersIds.map(uid => uid.userId),
          },
        },
      },
      { new: true },
    );
  }

  return usersIds;
}

export async function acceptInvitation({
  incubatorId,
  userId,
  firstName,
  lastName,
  password,
  timezone,
  validationObj = null,
}: {
  incubatorId: string;
  userId: string | Types.ObjectId;
  firstName: string;
  lastName: string;
  password?: string;
  timezone: string;
  validationObj?: { google: boolean } | null;
}) {
  const user = (await userRepository.findById(userId)) as IUserDocument;
  user.firstName = firstName;
  user.lastName = lastName;
  if (password) {
    user.password = password;
  }
  user.timezone = timezone;
  if (validationObj) {
    user.remoteAuth = validationObj;
    user.provider = AUTH_PROVIDERS.Google;
    user.password = undefined;
  }
  user.resetPasswordToken = undefined;
  user.status = UserStatuses.Active;
  user.adminValidated = true;
  user.validated = true;
  const updatedUser = (await user.save()) as AggregatedUserModel;
  // assign the group startup tasks to new cofounder if invited to a startup
  // ! TODO: Test this once again
  const userRole = await userRoleService.getUserRoleById(updatedUser?.role);
  if (
    userRole?.type.includes(UserRoles.Cofounder) &&
    updatedUser.startups &&
    updatedUser.startups.length
  ) {
    await Promise.all(
      updatedUser.startups.map(startup =>
        assignStartupTasksToNewCofounder({
          incubator: toObjectId(incubatorId),
          startup: startup as mongoose.Types.ObjectId,
          user: updatedUser._id,
        }),
      ),
    );
  }
  const authToken = signToken({
    userId: updatedUser._id,
    role: updatedUser.role._id,
    incubatorId,
  });

  await assignProfileCompletionAutomatedTaskToUser(updatedUser);

  return { value: authToken };
}

export async function userHmacIntercom(userId: string) {
  return createHmac('sha256', config.intercom.secretKey)
    .update(userId)
    .digest('hex');
}

export async function registerExternalUser(userId, incubator) {
  logger.info(
    `registerExternalUser::userId ${userId} and incubator ${incubator}`,
  );
  try {
    const authUser = await getAuth0UserById(userId);
    logger.info(`registerExternalUser::authUser ${authUser}`);
    if (authUser) {
      const existingUser: Modify<
        IUserDocument,
        { incubator: IIncubator }
      > | null = await userRepository
        .findOne({
          email: sanitize(authUser.email),
          incubator: sanitize(incubator),
        })
        .populate('incubator');
      if (existingUser) {
        if (existingUser?.incubator?.featureFlags?.auth0) {
          return userRepository.findOneAndUpdate(
            { _id: existingUser._id },
            {
              $set: {
                status: UserStatuses.Active,
                validated: true,
                identityProviderUserId: authUser.user_id,
                avatar: authUser.picture,
              },
            },
            { new: true },
          );
        }
        return existingUser;
      }

      const role = await userRoleService.getUserRoleBySlug({
        incubator,
        roleSlug: UserRoles.Applicant,
      });

      if (!role) {
        logger.error('role not found');
        throw new NotFoundError({ message: 'User role not found' });
      }

      const userObj = {
        firstName: authUser.given_name,
        lastName: authUser.family_name,
        avatar: authUser.picture,
        email: authUser.email,
        validated: true,
        incubator,
        password: nanoid(),
        role: role._id,
        status: UserStatuses.Active,
        identityProviderUserId: authUser.user_id,
      };
      logger.info(`creating external user ${userObj.email}`);
      const newUser = await userRepository.create(userObj);
      logger.info(`creating user in pg ${newUser.email}`);
      await userIntegration.create(newUser, incubator);
      return newUser;
    }
    logger.error(`Error getting user from auth0: ${userId}`);
    throw new Error('Error getting user from auth0');
  } catch (err) {
    logger.error(err.message);
    logger.error(`Error creating external user ${userId}`);
    return err;
  }
}

async function sendUserInvitationalEmail(
  incubator: Pick<
    IIncubator,
    | '_id'
    | 'name'
    | 'dateFormatForTransactionalEmails'
    | 'featureFlags'
    | 'slug'
    | 'domainUrl'
    | 'customDomain'
    | 'generalEmail'
    | 'active'
    | 'planInfo'
    | 'timezone'
    | 'timeDisplayPreference'
    | 'defaultLanguage'
  >,
  user: Pick<
    IUser,
    | '_id'
    | 'role'
    | 'email'
    | 'tempEmail'
    | 'firstName'
    | 'lastName'
    | 'validationToken'
    | 'timezone'
    | 'incubator'
  >,
  admin: Pick<IUser, 'role' | '_id'>,
) {
  const userRole = await userRoleService.getUserRoleById(user.role);
  if (!userRole) {
    logger.error('role not found');
    throw new NotFoundError({ message: 'User role not found' });
  }
  if (userRoleService.matchUserTypes([UserRoles.Applicant], userRole)) {
    await EmailService.Instance.sendApplicantSignupConfirmationEmail(user);
  } else {
    await EmailService.Instance.sendInvitationEmail(incubator, user, admin);
  }
}

async function validateUserProfileFormsAndSubmissions({
  user,
  userProfile = [],
  userProfileForm,
}: {
  user: IUserDocument;
  userProfile: IFormAnswer[];
  userProfileForm: IForm | null;
}) {
  if (!userProfileForm) {
    logger.error('createUsersFromZapierImport::missing user profile forms', {
      firstName: user.firstName,
      lastName: user.firstName,
      email: user.email,
      userProfileSubmissions: userProfile,
    });

    return false;
  }

  const userProfileFormArg = Array.isArray(userProfileForm)
    ? userProfileForm
    : [userProfileForm];

  const {
    isValid,
    formQuestionIds: submittedUserProfileQuestionKeys,
    submittedFormQuestionKeys: userProfileFormQuestionIds,
  } = submittedQuestionsAreValidForLatestForm(
    userProfileFormArg,
    userProfile[0],
  );

  if (!isValid) {
    const defaultingUserQuestionId = difference(
      submittedUserProfileQuestionKeys,
      userProfileFormQuestionIds,
    );

    logger.error(
      'createUsersFromZapierImport::invalid user profile submission',
      {
        firstName: user.firstName,
        lastName: user.firstName,
        email: user.email,
        userProfileSubmissions: userProfileFormQuestionIds,
        defaultingUserQuestionId,
      },
    );

    return false;
  }
  return true;
}

const userHasProfileSubmissions = userProfile => !!userProfile[0];

export interface CreateUserFromZapierImportJobParams {
  userId: Types.ObjectId;
  currentUserId: Types.ObjectId;
  sendInvite: boolean;
  userProfile?: IFormAnswer[];
  startupId: string;
  startupName: string;
}

export async function createUserFromZapierImportJob({
  userId,
  currentUserId,
  sendInvite,
  userProfile = [],
  startupId,
  startupName,
}: CreateUserFromZapierImportJobParams) {
  const newUser = await userRepository.findById(userId);
  if (!newUser) {
    logger.error('createUsersFromZapierImport:: User not found', {
      userId,
    });
    throw new BackendError('User not found', ErrorMetadata.NotFound.code);
  }

  const currentUser = await userRepository.findById(currentUserId);
  if (!currentUser) {
    logger.error('createUsersFromZapierImport:: Zapier admin user not found', {
      currentUserId,
    });
    throw new BackendError(
      'Zapier admin user not found',
      ErrorMetadata.NotFound.code,
    );
  }

  try {
    await userIntegration.create(newUser, currentUser.incubator);
  } catch (e) {
    logger.error('Error creating user in integration', e);
  }

  try {
    const createdUserRole = await userRoleService.getUserRoleById(newUser.role);
    if (!createdUserRole) {
      logger.error('createUsersFromZapierImport:: User role not found', {
        userId,
      });
      throw new BackendError(
        'User role not found',
        ErrorMetadata.NotFound.code,
      );
    }

    if (
      (startupId || startupName) &&
      userRoleService.matchUserTypes([UserRoles.Cofounder], createdUserRole)
    ) {
      await addUserToStartupCofounders({
        user: newUser,
        startupId,
        startupName,
      });
    }

    const userProfileForm: IForm | null =
      await ProfileFieldsService.getCurrentFormForIncubator(
        currentUser.incubator,
        FormTypes.UserProfile,
      );

    const isValid = await validateUserProfileFormsAndSubmissions({
      userProfile,
      user: newUser,
      userProfileForm,
    });

    let userProfileAnswers: MappedSubmission[] = [];
    if (isValid && userHasProfileSubmissions(userProfile)) {
      userProfileAnswers = await submissionsMapper(
        userProfile[0],
        userProfileForm?.questions,
        newUser,
      );

      await FormService.submitUserProfileAnswers(
        newUser,
        userProfileAnswers,
        userProfileForm,
        newUser,
      );
    } else {
      logger.error('createUsersFromZapierImport:: Invalid user profile', {
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        userId: newUser._id,
        userProfileSubmissions: userProfile,
      });
    }

    if (sendInvite) {
      const incubator = await IncubatorService.getIncubatorById(
        newUser.incubator,
        { cache: true },
      );
      if (!incubator) {
        logger.error('createUsersFromZapierImport:: Incubator not found', {
          incubatorId: newUser.incubator,
        });
        throw new BackendError(
          'Incubator not found',
          ErrorMetadata.NotFound.code,
        );
      }
      await sendUserInvitationalEmail(incubator, newUser, currentUser);
    }
    logger.debug('createUsersFromZapierImport:: Operation Successful', {
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      userId: newUser._id,
    });

    return true;
  } catch (err) {
    logger.error('createUsersFromZapierImport:: Unknown error', {
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      userId: newUser._id,
      userProfileSubmissions: userProfile,
      error: err,
    });
    throw new BackendError('Unknown error', ErrorMetadata.Unknown.code);
  }
}

export interface UpdateUserFromZapierImportJobParams {
  startupId: string;
  startupName: string;
  programs: string[];
  tags: string[];
  industries: string[];
  addReplacePrograms: 'add' | 'replace';
  addReplaceTags: 'add' | 'replace';
  addReplaceIndustries: 'add' | 'replace';
  userId: string;
  currentUserId: string;
  userProfile: IFormAnswer[];
}

export async function updateUserFromZapierImportJob({
  startupId,
  startupName,
  programs = [],
  tags = [],
  industries = [],
  addReplacePrograms,
  addReplaceTags,
  addReplaceIndustries,
  userId,
  currentUserId,
  userProfile,
}: UpdateUserFromZapierImportJobParams) {
  const userToUpdate = await userRepository.findById(userId);
  if (!userToUpdate) {
    logger.error('updateUserFromZapierImportJob:: User not found', {
      userId,
    });
    throw new BackendError('User not found', ErrorMetadata.NotFound.code);
  }

  const currentUser = await userRepository.findById(currentUserId);
  if (!currentUser) {
    logger.error(
      'updateUserFromZapierImportJob:: Zapier admin user not found',
      {
        currentUserId,
      },
    );
    throw new BackendError(
      'Zapier admin user not found',
      ErrorMetadata.NotFound.code,
    );
  }

  const currentUserRole = await userRoleService.getUserRoleById(
    currentUser.role,
  );
  if (!currentUserRole) {
    logger.error('updateUserFromZapierImportJob:: User role not found', {
      currentUserId,
    });
    throw new BackendError('User role not found', ErrorMetadata.NotFound.code);
  }

  try {
    const updatedTags = await handleAddOrReplaceOperation(
      currentUser.incubator,
      addReplaceTags,
      getTagsForUser,
      userToUpdate?.tags,
      tags,
    );

    const updatedPrograms = await handleAddOrReplaceOperation(
      currentUser.incubator,
      addReplacePrograms,
      getProgramsForUser,
      userToUpdate?.programs,
      programs,
    );

    const updatedIndustries = await handleAddOrReplaceOperation(
      currentUser.incubator,
      addReplaceIndustries,
      getIndustries,
      userToUpdate?.industries,
      industries,
    );

    const incubator = await IncubatorService.getIncubatorById(
      currentUser.incubator,
      { cache: true },
    );

    if (!incubator) {
      logger.error('updateUserFromZapierImportJob:: Incubator not found', {
        incubatorId: currentUser.incubator,
      });
      throw new BackendError(
        'Incubator not found',
        ErrorMetadata.NotFound.code,
      );
    }

    const updatedUser: IUser | null = await UserProcessor.update(
      { incubator, currentUser, currentUserRole },
      {
        updatingUserId: userId,
        update: {
          tags: updatedTags,
          programs: updatedPrograms,
          industries: updatedIndustries,
        },
      },
    );

    const userRole: IUserRole | null = await userRoleService.getUserRoleById(
      userToUpdate.role,
    );

    if (!userRole) {
      logger.error(`User role not found.`);
      throw new BackendError(
        'User role not found',
        ErrorMetadata.NotFound.code,
      );
    }

    if (
      (startupId || startupName) &&
      userRoleService.matchUserTypes([UserRoles.Cofounder], userRole)
    ) {
      await addUserToStartupCofounders({
        user: updatedUser,
        startupId,
        startupName,
      });
    }

    const userProfileForm =
      await ProfileFieldsService.getCurrentFormForIncubator(
        currentUser.incubator,
        FormTypes.UserProfile,
      );

    const isValid = await validateUserProfileFormsAndSubmissions({
      user: userToUpdate,
      userProfile,
      userProfileForm,
    });

    let userProfileAnswers: MappedSubmission[] = [];
    if (isValid && userProfile[0]) {
      userProfileAnswers = await submissionsMapper(
        userProfile[0],
        userProfileForm?.questions,
        updatedUser,
      );

      await FormService.submitUserProfileAnswers(
        updatedUser,
        userProfileAnswers,
        userProfileForm,
        updatedUser as IUser,
      );
    }

    return true;
  } catch (err) {
    logger.error('updateUserFromZapierImportJob:: Unknown error', {
      firstName: userToUpdate.firstName,
      lastName: userToUpdate.lastName,
      email: userToUpdate.email,
      userId: userToUpdate._id,
      userProfileSubmissions: userProfile,
      error: err,
    });

    throw new BackendError('Unknown error', ErrorMetadata.Unknown.code);
  }
}

export async function processGoogleAuthForLogin({
  code,
  redirectUri,
  incubatorId,
  credentials,
}: {
  code;
  redirectUri;
  incubatorId: string;
  credentials: IApiCredentials;
}): Promise<{ token: string }> {
  const tokenResponse = await getGoogleTokenFromAuthCode(
    code,
    redirectUri,
    credentials,
  );
  if ((tokenResponse as Response)?.text) {
    const { id_token: idToken } = JSON.parse((tokenResponse as Response).text);
    const decoded = await validateToken(idToken);
    if (decoded?.text) {
      const userInfo = JSON.parse(decoded.text);
      const { email, aud } = userInfo;
      if (aud !== credentials.clientId) {
        throw new Error('Bad Connection');
      }
      const user = await userRepository.findOne({
        email: email.toLowerCase(),
        incubator: incubatorId,
        status: UserStatuses.Active,
      });

      if (!user) {
        logger.info('processGoogleAuthForLogin::user not found', {
          incubatorId,
          userInfo,
        });
        throw new BackendError(
          'User is not registered',
          ErrorMetadata.NotFound.code,
        );
      }

      if (user.isLead) {
        logger.info(
          'getGoogleTokenFromAuthCode::attempt to log in to a lead user',
          {
            incubatorId,
            userInfo,
            user,
          },
        );
        throw new BackendError(
          'Cannot log in as a lead user',
          ErrorMetadata.Authentication.code,
        );
      }

      // Update User With Validation
      if (!user?.remoteAuth) {
        user.validated = true;
        user.remoteAuth = { google: true };
        await user.save();
      }
      // Return Token for Front End Login Cookie
      const token = signToken({
        userId: user._id,
        role: user.role,
        incubatorId,
      });
      return {
        token,
      };
    }
  }

  logger.error('processGoogleAuthForLogin::unexpected error', {
    tokenResponse,
  });

  throw new Error('An error ocurred, Please try again');
}

export async function processGoogleAuthForInvitation({
  code,
  redirectUri,
  incubatorId,
  timezone,
  credentials,
}: {
  code;
  redirectUri;
  incubatorId;
  timezone;
  credentials: IApiCredentials;
}): Promise<{ token: string }> {
  const tokenResponse = await getGoogleTokenFromAuthCode(
    code,
    redirectUri,
    credentials,
  );

  if ((tokenResponse as Response)?.text) {
    const { id_token: idToken } = JSON.parse((tokenResponse as Response).text);
    const decoded = await validateToken(idToken);
    if (decoded?.text) {
      const userInfo = JSON.parse(decoded.text);
      const {
        email,
        aud,
        family_name: familyName,
        given_name: givenName,
      } = userInfo;
      if (aud !== credentials.clientId) {
        throw new Error('Bad Connection');
      }
      const user = await userRepository.findOne({
        email: email.toLowerCase(),
        incubator: incubatorId,
      });

      if (!user) {
        throw new Error('This Account Is Not Recognized');
      }

      if (user.status !== 'pending') {
        throw new Error('This Account is not Pending for Invitation');
      }

      const { value: token } = await acceptInvitation({
        incubatorId: String(incubatorId),
        userId: user._id,
        firstName: givenName,
        lastName: familyName,
        timezone,
        validationObj: { google: true },
      });

      return {
        token,
      };
    }
  }

  throw new Error('An error ocurred, Please try Again');
}

export async function processGoogleAuthForApplication({
  code,
  redirectUri,
  incubatorId,
  credentials,
}: {
  code;
  redirectUri;
  incubatorId;
  credentials: IApiCredentials;
}): Promise<{ token: string } | { userExists: boolean }> {
  const tokenResponse = await getGoogleTokenFromAuthCode(
    code,
    redirectUri,
    credentials,
  );
  if ((tokenResponse as Response)?.text) {
    const { id_token: idToken, refreshToken } = JSON.parse(
      (tokenResponse as Response).text,
    );
    const decoded = await validateToken(idToken);
    if (decoded?.text) {
      const userInfo = JSON.parse(decoded.text);
      if (userInfo.aud !== credentials.clientId) {
        throw new Error('Bad Connection');
      }
      const {
        email,
        family_name: familyName,
        given_name: givenName,
      } = userInfo;

      const user: Pick<IUser, '_id'> | null = await userRepository
        .findOne(
          {
            email: email.toLowerCase(),
            incubator: incubatorId,
          },
          { _id: 1 },
        )
        .lean();

      if (user !== null) {
        return {
          userExists: true,
        };
      }
      const token = jwt.sign(
        { googleId: refreshToken, familyName, givenName, email },
        config.secrets.session,
        {
          expiresIn: 60 * 60 * 60 * 30, // 75 days
        },
      );
      return {
        token,
      };
    }
  }

  logger.debug(
    'processGoogleAuthForApplication::tokenResponse has no text attribute',
    { tokenResponse },
  );
  throw new Error('An error ocurred, Please try Again');
}

export async function getAssignedCategoryIds(
  userId: string | Types.ObjectId,
): Promise<string[]> {
  const redisKey = REDIS_KEYS.getAssignedCategoryIdsForAdmin(userId.toString());
  if ((await redisClient.exists(redisKey)) === 0) {
    const assignedCategories: {
      _id: null;
      categoryIds: (string | Types.ObjectId)[];
    }[] = await Category.aggregate([
      {
        $match: {
          $or: [
            { admin: new mongoose.Types.ObjectId(userId) },
            { people: new mongoose.Types.ObjectId(userId) },
          ],
        },
      },
      {
        $group: {
          _id: null,
          categoryIds: { $addToSet: '$_id' },
        },
      },
    ]);
    if (assignedCategories.length === 0) {
      return [];
    }

    const categoryIds: string[] = assignedCategories.reduce(
      (acc: string[], item) => {
        const stringIds = item.categoryIds.map(id => String(id));
        return acc.concat(stringIds);
      },
      [],
    );

    if (!categoryIds || categoryIds.length === 0) {
      return [];
    }

    await redisClient
      .multi()
      .sadd(redisKey, categoryIds)
      .expire(redisKey, getDaysInSeconds(1))
      .exec();

    return categoryIds;
  }

  return redisClient.smembers(redisKey);
}

/**
 * returns a list of valid and invalid users based on user status
 * valid users: UserStatuses[.Pending and .Active]
 */
export async function getValidUsersSegmentationByEmail(
  incubatorId: Types.ObjectId,
  emails: string[],
): Promise<IUser[]> {
  return userRepository
    .find({
      incubator: incubatorId,
      email: { $in: emails },
      status: { $in: [UserStatuses.Active, UserStatuses.Pending] },
      $or: [
        {
          isLead: false,
        },
        {
          isLead: { $exists: false },
        },
      ],
    })
    .lean();
}

export function getAccessFlagToCalendarIntegrationByRole(
  userRole: IUserRole,
): boolean {
  return userRole.type.length === 1 && userRole.type[0] === UserRoles.Applicant;
}

export async function getUsersByFilters({
  incubatorId,
  search,
  status,
  roles,
  tags,
  industries,
}: {
  incubatorId: string;
  search?: string;
  status?: string[];
  roles?: Types.ObjectId[];
  tags?: string[];
  industries?: string[];
}) {
  const query = buildQueryFromFilters(incubatorId, {
    name: search,
    statuses: status,
    roles,
    tags,
    industries,
  });

  const pipelinedAggregate: PipelineStage[] = [
    {
      $lookup: {
        from: 'expertise',
        localField: '_id',
        foreignField: 'user',
        as: 'expertises',
      },
    },
    {
      $addFields: {
        fullName: {
          $concat: ['$firstName', ' ', '$lastName'],
        },
      },
    },
    {
      $match: {
        ...(query as FilterQuery<IUser>),
        ...({ deletedAt: { $exists: false } } as FilterQuery<IUser>),
      },
    },
  ];

  return User.aggregate(pipelinedAggregate).collation({
    locale: 'en',
  });
}

export async function batchAssignUserRoleToUsers({
  incubatorId,
  currentUserId,
  selectedUserIds,
  userRoleId,
  batchOperationId,
}): Promise<boolean> {
  const currentUser = await userRepository.findById(currentUserId).lean();
  if (!currentUser) {
    throw new NotFoundError({ message: 'User not found' });
  }
  const children: CreateJobArgument[] = [];

  try {
    if (selectedUserIds) {
      await setupRedis(selectedUserIds, batchOperationId, currentUser);

      for (const userId of selectedUserIds) {
        children.push({
          type: 'update-user-batch-operation',
          payload: {
            incubatorId,
            currentUserId,
            userId: String(userId),
            userRoleId,
            batchOperationId,
          },
        });
      }
    }

    const parent: CreateJobArgument = {
      type: 'after-batch-succeeded',
      payload: {
        job: 'update-user-batch-operation',
        batchOperationId,
      },
    };

    const job = await JobQueue.Instance.createJobWithChildren(parent, children);
    return !!job.job?.id;
  } catch (err) {
    if (batchOperationId) {
      await JobQueue.Instance.createJob({
        type: 'after-batch-failed',
        payload: {
          job: 'update-user-batch-operation',
          batchOperationId,
        },
      });
    }
    logger.error('[updateUserBatchOperation] error', { err });
    return err;
  }
  return true;
}

export interface UpdateUserRoleOfUsersParams {
  incubatorId: Types.ObjectId;
  currentUserId: Types.ObjectId;
  userId: string;
  userRoleId: Types.ObjectId;
  batchOperationId: string;
}

export async function updateUserRoleOfUser({
  incubatorId,
  currentUserId,
  userId,
  userRoleId,
  batchOperationId,
}: UpdateUserRoleOfUsersParams) {
  const currentUser = await userRepository.findById(currentUserId).lean();
  if (!currentUser) {
    throw new NotFoundError({ message: 'User not found' });
  }

  const currentUserRole = await userRoleService.getUserRoleById(
    currentUser.role,
  );

  if (!currentUserRole) {
    throw new NotFoundError({ message: 'User role not found' });
  }

  const incubator = await IncubatorService.getIncubatorById(incubatorId, {
    cache: true,
  });

  if (!incubator) {
    throw new NotFoundError({ message: 'Incubator not found' });
  }

  try {
    const updatedUser: IUser | null = await UserProcessor.update(
      { incubator, currentUser, currentUserRole },
      {
        updatingUserId: userId,
        update: {
          role: userRoleId,
        },
      },
    );
    if (updatedUser && batchOperationId) {
      await UserBatchProcessingPubSubHandler.handleUserProcessingSucceeded(
        batchOperationId,
        userId.toString(),
      );
      await UserBatchProcessingLockService.setIsNotBatchProcessingForUsers([
        userId,
      ]);
    }
  } catch (err) {
    if (batchOperationId) {
      await UserBatchProcessingPubSubHandler.handleUserProcessingFailed(
        batchOperationId,
        userId.toString(),
      );
      await UserBatchProcessingLockService.setIsNotBatchProcessingForUsers([
        userId,
      ]);
    }
  }
}

export async function getBatchOperationStatus(
  batchOperationId: string,
): Promise<{
  total: string | null;
  succeeded: string | null;
  failed: string | null;
}> {
  const [total, succeeded, failed] = await redisClient.mget(
    REDIS_KEYS.getUserBatchOperationTotalCount(batchOperationId),
    REDIS_KEYS.getUserBatchOperationSucceededCount(batchOperationId),
    REDIS_KEYS.getUserBatchOperationFailedCount(batchOperationId),
  );

  return {
    total,
    succeeded,
    failed,
  };
}
