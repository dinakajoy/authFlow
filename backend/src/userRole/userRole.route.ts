import * as express from 'express';
import { createUserRoleValidation, validate } from './userRole.validation';
import { createUserRoleController } from './userRole.controller';
import { rateLimiter } from '../utils';

const router = express.Router();

router.post(
  '/create',
  rateLimiter,
  createUserRoleValidation(),
  validate,
  createUserRoleController
);

export default router;