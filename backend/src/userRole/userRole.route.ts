import * as express from 'express';
import { createUserRoleValidation, validate } from './userRole.validation';
import {
  createUserRoleController,
  getUserRoleController,
} from './userRole.controller';
import { rateLimiter } from '../utils';

const router = express.Router();

router.post(
  '/',
  rateLimiter,
  createUserRoleValidation(),
  validate,
  createUserRoleController
);

router.get(
  '/',
  // rateLimiter,
  getUserRoleController
);

export default router;
