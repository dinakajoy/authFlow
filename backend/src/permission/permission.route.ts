import * as express from 'express';
import { createPermissionValidation, validate } from './permission.validation';
import { createPermissionController, getPermissionsController } from './permission.controller';
import { rateLimiter } from '../utils';

const router = express.Router();

router.post(
  '/',
  rateLimiter,
  createPermissionValidation(),
  validate,
  createPermissionController
);

router.get(
  '/',
  // rateLimiter,
  getPermissionsController
);

export default router;