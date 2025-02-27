import * as express from 'express';
import { createPermissionValidation, validate } from './permission.validation';
import { createPermissionController } from './permission.controller';
import { rateLimiter } from '../utils';

const router = express.Router();

router.post(
  '/create',
  rateLimiter,
  createPermissionValidation(),
  validate,
  createPermissionController
);

export default router;