import * as express from 'express';
import { createUserValidation, validate } from './user.validation';
import { createUserController } from './user.controller';
import { rateLimiter } from '../utils';

const router = express.Router();

router.post(
  '/create',
  rateLimiter,
  createUserValidation,
  validate,
  createUserController
);

export default router;