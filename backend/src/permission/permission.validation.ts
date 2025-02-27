import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { PermissionGroupType } from 'constants';

export const createPermissionValidation = [
  body("name")
    .trim()
    .notEmpty()
    .withMessage("Permission name is required")
    .isString()
    .withMessage("Permission name must be a string"),

  body("description")
    .optional()
    .trim()
    .isString()
    .withMessage("Description must be a string"),

  body("group")
    .notEmpty()
    .withMessage("Permission group is required")
    .isIn(Object.values(PermissionGroupType))
    .withMessage("Invalid permission group"),
];

export const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors: any = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  res.status(422).json({
    status: 'error',
    error: `Invalid value for ${errors.array()[0].path}`,
  });
};
