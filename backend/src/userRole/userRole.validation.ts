import { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';
import mongoose from "mongoose";

export const createUserRoleValidation = [
  body("label")
    .trim()
    .notEmpty()
    .withMessage("Label is required")
    .isString()
    .withMessage("Label must be a string"),

  body("description")
    .optional()
    .trim()
    .isString()
    .withMessage("Description must be a string"),

  body("permissions")
    .optional()
    .isArray()
    .withMessage("Permissions must be an array of IDs")
    .custom((permissions) => {
      if (!permissions.every((id) => mongoose.Types.ObjectId.isValid(id))) {
        throw new Error("Invalid permission ID format");
      }
      return true;
    }),
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
