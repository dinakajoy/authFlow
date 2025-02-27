import { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';
import mongoose from "mongoose";

export const createUserValidation = [
  body("firstName")
    .optional()
    .trim()
    .isString()
    .withMessage("First name must be a string"),

  body("lastName")
    .optional()
    .trim()
    .isString()
    .withMessage("Last name must be a string"),

  body("username")
    .trim()
    .notEmpty()
    .withMessage("Username is required")
    .isString()
    .withMessage("Username must be a string"),

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Invalid email format"),

  body("roles")
    .optional()
    .isArray()
    .withMessage("Roles must be an array of IDs")
    .custom((roles) => {
      if (!roles.every((role) => mongoose.Types.ObjectId.isValid(role))) {
        throw new Error("Invalid role ID format");
      }
      return true;
    }),

  body("password")
    .trim()
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long"),
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
