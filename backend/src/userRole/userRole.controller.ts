import { Request, Response, NextFunction } from 'express';
import UserRole from './userRole.model';

export const createUserRoleController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { label, description, permission } = req.body;
    const userRole = new UserRole({ label, description, permission });
    await userRole.save();
    res.status(201).json(userRole);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};

export const getUserRoleController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userRoles = await UserRole.find({});

    res.status(200).json({ status: 'success', userRoles });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};
