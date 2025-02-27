import { Request, Response, NextFunction } from 'express';
import UserRole from './userRole.model'

export const createUserRoleController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { type, label, description, permissions } = req.body;
    const userRole = new UserRole({ type, label, description, permissions });
    await userRole.save();
    res.status(201).json(userRole);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};
