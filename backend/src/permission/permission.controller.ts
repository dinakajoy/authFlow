import { Request, Response, NextFunction } from 'express';
import Permission from './permission.model'

export const createPermissionController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, group } = req.body;
    const permission = new Permission({ name, group });
    await permission.save();
    res.status(201).json(permission);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};
