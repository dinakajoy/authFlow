import { Request, Response, NextFunction } from 'express';
import Permission from './permission.model';

export const createPermissionController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, group, description } = req.body;
    const permission = new Permission({ name, group, description });
    await permission.save();
    res.status(201).json(permission);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};

export const getPermissionsController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const permissions = await Permission.find({});

    res.status(200).json({ status: 'success', permissions });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};
