import { Request, Response, NextFunction } from 'express';
import User from './user.model'

export const createUserController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { firstName, lastName, phone, email, role, password } = req.body;
    const user = new User({ firstName, lastName, phone, email, role, password });
    await user.save();
    res.status(201).json(user);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
};
