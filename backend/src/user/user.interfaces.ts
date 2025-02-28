import { Types, HydratedDocument, Model } from 'mongoose';
import { ITimestamp } from '../interfaces';

export interface IUser extends ITimestamp {
  _id: Types.ObjectId;
  firstName: string;
  lastName: string;
  phone: string;
  email?: string;
  role: Types.ObjectId;
  password?: string;
}

export type IUserDocument = HydratedDocument<
  IUser,
  {
    authenticate(password: string): Promise<boolean>;
    makeSalt(byteSize?: number): Promise<string>;
    encryptPassword(password: string): Promise<string>;
  }
>;

export type IUserModel = Model<IUserDocument>;
