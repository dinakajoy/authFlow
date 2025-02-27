import { Types, HydratedDocument, Model } from "mongoose";
import { IUserRoles as UserRoleTypes } from "../constants";

export interface IUserRole {
  type: UserRoleTypes[];
  label: string;
  description: string;
  permissions: Types.ObjectId[];
}

export type IUserRoleDocument = HydratedDocument<
  IUserRole,
  {
    _id: Types.ObjectId;
  }
>;

export interface IUserRoleModel extends Model<IUserRoleDocument> {
  findAsOptions(roleIds: Types.ObjectId[]): { value: string; label: string }[];
}
