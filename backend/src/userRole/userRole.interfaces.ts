import { Types, HydratedDocument, Model } from "mongoose";

export interface IUserRole {
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
