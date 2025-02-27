import { Types, HydratedDocument, Model } from "mongoose";

export interface IPermission {
  name: string;
  description: string;
  group: string;
}

export type IPermissionDocument = HydratedDocument<
  IPermission,
  {
    _id: Types.ObjectId;
  }
>;

export type IPermissionModel = Model<IPermissionDocument>;
