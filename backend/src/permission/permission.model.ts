import mongoose, { Schema } from "mongoose";
import { PermissionGroupType } from "../constants";
import { IPermissionDocument, IPermissionModel } from "./permission.interfaces";

const PermissionSchema = new Schema({
  name: { type: String },
  description: { type: String },
  group: { type: String, enum: PermissionGroupType }, // E.g. User Management
});

export default mongoose.model<IPermissionDocument, IPermissionModel>(
  "Permission",
  PermissionSchema
);
