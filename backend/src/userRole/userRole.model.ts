import mongoose, { Schema } from "mongoose";
import { IUserRoleModel, IUserRoleDocument } from "./userRole.interfaces";

const UserRoleSchema = new Schema({
  label: { type: String, required: true },
  description: { type: String, required: false },
  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: "Permission" }],
});

export default mongoose.model<IUserRoleDocument, IUserRoleModel>(
  "UserRole",
  UserRoleSchema
);
