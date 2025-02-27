import mongoose, { Schema } from "mongoose";
import { IUserDocument, IUserModel } from "./user.interfaces";

const UserSchema = new Schema({
  firstName: { type: String, default: "" },
  lastName: { type: String, default: "" },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  roles: [{ type: mongoose.Schema.Types.ObjectId, ref: "UserRole" }],
  password: { type: String, required: true },
});

export default mongoose.model<IUserDocument, IUserModel>("User", UserSchema);
