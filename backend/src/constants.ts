export const EMAIL_ADDRESS_REGEX = new RegExp(
  /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
);

export enum PermissionGroupType {
  Profile = "profile",
  UserProfile = "userProfile",
  User = "user",
  UserRole = "userRole",
  Permissions = "permissions",
}
