export interface IRole {
  _id?: string;
  label: string;
  description?: string;
  permission: string[];
}

export interface IPermission {
  _id?: string;
  name: string;
  description: string;
  group: string;
}