import { useState } from "react";
import { PermissionGroup } from "../constants";

interface Permission {
  name: string;
  description: string;
  group: string;
}

const Permission = () => {
  const [permissions, setPermission] = useState<Permission[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [group, setGroup] = useState<string>("");
  const [showSidebar, setShowSidebar] = useState(false);
  const [error, setError] = useState<string>("");

  const validateAndPostData = async () => {
    if (!name.trim()) {
      setError("Label is required");
      return;
    }
    setError("");

    const newPermission: Permission = {
      name,
      description,
      group,
    };

    try {
      const response = await fetch("/permissions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newPermission),
      });
      if (!response.ok) throw new Error("Failed to save role");

      setPermission([...permissions, newPermission]);
      setName("");
      setDescription("");
      setGroup("");
      setShowSidebar(false);
    } catch (err) {
      setError("Error saving role");
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="bg-white shadow-md rounded-lg p-4">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold">Roles</h2>
          <button
            onClick={() => setShowSidebar(true)}
            className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600"
          >
            Add Permission
          </button>
        </div>
        <table className="w-full border-collapse border border-gray-50">
          <thead>
            <tr className="bg-gray-50">
              <th className="p-2">Name</th>
              <th className="p-2">Description</th>
              <th className="p-2">Group</th>
            </tr>
          </thead>
          <tbody>
            {permissions.map((permission, index) => (
              <tr key={index} className="border">
                <td className="p-2">{permission.name}</td>
                <td className="p-2">{permission.description || "-"}</td>
                <td className="p-2">{permission.group}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showSidebar && (
        <div className="fixed inset-0 flex justify-end bg-transparent bg-opacity-90">
          <div className=" items-start w-[50vw] bg-white p-6 shadow-lg h-full">
            <h3 className="text-xl font-bold mb-3">Create Role</h3>
            {error && (
              <p className="bg-red-50 text-red-700 my-4 p-2 rounded-lg font-semibold">
                {error}
              </p>
            )}
            <div className="text-left my-4">
              <label className="block text-sm font-medium mb-2">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter role label"
                className="w-full border p-2 rounded-md mb-2"
              />
            </div>
            <div className="text-left my-4">
              <label className="block text-sm font-medium mb-2">
                Description
              </label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Enter role description"
                className="w-full border p-2 rounded-md mb-2"
              />
            </div>
            <div className="text-left my-4">
              <label className="block text-sm font-medium mb-2">Group</label>
              <select
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                className="w-full border p-2 rounded-md mb-2"
              >
                <option value="" disabled>
                  Select a permission group
                </option>
                {Object.entries(PermissionGroup[0]).map(([key, value]) => (
                  <option key={key} value={key}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex justify-end space-x-2 mt-4">
              <button
                onClick={() => setShowSidebar(false)}
                className="bg-gray-400 text-white px-4 py-2 rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={validateAndPostData}
                className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Permission;
