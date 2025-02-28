import { useState } from "react";

interface Role {
  label: string;
  description?: string;
  permissions: string[];
}

const Role = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [label, setLabel] = useState("");
  const [description, setDescription] = useState("");
  const [permissions, setPermissions] = useState<string>("");
  const [showSidebar, setShowSidebar] = useState(false);
  const [error, setError] = useState<string>("");

  const validateAndPostData = async () => {
    if (!label.trim()) {
      setError("Label is required");
      return;
    }
    setError("");

    const newRole: Role = {
      label,
      description,
      permissions: permissions
        .split(",")
        .map((p) => p.trim())
        .filter((p) => p !== ""),
    };

    try {
      const response = await fetch("/user-role", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newRole),
      });
      if (!response.ok) throw new Error("Failed to save role");

      setRoles([...roles, newRole]);
      setLabel("");
      setDescription("");
      setPermissions("");
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
            Add Role
          </button>
        </div>
        <table className="w-full border-collapse border border-gray-50">
          <thead>
            <tr className="bg-gray-50">
              <th className="p-2">Label</th>
              <th className="p-2">Description</th>
              <th className="p-2">Permissions</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {roles.map((role) => (
              <tr key={role.id} className="border">
                <td className="p-2">{role.label}</td>
                <td className="p-2">{role.description || "-"}</td>
                <td className="p-2">{role.permissions.join(", ") || "-"}</td>
                <td className="p-2">
                  <div className="flex justify-center items-center gap-4">
                    <span className="text-blue-600 hover:text-blue-800 transition duration-300 cursor-pointer">
                      <SquarePen />
                    </span>
                    <span className="text-red-600 hover:text-red-800 transition duration-300 cursor-pointer">
                      <Trash2 />
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showSidebar && (
        <div className="fixed inset-0 flex justify-end bg-black bg-opacity-50">
          <div className=" items-start w-[50vw] bg-white p-6 shadow-lg h-full">
            <h3 className="text-xl font-bold mb-3">Create Role</h3>
            {error && (
              <p className="bg-red-50 text-red-700 my-4 p-2 rounded-lg font-semibold">
                {error}
              </p>
            )}
            <div className="text-left my-4">
              <label className="block text-sm font-medium mb-2">Label</label>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
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
              <label className="block text-sm font-medium mb-2">
                Permissions (comma-separated)
              </label>
              <input
                value={permissions}
                onChange={(e) => setPermissions(e.target.value)}
                placeholder="Enter permissions"
                className="w-full border p-2 rounded-md mb-2"
              />
            </div>
            <div className="flex justify-end space-x-2 mt-4">
              <button
                onClick={() => setShowSidebar(false)}
                className="bg-gray-400 text-white px-4 py-2 rounded-md"
              >
                Cancel
              </button>
              <button
                // onClick={addRole}
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

export default Role;
