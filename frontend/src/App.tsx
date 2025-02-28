import Role from "./pages/Role";
import Permission from "./pages/Permission";

function App() {
  return (
    <>
      <h1 className="bg-gray-700 text-white text-2xl font-bold mb-4 text-center p-12">RBAC Management</h1>
      <Permission />
      <div className="my-12" />
      <Role />
    </>
  );
}

export default App;
