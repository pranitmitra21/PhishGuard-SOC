import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Users, Shield, ShieldAlert, Key } from 'lucide-react';

const API_URL = 'http://127.0.0.1:8000';

export default function AuthMatrix() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/admin/users`);
      setUsers(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRoleChange = async (user, newRole) => {
    let payload = { role: newRole };
    
    if (newRole === 'Admin') {
      const pin = prompt("Enter Admin Security PIN to grant Admin privileges:");
      if (!pin) return; // User cancelled
      payload.admin_pin = pin;
    } else if (newRole === 'Analyst') {
      if (!user.wallet_id) {
        const wallet = prompt("Enter Ethereum Sepolia Wallet ID for Analyst blockchain logging:");
        if (!wallet || wallet.trim() === '') {
          alert("Wallet ID is required to grant Analyst clearance.");
          fetchUsers(); // reset dropdown
          return;
        }
        payload.wallet_id = wallet;
      }
    }

    try {
      await axios.put(`${API_URL}/api/admin/users/${user.id}/role`, payload);
      fetchUsers();
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        alert("Failed to update role: " + err.response.data.detail);
      } else {
        alert("Failed to update role");
      }
      fetchUsers(); // reset dropdown visually
    }
  };

  if (loading) return <div className="p-6 text-cyber-cyan font-mono animate-pulse">LOADING MATRIX...</div>;

  return (
    <div className="max-w-7xl mx-auto flex flex-col p-6 font-mono text-gray-300">
      <div className="mb-6 border-b border-cyber-cyan/30 pb-4">
        <h1 className="text-2xl font-black text-white uppercase flex items-center gap-3">
          <Users className="text-cyber-cyan" /> Auth Matrix
        </h1>
        <p className="text-xs text-cyber-cyan/60 mt-1 uppercase">Manage Identity Access and Permissions</p>
      </div>

      <div className="bg-black/60 border border-cyber-cyan/30 p-4 shadow-[0_0_15px_rgba(0,0,0,0.8)]">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="text-cyber-cyan/60 border-b border-cyber-cyan/20">
            <tr>
              <th className="px-4 py-2 uppercase">ID</th>
              <th className="px-4 py-2 uppercase">Username</th>
              <th className="px-4 py-2 uppercase">Clearance Level</th>
              <th className="px-4 py-2 uppercase">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-cyan/10">
            {users.map((user) => (
              <tr key={user.id} className="hover:bg-cyber-cyan/5 transition-colors">
                <td className="px-4 py-3 text-cyber-cyan/50">[{user.id.toString().padStart(4, '0')}]</td>
                <td className="px-4 py-3 font-bold">{user.username}</td>
                <td className="px-4 py-3">
                  <select 
                    value={user.role}
                    onChange={(e) => handleRoleChange(user, e.target.value)}
                    className="bg-black border border-cyber-cyan/30 text-cyber-cyan text-xs uppercase px-2 py-1 outline-none focus:border-cyber-cyan"
                  >
                    <option value="User">User</option>
                    <option value="Analyst">Analyst</option>
                    <option value="Admin">Admin</option>
                  </select>
                </td>
                <td className="px-4 py-3">
                  {user.is_active ? 
                    <span className="text-cyber-green text-xs font-bold px-2 border border-cyber-green/50 bg-cyber-green/10">ACTIVE</span> : 
                    <span className="text-cyber-pink text-xs font-bold px-2 border border-cyber-pink/50 bg-cyber-pink/10">REVOKED</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
