import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Settings, Save, Server, Shield } from 'lucide-react';

const API_URL = 'http://127.0.0.1:8000';

export default function SysConfig() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/admin/config`);
      setConfig(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      await axios.put(`${API_URL}/api/admin/config`, config);
      alert("System Configuration Saved Successfully.");
    } catch (err) {
      console.error(err);
      alert("Failed to save config.");
    }
  };

  if (loading) return <div className="p-6 text-cyber-cyan font-mono animate-pulse">LOADING CONFIG...</div>;

  return (
    <div className="max-w-4xl mx-auto flex flex-col p-6 font-mono text-gray-300">
      <div className="mb-6 border-b border-cyber-cyan/30 pb-4 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-black text-white uppercase flex items-center gap-3">
            <Settings className="text-cyber-cyan" /> Sys.Config
          </h1>
          <p className="text-xs text-cyber-cyan/60 mt-1 uppercase">Global System Parameters</p>
        </div>
        <button 
          onClick={handleSave}
          className="flex items-center gap-2 bg-cyber-cyan/10 border border-cyber-cyan text-cyber-cyan px-4 py-2 text-sm font-bold uppercase hover:bg-cyber-cyan/20 hover:shadow-[0_0_15px_rgba(0,243,255,0.4)] transition-all"
        >
          <Save className="w-4 h-4" /> COMMIT CHANGES
        </button>
      </div>

      <div className="bg-black/60 border border-cyber-cyan/30 p-6 shadow-[0_0_15px_rgba(0,0,0,0.8)] space-y-6">
        
        <div>
          <h3 className="text-cyber-cyan font-bold uppercase flex items-center gap-2 mb-4 border-b border-cyber-cyan/20 pb-2">
            <Shield className="w-4 h-4" /> Machine Learning Thresholds
          </h3>
          <div className="grid grid-cols-2 gap-6">
            <div className="flex flex-col gap-2">
              <label className="text-xs text-gray-400 uppercase">Phishing Critical Threshold (%)</label>
              <input 
                type="number" 
                value={config.confidence_threshold_phishing}
                onChange={(e) => setConfig({...config, confidence_threshold_phishing: parseFloat(e.target.value)})}
                className="bg-black border border-cyber-cyan/30 text-cyber-cyan px-3 py-2 outline-none focus:border-cyber-cyan focus:shadow-[inset_0_0_10px_rgba(0,243,255,0.1)]"
              />
            </div>
            <div className="flex flex-col gap-2">
              <label className="text-xs text-gray-400 uppercase">Suspicious Warn Threshold (%)</label>
              <input 
                type="number" 
                value={config.confidence_threshold_suspicious}
                onChange={(e) => setConfig({...config, confidence_threshold_suspicious: parseFloat(e.target.value)})}
                className="bg-black border border-cyber-amber/50 text-cyber-amber px-3 py-2 outline-none focus:border-cyber-amber focus:shadow-[inset_0_0_10px_rgba(255,176,0,0.1)]"
              />
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-cyber-cyan font-bold uppercase flex items-center gap-2 mb-4 border-b border-cyber-cyan/20 pb-2 mt-8">
            <Server className="w-4 h-4" /> External Integrations
          </h3>
          <div className="space-y-4">
            <label className="flex items-center gap-3 cursor-pointer group">
              <input 
                type="checkbox" 
                checked={config.enable_blockchain_logging}
                onChange={(e) => setConfig({...config, enable_blockchain_logging: e.target.checked})}
                className="w-5 h-5 accent-cyber-cyan bg-black border border-cyber-cyan/50"
              />
              <span className="text-sm uppercase group-hover:text-cyber-cyan transition-colors">Enable Sepolia Blockchain Logging</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer group">
              <input 
                type="checkbox" 
                checked={config.enable_safe_browsing}
                onChange={(e) => setConfig({...config, enable_safe_browsing: e.target.checked})}
                className="w-5 h-5 accent-cyber-cyan bg-black border border-cyber-cyan/50"
              />
              <span className="text-sm uppercase group-hover:text-cyber-cyan transition-colors">Enable Google Safe Browsing API</span>
            </label>
          </div>
        </div>

      </div>
    </div>
  );
}
