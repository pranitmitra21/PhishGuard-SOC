import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, Play, CheckCircle2, Server, Terminal } from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip as RechartsTooltip, Legend
} from 'recharts';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function RetrainModel() {
  const [status, setStatus] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [epochs, setEpochs] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const source = new EventSource(`${API_URL}/api/admin/retrain/status?token=${token}`);
    
    source.onmessage = (e) => {
      const data = JSON.parse(e.data);
      setStatus(data.status);
      setProgress(data.progress);
      setEpochs(data.epochs);
      
      if (data.status === "completed") {
        source.close();
      }
    };
    
    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) {
        // Closed by server or error, it will auto-reconnect unless we close it
      }
    };
    
    return () => source.close();
  }, [status]); // Re-subscribe if status changes (e.g. from idle to running via trigger)

  const triggerRetrain = async () => {
    if (status === "running") return;
    try {
      await axios.post(`${API_URL}/api/admin/retrain`);
      setStatus("running");
      setProgress(0);
      setEpochs([]);
    } catch (err) {
      console.error(err);
      alert("Failed to trigger retraining.");
    }
  };

  return (
    <div className="max-w-6xl mx-auto flex flex-col p-6 font-mono text-gray-300">
      <div className="mb-6 border-b border-cyber-cyan/30 pb-4 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-black text-white uppercase flex items-center gap-3">
            <Activity className="text-cyber-amber" /> MLOps Retraining
          </h1>
          <p className="text-xs text-cyber-cyan/60 mt-1 uppercase">Dynamic Model Retraining Pipeline</p>
        </div>
        <button 
          onClick={triggerRetrain}
          disabled={status === "running"}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase transition-all ${status === "running" ? 'bg-cyber-amber/20 text-cyber-amber/50 cursor-not-allowed border border-cyber-amber/20' : 'bg-cyber-amber/10 border border-cyber-amber text-cyber-amber hover:bg-cyber-amber/20 hover:shadow-[0_0_15px_rgba(255,176,0,0.4)]'}`}
        >
          {status === "running" ? <Activity className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {status === "running" ? 'PIPELINE ACTIVE' : 'INITIATE PIPELINE'}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Status Panel */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-black/60 border border-cyber-cyan/30 p-6 shadow-[0_0_15px_rgba(0,0,0,0.8)]">
            <h3 className="text-cyber-cyan font-bold uppercase flex items-center gap-2 mb-4 border-b border-cyber-cyan/20 pb-2">
              <Server className="w-4 h-4" /> System Status
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">PostgreSQL DB</span>
                <span className="text-cyber-green font-bold">ONLINE</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">Redis Cache</span>
                <span className="text-cyber-green font-bold">ONLINE</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">Architecture</span>
                <span className="text-cyber-cyan font-bold">XGBoost + Deep Learning</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">Feature Vectors</span>
                <span className="text-white font-bold">22 Network/Lexical Signals</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">Training Dataset</span>
                <span className="text-cyber-green font-bold">Web Page Phishing DB</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="uppercase text-gray-400">Dataset Rows</span>
                <span className="text-white font-bold">11,430 (Balanced)</span>
              </div>
            </div>
          </div>

          <div className="bg-black/60 border border-cyber-amber/30 p-6 shadow-[0_0_15px_rgba(255,176,0,0.2)]">
            <h3 className="text-cyber-amber font-bold uppercase flex items-center gap-2 mb-4 border-b border-cyber-amber/20 pb-2">
              <Terminal className="w-4 h-4" /> Pipeline Progress
            </h3>
            <div className="flex justify-between text-xs mb-2">
              <span className="text-gray-400 uppercase">Training Stage</span>
              <span className="text-white font-bold">{progress}%</span>
            </div>
            <div className="w-full bg-black border border-gray-800 h-2 mb-4">
              <div 
                className="bg-cyber-amber h-full transition-all duration-500 shadow-[0_0_10px_#ffb000]"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            <div className="text-[10px] text-gray-500 uppercase mt-4">
              {status === "idle" && "System Idle. Awaiting commands."}
              {status === "running" && "Pipeline active. Generating synthetic epochs and computing gradients."}
              {status === "completed" && (
                <div className="text-cyber-green mt-4">
                  <span className="flex items-center gap-1 font-bold mb-2">
                    <CheckCircle2 className="w-3 h-3" /> Training Complete. Model Reloaded.
                  </span>
                  {epochs.length > 0 && (
                    <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-cyber-green/20">
                      <div>
                        <span className="text-cyber-green/60 text-[9px] block uppercase">Final Accuracy</span>
                        <span className="text-lg">{(epochs[epochs.length - 1].accuracy * 100).toFixed(2)}%</span>
                      </div>
                      <div>
                        <span className="text-cyber-green/60 text-[9px] block uppercase">Final Loss</span>
                        <span className="text-lg">{(epochs[epochs.length - 1].loss).toFixed(4)}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Graph Panel */}
        <div className="lg:col-span-2 bg-black/60 border border-cyber-cyan/30 p-6 shadow-[0_0_15px_rgba(0,0,0,0.8)] flex flex-col">
          <h3 className="text-cyber-cyan font-bold uppercase flex items-center gap-2 mb-4 border-b border-cyber-cyan/20 pb-2">
            <Activity className="w-4 h-4" /> Training Telemetry
          </h3>
          
          <div className="flex-1 min-h-[300px]">
            {epochs.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={epochs}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a1a2e" vertical={false} />
                  <XAxis dataKey="epoch" tick={{ fill: '#00f3ff', fontSize: 10, fontFamily: 'monospace' }} stroke="#1a1a2e" />
                  <YAxis yAxisId="left" domain={[0.6, 1.0]} tick={{ fill: '#39ff14', fontSize: 10, fontFamily: 'monospace' }} stroke="#1a1a2e" />
                  <YAxis yAxisId="right" orientation="right" domain={[0, 1.0]} tick={{ fill: '#ff003c', fontSize: 10, fontFamily: 'monospace' }} stroke="#1a1a2e" />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#09090b', border: '1px solid #00f3ff', fontFamily: 'monospace', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '10px', fontFamily: 'monospace' }} />
                  <Line yAxisId="left" type="monotone" dataKey="accuracy" name="Accuracy" stroke="#39ff14" strokeWidth={2} dot={{ r: 3, fill: '#09090b', stroke: '#39ff14' }} activeDot={{ r: 6 }} />
                  <Line yAxisId="right" type="monotone" dataKey="loss" name="Loss" stroke="#ff003c" strokeWidth={2} dot={{ r: 3, fill: '#09090b', stroke: '#ff003c' }} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-cyber-cyan/30 text-xs uppercase tracking-widest animate-pulse border border-dashed border-cyber-cyan/20 m-4">
                AWAITING TELEMETRY STREAM
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
