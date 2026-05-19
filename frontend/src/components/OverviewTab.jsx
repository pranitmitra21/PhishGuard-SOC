import React from 'react';
import { Activity, ShieldCheck, ShieldAlert } from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip,
  Legend, LineChart, Line, XAxis, YAxis, CartesianGrid
} from 'recharts';

function StatCard({ title, value, subtitle, icon, color, onClick, isActive }) {
  const getColors = () => {
      switch(color) {
          case 'cyan': return { border: 'border-cyber-cyan/50', bg: 'bg-cyber-cyan/10', text: 'text-cyber-cyan', hover: 'hover:shadow-[0_0_20px_rgba(0,243,255,0.3)]', shadow: 'shadow-[0_0_10px_rgba(0,243,255,0.1)]', ring: 'ring-cyber-cyan' };
          case 'pink': return { border: 'border-cyber-pink/50', bg: 'bg-cyber-pink/10', text: 'text-cyber-pink', hover: 'hover:shadow-[0_0_20px_rgba(255,0,60,0.3)]', shadow: 'shadow-[0_0_10px_rgba(255,0,60,0.1)]', ring: 'ring-cyber-pink' };
          case 'green': return { border: 'border-cyber-green/50', bg: 'bg-cyber-green/10', text: 'text-cyber-green', hover: 'hover:shadow-[0_0_20px_rgba(57,255,20,0.3)]', shadow: 'shadow-[0_0_10px_rgba(57,255,20,0.1)]', ring: 'ring-cyber-green' };
          case 'amber': return { border: 'border-cyber-amber/50', bg: 'bg-cyber-amber/10', text: 'text-cyber-amber', hover: 'hover:shadow-[0_0_20px_rgba(255,176,0,0.3)]', shadow: 'shadow-[0_0_10px_rgba(255,176,0,0.1)]', ring: 'ring-cyber-amber' };
          default: return { border: 'border-gray-500', bg: 'bg-gray-800', text: 'text-white', hover: 'hover:shadow-md', ring: 'ring-gray-400' };
      }
  }
  const theme = getColors();

  return (
    <div 
      onClick={onClick}
      className={`bg-black/60 backdrop-blur-md p-5 relative overflow-hidden transition-all duration-300 border ${theme.border} border-l-4 border-l-${theme.text} ${theme.hover} ${theme.shadow} group ${onClick ? 'cursor-pointer transform hover:-translate-y-1' : ''} ${isActive ? `ring-1 ring-inset ${theme.ring} bg-black/80` : ''}`}
    >
      <div className="absolute inset-0 scanlines opacity-50 pointer-events-none"></div>
      
      <div className="relative z-10 flex justify-between items-start">
        <div>
          <p className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest mb-1">{title}</p>
          <h3 className={`text-3xl font-black ${theme.text} font-mono mt-1 mb-2`}>{value}</h3>
          <span className="text-[9px] font-mono text-gray-400 bg-gray-900 border border-gray-700 px-1 py-0.5 uppercase tracking-wider">{subtitle}</span>
        </div>
        <div className={`p-2 bg-black border ${theme.border} shadow-inner`}>
          {icon}
        </div>
      </div>
      
      <div className={`absolute top-0 left-0 w-2 h-2 border-t border-l ${theme.border}`}></div>
      <div className={`absolute bottom-0 right-0 w-2 h-2 border-b border-r ${theme.border}`}></div>
    </div>
  );
}

export default function OverviewTab({ stats, filterMode, setFilterMode, systemHealth, progressionData }) {
  return (
    <>
      {/* Premium Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <StatCard
          title="Total.Requests"
          value={stats?.total_scanned || 0}
          subtitle="TCP/UDP Datagrams"
          icon={<Activity className="text-cyber-cyan" />}
          color="cyan"
          onClick={() => setFilterMode(null)}
          isActive={filterMode === null}
        />
        <StatCard
          title="Safe.Nodes"
          value={stats?.safe_detected || 0}
          subtitle="Verified by ML"
          icon={<ShieldCheck className="text-cyber-green" />}
          color="green"
          onClick={() => setFilterMode(filterMode === 'Safe' ? null : 'Safe')}
          isActive={filterMode === 'Safe'}
        />
        <StatCard
          title="Threats.Nullified"
          value={stats?.phishing_detected || 0}
          subtitle="Blockchain Sealed"
          icon={<ShieldAlert className="text-cyber-pink" />}
          color="pink"
          onClick={() => setFilterMode(filterMode === 'Phishing' ? null : 'Phishing')}
          isActive={filterMode === 'Phishing'}
        />
        <StatCard
          title="Active.Warnings"
          value={stats?.suspicious_detected || 0}
          subtitle="Requires Review"
          icon={<ShieldAlert className="text-cyber-amber" />}
          color="amber"
          onClick={() => setFilterMode(filterMode === 'Suspicious' ? null : 'Suspicious')}
          isActive={filterMode === 'Suspicious'}
        />
        <StatCard
          title="AI.Confidence"
          value={
            <div className="flex items-baseline gap-2">
              <span>{stats?.model_accuracy || 0}%</span>
              <span className="text-xs text-cyber-amber font-normal tracking-wide">FPR: {stats?.false_positive_rate || 0}%</span>
            </div>
          }
          subtitle="Model F1-Score"
          icon={<Activity className="text-gray-400" />}
          color="gray"
        />
      </div>

      {/* Risk & Progression Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Security Health Gauge */}
        <div className="bg-black/60 backdrop-blur-md border border-cyber-cyan/30 p-6 relative overflow-hidden group hover:border-cyber-cyan/60 transition-all shadow-[0_0_20px_rgba(0,0,0,0.7)]">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyber-green/5 -mr-8 -mt-8 rotate-45 border-b border-cyber-green/30"></div>
          
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-sm font-bold tracking-widest text-cyber-cyan uppercase">Integrity Index</h2>
            <span className={`px-2 py-1 text-[10px] font-mono border ${systemHealth > 80 ? 'border-cyber-green text-cyber-green shadow-[0_0_10px_rgba(57,255,20,0.3)]' : 'border-cyber-amber text-cyber-amber bg-cyber-amber/10'}`}>
              {systemHealth > 80 ? 'STATUS: OPTIMAL' : 'STATUS: DEGRADED'}
            </span>
          </div>
          
          <div className="h-48 relative flex flex-col items-center justify-center">
            <ResponsiveContainer width="100%" height="200%">
              <PieChart>
                <Pie
                  data={[
                    { name: 'Score', value: systemHealth, fill: systemHealth > 80 ? '#39ff14' : '#ffb000' },
                    { name: 'Remainder', value: 100 - systemHealth, fill: '#1a1a1a' }
                  ]}
                  cx="50%"
                  cy="100%"
                  startAngle={180}
                  endAngle={0}
                  innerRadius={100}
                  outerRadius={130}
                  dataKey="value"
                  stroke="none"
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute top-1/2 mt-4 text-center">
              <span className="text-5xl font-black text-white" style={{ textShadow: `0 0 20px ${systemHealth > 80 ? '#39ff14' : '#ffb000'}` }}>{systemHealth}</span>
              <p className="text-[10px] text-cyber-cyan/50 font-mono tracking-[0.3em] font-bold mt-1">PERCENTILE</p>
            </div>
          </div>
        </div>

        {/* Trend Line Chart */}
        <div className="bg-black/60 backdrop-blur-md border border-cyber-cyan/30 p-6 relative overflow-hidden shadow-[0_0_20px_rgba(0,0,0,0.7)]">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-sm font-bold tracking-widest text-cyber-cyan uppercase">Threat Telemetry</h2>
            <select className="text-[10px] font-mono border border-cyber-cyan/30 text-cyber-cyan bg-black py-1 px-2 uppercase outline-none focus:border-cyber-cyan">
              <option>LAST_07_CYCLES</option>
            </select>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={progressionData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1a1a2e" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#00f3ff', fontSize: 10, fontFamily: 'monospace' }} dy={10} />
                <YAxis domain={['auto', 'auto']} axisLine={false} tickLine={false} tick={{ fill: '#00f3ff', fontSize: 10, fontFamily: 'monospace' }} dx={-10} />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: '#09090b', border: '1px solid #00f3ff', color: '#00f3ff', fontFamily: 'monospace', fontSize: '12px', boxShadow: '0 0 15px rgba(0,243,255,0.2)' }}
                  itemStyle={{ color: '#00f3ff' }}
                />
                <Line type="monotone" dataKey="score" stroke="#00f3ff" strokeWidth={2} dot={{ r: 3, fill: '#09090b', stroke: '#00f3ff', strokeWidth: 2 }} activeDot={{ r: 6, fill: '#00f3ff', shadow: '0 0 10px #00f3ff' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </>
  );
}
