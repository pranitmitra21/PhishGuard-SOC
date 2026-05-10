import React, { useEffect, useState, useMemo } from 'react';
import axios from 'axios';
import {
  ShieldAlert, ShieldCheck, Shield, Database,
  Activity, Clock, LayoutDashboard, Users,
  Globe, Settings, Search, Bell, ChevronDown, Flag, FileText, Menu,
  Terminal, X
} from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip,
  Legend, LineChart, Line, XAxis, YAxis, CartesianGrid
} from 'recharts';

const API_URL = 'http://127.0.0.1:8000';

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);
  const [filterMode, setFilterMode] = useState(null);
  const [warningDismissed, setWarningDismissed] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  const toggleRow = (id) => setExpandedRow(expandedRow === id ? null : id);

  const generateAiExplanation = (log) => {
    if (log.status === 'Safe') return "The Artificial Intelligence verified this node as mathematically sound. The domain structure, protocol security, and embedded code elements passed all heuristic baseline checks without triggering any anomaly alerts.";
    
    let reasons = [];
    if (log.has_at_symbol) reasons.push("an obfuscated '@' symbol designed to mask the true destination");
    if (!log.is_https) reasons.push("a critically insecure HTTP connection which exposes user data");
    if (log.num_subdomains > 2) reasons.push("an abnormally long chain of subdomains typically used to impersonate legitimate brand websites");
    if (log.url_length > 75) reasons.push("a heavily extended URL character length designed to push malicious routing parameters off-screen");
    if (log.suspicious_dom_elements > 0) reasons.push(`anomalous HTML structures (${log.suspicious_dom_elements} instances) such as hidden scripts or unsecured password forms`);
    
    if (reasons.length === 0) {
      return `The Random Forest AI flagged this site as ${log.status.toUpperCase()} based on complex multi-layer machine learning heuristics and tranco whitelist data, despite surface-level traits appearing nominal.`;
    }
    
    let formattedReasons = reasons.length > 1 ? reasons.slice(0, -1).join(", ") + ", and " + reasons[reasons.length - 1] : reasons[0];
    
    return `The Random Forest AI quarantined this Threat Vector because it explicitly detected ${formattedReasons}. Extreme caution is advised.`;
  };

  const displayedLogs = useMemo(() => {
    let filtered = logs;
    if (filterMode) {
      filtered = filtered.filter(log => log.status === filterMode);
    }
    if (searchQuery) {
      const lowerQuery = searchQuery.toLowerCase();
      filtered = filtered.filter(log => 
        log.url.toLowerCase().includes(lowerQuery) || 
        log.url_hash.includes(lowerQuery) ||
        log.status.toLowerCase().includes(lowerQuery)
      );
    }
    return filtered;
  }, [logs, filterMode, searchQuery]);

  const executeManualScan = async () => {
    if (!searchQuery || !searchQuery.includes('.')) return;
    setIsScanning(true);
    try {
      const payload = {
        url: searchQuery.startsWith('http') ? searchQuery : `https://${searchQuery}`,
        url_length: searchQuery.length,
        has_at_symbol: searchQuery.includes("@"),
        num_subdomains: (searchQuery.match(/\./g) || []).length > 1 ? (searchQuery.match(/\./g) || []).length - 1 : 0,
        is_https: searchQuery.startsWith("https") || !searchQuery.startsWith("http"),
        num_redirects: 0,
        suspicious_dom_elements: 0
      };
      await axios.post(`${API_URL}/detect`, payload);
      await fetchData(); // Refresh table and stats
      setSearchQuery(""); // Clear the search bar
    } catch (e) {
      console.error("Manual scan failed:", e);
    } finally {
      setIsScanning(false);
    }
  };

  const fetchData = async () => {
    try {
      const statsRes = await axios.get(`${API_URL}/stats`);
      setStats(statsRes.data);

      const logsRes = await axios.get(`${API_URL}/logs?limit=1000`);
      setLogs(logsRes.data);
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const systemHealth = useMemo(() => {
    if (!stats || stats.total_scanned === 0) return 100;
    const safeRatio = stats.safe_detected / stats.total_scanned;
    return Math.round(safeRatio * 100);
  }, [stats]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-void text-cyber-cyan font-mono scanlines">
        <div className="flex flex-col items-center gap-4">
          <div className="w-16 h-16 border-4 border-cyber-cyan border-t-cyber-pink rounded-full animate-spin shadow-[0_0_15px_#00f3ff]"></div>
          <span className="text-xl tracking-widest uppercase animate-pulse">INITIATING SECURE UPLINK...</span>
        </div>
      </div>
    );
  }

  const pieData = stats ? [
    { name: 'Safe', value: stats.safe_detected, color: '#39ff14' },
    { name: 'Suspicious', value: stats.suspicious_detected, color: '#ffb000' },
    { name: 'Phishing', value: stats.phishing_detected, color: '#ff003c' },
  ] : [];

  const progressionData = stats?.progression || [
    { name: 'Mon', score: 85 }, { name: 'Tue', score: 88 },
    { name: 'Wed', score: 92 }, { name: 'Thu', score: 90 },
    { name: 'Fri', score: 95 }, { name: 'Sat', score: systemHealth },
  ];

  return (
    <div className="flex h-screen bg-cyber-void text-gray-300 font-sans overflow-hidden scanlines">
      {/* Sidebar */}
      <aside className="w-64 bg-opacity-50 bg-black border-r border-cyber-cyan/30 flex-col hidden md:flex backdrop-blur-md relative z-10 shadow-[2px_0_15px_rgba(0,243,255,0.1)]">
        <div className="h-16 flex items-center px-6 border-b border-cyber-cyan/30 bg-cyber-cyan/5">
          <ShieldAlert className="text-cyber-pink h-6 w-6 mr-3 drop-shadow-[0_0_8px_#ff003c]" />
          <span className="text-xl font-black tracking-widest text-cyber-cyan uppercase glitch-effect" style={{ textShadow: '0 0 10px #00f3ff' }}>PHISHGUARD</span>
        </div>

        <nav className="flex-1 overflow-y-auto px-4 py-6 space-y-2">
          <p className="px-2 text-[10px] font-bold text-cyber-cyan/60 uppercase tracking-[0.2em] mb-3">System.Root\Modules</p>
          
          <button className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-bold uppercase tracking-wider rounded-none bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]">
            <LayoutDashboard className="h-4 w-4" /> Terminal.Dash
          </button>
          
          <button onClick={() => alert("Module locked.")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50 transition-all">
            <Globe className="h-4 w-4" /> Net.Graph
          </button>
          
          <button onClick={() => alert("Module locked.")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50 transition-all">
            <Database className="h-4 w-4" /> Threat.Logs
          </button>

          <div className="pt-8 pb-2">
            <p className="px-2 text-[10px] font-bold text-cyber-cyan/60 uppercase tracking-[0.2em] mb-3">Admin.Access</p>
            <button onClick={() => alert("Access Denied.")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50 transition-all">
              <Users className="h-4 w-4" /> Auth.Matrix
            </button>
            <button onClick={() => alert("Access Denied.")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50 transition-all">
              <Settings className="h-4 w-4" /> Sys.Config
            </button>
          </div>
        </nav>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative z-0">
        {/* Top Navbar */}
        <header className="h-16 bg-black/40 backdrop-blur-sm border-b border-cyber-cyan/30 flex items-center justify-between px-4 sm:px-6 lg:px-8 shadow-[0_2px_15px_rgba(0,243,255,0.05)]">
          <div className="flex items-center flex-1">
            <button className="md:hidden text-cyber-cyan mr-4">
              <Menu className="h-6 w-6" />
            </button>
            <div className="max-w-md w-full relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-4 w-4 text-cyber-cyan" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') executeManualScan(); }}
                disabled={isScanning}
                placeholder={isScanning ? "SCANNING EXTERNAL MAINFRAME..." : "EXECUTE QUERY: HASH / IP / URL..."}
                className={`block w-full pl-10 pr-3 py-2 border border-cyber-cyan/30 leading-5 bg-black/50 ${isScanning ? 'text-cyber-amber animate-pulse' : 'text-cyber-cyan'} font-mono placeholder-cyber-cyan/40 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan sm:text-xs transition duration-150 ease-in-out shadow-[inset_0_0_10px_rgba(0,243,255,0.1)] uppercase`}
              />
            </div>
          </div>
          <div className="flex items-center gap-5">
            <button 
              className="text-cyber-cyan hover:text-white relative cursor-pointer transition-colors"
              onClick={() => setFilterMode(filterMode === 'Suspicious' ? null : 'Suspicious')}
            >
              <Bell className="h-5 w-5" />
              <span className="absolute -top-1 -right-1 block h-2 w-2 rounded-none bg-cyber-pink shadow-[0_0_8px_#ff003c]"></span>
            </button>
            
            <div className="flex items-center gap-3 cursor-pointer pl-4 border-l border-cyber-cyan/30">
              <div className="h-8 w-8 bg-cyber-cyan/20 border border-cyber-cyan flex items-center justify-center text-cyber-cyan font-black text-sm shadow-[0_0_10px_rgba(0,243,255,0.3)]">
                ROOT
              </div>
            </div>
          </div>
        </header>

        {/* Dashboard Content */}
        <main className="flex-1 overflow-x-hidden overflow-y-auto p-6 md:p-8">
          <div className="max-w-7xl mx-auto">

            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                 <h1 className="text-3xl font-black text-white tracking-wider uppercase drop-shadow-[0_0_10px_rgba(255,255,255,0.4)]">Operations Center</h1>
                 <p className="text-cyber-cyan font-mono text-xs mt-1">ESTABLISHED CONNECTION TO MAINFRAME // SECTOR 7G</p>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyber-green bg-cyber-green/10 px-4 py-2 border border-cyber-green/50 shadow-[0_0_15px_rgba(57,255,20,0.2)]">
                <span className="w-2 h-2 bg-cyber-green animate-pulse border border-black"></span>
                SYSTEM: SECURE
              </div>
            </div>

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

            {/* Bottom Section: Logs & Pie */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

              {/* Detailed Threat Logs */}
              <div className="lg:col-span-2 bg-black/60 backdrop-blur-md border border-cyber-cyan/30 overflow-hidden shadow-[0_0_20px_rgba(0,0,0,0.7)]">
                <div className="p-4 border-b border-cyber-cyan/30 flex justify-between items-center bg-cyber-cyan/5">
                  <h2 className="text-xs font-bold font-mono text-cyber-cyan flex items-center gap-2 uppercase tracking-widest">
                    <Terminal className="h-4 w-4" />
                    Terminal.Out &gt;&gt; Threat Matrix
                  </h2>
                  <button className="text-[10px] font-mono font-bold text-cyber-cyan/70 hover:text-cyber-cyan hover:shadow-[0_0_8px_#00f3ff] transition-all uppercase border border-cyber-cyan/30 px-2 py-1">/VAR/LOG/ALL</button>
                </div>
                
                <div className="overflow-x-auto overflow-y-auto max-h-[350px] p-4 font-mono">
                  <table className="w-full text-left text-xs whitespace-nowrap">
                    <thead className="text-cyber-cyan/60 border-b border-cyber-cyan/20">
                      <tr>
                        <th className="px-4 py-2 font-normal uppercase tracking-wider">Target_URI</th>
                        <th className="px-4 py-2 font-normal uppercase tracking-wider">Type_Class</th>
                        <th className="px-4 py-2 font-normal uppercase tracking-wider">AI_Conf</th>
                        <th className="px-4 py-2 font-normal uppercase tracking-wider text-right">Blockchain_Tx</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-cyan/10">
                      {displayedLogs.length > 0 ? displayedLogs.map((log) => (
                        <React.Fragment key={log.id}>
                          <tr
                            onClick={() => toggleRow(log.id)}
                            className={`cursor-pointer transition-colors ${expandedRow === log.id ? 'bg-cyber-cyan/10 ring-1 ring-inset ring-cyber-cyan' : 'hover:bg-cyber-cyan/5'}`}
                          >
                            <td className="px-4 py-3">
                              <span className="text-gray-300 font-bold truncate max-w-[200px] sm:max-w-xs inline-block" title={log.url}>{log.url}</span>
                            </td>
                            <td className="px-4 py-3">
                              <StatusBadge status={log.status} />
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="w-12 h-1 bg-gray-800 overflow-hidden border border-gray-700">
                                  <div
                                    className={`h-full ${log.confidence > 80 ? 'bg-cyber-green shadow-[0_0_5px_#39ff14]' : 'bg-cyber-cyan shadow-[0_0_5px_#00f3ff]'}`}
                                    style={{ width: `${log.confidence}%` }}>
                                  </div>
                                </div>
                                <span className="text-[10px] font-bold text-cyber-cyan">{log.confidence.toFixed(0)}%</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-right">
                              {log.status === "Phishing" ? (
                                <span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-cyber-pink tracking-wider">
                                  <Database className="h-3 w-3" /> COMMITTED
                                </span>
                              ) : (
                                <span className="text-gray-600 text-[10px] tracking-wider uppercase">NULL</span>
                              )}
                            </td>
                          </tr>

                          {/* Expanded Feature Row */}
                          {expandedRow === log.id && (
                            <tr className="bg-black">
                              <td colSpan="4" className="px-4 py-3">
                                <div className="border border-cyber-cyan/20 p-3 relative overflow-hidden bg-cyber-void group">
                                  {/* Decor */}
                                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-cyan"></div>
                                  <div className="absolute opacity-[0.03] -top-16 -right-10 pointer-events-none group-hover:opacity-10 transition-opacity duration-500">
                                    <Shield className="w-64 h-64 text-cyber-cyan" />
                                  </div>

                                  <h4 className="text-cyber-cyan mb-2 flex items-center gap-2 uppercase tracking-widest text-[10px] font-bold border-b border-cyber-cyan/20 pb-1">
                                    <Activity className="h-3 w-3" /> DEEP_SCAN_MATRIX_OUTPUT
                                  </h4>

                                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4 border-b border-cyber-cyan/10 pb-4">
                                    <div className="flex flex-col">
                                      <span className="text-cyber-cyan/50 text-[9px] uppercase mb-1">Str.Len</span>
                                      <span className="text-white font-bold">{log.url_length} bytes</span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-cyber-cyan/50 text-[9px] uppercase mb-1">Sym.[@]</span>
                                      <span className={`font-bold ${log.has_at_symbol ? 'text-cyber-pink' : 'text-cyber-green'}`}>
                                        {log.has_at_symbol ? 'TRUE' : 'FALSE'}
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-cyber-cyan/50 text-[9px] uppercase mb-1">Sub.Nodes</span>
                                      <span className={`font-bold ${log.num_subdomains > 3 ? 'text-cyber-amber' : 'text-white'}`}>
                                        {log.num_subdomains}
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-cyber-cyan/50 text-[9px] uppercase mb-1">Proto</span>
                                      <span className={`font-bold flex items-center gap-1 ${log.is_https ? 'text-cyber-green' : 'text-cyber-pink'}`}>
                                        {log.is_https ? 'HTTPS/SEC' : 'HTTP/RAW'}
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-cyber-cyan/50 text-[9px] uppercase mb-1">DOM.Anom</span>
                                      <span className="text-white font-bold inline-flex items-center gap-1">
                                            {log.suspicious_dom_elements} <span className="text-cyber-pink font-normal text-[8px]">[WARN]</span>
                                      </span>
                                    </div>
                                  </div>
                                  
                                  <div className="bg-black/80 border border-cyber-cyan/10 p-3 relative shadow-[inset_0_0_10px_rgba(0,0,0,0.8)]">
                                    <span className="text-cyber-amber/80 text-[10px] font-bold uppercase tracking-widest block mb-1 flex items-center gap-2">
                                      <Search className="h-3 w-3" /> AI_HEURISTIC_EXPLANATION
                                    </span>
                                    <p className="text-white/80 text-xs leading-relaxed font-sans">
                                      {generateAiExplanation(log)}
                                    </p>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      )) : (
                        <tr>
                          <td colSpan="4" className="text-center py-10">
                            <span className="text-cyber-cyan/30 uppercase tracking-widest text-xs">/dev/null - NO RECORDS FOUND</span>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Distribution Pie Chart */}
              <div className="bg-black/60 backdrop-blur-md border border-cyber-cyan/30 p-6 flex flex-col shadow-[0_0_20px_rgba(0,0,0,0.7)]">
                <h2 className="text-sm font-bold tracking-widest text-cyber-cyan mb-4 text-center uppercase">Threat Vectors</h2>
                <div className="flex-1 min-h-[200px] relative">
                  {stats && stats.total_scanned > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={2}
                          dataKey="value"
                          stroke="#09090b"
                          strokeWidth={2}
                        >
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <RechartsTooltip
                          contentStyle={{ backgroundColor: '#09090b', border: '1px solid #00f3ff', color: '#00f3ff', fontFamily: 'monospace', fontSize: '12px' }}
                          itemStyle={{ color: '#fff' }}
                        />
                        <Legend verticalAlign="bottom" height={36} iconType="square" wrapperStyle={{ fontFamily: 'monospace', fontSize: '10px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="absolute inset-0 flex items-center justify-center text-cyber-cyan/30 font-mono text-xs uppercase tracking-widest">
                       AWAITING INFEED
                    </div>
                  )}
                </div>
              </div>

            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

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
      {/* Scanline overlay over the card */}
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
      
      {/* Decorative corner brackets */}
      <div className={`absolute top-0 left-0 w-2 h-2 border-t border-l ${theme.border}`}></div>
      <div className={`absolute bottom-0 right-0 w-2 h-2 border-b border-r ${theme.border}`}></div>
    </div>
  );
}

function StatusBadge({ status }) {
  let config = { border: "border-gray-500", text: "text-gray-400", label: "UNKNOWN" };

  if (status === "Safe") config = { border: "border-cyber-green/50", text: "text-cyber-green", label: "SAFE" };
  if (status === "Suspicious") config = { border: "border-cyber-amber/50", text: "text-cyber-amber", label: "WARN" };
  if (status === "Phishing") config = { border: "border-cyber-pink/50", text: "text-cyber-pink shadow-[0_0_8px_#ff003c]", label: "CRIT" };

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-black border ${config.border} ${config.text} bg-black uppercase tracking-widest`}>
      [{config.label}]
    </span>
  );
}

export default App;
