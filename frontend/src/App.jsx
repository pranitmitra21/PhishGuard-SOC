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
import NetGraph from './components/NetGraph';
import AuthMatrix from './components/AuthMatrix';
import SysConfig from './components/SysConfig';
import RetrainModel from './components/RetrainModel';
import OverviewTab from './components/OverviewTab';
import ThreatLogsTab from './components/ThreatLogsTab';

const API_URL = 'http://127.0.0.1:8000';

// Setup global Axios interceptor for JWT
axios.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);
  const [filterMode, setFilterMode] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    if (tokenFromUrl) {
      localStorage.setItem('token', tokenFromUrl);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    const token = localStorage.getItem('token');
    if (token) {
      try {
        const role = JSON.parse(atob(token.split('.')[1])).role;
        if (role === 'Analyst') return 'Threat.Logs';
      } catch (err) { console.error("Error parsing token role:", err); }
    }
    return 'Terminal.Dash';
  });
  const [userRole, setUserRole] = useState(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        return JSON.parse(atob(token.split('.')[1])).role;
      } catch (err) {
        console.error("Error parsing token:", err);
        localStorage.removeItem('token');
        return null;
      }
    }
    return null;
  });
  const [threatLogFilter, setThreatLogFilter] = useState('THREATS_ONLY');

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUserRole(null);
  };

  const toggleRow = (id) => setExpandedRow(expandedRow === id ? null : id);

  const generateAiExplanation = (log) => {
    if (log.status === 'Safe') return "The PhishGuard AI engine verified this vector as SAFE. The XGBoost + MLP neural ensemble analyzed structural DOM integrity, WHOIS age, and routing protocols, finding zero anomalies. Cross-referenced with the Tranco Top 1M whitelist and global threat intel.";
    
    let reasons = [];
    if (log.confidence >= 99.9) reasons.push("a verified match against global Threat Intelligence databases (Safe Browsing / Known Blocklists)");
    if (log.has_at_symbol) reasons.push("an obfuscated '@' symbol designed to mask the true routing destination");
    if (!log.is_https) reasons.push("a critically insecure HTTP transport layer which exposes user packets");
    if (log.num_subdomains > 2) reasons.push(`an abnormally long chain of subdomains (${log.num_subdomains} levels) typically used to spoof legitimate brand identities`);
    if (log.url_length > 75) reasons.push("a heavily extended URL string designed to push malicious parameters off-screen");
    if (log.suspicious_dom_elements > 0) reasons.push(`anomalous HTML/DOM structures (${log.suspicious_dom_elements} instances) such as hidden scripts, credential harvesting forms, or cross-origin overlays`);
    
    if (reasons.length === 0) {
      if (log.status === 'Suspicious') return "The PhishGuard Neural Ensemble (XGBoost + MLP) flagged this vector as SUSPICIOUS. While explicit heuristic violations are absent, the model detected deep statistical anomalies in the URL's lexical structure and network routing path. Proceed with heightened caution.";
      return "The PhishGuard Neural Ensemble (XGBoost + MLP) quarantined this vector as PHISHING based on deep statistical pattern matching. The combination of domain age, WHOIS anonymity, and URL structure highly correlates with zero-day credential harvesting infrastructure.";
    }
    
    let formattedReasons = reasons.length > 1 ? reasons.slice(0, -1).join(" | ") + " | " + reasons[reasons.length - 1] : reasons[0];
    
    if (log.status === 'Suspicious') {
        return `The Heuristics Engine flagged this Threat Vector as SUSPICIOUS. The following risk factors were identified: [ ${formattedReasons} ]. The AI confidence score has not reached critical mass for an absolute block, but extreme caution is advised.`;
    }
    
    return `The PhishGuard Neural Ensemble successfully quarantined this Threat Vector as PHISHING. The pipeline explicitly detected: [ ${formattedReasons} ]. Forensic evidence has been hashed and pinned to the Ethereum Sepolia network via IPFS.`;
  };

  const displayedLogs = useMemo(() => {
    let filtered = logs;
    
    // In Threat.Logs tab, we use the threatLogFilter dropdown and ignore the Dashboard filter cards
    if (activeTab === 'Threat.Logs') {
      if (threatLogFilter === 'THREATS_ONLY') {
        filtered = filtered.filter(log => log.status !== 'Safe');
      } else if (threatLogFilter === 'SUSPICIOUS') {
        filtered = filtered.filter(log => log.status === 'Suspicious');
      } else if (threatLogFilter === 'PHISHING') {
        filtered = filtered.filter(log => log.status === 'Phishing');
      }
    } else {
      // In Dashboard tab, we apply the filterMode from the stat cards
      if (filterMode) {
        filtered = filtered.filter(log => log.status === filterMode);
      }
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
  }, [logs, filterMode, searchQuery, threatLogFilter, activeTab]);

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
      await axios.post(`${API_URL}/api/detect`, payload);
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
      const statsRes = await axios.get(`${API_URL}/api/stats`);
      setStats(statsRes.data);

      const logsRes = await axios.get(`${API_URL}/api/logs?limit=1000`);
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

  if (!userRole) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-black text-cyber-cyan font-mono p-4 scanlines">
        <ShieldAlert className="w-20 h-20 text-cyber-pink mb-6 drop-shadow-[0_0_15px_#ff003c]" />
        <h1 className="text-2xl font-black mb-2 uppercase tracking-widest text-center">ACCESS DENIED</h1>
        <p className="text-center text-xs text-gray-400 mb-8 max-w-md">
          Hardware Auth Key missing. Please authenticate via the PhishGuard Chrome Extension to access the SOC.
        </p>
      </div>
    );
  }  if (loading) {
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
          
          {userRole !== 'Analyst' && (
              <>
                  <button 
                    onClick={() => setActiveTab('Terminal.Dash')}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm font-bold uppercase tracking-wider rounded-none transition-all ${activeTab === 'Terminal.Dash' ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]' : 'text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50'}`}>
                    <LayoutDashboard className="h-4 w-4" /> Terminal.Dash
                  </button>
                  
                  <button 
                    onClick={() => setActiveTab('Net.Graph')} 
                    className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm font-bold uppercase tracking-wider rounded-none transition-all ${activeTab === 'Net.Graph' ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]' : 'text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50'}`}>
                    <Globe className="h-4 w-4" /> Net.Graph
                  </button>
              </>
          )}
          
          {userRole !== 'User' && (
              <button onClick={() => { setActiveTab('Threat.Logs'); setTimeout(() => document.getElementById('threat-logs-table')?.scrollIntoView({behavior: 'smooth'}), 100); }} className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm font-bold uppercase tracking-wider rounded-none transition-all ${activeTab === 'Threat.Logs' ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]' : 'text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50'}`}>
                <Database className="h-4 w-4" /> Threat.Logs
              </button>
          )}

          {userRole === 'Admin' && (
            <div className="pt-8 pb-2">
              <p className="px-2 text-[10px] font-bold text-cyber-cyan/60 uppercase tracking-[0.2em] mb-3">Admin.Access</p>
              <button onClick={() => setActiveTab('Auth.Matrix')} className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider transition-all ${activeTab === 'Auth.Matrix' ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]' : 'text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50'}`}>
                <Users className="h-4 w-4" /> Auth.Matrix
              </button>
              <button onClick={() => setActiveTab('Sys.Config')} className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider transition-all ${activeTab === 'Sys.Config' ? 'bg-cyber-cyan/10 text-cyber-cyan border-l-4 border-cyber-cyan shadow-[inset_4px_0_0_rgba(0,243,255,0.5)]' : 'text-gray-400 hover:bg-cyber-cyan/5 hover:text-cyber-cyan border-l-4 border-transparent hover:border-cyber-cyan/50'}`}>
                <Settings className="h-4 w-4" /> Sys.Config
              </button>
              <button onClick={() => setActiveTab('Retrain.Model')} className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium uppercase tracking-wider transition-all ${activeTab === 'Retrain.Model' ? 'bg-cyber-amber/10 text-cyber-amber border-l-4 border-cyber-amber' : 'text-cyber-amber hover:bg-cyber-amber/10 border-l-4 border-transparent hover:border-cyber-amber/50'}`}>
                <Activity className="h-4 w-4" /> Retrain.Model
              </button>
            </div>
          )}
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
            
            <div className="flex items-center gap-3 cursor-pointer pl-4 border-l border-cyber-cyan/30" onClick={handleLogout} title="Click to logout">
              <div className="h-8 px-3 bg-cyber-cyan/20 border border-cyber-cyan flex items-center justify-center text-cyber-cyan font-black text-sm shadow-[0_0_10px_rgba(0,243,255,0.3)]">
                {userRole.toUpperCase()}
              </div>
            </div>
          </div>
        </header>
        {/* Dashboard Content */}
        <main className="flex-1 overflow-hidden relative">
          <div className="h-full flex flex-col">

            {/* NetGraph: conditionally rendered so it always mounts at the
                 correct window size. Graph data is cached in App state so
                 remounting never triggers a redundant network fetch. */}
            {activeTab === 'Net.Graph' && (
              <div style={{ position: 'absolute', inset: 0, zIndex: 10 }}>
                <NetGraph />
              </div>
            )}
            {activeTab === 'Auth.Matrix' && (
              <div style={{ position: 'absolute', inset: 0, zIndex: 10, overflowY: 'auto', backgroundColor: '#09090b' }}>
                <AuthMatrix />
              </div>
            )}
            {activeTab === 'Sys.Config' && (
              <div style={{ position: 'absolute', inset: 0, zIndex: 10, overflowY: 'auto', backgroundColor: '#09090b' }}>
                <SysConfig />
              </div>
            )}
            {activeTab === 'Retrain.Model' && (
              <div style={{ position: 'absolute', inset: 0, zIndex: 10, overflowY: 'auto', backgroundColor: '#09090b' }}>
                <RetrainModel />
              </div>
            )}

            {/* Dashboard panel */}
            <div style={{
              display: (activeTab === 'Net.Graph' || activeTab === 'Auth.Matrix' || activeTab === 'Sys.Config' || activeTab === 'Retrain.Model') ? 'none' : 'block',
              position: 'absolute', inset: 0, overflowX: 'hidden', overflowY: 'auto', padding: '2rem 3rem'
            }}>
              <div className="max-w-7xl mx-auto flex flex-col">
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

            {userRole !== 'Analyst' && activeTab === 'Terminal.Dash' && (
                <>
                    <OverviewTab 
                      stats={stats} 
                      filterMode={filterMode} 
                      setFilterMode={setFilterMode} 
                      systemHealth={systemHealth} 
                      progressionData={progressionData} 
                    />
                </>
            )}

            {/* Bottom Section: Logs & Pie */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

              {/* Detailed Threat Logs */}
              <ThreatLogsTab 
                activeTab={activeTab}
                threatLogFilter={threatLogFilter}
                setThreatLogFilter={setThreatLogFilter}
                displayedLogs={displayedLogs}
                toggleRow={toggleRow}
                expandedRow={expandedRow}
                generateAiExplanation={generateAiExplanation}
              />

              {/* Distribution Pie Chart */}
              {activeTab === 'Terminal.Dash' && (
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

export default App;
