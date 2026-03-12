import React, { useEffect, useState, useMemo } from 'react';
import axios from 'axios';
import {
  ShieldAlert, ShieldCheck, Shield, Database,
  Activity, Clock, LayoutDashboard, Users,
  Globe, Settings, Search, Bell, ChevronDown, Flag, FileText, Menu
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

  const toggleRow = (id) => setExpandedRow(expandedRow === id ? null : id);

  const fetchData = async () => {
    try {
      const statsRes = await axios.get(`${API_URL}/stats`);
      setStats(statsRes.data);

      const logsRes = await axios.get(`${API_URL}/logs?limit=10`);
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
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
          <span className="text-slate-500 font-medium">Loading Enterprise Dashboard...</span>
        </div>
      </div>
    );
  }

  const pieData = stats ? [
    { name: 'Safe', value: stats.safe_detected, color: '#10b981' },
    { name: 'Suspicious', value: stats.suspicious_detected, color: '#f59e0b' },
    { name: 'Phishing', value: stats.phishing_detected, color: '#ef4444' },
  ] : [];

  // Dummy progression data for visual appeal
  const progressionData = [
    { name: 'Mon', score: 85 }, { name: 'Tue', score: 88 },
    { name: 'Wed', score: 92 }, { name: 'Thu', score: 90 },
    { name: 'Fri', score: 95 }, { name: 'Sat', score: systemHealth },
  ];

  return (
    <div className="flex h-screen bg-slate-50 font-sans text-slate-800 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col hidden md:flex">
        <div className="h-16 flex items-center px-6 border-b border-slate-200">
          <ShieldAlert className="text-indigo-600 h-6 w-6 mr-2" />
          <span className="text-lg font-bold tracking-tight text-slate-900">PHISHGUARD</span>
        </div>

        <nav className="flex-1 overflow-y-auto px-4 py-6 space-y-1">
          <p className="px-2 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Platform</p>
          <button className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 text-indigo-700">
            <LayoutDashboard className="h-4 w-4" /> Dashboard
          </button>
          <button onClick={() => alert("Real-time Analytics module coming in v2.0")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
            <Globe className="h-4 w-4" /> Real-time Analytics
          </button>
          <button onClick={() => alert("Advanced Threat Logs view coming soon")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
            <Database className="h-4 w-4" /> Threat Logs
          </button>

          <div className="pt-6 pb-2">
            <p className="px-2 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Management</p>
            <button onClick={() => alert("User Management requires Super Admin privileges")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
              <Users className="h-4 w-4" /> Roles & Users
            </button>
            <button onClick={() => alert("Platform Settings module")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
              <Settings className="h-4 w-4" /> Settings
            </button>
            <button onClick={() => alert("Opening API Documentation...")} className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
              <FileText className="h-4 w-4" /> API Docs
            </button>
          </div>
        </nav>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center flex-1">
            <button className="md:hidden text-slate-500 hover:text-slate-700 mr-4">
              <Menu className="h-6 w-6" />
            </button>
            <div className="max-w-md w-full relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-4 w-4 text-slate-400" />
              </div>
              <input
                type="text"
                placeholder="Search logs, URLs, or hashes..."
                className="block w-full pl-10 pr-3 py-2 border border-slate-200 rounded-md leading-5 bg-slate-50 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 sm:text-sm transition duration-150 ease-in-out"
              />
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button className="text-slate-400 hover:text-slate-500 relative">
              <Bell className="h-5 w-5" />
              <span className="absolute top-0 right-0 block h-2 w-2 rounded-full bg-red-400 ring-2 ring-white"></span>
            </button>
            <div className="flex items-center gap-2 cursor-pointer pl-4 border-l border-slate-200">
              <div className="h-8 w-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 font-bold text-sm">
                AD
              </div>
              <span className="text-sm font-medium text-slate-700 hidden sm:block">Admin</span>
              <ChevronDown className="h-4 w-4 text-slate-400" />
            </div>
          </div>
        </header>

        {/* Dashboard Content */}
        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-50 p-6 md:p-8">
          <div className="max-w-7xl mx-auto">

            <div className="mb-8 flex items-center justify-between">
              <h1 className="text-2xl font-bold text-slate-900">Security Overview</h1>
              <div className="flex items-center gap-2 text-sm text-slate-500 bg-white px-3 py-1.5 rounded-md border border-slate-200 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                System Core Active
              </div>
            </div>

            {/* Premium Stat Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
              <StatCard
                title="Total Scans"
                value={stats?.total_scanned || 0}
                subtitle="All time requests"
                icon={<Activity className="text-indigo-600" />}
              />
              <StatCard
                title="Safe Sites"
                value={stats?.safe_detected || 0}
                subtitle="Verified secure"
                icon={<ShieldCheck className="text-emerald-500" />}
              />
              <StatCard
                title="Caught Phishing"
                value={stats?.phishing_detected || 0}
                subtitle="Blockchain secured"
                icon={<ShieldAlert className="text-red-500" />}
                highlight={true}
              />
              <StatCard
                title="Model Accuracy"
                value={`${stats?.model_accuracy || 0}%`}
                subtitle="Random Forest Env."
                icon={<Shield className="text-blue-500" />}
              />
            </div>

            {/* Risk & Progression Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Security Health Gauge */}
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-lg font-semibold text-slate-800">Security Health Score</h2>
                  <span className={`px-3 py-1 text-xs font-medium rounded-full ${systemHealth > 80 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                    {systemHealth > 80 ? 'Excellent' : 'Needs Review'}
                  </span>
                </div>
                <div className="h-48 relative flex flex-col items-center justify-center">
                  <ResponsiveContainer width="100%" height="200%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Score', value: systemHealth, fill: systemHealth > 80 ? '#10b981' : '#f59e0b' },
                          { name: 'Remainder', value: 100 - systemHealth, fill: '#f1f5f9' }
                        ]}
                        cx="50%"
                        cy="100%"
                        startAngle={180}
                        endAngle={0}
                        innerRadius={110}
                        outerRadius={140}
                        dataKey="value"
                        stroke="none"
                        cornerRadius={10}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute top-1/2 mt-4 text-center">
                    <span className="text-5xl font-extrabold text-slate-900">{systemHealth}</span>
                    <p className="text-sm text-slate-400 font-medium">Out of 100</p>
                  </div>
                </div>
              </div>

              {/* Trend Line Chart */}
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-lg font-semibold text-slate-800">Threat Progression</h2>
                  <select className="text-sm border-slate-200 rounded-md text-slate-600 bg-slate-50 py-1 pl-2 pr-6">
                    <option>Last 7 days</option>
                  </select>
                </div>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={progressionData}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                      <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#94a3b8', fontSize: 12 }} dy={10} />
                      <YAxis domain={['auto', 'auto']} axisLine={false} tickLine={false} tick={{ fill: '#94a3b8', fontSize: 12 }} dx={-10} />
                      <RechartsTooltip
                        contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                      />
                      <Line type="monotone" dataKey="score" stroke="#6366f1" strokeWidth={3} dot={{ r: 4, strokeWidth: 2 }} activeDot={{ r: 6, stroke: '#4f46e5' }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Bottom Section: Logs & Pie */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

              {/* Detailed Threat Logs */}
              <div className="lg:col-span-2 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                <div className="p-6 border-b border-slate-200 flex justify-between items-center bg-white">
                  <h2 className="text-lg font-semibold text-slate-800 flex items-center gap-2">
                    <Clock className="h-5 w-5 text-indigo-500" />
                    Threat Detection Logs
                  </h2>
                  <button onClick={() => alert("Loading full pagination interface...")} className="text-sm font-medium text-indigo-600 hover:text-indigo-800 transition-colors">View All Logs</button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm whitespace-nowrap">
                    <thead className="bg-slate-50 text-slate-500 font-medium border-y border-slate-200">
                      <tr>
                        <th className="px-6 py-4">Target URL</th>
                        <th className="px-6 py-4">Classification</th>
                        <th className="px-6 py-4">AI Confidence</th>
                        <th className="px-6 py-4 text-right">Blockchain Record</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {logs.length > 0 ? logs.map((log) => (
                        <React.Fragment key={log.id}>
                          <tr
                            onClick={() => toggleRow(log.id)}
                            className={`cursor-pointer transition-colors ${expandedRow === log.id ? 'bg-indigo-50/30' : 'hover:bg-slate-50'}`}
                          >
                            <td className="px-6 py-4">
                              <div className="flex items-center">
                                <span className="font-medium text-slate-900 truncate max-w-[200px] sm:max-w-xs" title={log.url}>{log.url}</span>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <StatusBadge status={log.status} />
                            </td>
                            <td className="px-6 py-4 text-slate-600">
                              <div className="flex items-center gap-2">
                                <div className="w-16 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full ${log.confidence > 80 ? 'bg-emerald-500' : 'bg-indigo-500'}`}
                                    style={{ width: `${log.confidence}%` }}>
                                  </div>
                                </div>
                                <span className="text-xs font-semibold">{log.confidence.toFixed(0)}%</span>
                              </div>
                            </td>
                            <td className="px-6 py-4 text-right">
                              {log.status === "Phishing" ? (
                                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-100 shadow-sm">
                                  <Database className="h-3 w-3" /> Immutable
                                </span>
                              ) : (
                                <span className="text-slate-400 text-xs italic">Skipped</span>
                              )}
                            </td>
                          </tr>

                          {/* Expanded Feature Row */}
                          {expandedRow === log.id && (
                            <tr className="bg-slate-50 border-b border-indigo-100">
                              <td colSpan="4" className="px-6 py-4">
                                <div className="bg-white border text-xs border-indigo-100 rounded-lg p-4 shadow-sm relative overflow-hidden">
                                  {/* Decorative side accent */}
                                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-indigo-500"></div>

                                  <h4 className="font-bold text-slate-800 mb-3 ml-2 flex items-center gap-2 uppercase tracking-wide text-[10px]">
                                    <Activity className="h-3 w-3" /> Extended Analysis Matrix
                                  </h4>

                                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 ml-2">
                                    <div className="flex flex-col">
                                      <span className="text-slate-400 font-medium mb-1">URL Length</span>
                                      <span className="text-slate-800 font-bold text-sm tracking-tight">{log.url_length} chars</span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-slate-400 font-medium mb-1">Has '@' Char</span>
                                      <span className={`font-bold text-sm ${log.has_at_symbol ? 'text-red-600' : 'text-slate-800'}`}>
                                        {log.has_at_symbol ? 'Detected' : 'Clean'}
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-slate-400 font-medium mb-1">Subdomains</span>
                                      <span className={`font-bold text-sm ${log.num_subdomains > 3 ? 'text-orange-500' : 'text-slate-800'}`}>
                                        {log.num_subdomains} levels
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-slate-400 font-medium mb-1">Transport</span>
                                      <span className={`font-bold text-sm flex items-center gap-1 ${log.is_https ? 'text-emerald-600' : 'text-red-600'}`}>
                                        {log.is_https ? <ShieldCheck className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />}
                                        {log.is_https ? 'HTTPS Encrypted' : 'Insecure HTTP'}
                                      </span>
                                    </div>
                                    <div className="flex flex-col">
                                      <span className="text-slate-400 font-medium mb-1">DOM Anomalies</span>
                                      <span className="text-slate-800 font-bold text-sm">{log.suspicious_dom_elements} flags</span>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      )) : (
                        <tr>
                          <td colSpan="4" className="text-center py-12 text-slate-500 bg-white">
                            <Database className="h-8 w-8 mx-auto text-slate-300 mb-3" />
                            <p className="font-medium text-slate-600">No telemetry recorded</p>
                            <p className="text-xs text-slate-400 mt-1">Initiate scans via the browser extension to populate database.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Distribution Pie Chart */}
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 flex flex-col">
                <h2 className="text-lg font-semibold text-slate-800 mb-6 text-center">Threat Distribution</h2>
                <div className="flex-1 min-h-[250px] relative">
                  {stats && stats.total_scanned > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={70}
                          outerRadius={95}
                          paddingAngle={5}
                          dataKey="value"
                          stroke="none"
                        >
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <RechartsTooltip
                          contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                        />
                        <Legend verticalAlign="bottom" height={36} iconType="circle" />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="absolute inset-0 flex items-center justify-center text-slate-400 text-sm font-medium">
                      Awaiting Data...
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

function StatCard({ title, value, subtitle, icon, highlight = false }) {
  return (
    <div className={`bg-white rounded-xl shadow-sm border p-6 relative overflow-hidden transition-all duration-200 hover:shadow-md ${highlight ? 'border-red-100' : 'border-slate-200'}`}>
      {highlight && <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-bl-full -z-0 opacity-50"></div>}
      <div className="relative z-10">
        <div className="flex justify-between items-start mb-4">
          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100 shadow-sm">
            {icon}
          </div>
        </div>
        <div>
          <h3 className="text-3xl font-extrabold text-slate-900 tracking-tight">{value}</h3>
          <div className="flex items-center gap-2 mt-1">
            <p className="text-sm font-semibold text-slate-700">{title}</p>
            <span className="text-xs text-slate-400 bg-slate-100 px-2 py-0.5 rounded-full">{subtitle}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  let config = { bg: "bg-slate-100", text: "text-slate-700", dot: "bg-slate-500", icon: Flag };

  if (status === "Safe") config = { bg: "bg-emerald-50", text: "text-emerald-700", border: "border-emerald-200", icon: ShieldCheck };
  if (status === "Suspicious") config = { bg: "bg-amber-50", text: "text-amber-700", border: "border-amber-200", icon: ShieldAlert };
  if (status === "Phishing") config = { bg: "bg-red-50", text: "text-red-700", border: "border-red-200", icon: ShieldAlert };

  const Icon = config.icon;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold border ${config.bg} ${config.text} ${config.border}`}>
      <Icon className="h-3.5 w-3.5" />
      {status}
    </span>
  );
}

export default App;
