import React from 'react';
import { Terminal, Database, Shield, Activity, Search } from 'lucide-react';

export default function ThreatLogsTab({ 
  activeTab, 
  threatLogFilter, 
  setThreatLogFilter, 
  displayedLogs, 
  toggleRow, 
  expandedRow, 
  generateAiExplanation 
}) {

  const StatusBadge = ({ status }) => {
    let config = { border: "border-gray-500", text: "text-gray-400", label: "UNKNOWN" };
  
    if (status === "Safe") config = { border: "border-cyber-green/50", text: "text-cyber-green", label: "SAFE" };
    if (status === "Suspicious") config = { border: "border-cyber-amber/50", text: "text-cyber-amber", label: "WARN" };
    if (status === "Phishing") config = { border: "border-cyber-pink/50", text: "text-cyber-pink shadow-[0_0_8px_#ff003c]", label: "CRIT" };
  
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-black border ${config.border} ${config.text} bg-black uppercase tracking-widest`}>
        [{config.label}]
      </span>
    );
  };

  return (
    <div id="threat-logs-table" className={`${activeTab === 'Threat.Logs' ? 'lg:col-span-3' : 'lg:col-span-2'} bg-black/60 backdrop-blur-md border border-cyber-cyan/30 overflow-hidden shadow-[0_0_20px_rgba(0,0,0,0.7)]`}>
      <div className="p-4 border-b border-cyber-cyan/30 flex justify-between items-center bg-cyber-cyan/5">
        <h2 className="text-xs font-bold font-mono text-cyber-cyan flex items-center gap-2 uppercase tracking-widest">
          <Terminal className="h-4 w-4" />
          Terminal.Out &gt;&gt; Threat Matrix
        </h2>
        <div className="flex items-center gap-3">
          {activeTab === 'Threat.Logs' && (
            <select 
              value={threatLogFilter}
              onChange={(e) => setThreatLogFilter(e.target.value)}
              className="bg-black border border-cyber-cyan/50 text-[10px] font-mono text-cyber-cyan px-2 py-1 outline-none focus:border-cyber-cyan uppercase cursor-pointer"
            >
              <option value="THREATS_ONLY">THREATS ONLY (HIDE SAFE)</option>
              <option value="SUSPICIOUS">SUSPICIOUS [WARN] ONLY</option>
              <option value="PHISHING">PHISHING [CRIT] ONLY</option>
              <option value="ALL">ALL LOGS</option>
            </select>
          )}
          <button className="text-[10px] font-mono font-bold text-cyber-cyan/70 hover:text-cyber-cyan hover:shadow-[0_0_8px_#00f3ff] transition-all uppercase border border-cyber-cyan/30 px-2 py-1">/VAR/LOG/ALL</button>
        </div>
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
                      log.logged_to_blockchain ? (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-cyber-pink tracking-wider">
                          <Database className="h-3 w-3" /> COMMITTED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-cyber-amber tracking-wider animate-pulse">
                          <Database className="h-3 w-3" /> PENDING
                        </span>
                      )
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
                        <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-cyan"></div>
                        <div className="absolute opacity-[0.03] -top-16 -right-10 pointer-events-none group-hover:opacity-10 transition-opacity duration-500">
                          <Shield className="w-64 h-64 text-cyber-cyan" />
                        </div>

                        <div className="flex items-center justify-between border-b border-cyber-cyan/20 pb-2 mb-3">
                          <h4 className="text-cyber-cyan flex items-center gap-2 uppercase tracking-widest text-[10px] font-bold">
                            <Activity className="h-3 w-3" /> DEEP_SCAN_MATRIX_OUTPUT
                          </h4>
                          {log.status === "Phishing" && log.logged_to_blockchain && (
                            <a 
                              href={`https://sepolia.etherscan.io/address/0x18f9356d3643067A4a371f5cfE2E85B966E8A516`}
                              target="_blank" 
                              rel="noreferrer"
                              className="inline-flex items-center gap-1.5 px-3 py-1 bg-cyber-pink/20 hover:bg-cyber-pink/40 border border-cyber-pink/50 text-cyber-pink text-[9px] font-bold uppercase tracking-wider transition-all shadow-[0_0_8px_rgba(255,0,60,0.3)]"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <Database className="h-3 w-3" /> VERIFY SMART CONTRACT
                            </a>
                          )}
                        </div>

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
  );
}
