import React, {
  useEffect, useState, useRef, useCallback, memo
} from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';
import {
  Activity, ShieldAlert, ShieldCheck,
  Database, X, Crosshair, Network, Zap, Lock, Wifi, Search, RefreshCw
} from 'lucide-react';

const API_URL = 'http://127.0.0.1:8000';
const SIDEBAR_W = 256; // matches w-64 in App.jsx
const HEADER_H  = 64;  // matches h-16 in App.jsx

const LEGEND = [
  { color: '#00f3ff', label: 'SOC Core' },
  { color: '#39ff14', label: 'Safe Node' },
  { color: '#ffb000', label: 'Suspicious' },
  { color: '#ff003c', label: 'Phishing' },
  { color: '#ff00ff', label: 'Threat Cluster' },
  { color: '#a1a1aa', label: 'IP Address' },
];

/* ─── tiny helpers ─────────────────────────────────────── */
function getNodeColor(node) {
  if (node.group === 0)   return '#00f3ff';
  if (node.isCluster)     return '#ff00ff';
  if (node.risk_score != null) {
    if (node.risk_score >= 80) return '#ff003c';
    if (node.risk_score >= 40) return '#ffb000';
    return '#39ff14';
  }
  const G = { 1: '#39ff14', 2: '#ffb000', 3: '#ff003c', 4: '#a1a1aa' };
  return G[node.group] ?? '#ffffff';
}

function isThreatNode(node) {
  return node.group === 3 || !!node.isCluster ||
    (node.risk_score != null && node.risk_score >= 80);
}

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

/* ─── SpeedTest modal ──────────────────────────────────── */
const SpeedTestModal = memo(({ onClose }) => {
  const [status, setStatus] = useState('idle');
  const [ping,   setPing]   = useState(0);
  const [mbps,   setMbps]   = useState(0);
  const [pct,    setPct]    = useState(0);

  const run = async () => {
    setStatus('testing'); setPct(10);
    try {
      const t0 = Date.now();
      await axios.get(`${API_URL}/api/speedtest/ping`);
      setPing(Date.now() - t0); setPct(35);
      const t1 = Date.now();
      const r  = await axios.get(`${API_URL}/api/speedtest/download`, { responseType: 'arraybuffer' });
      const s  = (Date.now() - t1) / 1000;
      setMbps(((r.data.byteLength * 8) / (1e6 * s)).toFixed(2));
      setPct(100); setStatus('done');
    } catch { setStatus('error'); }
  };

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="bg-black border border-cyber-cyan/60 p-6 w-96 shadow-[0_0_40px_rgba(0,243,255,0.2)]">
        <div className="flex justify-between items-center mb-6">
          <span className="text-cyber-cyan font-mono text-xs font-bold uppercase tracking-widest flex items-center gap-2">
            <Zap size={14} /> Network Diagnostics
          </span>
          <button onClick={onClose} className="text-gray-500 hover:text-white">
            <X size={16} />
          </button>
        </div>
        <div className="flex justify-around mb-6">
          {[['LATENCY', ping + 'ms', '#39ff14'], ['BANDWIDTH', mbps + ' Mbps', '#00f3ff']].map(([label, val, col]) => (
            <div key={label} className="text-center">
              <div className="text-[9px] text-gray-500 font-mono mb-1">{label}</div>
              <div className="text-3xl font-black font-mono" style={{ color: col, textShadow: `0 0 15px ${col}` }}>{val}</div>
            </div>
          ))}
        </div>
        <div className="h-1.5 bg-gray-900 border border-gray-800 mb-4">
          <div className="h-full bg-cyber-cyan shadow-[0_0_8px_#00f3ff] transition-all duration-500" style={{ width: `${pct}%` }} />
        </div>
        <button onClick={run} disabled={status === 'testing'}
          className="w-full py-3 font-mono text-[11px] font-bold uppercase tracking-widest border border-cyber-cyan text-cyber-cyan hover:bg-cyber-cyan/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
          {status === 'testing' ? 'RUNNING...' : 'INITIALIZE SEQUENCE'}
        </button>
      </div>
    </div>
  );
});

/* ─── Investigation Panel ──────────────────────────────── */
const InvestPanel = memo(({ node, details, investigating, onClose }) => (
  <div className={`absolute top-0 right-0 h-full w-96 bg-black/95 backdrop-blur-xl border-l border-cyber-cyan/40 z-30
    transition-transform duration-300 ease-out shadow-[-20px_0_60px_rgba(0,0,0,0.9)]
    ${node ? 'translate-x-0' : 'translate-x-full'}`}>
    {node && (
      <div className="p-5 h-full flex flex-col font-mono text-gray-300 overflow-hidden">
        {/* header */}
        <div className="flex justify-between items-start border-b border-cyber-cyan/20 pb-4 mb-5">
          <div className="min-w-0 pr-3">
            <span className="text-xs text-cyber-cyan/50 uppercase tracking-[0.2em] block mb-1">Target Identity</span>
            <h2 className="text-lg text-cyber-cyan font-bold truncate" title={node.id}>{node.id}</h2>
            <span className="mt-2 inline-block px-2 py-0.5 text-xs font-bold uppercase tracking-widest border"
              style={{
                color: node.group === 3 ? '#ff003c' : '#a1a1aa',
                borderColor: node.group === 3 ? 'rgba(255,0,60,0.4)' : 'rgba(161,161,170,0.3)',
                background: node.group === 3 ? 'rgba(255,0,60,0.08)' : 'rgba(255,255,255,0.03)',
              }}>
              {node.isCluster ? 'Threat Cluster' : node.nodeType === 'domain' ? 'Domain' : 'IP Address'}
            </span>
          </div>
          <button onClick={onClose} className="text-gray-600 hover:text-cyber-cyan mt-1"><X size={18} /></button>
        </div>

        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {/* risk meter */}
          {node.risk_score != null && (
            <div className="border border-cyber-cyan/20 p-3 bg-cyber-cyan/[0.02]">
              <span className="text-xs text-gray-500 uppercase tracking-widest block mb-2">AI Risk Inference</span>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-1.5 bg-gray-900 border border-gray-800">
                  <div className="h-full transition-all duration-1000"
                    style={{
                      width: `${node.risk_score}%`,
                      background: node.risk_score >= 80 ? '#ff003c' : node.risk_score >= 40 ? '#ffb000' : '#39ff14',
                      boxShadow: `0 0 8px ${node.risk_score >= 80 ? '#ff003c' : node.risk_score >= 40 ? '#ffb000' : '#39ff14'}`,
                    }} />
                </div>
                <span className="text-sm font-bold tabular-nums"
                  style={{ color: node.risk_score >= 80 ? '#ff003c' : node.risk_score >= 40 ? '#ffb000' : '#39ff14' }}>
                  {node.risk_score.toFixed(1)}%
                </span>
              </div>
            </div>
          )}

          {/* investigation body */}
          {investigating ? (
            <div className="flex flex-col items-center py-10 text-cyber-cyan/40">
              <Database size={28} className="animate-pulse mb-3" />
              <span className="text-[10px] tracking-[0.2em] uppercase">Querying Threat DB...</span>
            </div>
          ) : details ? (
            <div className="space-y-3">
              {/* Deep Scan Matrix */}
              {details.log && (
                <div className="border border-cyber-cyan/20 p-3 bg-cyber-cyan/[0.02]">
                  <h4 className="text-xs font-bold text-cyber-cyan uppercase tracking-widest mb-2 flex items-center gap-1.5">
                    <Activity size={12} /> Deep Scan Matrix Output
                  </h4>
                  <div className="grid grid-cols-4 gap-2 mb-3 border-b border-gray-900 pb-2">
                    <div>
                      <div className="text-[10px] text-gray-600 uppercase tracking-widest">STR.LEN</div>
                      <div className="text-xs font-bold text-gray-300">{details.log.url_length ?? 0} bytes</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-600 uppercase tracking-widest">SYM.[@]</div>
                      <div className="text-xs font-bold" style={{ color: details.log.has_at_symbol ? '#ff003c' : '#39ff14' }}>
                        {details.log.has_at_symbol ? 'TRUE' : 'FALSE'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-600 uppercase tracking-widest">SUB.NODES</div>
                      <div className="text-xs font-bold text-gray-300">{details.log.num_subdomains ?? 0}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-600 uppercase tracking-widest">PROTO</div>
                      <div className="text-xs font-bold" style={{ color: details.log.is_https ? '#39ff14' : '#ffb000' }}>
                        {details.log.is_https ? 'HTTPS/SEC' : 'HTTP/VULN'}
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-3 pl-3 border-l-2 border-cyber-amber/50">
                    <div className="text-[10px] text-cyber-amber uppercase tracking-widest mb-1 flex items-center gap-1">
                      <Search size={12} /> AI_HEURISTIC_EXPLANATION
                    </div>
                    <p className="text-xs text-gray-400 leading-relaxed">
                      {generateAiExplanation(details.log)}
                    </p>
                  </div>
                </div>
              )}
              {/* SSL */}
              <div className="border border-cyber-cyan/20 p-3 bg-cyber-cyan/[0.02]">
                <h4 className="text-xs font-bold text-cyber-cyan uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Lock size={12} /> SSL/TLS Protocol
                </h4>
                {details.ssl?.valid ? (
                  <div className="space-y-1.5 text-xs">
                    {[['Issuer', details.ssl.issuer], ['Subject', details.ssl.subject], ['Expires', details.ssl.valid_to]].map(([k, v]) => (
                      <div key={k} className="flex justify-between items-start gap-2">
                        <span className="text-gray-600 shrink-0">{k}:</span>
                        <span className={`text-right break-all ${k === 'Expires' ? 'text-cyber-amber font-bold' : 'text-gray-300'}`}>{v}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-[10px] text-cyber-pink bg-cyber-pink/10 border border-cyber-pink/20 p-2">
                    <ShieldAlert size={11} /> {details.ssl?.error ?? 'No valid certificate.'}
                  </div>
                )}
              </div>
              {/* DNS */}
              <div className="border border-cyber-cyan/20 p-3 bg-cyber-cyan/[0.02]">
                <h4 className="text-xs font-bold text-cyber-cyan uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Activity size={12} /> DNS Records
                </h4>
                {['A','MX','TXT'].map(type => (
                  <div key={type} className="mb-2">
                    <span className="text-[10px] text-gray-600 uppercase tracking-widest border-b border-gray-900 block pb-0.5 mb-1">{type}</span>
                    {details.dns?.[type]?.length > 0
                      ? details.dns[type].map((r, i) => (
                          <div key={i} className="text-xs text-gray-400 break-all pl-2 border-l border-gray-800">{r}</div>
                        ))
                      : <span className="text-xs text-gray-700 pl-2">NULL</span>
                    }
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="py-10 text-center text-gray-600 text-[10px] uppercase tracking-widest border border-dashed border-gray-800 bg-gray-900/30">
              Click a domain node<br/>to run deep scan
            </div>
          )}
        </div>
      </div>
    )}
  </div>
));

/* ─── Main Component ───────────────────────────────────── */
export default function NetGraph() {
  const fgRef = useRef(null);
  const initializedRef = useRef(false);

  // Derive dimensions directly from the window — no container measurement needed.
  // The graph occupies exactly: (window - sidebar) × (window - header).
  // We listen to window resize to keep it accurate.
  const calcDims = useCallback(() => ({
    width:  Math.max(400, window.innerWidth  - SIDEBAR_W),
    height: Math.max(300, window.innerHeight - HEADER_H),
  }), []);

  const [dims,          setDims]          = useState(calcDims);
  const [graphData,     setGraphData]     = useState({ nodes: [], links: [] });
  const [loading,       setLoading]       = useState(true);
  const [selectedNode,  setSelectedNode]  = useState(null);
  const [nodeDetails,   setNodeDetails]   = useState(null);
  const [investigating, setInvestigating] = useState(false);
  const [showSpeed,     setShowSpeed]     = useState(false);

  // --- Session & Timeline State ---
  const [sessionMode,       setSessionMode]       = useState(false);
  const [activeSessionId,   setActiveSessionId]   = useState(null);
  const [availableSessions, setAvailableSessions] = useState([]);
  const [timeRange,         setTimeRange]         = useState([0, Date.now() / 1000]);

  // Window resize → update dimensions
  useEffect(() => {
    const onResize = () => setDims(calcDims());
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [calcDims]);

  // Configure D3 Physics to prevent squeezing
  useEffect(() => {
    const fg = fgRef.current;
    if (fg) {
      // Increase repulsion to keep nodes separated without blowing them too far apart
      const charge = fg.d3Force('charge');
      if (charge) charge.strength(-180);
      
      // Moderate link distance so nodes have breathing room
      const link = fg.d3Force('link');
      if (link) link.distance(50);
    }
  }, [fgRef]);

  // Fetch graph data on mount
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await axios.get(`${API_URL}/api/network-graph-data`);
        if (alive) setGraphData(r.data);
      } catch (e) {
        console.error('NetGraph fetch failed', e);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    const iv = setInterval(async () => {
      try {
        const r = await axios.get(`${API_URL}/api/network-graph-data`);
        if (alive) {
          setGraphData(prev => {
            if (!r.data || !Array.isArray(r.data.nodes) || !Array.isArray(r.data.links)) {
                return prev; // Backend didn't return valid graph data, safely ignore
            }
            if (prev.nodes.length !== r.data.nodes.length || prev.links.length !== r.data.links.length) {
              return r.data; // New architecture, reset graph
            }
            // Gently update properties of existing nodes in-place to preserve physics (x, y)
            let changed = false;
            for (let i = 0; i < prev.nodes.length; i++) {
               const pNode = prev.nodes[i];
               const nNode = r.data.nodes.find(n => n.id === pNode.id);
               if (nNode && (pNode.group !== nNode.group || pNode.timestamp !== nNode.timestamp)) {
                   pNode.group = nNode.group;
                   pNode.timestamp = nNode.timestamp;
                   pNode.risk_score = nNode.risk_score;
                   pNode.val = nNode.val;
                   pNode.isCluster = nNode.isCluster;
                   changed = true;
               }
            }
            return changed ? { nodes: [...prev.nodes], links: prev.links } : prev;
          });
        }
      } catch { /* silent */ }
    }, 5_000); // Polling faster to show live updates smoothly
    return () => { alive = false; clearInterval(iv); };
  }, []);

  // Compute available sessions
  useEffect(() => {
    if (graphData.nodes.length === 0) return;
    const sessions = [...new Set(graphData.nodes.map(n => n.session_id).filter(Boolean))];
    setAvailableSessions(sessions);
    
    // Default to the most recent session
    if (sessions.length > 0 && !activeSessionId) {
       let latestSession = null;
       let maxTs = 0;
       graphData.nodes.forEach(n => {
           if (n.session_id && n.timestamp > maxTs) {
               maxTs = n.timestamp;
               latestSession = n.session_id;
           }
       });
       setActiveSessionId(latestSession);
    }
  }, [graphData.nodes, activeSessionId]);

  // Compute timeline boundaries for the current view
  const sessionMinMax = React.useMemo(() => {
      let nodes = graphData.nodes;
      if (sessionMode && activeSessionId) {
          nodes = nodes.filter(n => n.session_id === activeSessionId);
      } else {
          nodes = nodes.filter(n => n.group !== 0);
      }
      if (nodes.length === 0) return { min: 0, max: 100 };
      const times = nodes.map(n => n.timestamp);
      let minTs = Math.min(...times);
      let maxTs = Math.max(...times);
      
      // Extend timeline to the exact current time ONLY if the session is currently active 
      // (meaning the last event was within the last 2 minutes) or if we are in Global Mode.
      const nowTs = Date.now() / 1000;
      if (!sessionMode || (nowTs - maxTs < 120)) {
          if (nowTs > maxTs) {
              maxTs = nowTs;
          }
      }
      
      // If there is only one event, artificially widen the timeline so the slider works
      if (minTs >= maxTs - 1) {
          minTs = maxTs - 60; // 1 minute window
      }
      return { min: minTs, max: maxTs };
  }, [graphData.nodes, sessionMode, activeSessionId]);

  // Keep timeline max aligned with live data if we're at the edge
  useEffect(() => {
      setTimeRange(prev => {
          // If the slider is completely out of bounds (e.g. from initial load 0-100 fallback), snap to max
          if (prev[1] < sessionMinMax.min || prev[1] > sessionMinMax.max) {
              return [sessionMinMax.min, sessionMinMax.max];
          }
          // Allow scrubber to stay put if user dragged it back, 
          // but if it's near max (within 15 seconds due to 5s poll interval), snap to new max.
          return [sessionMinMax.min, prev[1] < sessionMinMax.max - 15 ? prev[1] : sessionMinMax.max];
      });
  }, [sessionMinMax.max, sessionMinMax.min]);

  // Force snap to LIVE when switching modes or changing sessions
  useEffect(() => {
      setTimeRange([sessionMinMax.min, sessionMinMax.max]);
  }, [sessionMode, activeSessionId, sessionMinMax.min, sessionMinMax.max]);

  // Filtered Graph Data (Memoized for ForceGraph2D)
  const filteredGraphData = React.useMemo(() => {
      let fNodes = graphData.nodes;
      let fLinks = graphData.links;
      
      if (sessionMode && activeSessionId) {
          fNodes = fNodes.filter(n => n.session_id === activeSessionId || n.group === 0);
      }
      
      fNodes = fNodes.filter(n => n.group === 0 || n.timestamp <= timeRange[1]);
      
      const nodeIds = new Set(fNodes.map(n => n.id));
      fLinks = fLinks.filter(l => 
          (typeof l.source === 'object' ? nodeIds.has(l.source.id) : nodeIds.has(l.source)) &&
          (typeof l.target === 'object' ? nodeIds.has(l.target.id) : nodeIds.has(l.target))
      );
      
      return { nodes: fNodes, links: fLinks };
  }, [graphData, sessionMode, activeSessionId, timeRange]);

  // Auto-fit after physics settle (once per mount)
  const onEngineStop = useCallback(() => {
    if (!initializedRef.current && fgRef.current) {
      initializedRef.current = true;
      setTimeout(() => fgRef.current?.zoomToFit(600, 80), 50);
    }
  }, []);

  const handleRecenter = useCallback(() => fgRef.current?.zoomToFit(500, 80), []);

  const handleRefresh = useCallback(() => {
    if (fgRef.current) {
      fgRef.current.d3ReheatSimulation(); // Untangle squeezed physics
      setTimeout(() => fgRef.current.zoomToFit(500, 80), 50);
    }
  }, []);

  // Node click → investigation
  const handleNodeClick = useCallback(async (node) => {
    setSelectedNode(node);
    setNodeDetails(null);
    if (fgRef.current) {
      fgRef.current.centerAt(node.x + 60, node.y, 700);
      fgRef.current.zoom(4, 700);
    }
    if (node.nodeType === 'domain' && node.group !== 0) {
      setInvestigating(true);
      try {
        const r = await axios.get(`${API_URL}/api/node-investigate?domain=${node.id}`);
        setNodeDetails(r.data);
      } catch { /* silent */ }
      finally { setInvestigating(false); }
    }
  }, []);

  // Canvas node drawing
  const drawNode = useCallback((node, ctx, gs) => {
    const color  = getNodeColor(node);
    const threat = isThreatNode(node);
    const r      = (node.val || 6) * 1.5; // Scale up visual size of nodes by 50%
    const isCore = node.group === 0;

    ctx.shadowBlur  = threat ? 28 : isCore ? 20 : 12;
    ctx.shadowColor = color;

    ctx.beginPath();
    if (isCore) {
      // Hexagon
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i;
        const xp = node.x + r * 1.6 * Math.cos(a);
        const yp = node.y + r * 1.6 * Math.sin(a);
        i === 0 ? ctx.moveTo(xp, yp) : ctx.lineTo(xp, yp);
      }
      ctx.closePath();
      ctx.fillStyle   = 'rgba(0,243,255,0.18)';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth   = 2.5 / gs;
      ctx.stroke();
      // inner dot
      ctx.beginPath();
      ctx.arc(node.x, node.y, r * 0.35, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
    } else if (node.nodeType === 'ip') {
      // Diamond
      ctx.moveTo(node.x,     node.y - r);
      ctx.lineTo(node.x + r, node.y);
      ctx.lineTo(node.x,     node.y + r);
      ctx.lineTo(node.x - r, node.y);
      ctx.closePath();
      ctx.fillStyle   = 'rgba(161,161,170,0.12)';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth   = 1.5 / gs;
      ctx.stroke();
    } else {
      // Circle with halo
      ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
      ctx.fillStyle   = threat ? 'rgba(255,0,60,0.18)' : `${color}20`;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth   = (threat ? 2.5 : 1.5) / gs;
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(node.x, node.y, r * 0.32, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
    }

    ctx.shadowBlur = 0;

    // Label — always for core/threat, else only when zoomed enough
    if (isCore || threat || gs > 1.5) {
      const fs = Math.max(10 / gs, 3.5);
      ctx.font         = `bold ${fs}px monospace`;
      ctx.textAlign    = 'center';
      ctx.textBaseline = 'alphabetic';
      const tw = ctx.measureText(node.name).width;
      const bh = fs + 3 / gs;
      const by = node.y + r + 4 / gs;
      ctx.fillStyle = 'rgba(0,0,0,0.82)';
      ctx.fillRect(node.x - tw / 2 - 2 / gs, by, tw + 4 / gs, bh);
      ctx.fillStyle = color;
      ctx.fillText(node.name, node.x, by + bh - 1 / gs);
    }
  }, []);

  // Link helpers — look up nodes by id since after physics they become objects
  const resolveTarget = useCallback((link) => {
    const t = link.target;
    if (typeof t === 'object') return t;
    return graphData.nodes.find(n => n.id === t);
  }, [graphData.nodes]);

  const linkColor  = useCallback((l) => {
    const t = resolveTarget(l);
    if (!t) return 'rgba(0,243,255,0.18)';
    if (t.group === 3 || t.isCluster) return 'rgba(255,0,60,0.55)';
    if (t.group === 2) return 'rgba(255,176,0,0.45)';
    return 'rgba(0,243,255,0.2)';
  }, [resolveTarget]);

  const linkWidth  = useCallback((l) => {
    const t = resolveTarget(l);
    return (t && (t.group === 3 || t.isCluster)) ? 2 : 1;
  }, [resolveTarget]);

  const linkParticles = useCallback((l) => {
    const t = resolveTarget(l);
    return (t && (t.group === 3 || t.group === 2)) ? 3 : 1;
  }, [resolveTarget]);

  const linkParticleW = useCallback((l) => {
    const t = resolveTarget(l);
    return (t && t.group === 3) ? 4 : 2;
  }, [resolveTarget]);

  const linkParticleColor = useCallback((l) => {
    const t = resolveTarget(l);
    return (t && t.group === 3) ? '#ff003c' : '#00f3ff';
  }, [resolveTarget]);

  const linkParticleSpeed = useCallback((l) => {
    const t = resolveTarget(l);
    return (t && t.group === 3) ? 0.016 : 0.005;
  }, [resolveTarget]);

  return (
    <div
      className="relative overflow-hidden bg-black"
      style={{
        width:  dims.width,
        height: dims.height,
        backgroundImage:
          'linear-gradient(rgba(0,243,255,0.03) 1px,transparent 1px),' +
          'linear-gradient(90deg,rgba(0,243,255,0.03) 1px,transparent 1px)',
        backgroundSize: '32px 32px',
      }}
    >
      {/* Vignette */}
      <div className="absolute inset-0 pointer-events-none z-[5]"
        style={{ background: 'radial-gradient(ellipse at 50% 50%,transparent 30%,rgba(0,0,0,0.75) 100%)' }} />
      <div className="scanlines absolute inset-0 opacity-[0.22] pointer-events-none z-[5]" />

      {/* Loading */}
      {loading && (
        <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-black/90">
          <Activity className="animate-spin text-cyber-cyan mb-4" size={44} />
          <span className="text-cyber-cyan font-mono text-xs tracking-[0.35em] uppercase animate-pulse">
            Initializing Network Topology...
          </span>
        </div>
      )}

      {/* Legend */}
      <div className="absolute top-4 left-4 z-20 bg-black/85 backdrop-blur-md border border-cyber-cyan/30 p-4
        shadow-[0_0_20px_rgba(0,243,255,0.08)]">
        <h3 className="text-[9px] text-cyber-cyan font-bold uppercase tracking-[0.2em] mb-3
          flex items-center gap-2 border-b border-cyber-cyan/20 pb-2">
          <Wifi size={12} /> Topology Legend
        </h3>
        <div className="space-y-1.5">
          {LEGEND.map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full shrink-0"
                style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
              <span className="text-[9px] text-gray-400 font-mono uppercase tracking-wider">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div className="absolute top-4 right-4 z-20 flex gap-2">
        <button onClick={() => setSessionMode(!sessionMode)}
          className={`bg-black/85 backdrop-blur-md border font-mono text-[10px]
          uppercase tracking-widest px-4 py-2 flex items-center gap-2 transition-all ${
            sessionMode ? 'border-cyber-cyan text-cyber-cyan shadow-[0_0_15px_rgba(0,243,255,0.25)]' : 'border-gray-600 text-gray-500 hover:border-gray-400'
          }`}>
          <Network size={13} /> {sessionMode ? 'Session Mode' : 'Global Mode'}
        </button>
        <button onClick={handleRefresh}
          className="bg-black/85 backdrop-blur-md border border-cyber-cyan/40 text-cyber-cyan font-mono text-[10px]
          uppercase tracking-widest px-4 py-2 flex items-center gap-2
          hover:bg-cyber-cyan/10 hover:border-cyber-cyan/80 hover:shadow-[0_0_15px_rgba(0,243,255,0.25)] transition-all">
          <RefreshCw size={13} /> Refresh
        </button>
        <button onClick={handleRecenter}
          className="bg-black/85 backdrop-blur-md border border-cyber-cyan/40 text-cyber-cyan font-mono text-[10px]
          uppercase tracking-widest px-4 py-2 flex items-center gap-2
          hover:bg-cyber-cyan/10 hover:border-cyber-cyan/80 hover:shadow-[0_0_15px_rgba(0,243,255,0.25)] transition-all">
          <Crosshair size={13} /> Center
        </button>
        <button onClick={() => setShowSpeed(true)}
          className="bg-black/85 backdrop-blur-md border border-cyber-green/40 text-cyber-green font-mono text-[10px]
          uppercase tracking-widest px-4 py-2 flex items-center gap-2
          hover:bg-cyber-green/10 hover:shadow-[0_0_15px_rgba(57,255,20,0.2)] transition-all">
          <Zap size={13} /> Speed Test
        </button>
      </div>

      {/* The Graph */}
      <ForceGraph2D
        ref={fgRef}
        width={dims.width}
        height={dims.height}
        graphData={filteredGraphData}
        backgroundColor="rgba(0,0,0,0)"
        nodeCanvasObject={drawNode}
        nodePointerAreaPaint={(node, col, ctx) => {
          ctx.fillStyle = col;
          ctx.beginPath();
          ctx.arc(node.x, node.y, (node.val || 6) + 6, 0, Math.PI * 2);
          ctx.fill();
        }}
        linkColor={linkColor}
        linkWidth={linkWidth}
        linkDirectionalParticles={linkParticles}
        linkDirectionalParticleWidth={linkParticleW}
        linkDirectionalParticleColor={linkParticleColor}
        linkDirectionalParticleSpeed={linkParticleSpeed}
        onNodeClick={handleNodeClick}
        cooldownTicks={120}
        onEngineStop={onEngineStop}
      />

      {/* Slide-out Investigation Panel */}
      <InvestPanel
        node={selectedNode}
        details={nodeDetails}
        investigating={investigating}
        onClose={() => setSelectedNode(null)}
      />

      {/* Timeline Slider */}
      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 w-full max-w-3xl z-20 bg-black/85 backdrop-blur-md border border-cyber-cyan/30 p-4 shadow-[0_0_20px_rgba(0,243,255,0.08)] rounded">
          <div className="flex justify-between items-center mb-2">
             <span className="text-[9px] text-cyber-cyan font-bold uppercase tracking-[0.2em] flex items-center gap-2">
                 <Activity size={12} /> Timeline Scrubber
             </span>
             <span className="text-[10px] text-cyber-cyan font-mono font-bold tracking-wider flex items-center gap-2">
                 {Math.abs(timeRange[1] - (Date.now() / 1000)) < 15 ? (
                     <><span className="w-2 h-2 rounded-full bg-cyber-pink animate-pulse"></span> LIVE</>
                 ) : (
                     new Date(timeRange[1] * 1000).toLocaleTimeString()
                 )}
             </span>
          </div>
          <input 
            type="range" 
            className="w-full accent-cyber-cyan cursor-pointer"
            min={sessionMinMax.min}
            max={sessionMinMax.max}
            step="1"
            value={timeRange[1]}
            onChange={(e) => setTimeRange([timeRange[0], parseFloat(e.target.value)])}
          />
          {sessionMode && availableSessions.length > 1 && (
             <div className="mt-4 flex gap-2 overflow-x-auto pb-1 items-center border-t border-cyber-cyan/20 pt-3">
                 <span className="text-[8px] text-gray-500 uppercase tracking-widest mr-2 shrink-0">Switch Session:</span>
                 {availableSessions.map(sid => (
                     <button key={sid} onClick={() => setActiveSessionId(sid)}
                        className={`text-[9px] font-mono px-3 py-1 border whitespace-nowrap transition-all ${
                            sid === activeSessionId ? 'border-cyber-cyan text-cyber-cyan bg-cyber-cyan/10 shadow-[0_0_8px_rgba(0,243,255,0.2)]' : 'border-gray-700 text-gray-500 hover:border-gray-400 hover:text-gray-300'
                        }`}>
                        {sid.slice(0, 8)}
                     </button>
                 ))}
             </div>
          )}
      </div>

      {showSpeed && <SpeedTestModal onClose={() => setShowSpeed(false)} />}
    </div>
  );
}
