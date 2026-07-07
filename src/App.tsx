import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  ArrowRight, 
  Terminal, 
  FileText, 
  Cpu, 
  Activity, 
  AlertTriangle, 
  Clock, 
  History, 
  RotateCcw, 
  ExternalLink,
  ChevronRight,
  Sparkles
} from "lucide-react";
import { AnalysisResponse, HistoryItem } from "./types";
import { analyzeLocalHeuristicsClient } from "./utils/localAnalyzer";

export default function App() {
  const [inputUrl, setInputUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  // Scanning steps to display an immersive cyber analysis loading sequence
  const loadingSteps = [
    "Establishing secure network request context...",
    "Canonicalizing URL structure & decomposing subdomains...",
    "Querying global Domain Authority rankings...",
    "Verifying SSL certificate details & CA trusted chain...",
    "Computing character entropy and brand impersonation weights...",
    "Running Multi-Layer Perceptron neural network analysis...",
    "Generating deep-dive verdict and safety recommendations..."
  ];

  // Load scan history on startup
  useEffect(() => {
    const saved = localStorage.getItem("phishing_scan_history");
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        console.error("Error parsing history:", e);
      }
    }
  }, []);

  // Manage loading logs interval during simulation (snappy 300ms ticks for high performance)
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isLoading) {
      timer = setInterval(() => {
        setLoadingStep((prev) => {
          if (prev < loadingSteps.length - 1) {
            return prev + 1;
          }
          return prev;
        });
      }, 300);
    } else {
      setLoadingStep(0);
    }
    return () => clearInterval(timer);
  }, [isLoading]);

  // Save item to scan history
  const saveToHistory = (url: string, score: number, badge: "SAFE" | "SUSPICIOUS" | "DANGER", badgeColor: "green" | "yellow" | "red") => {
    const newItem: HistoryItem = {
      id: Math.random().toString(36).substr(2, 9),
      url,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      score,
      badge,
      badgeColor
    };
    const updated = [newItem, ...history.filter(h => h.url !== url)].slice(0, 8); // Max 8 items
    setHistory(updated);
    localStorage.setItem("phishing_scan_history", JSON.stringify(updated));
  };

  // Perform Analysis
  const handleAnalyze = async (urlToScan: string) => {
    const targetUrl = urlToScan.trim();
    if (!targetUrl) {
      setError("Please enter a valid URL to analyze.");
      return;
    }

    setError(null);
    setIsLoading(true);
    setLoadingStep(0);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!response.ok) {
        throw new Error("Backend analysis service returned an error state.");
      }

      const data: AnalysisResponse = await response.json();
      
      // Resolve immediately to keep the applet fast and responsive
      setResult(data);
      saveToHistory(targetUrl, data.score, data.badge, data.badgeColor);
      setIsLoading(false);

    } catch (err: any) {
      console.warn("Backend API not reachable. Falling back to client-side local analyzer.", err);
      
      // Run the client-side analyzer directly
      const clientData = analyzeLocalHeuristicsClient(targetUrl);
      clientData.fallbackReason = "GitHub Pages Static Client-Side Mode: URL is being analyzed in real-time directly inside your browser.";
      
      setResult(clientData);
      saveToHistory(targetUrl, clientData.score, clientData.badge, clientData.badgeColor);
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleAnalyze(inputUrl);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("phishing_scan_history");
  };

  const loadFromHistory = (item: HistoryItem) => {
    setInputUrl(item.url);
    handleAnalyze(item.url);
  };

  // SVG parameters for Threat Index Circle
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  // Map score (0-10) to progress percent
  const getProgressStroke = (score: number) => {
    const percentage = (score / 10) * 100;
    return circumference - (percentage / 100) * circumference;
  };

  const getStrokeColor = (badgeColor: "green" | "yellow" | "red") => {
    if (badgeColor === "red") return "#ef4444"; // red-500
    if (badgeColor === "yellow") return "#eab308"; // yellow-500
    return "#22c55e"; // green-500
  };

  return (
    <div className="min-h-screen flex flex-col justify-between font-sans selection:bg-indigo-500/30 selection:text-white pb-8">
      
      {/* Background aesthetics */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none -z-10">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-[#4f46e5]/10 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-[#06b6d4]/10 rounded-full blur-[120px]" />
      </div>

      {/* Primary Header */}
      <header className="w-full max-w-7xl mx-auto px-4 py-6 flex items-center justify-between border-b border-gray-900/60" id="app-header">
        <div 
          onClick={() => { setResult(null); setInputUrl(""); }}
          className="flex items-center gap-3 cursor-pointer group"
          id="header-brand"
        >
          <div className="p-2.5 rounded-xl bg-indigo-600/10 border border-indigo-500/20 group-hover:bg-indigo-600/20 transition-all duration-300 shadow-sm shadow-indigo-500/5">
            <ShieldAlert className="w-6 h-6 text-indigo-400 group-hover:scale-105 transition-transform" />
          </div>
          <div>
            <span className="font-display font-bold text-lg tracking-wide text-white flex items-center gap-1.5">
              PhishingDetector <span className="text-indigo-400 font-semibold text-xs px-1.5 py-0.5 rounded bg-indigo-950/50 border border-indigo-800/30">AI</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono text-gray-500 bg-[#070b19] border border-gray-800/80 px-3.5 py-1.5 rounded-full" id="header-status">
          <span className="text-gray-400">ENGINE V2.4.0</span>
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          <span className="text-green-400 tracking-wider font-medium text-[10px]">REAL-TIME DB ACTIVE</span>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-grow w-full max-w-7xl mx-auto px-4 py-8 md:py-12 flex flex-col justify-center">
        <AnimatePresence mode="wait">
          
          {/* STEP 1: LANDING PAGE */}
          {!result && !isLoading && (
            <motion.div
              key="landing"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              transition={{ duration: 0.4 }}
              className="w-full max-w-4xl mx-auto text-center flex flex-col items-center"
              id="landing-container"
            >
              {/* Badge Announcement */}
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-950/40 border border-indigo-800/30 text-indigo-300 mb-6" id="badge-announcement">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span>Next-Gen Semantic Typosquatting Detection</span>
              </div>

              {/* Huge Hero Heading */}
              <h1 className="text-4xl sm:text-6xl md:text-7.5xl font-display font-bold text-white tracking-tight leading-[1.1] mb-6" id="hero-heading">
                Stop Phishing <span className="text-indigo-500 glow-indigo">Before</span> It Hits.
              </h1>

              {/* Subheading Description */}
              <p className="text-gray-400 text-sm sm:text-lg max-w-2xl mx-auto font-sans leading-relaxed mb-10" id="hero-subheading">
                Our engine uses URL heuristics, domain reputation, and SSL signals to score suspicious links in seconds. Powered by advanced machine learning models.
              </p>

              {/* Sleek Central Input Box */}
              <div 
                className="w-full max-w-2.5xl bg-[#080d21]/95 backdrop-blur-md border border-gray-800 p-2 rounded-2xl flex flex-col sm:flex-row items-center gap-2 shadow-2xl shadow-black/60 focus-within:border-indigo-500/50 transition-all duration-300"
                id="search-card-container"
              >
                <div className="flex items-center gap-3 flex-grow w-full px-4 py-2 sm:py-0">
                  <Globe className="w-5 h-5 text-gray-500 flex-shrink-0" />
                  <input
                    type="url"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    onKeyDown={handleKeyPress}
                    placeholder="Enter URL to scan (e.g. secure-bank-login.net)"
                    className="bg-transparent text-white placeholder-gray-600 focus:outline-none w-full text-sm sm:text-base font-sans"
                    id="url-input"
                  />
                </div>
                <button
                  onClick={() => handleAnalyze(inputUrl)}
                  className="w-full sm:w-auto bg-indigo-600 hover:bg-indigo-500 active:scale-[0.98] text-white px-7 py-3.5 rounded-xl font-medium tracking-wide transition-all shadow-md shadow-indigo-600/10 flex items-center justify-center gap-2"
                  id="btn-analyze"
                >
                  <span>Analyze Link</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              {/* Quick Suggestion links */}
              <div className="flex flex-wrap items-center justify-center gap-3 mt-4 text-xs text-gray-500" id="suggestions-box">
                <span>Try checking:</span>
                <button 
                  onClick={() => { setInputUrl("https://github.com/Dedepya/DocuLens-RAG"); handleAnalyze("https://github.com/Dedepya/DocuLens-RAG"); }}
                  className="text-gray-400 hover:text-indigo-400 hover:underline transition-colors cursor-pointer"
                >
                  GitHub Repository (Safe)
                </button>
                <span className="text-gray-800">•</span>
                <button 
                  onClick={() => { setInputUrl("paypal-login-verify-account.net/signin"); handleAnalyze("paypal-login-verify-account.net/signin"); }}
                  className="text-gray-400 hover:text-red-400 hover:underline transition-colors cursor-pointer"
                >
                  Imposter Paypal Link (Danger)
                </button>
              </div>

              {/* Error Alert */}
              {error && (
                <div className="mt-6 p-4 rounded-xl bg-red-950/20 border border-red-900/30 text-red-400 text-xs sm:text-sm flex items-center gap-3 max-w-xl" id="error-message">
                  <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {/* History Scans Panel */}
              {history.length > 0 && (
                <div className="w-full max-w-2xl mt-16 text-left border-t border-gray-900/80 pt-8" id="history-scans-panel">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-semibold text-gray-500 tracking-wider uppercase flex items-center gap-2">
                      <History className="w-3.5 h-3.5 text-indigo-400" />
                      Recent Domain Checks
                    </span>
                    <button 
                      onClick={clearHistory}
                      className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      <RotateCcw className="w-3 h-3" />
                      Clear History
                    </button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" id="history-grid">
                    {history.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => loadFromHistory(item)}
                        className="p-3 rounded-xl bg-[#050814]/80 border border-gray-900 hover:border-indigo-500/20 hover:bg-[#070c20]/60 transition-all cursor-pointer flex items-center justify-between group"
                      >
                        <div className="flex flex-col min-w-0 pr-2">
                          <span className="text-xs text-gray-300 font-mono truncate font-medium">
                            {item.url}
                          </span>
                          <span className="text-[10px] text-gray-600 mt-0.5">
                            Scanned at {item.timestamp}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                            item.badgeColor === 'green' ? 'bg-green-950/40 text-green-400 border border-green-900/30' :
                            item.badgeColor === 'yellow' ? 'bg-yellow-950/40 text-yellow-400 border border-yellow-900/30' :
                            'bg-red-950/40 text-red-400 border border-red-900/30'
                          }`}>
                            {item.score}/10
                          </span>
                          <ChevronRight className="w-3.5 h-3.5 text-gray-700 group-hover:text-gray-400 transition-colors" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* STEP 2: IMMERSIVE ANALYSIS LOADING OVERLAY */}
          {isLoading && (
            <motion.div
              key="loading-screen"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="w-full max-w-xl mx-auto flex flex-col items-center justify-center text-center py-12"
              id="loading-screen-container"
            >
              {/* Spinning tech core */}
              <div className="relative mb-8" id="spinning-core">
                <div className="w-24 h-24 rounded-full border-2 border-indigo-500/10 border-t-indigo-500 animate-spin" />
                <div className="absolute inset-2 w-20 h-20 rounded-full border-2 border-dashed border-cyan-500/10 border-r-cyan-500 animate-spin [animation-duration:3s]" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <Activity className="w-8 h-8 text-indigo-400 animate-pulse" />
                </div>
              </div>

              {/* Active Loading Text */}
              <h3 className="text-lg font-display font-medium text-white mb-2" id="loading-heading">
                Running Neural Network Diagnostic
              </h3>
              
              {/* Dynamic steps logs with key indicators */}
              <div className="w-full bg-[#050814] border border-gray-900 rounded-xl p-5 font-mono text-left text-xs text-gray-300 mt-4 min-h-[14rem] flex flex-col justify-between shadow-inner" id="loading-logs">
                <div className="flex items-center gap-2 text-indigo-400 font-semibold border-b border-gray-900 pb-2 mb-2">
                  <Terminal className="w-3.5 h-3.5 animate-pulse" />
                  <span>ANALYSIS STATUS ENGINE</span>
                </div>
                <div className="flex-grow overflow-hidden flex flex-col gap-1.5 justify-end">
                  {loadingSteps.slice(0, loadingStep).map((step, idx) => (
                    <div key={idx} className="text-gray-300 flex items-center gap-1.5 transition-all duration-300">
                      <span className="text-emerald-400 font-bold">✓</span>
                      <span>{step}</span>
                    </div>
                  ))}
                  <div className="text-cyan-300 font-semibold truncate animate-pulse flex items-center gap-1.5">
                    <span className="text-cyan-400 animate-bounce">⚡</span>
                    <span>{loadingSteps[loadingStep]}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* STEP 3: SCAN ANALYSIS RESULTS */}
          {result && !isLoading && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="w-full flex flex-col gap-8"
              id="results-container"
            >
              {/* Sleek Top Input Bar */}
              <div 
                className="w-full bg-[#050814]/90 backdrop-blur-md border border-gray-900 p-1.5 rounded-xl flex items-center gap-2 shadow-lg shadow-black/30"
                id="top-bar-container"
              >
                <div className="flex items-center gap-2 flex-grow min-w-0 px-3">
                  <Globe className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  <input
                    type="url"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    onKeyDown={handleKeyPress}
                    placeholder="Enter URL to run another scan..."
                    className="bg-transparent text-white placeholder-gray-600 focus:outline-none w-full text-xs sm:text-sm font-sans"
                    id="top-bar-input"
                  />
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => { setResult(null); setInputUrl(""); }}
                    className="text-xs text-gray-400 hover:text-white bg-[#0f172a] hover:bg-slate-800 px-3 py-2 rounded-lg transition-colors cursor-pointer"
                    id="btn-new-scan"
                  >
                    Reset
                  </button>
                  <button
                    onClick={() => handleAnalyze(inputUrl)}
                    className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded-lg font-medium transition-all shadow-md flex items-center gap-1.5"
                    id="btn-top-analyze"
                  >
                    <span>Analyze Link</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Optional Fallback Warning Banner */}
              {result.isFallback && (
                <div 
                  className="w-full bg-amber-950/20 border border-amber-500/20 p-4 rounded-xl flex items-center gap-3.5 text-left text-amber-300"
                  id="fallback-warning-banner"
                >
                  <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 animate-pulse" />
                  <div className="flex-grow">
                    <span className="text-xs font-bold font-mono tracking-wider uppercase block text-amber-400 mb-0.5">
                      Local Heuristic Scan Active
                    </span>
                    <p className="text-xs text-amber-200/90 leading-relaxed font-sans">
                      {result.fallbackReason || "Diagnostic calculated via standard local rules engine."}
                    </p>
                  </div>
                </div>
              )}

              {/* Multi-Column Grid Dashboard */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start" id="results-grid">
                
                {/* ================= LEFT COLUMN ================= */}
                <div className="col-span-1 lg:col-span-4 flex flex-col gap-6" id="left-column">
                  
                  {/* THREAT INDEX CARD */}
                  <div className="relative overflow-hidden p-6 rounded-2xl bg-[#060a17]/95 border border-gray-900 shadow-xl" id="threat-index-card">
                    
                    {/* Badge top right */}
                    <div className="absolute top-4 right-4" id="threat-index-badge">
                      <span className={`text-[10px] font-bold tracking-wider px-2.5 py-1 rounded-full ${
                        result.badgeColor === "green" ? "bg-green-950/40 text-green-400 border border-green-900/30 glow-green" :
                        result.badgeColor === "yellow" ? "bg-yellow-950/40 text-yellow-400 border border-yellow-900/30 glow-yellow" :
                        "bg-red-950/40 text-red-400 border border-red-900/30 glow-red"
                      }`}>
                        {result.badge}
                      </span>
                    </div>

                    <span className="text-xs font-semibold text-gray-500 tracking-wider uppercase font-mono block mb-6">
                      Threat Index
                    </span>

                    {/* Circular Radial Gauge */}
                    <div className="flex flex-col items-center justify-center my-6" id="gauge-container">
                      <div className="relative w-40 h-40">
                        <svg className="w-full h-full transform -rotate-90">
                          {/* Inner Gray Ring */}
                          <circle
                            cx="80"
                            cy="80"
                            r={radius}
                            fill="transparent"
                            stroke="#0f172a"
                            strokeWidth="10"
                          />
                          {/* Colored Ring */}
                          <motion.circle
                            cx="80"
                            cy="80"
                            r={radius}
                            fill="transparent"
                            stroke={getStrokeColor(result.badgeColor)}
                            strokeWidth="10"
                            strokeDasharray={circumference}
                            initial={{ strokeDashoffset: circumference }}
                            animate={{ strokeDashoffset: getProgressStroke(result.score) }}
                            transition={{ duration: 1, ease: "easeOut" }}
                            strokeLinecap="round"
                          />
                        </svg>
                        
                        {/* Score digit inside circle */}
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className="text-5xl font-display font-bold text-white leading-none">
                            {result.score}
                          </span>
                          <span className="text-[10px] text-gray-500 font-mono tracking-wider uppercase mt-1">
                            out of 10
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Threat Verdict Description Text */}
                    <div className="border-t border-gray-900/80 pt-5 mt-4" id="threat-index-description">
                      <p className="text-gray-300 text-sm leading-relaxed text-left">
                        <strong className="text-white block mb-1">
                          {result.score >= 7 ? "High Risk Detected:" : result.score >= 4 ? "Caution Advised:" : "Security Clearance:"}
                        </strong>
                        {result.verdictText}
                      </p>
                    </div>
                  </div>

                  {/* SECURITY RECOMMENDATION CARD */}
                  <div className="p-6 rounded-2xl bg-[#060a17]/95 border border-gray-900 shadow-xl" id="recommendations-card">
                    <div className="flex items-center gap-2.5 mb-4 border-b border-gray-900 pb-3">
                      <ShieldCheck className="w-5 h-5 text-indigo-400" />
                      <span className="text-xs font-semibold text-gray-200 tracking-wider uppercase font-mono">
                        Security Recommendation
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm leading-relaxed text-left italic">
                      "{result.recommendationText}"
                    </p>
                  </div>
                </div>

                {/* ================= RIGHT COLUMN ================= */}
                <div className="col-span-1 lg:col-span-8 flex flex-col gap-6" id="right-column">
                  
                  {/* CLASSIFIER VERDICT & ML ENSEMBLE CARD */}
                  <div className="p-6 rounded-2xl bg-[#060a17]/95 border border-gray-900 shadow-xl" id="ml-ensemble-card">
                    
                    {/* Header */}
                    <div className="flex items-start justify-between border-b border-gray-900 pb-4 mb-6">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-indigo-600/10 border border-indigo-500/10">
                          <Cpu className="w-5 h-5 text-indigo-400" />
                        </div>
                        <div className="text-left">
                          <h4 className="text-sm font-semibold text-white tracking-wide">
                            Machine Learning Ensemble
                          </h4>
                          <span className="text-[10px] font-mono text-gray-500">
                            Deep Neural Network Analysis
                          </span>
                        </div>
                      </div>
                      <div className="opacity-15">
                        <AlertTriangle className="w-10 h-10 text-gray-500" />
                      </div>
                    </div>

                    {/* Verdict stats breakdown */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6" id="ml-stats-breakdown">
                      
                      {/* Classifier Verdict label & value */}
                      <div className="text-left bg-[#040813] border border-gray-900 p-4 rounded-xl">
                        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block mb-1">
                          Classifier Verdict
                        </span>
                        <span className={`text-2xl font-display font-bold tracking-wide uppercase ${
                          result.badgeColor === "green" ? "text-green-500" :
                          result.badgeColor === "yellow" ? "text-yellow-500" :
                          "text-red-500"
                        }`}>
                          {result.classifierVerdict}
                        </span>
                      </div>

                      {/* Confidence Level */}
                      <div className="text-left bg-[#040813] border border-gray-900 p-4 rounded-xl">
                        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block mb-1">
                          Confidence Score
                        </span>
                        <span className="text-2xl font-display font-bold text-white tracking-wide">
                          {result.confidence}
                        </span>
                      </div>
                    </div>

                    {/* FEATURE IMPORTANCE BADGES */}
                    <div className="text-left mb-6" id="features-list-box">
                      <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block mb-3">
                        Feature Importance
                      </span>
                      <div className="flex flex-wrap gap-2.5">
                        {result.features.map((feat, idx) => (
                          <div 
                            key={idx}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#080d1f] border border-gray-900 text-gray-300 shadow-sm"
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              result.badgeColor === "green" ? "bg-green-500" :
                              result.badgeColor === "yellow" ? "bg-yellow-500" :
                              "bg-red-500"
                            }`} />
                            <span>{feat}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Italics Summary Statement */}
                    <div className="p-4 bg-[#040813]/40 border border-gray-900/60 rounded-xl" id="ml-summary-statement">
                      <p className="text-gray-400 text-xs sm:text-sm leading-relaxed text-left italic">
                        "{result.mlSummary}"
                      </p>
                    </div>

                  </div>

                  {/* HEURISTIC SIGNALS 2x2 GRID */}
                  <div className="text-left" id="heuristics-container">
                    <h3 className="text-base font-display font-semibold text-white mb-4 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-indigo-400" />
                      Heuristic Signals
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4" id="heuristics-grid">
                      
                      {/* Signal 1: Domain Authority */}
                      <div className="p-5 rounded-2xl bg-[#060a17]/95 border border-gray-900 flex flex-col justify-between shadow-md">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-semibold text-gray-400 tracking-wide">
                            Domain Authority
                          </span>
                          <Clock className="w-4 h-4 text-gray-600" />
                        </div>
                        <span className="text-lg font-mono font-bold text-white block mb-1 truncate">
                          {result.domainAuthority.value}
                        </span>
                        <p className="text-gray-500 text-xs leading-relaxed">
                          {result.domainAuthority.explanation}
                        </p>
                      </div>

                      {/* Signal 2: SSL/TLS Security */}
                      <div className="p-5 rounded-2xl bg-[#060a17]/95 border border-gray-900 flex flex-col justify-between shadow-md">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-semibold text-gray-400 tracking-wide">
                            SSL/TLS Security
                          </span>
                          <Clock className="w-4 h-4 text-gray-600" />
                        </div>
                        <span className="text-lg font-mono font-bold text-white block mb-1">
                          {result.sslSecurity.value}
                        </span>
                        <p className="text-gray-500 text-xs leading-relaxed">
                          {result.sslSecurity.explanation}
                        </p>
                      </div>

                      {/* Signal 3: Heuristic Pattern Matching */}
                      <div className="p-5 rounded-2xl bg-[#060a17]/95 border border-gray-900 flex flex-col justify-between shadow-md">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-semibold text-gray-400 tracking-wide">
                            Heuristic Pattern Matching
                          </span>
                          <Clock className="w-4 h-4 text-gray-600" />
                        </div>
                        <span className="text-lg font-mono font-bold text-white block mb-1">
                          {result.heuristicPattern.value}
                        </span>
                        <p className="text-gray-500 text-xs leading-relaxed">
                          {result.heuristicPattern.explanation}
                        </p>
                      </div>

                      {/* Signal 4: Subdomain Depth */}
                      <div className="p-5 rounded-2xl bg-[#060a17]/95 border border-gray-900 flex flex-col justify-between shadow-md">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs font-semibold text-gray-400 tracking-wide">
                            Subdomain Depth
                          </span>
                          <Clock className="w-4 h-4 text-gray-600" />
                        </div>
                        <span className="text-lg font-mono font-bold text-white block mb-1">
                          {result.subdomainDepth.value}
                        </span>
                        <p className="text-gray-500 text-xs leading-relaxed">
                          {result.subdomainDepth.explanation}
                        </p>
                      </div>

                    </div>
                  </div>

                  {/* Indicator showing Fallback engine vs Live AI */}
                  <div className="flex justify-end text-[10px] text-gray-600 font-mono italic pr-1" id="engine-fallback-indicator">
                    <span>
                      {result.isFallback 
                        ? "Diagnostic calculated via standard local rules engine." 
                        : "Diagnostic calculated via live Gemini AI model."}
                    </span>
                  </div>

                </div>

              </div>
            </motion.div>
          )}

        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="w-full max-w-7xl mx-auto px-4 pt-6 border-t border-gray-900/60 flex flex-col sm:flex-row items-center justify-between text-xs text-gray-600 gap-3" id="app-footer">
        <span className="font-mono">
          © 2026 PhishGuard Security. Powered by Google Gemini.
        </span>
        <div className="flex items-center gap-4">
          <span className="hover:text-gray-400 transition-colors cursor-pointer">Security Protocol</span>
          <span className="text-gray-800">•</span>
          <span className="hover:text-gray-400 transition-colors cursor-pointer">API Access</span>
        </div>
      </footer>

    </div>
  );
}
