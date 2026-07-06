export interface HeuristicSignal {
  value: string;
  explanation: string;
}

export interface AnalysisResponse {
  score: number; // 0 to 10
  badge: "SAFE" | "SUSPICIOUS" | "DANGER";
  badgeColor: "green" | "yellow" | "red";
  verdictText: string;
  recommendationText: string;
  classifierVerdict: "LEGITIMATE" | "SUSPICIOUS" | "PHISHING";
  confidence: string;
  features: string[];
  mlSummary: string;
  domainAuthority: HeuristicSignal;
  sslSecurity: HeuristicSignal;
  heuristicPattern: HeuristicSignal;
  subdomainDepth: HeuristicSignal;
  isFallback?: boolean; // True if calculated via backend fallback instead of live Gemini
  fallbackReason?: string; // Optional reason for the fallback
}

export interface HistoryItem {
  id: string;
  url: string;
  timestamp: string;
  score: number;
  badge: "SAFE" | "SUSPICIOUS" | "DANGER";
  badgeColor: "green" | "yellow" | "red";
}
