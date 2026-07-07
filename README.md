# 🛡️ Phishing Detector (Phishy-URL-Detector)

A full-stack, real-time phishing and malicious URL detection platform. Combining lightning-fast client-side heuristics with server-side Google Gemini intelligence, it dissects suspicious links, identifies credential-harvesting campaigns, exposes brand impersonation, and explains visual/lexical anomalies in plain, human-readable English.

---

## 🚀 Key Features

*   **Dual Analysis Engines**:
    *   **⚡ Local Heuristics Engine**: Performs instant analysis using regex, high-risk pattern matching, SSL protocols validation, subdomain depth measurements, and trusted-brand spoofing rules.
    *   **🧠 AI-Powered Gemini Dissector**: For advanced URLs, the server-side **Gemini API** analyzes social-engineering tactics, obfuscation techniques, character-level entropy, and provides structured explanations.
*   **Comprehensive Risk Scoring**: Grades URLs from `0` (Completely Safe) to `10` (Highly Dangerous) with dynamic, high-contrast visual badges:
    *   🟢 **SAFE**
    *   🟡 **SUSPICIOUS**
    *   🔴 **DANGER**
*   **Lexical & Structural Insights**: Breakdown details on:
    *   **Domain Reputation / Authority**: Flags unranked, new, or typo-squatting domains.
    *   **SSL Protocol Checks**: Detects insecure unencrypted HTTP routes.
    *   **Obfuscated Subdomains**: Measures excessive subdomain levels designed to deceive users.
    *   **Dangerous Heuristic Terms**: Searches for keywords like `login`, `secure`, `bank`, `update`, and `password` in the host and path.
*   **Polished Dark Aesthetics**: Built with high visual craft featuring a spacious input console, interactive progress gauges, glassmorphic card overlays, clean layouts, and responsive micro-interactions powered by `motion`.

---

## 🛠️ Stack & Technologies

*   **Frontend**: React (v19), Vite (v6), TypeScript, Tailwind CSS (v4)
*   **Animations**: Motion (v12) for layout transitions and stagger elements
*   **Icons**: Lucide React
*   **Backend Server**: Node.js with Express
*   **Bundling & Build**:
    *   `vite` for static client bundle.
    *   `esbuild` for compiling and self-bundling the server.ts into `dist/server.cjs` (automatically resolving Node's strict ESM requirements for flawless server containerization).

---

## 📂 Project Structure

```text
├── .github/workflows/   # CI/CD Action pipelines (e.g., Static site deploy)
├── src/
│   ├── components/      # Modular UI components (Dashboard, Results, Scanners)
│   ├── utils/
│   │   └── localAnalyzer.ts # Client-side heuristics and rule processor
│   ├── App.tsx          # Master client component and interactive layout
│   ├── index.css        # Tailwind v4 directives and typography definitions
│   ├── types.ts         # Shared interfaces and types
│   └── main.tsx         # React root bootstrapping
├── .env.example         # Example configuration for key secrets
├── server.ts            # Full-stack API Gateway with Vite middleware & Gemini proxy
├── package.json         # Unified dependencies and build pipeline
└── tsconfig.json        # TypeScript compile configuration
```

---

## 🏃 Getting Started

### Prerequisites

*   **Node.js** (v18 or higher recommended)

### 1. Installation

Clone this repository and install all node modules:
```bash
npm install
```

### 2. Environment Variables

Create a local `.env` file in the root directory (based on `.env.example`):
```env
API_KEY=your_actual_api_key_here
```

### 3. Running in Development

To spin up the server with hot-reloading for local testing:
```bash
npm run dev
```
The server will boot on port `3000`. It mounts a development Vite server instance as a middleware, giving you a full-stack running proxy with near-zero cold starts.

### 4. Compiling & Production Execution

To compile the React front-end and bundle the TypeScript server using `esbuild`:
```bash
npm run build
```
The output is written into the self-contained `dist/` directory. To start the compiled production app:
```bash
npm run start
```

---

## 🛰️ API Endpoints

The backend exposes the following internal endpoints:

### `POST /api/analyze`
Analyzes a URL using Google's Gemini models.
*   **Payload**: `{ "url": "https://suspicious-login-github.com/auth" }`
*   **Response**: A detailed `AnalysisResponse` object including risk rating, confidence rating, lexical breakdowns, and natural language warning explanations.

---

## 📦 CI/CD Deployment

This project includes a fully optimized GitHub Actions deployment pipeline located under `.github/workflows/deploy.yml`. 
*   **Self-contained build workflow**: Cleans, builds, compiles, and packages static assets securely.
*   **Artifact-ready upload**: Packages build outputs cleanly to deploy them effortlessly to platforms like GitHub Pages.
