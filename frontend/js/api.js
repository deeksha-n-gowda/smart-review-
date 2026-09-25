/**
 * api.js — Backend API Client
 * ============================
 * Centralised fetch wrappers for every backend endpoint.
 * All functions are async and return parsed JSON or throw a typed ApiError.
 *
 * Usage:
 *   import { api } from './api.js';
 *   const project = await api.createProject({ name: 'My Project' });
 *   const files   = await api.uploadFile(projectId, file);
 *
 * The BASE_URL constant is the only thing to change when deploying.
 */

// ─── Configuration ───────────────────────────────────────────────────────────

// Same-origin API base — works on localhost, Docker, and any deployed host.
// (Previously hardcoded to http://localhost:8000, which broke every request
// once the app was served from another machine or a public URL.)
// Standalone preview via serve_frontend.py falls back to mock data when this
// origin's health check fails — see useMockData().
const BASE_URL = `${window.location.origin}/api/v1`;

// How long to wait before aborting a request (ms)
const DEFAULT_TIMEOUT_MS = 30_000;

// ─── Error Class ─────────────────────────────────────────────────────────────

/**
 * Typed API error — carries the HTTP status and server message.
 * Lets callers distinguish network failures from 4xx/5xx errors.
 */
export class ApiError extends Error {
  /**
   * @param {string} message  Human-readable error description
   * @param {number} status   HTTP status code (0 = network error)
   * @param {object} [body]   Parsed response body (if available)
   */
  constructor(message, status = 0, body = null) {
    super(message);
    this.name    = "ApiError";
    this.status  = status;
    this.body    = body;
  }
}

// ─── Core Fetch Helper ───────────────────────────────────────────────────────

/**
 * Makes a fetch request with timeout, JSON parsing, and error normalisation.
 *
 * @param {string} path      URL path (relative to BASE_URL), e.g. '/projects/'
 * @param {object} [options] Standard fetch options, plus optional `timeoutMs`
 * @returns {Promise<any>}   Parsed JSON response body
 * @throws {ApiError}        On HTTP error or network failure
 */
async function request(path, options = {}) {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...fetchOptions } = options;

  // Build a combined AbortController for the timeout
  const controller = new AbortController();
  const timerId    = setTimeout(() => controller.abort(), timeoutMs);

  const url = `${BASE_URL}${path}`;

  // Default headers — always send/accept JSON
  const headers = {
    "Accept": "application/json",
    ...fetchOptions.headers,
  };

  // Don't force Content-Type on FormData (browser sets multipart boundary automatically)
  if (!(fetchOptions.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(url, {
      ...fetchOptions,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    // Network error or abort
    if (err.name === "AbortError") {
      throw new ApiError(`Request timed out after ${timeoutMs}ms`, 0);
    }
    throw new ApiError(`Network error: ${err.message}`, 0);
  } finally {
    clearTimeout(timerId);
  }

  // Parse response body (try JSON, fall back to text)
  let body;
  const contentType = response.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  // Treat 4xx / 5xx as errors
  if (!response.ok) {
    const detail  = body?.detail || body?.error || (typeof body === "string" ? body : "Unknown error");
    const message = `[${response.status}] ${detail}`;
    throw new ApiError(message, response.status, body);
  }

  return body;
}

// Convenience wrappers for common HTTP methods
const get    = (path, opts = {})       => request(path, { method: "GET",    ...opts });
const post   = (path, data, opts = {}) => request(path, { method: "POST",   body: JSON.stringify(data), ...opts });
const del    = (path, opts = {})       => request(path, { method: "DELETE", ...opts });
const postForm = (path, formData, opts = {}) =>
  request(path, { method: "POST", body: formData, ...opts });


// ─── API Surface ─────────────────────────────────────────────────────────────

export const api = {

  // ── Health ──────────────────────────────────────────────────────────────

  /**
   * GET /health/ — Check if the backend is reachable.
   * @returns {{ status: string, service: string, database: string }}
   */
  health() {
    return get("/health/");
  },


  // ── Projects ────────────────────────────────────────────────────────────

  /**
   * GET /projects/ — List all projects (paginated).
   * @param {{ page?: number }} [params]
   * @returns {{ count: number, results: Project[] }}
   */
  listProjects(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return get(`/projects/${qs ? "?" + qs : ""}`);
  },

  /**
   * POST /projects/ — Create a new project.
   * @param {{ name: string, description?: string }} data
   * @returns {Project}
   */
  createProject(data) {
    return post("/projects/", data);
  },

  /**
   * GET /projects/<id>/ — Get a project with summary stats.
   * @param {string} projectId UUID
   * @returns {Project}
   */
  getProject(projectId) {
    return get(`/projects/${projectId}/`);
  },

  /**
   * DELETE /projects/<id>/ — Delete a project and all its files.
   * @param {string} projectId UUID
   */
  deleteProject(projectId) {
    return del(`/projects/${projectId}/`);
  },


  // ── File Upload ──────────────────────────────────────────────────────────

  /**
   * POST /projects/<id>/upload/ — Upload a source file for analysis.
   *
   * Sends as multipart/form-data so the file bytes reach Django directly.
   * Optionally pass `language` if auto-detection should be overridden.
   *
   * @param {string}  projectId  UUID of the parent project
   * @param {File}    file       A File object from an <input> or drag-drop
   * @param {string}  [language] Override language detection ('python', 'java', etc.)
   * @param {function} [onProgress] Callback receiving upload % (0–100)
   * @returns {CodeFile}
   */
  async uploadFile(projectId, file, language = null, onProgress = null) {
    const formData = new FormData();
    formData.append("file", file, file.name);
    if (language) formData.append("language", language);

    // If a progress callback is provided, use XMLHttpRequest for progress events.
    // fetch() does not natively support upload progress.
    if (onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener("progress", (e) => {
          if (e.lengthComputable) {
            onProgress(Math.round((e.loaded / e.total) * 100));
          }
        });

        xhr.addEventListener("load", () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(JSON.parse(xhr.responseText));
          } else {
            let body;
            try { body = JSON.parse(xhr.responseText); } catch { body = xhr.responseText; }
            reject(new ApiError(`[${xhr.status}] ${body?.detail || "Upload failed"}`, xhr.status, body));
          }
        });

        xhr.addEventListener("error",   () => reject(new ApiError("Network error during upload", 0)));
        xhr.addEventListener("timeout", () => reject(new ApiError("Upload timed out", 0)));

        xhr.open("POST", `${BASE_URL}/projects/${projectId}/upload/`);
        xhr.setRequestHeader("Accept", "application/json");
        xhr.timeout = 60_000;  // 60 second timeout for file uploads
        xhr.send(formData);
      });
    }

    // Simple upload without progress
    return postForm(`/projects/${projectId}/upload/`, formData);
  },


  // ── Files ────────────────────────────────────────────────────────────────

  /**
   * GET /files/<id>/ — Get file details, status, and all vulnerabilities.
   * @param {string} fileId UUID
   * @returns {CodeFile}
   */
  getFile(fileId) {
    return get(`/files/${fileId}/`);
  },

  /**
   * POST /files/<id>/analyze/ — Trigger ML analysis for a file.
   * @param {string} fileId UUID
   * @returns {{ status: string, message: string }}
   */
  analyzeFile(fileId) {
    return post(`/files/${fileId}/analyze/`, {});
  },

  /**
   * GET /files/<id>/source/ — Get the decrypted source code.
   * Only available in DEBUG mode.
   * @param {string} fileId UUID
   * @returns {{ filename: string, language: string, source: string }}
   */
  getFileSource(fileId) {
    return get(`/files/${fileId}/source/`);
  },


  // ── Vulnerabilities ──────────────────────────────────────────────────────

  /**
   * GET /vulnerabilities/<id>/ — Get a single vulnerability.
   * @param {string} vulnId UUID
   * @returns {Vulnerability}
   */
  getVulnerability(vulnId) {
    return get(`/vulnerabilities/${vulnId}/`);
  },

  /**
   * GET /vulnerabilities/<id>/explanation/ — Get the XAI explanation.
   * @param {string} vulnId UUID
   * @returns {Explanation}
   */
  getExplanation(vulnId) {
    return get(`/vulnerabilities/${vulnId}/explanation/`);
  },

};


// ─── Polling Helper ───────────────────────────────────────────────────────────

/**
 * Polls a file's status until it reaches 'complete' or 'failed'.
 * Useful after triggering analysis to know when results are ready.
 *
 * @param {string}   fileId      UUID of the file to poll
 * @param {object}   [options]
 * @param {number}   [options.intervalMs=2000]  How often to poll (ms)
 * @param {number}   [options.maxAttempts=60]   Max polls before giving up
 * @param {function} [options.onUpdate]         Called with the file object on each poll
 * @returns {Promise<CodeFile>}  Resolves when status is complete/failed
 * @throws {ApiError}            After maxAttempts exceeded
 */
export async function pollFileStatus(fileId, { intervalMs = 2000, maxAttempts = 60, onUpdate } = {}) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const file = await api.getFile(fileId);
    if (onUpdate) onUpdate(file);

    if (file.status === "complete" || file.status === "failed") {
      return file;
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }

  throw new ApiError(
    `File ${fileId} did not complete after ${maxAttempts} polls (${(maxAttempts * intervalMs) / 1000}s)`,
    0
  );
}


// ─── Mock Data (used when backend is unreachable in dev) ─────────────────────

/**
 * Returns rich mock data so the frontend renders correctly even without
 * a running Django server. Activated automatically when the health check fails.
 *
 * Call useMockData() to switch the api object to mock mode.
 */
export function useMockData() {
  console.info("[api] Backend unreachable — switching to mock data mode.");

  const MOCK_PROJECTS = [
    {
      id: "11111111-1111-1111-1111-111111111111",
      name: "Sample Assignment — Security Audit",
      description: "A sample student project with intentional vulnerabilities for demonstration.",
      overall_risk_score: 0.87,
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      summary: {
        total_files: 2,
        completed_files: 2,
        total_vulnerabilities: 7,
        critical_count: 3,
        high_count: 2,
      },
    },
    {
      id: "22222222-2222-2222-2222-222222222222",
      name: "E-Commerce Backend",
      description: "Node.js + Express API for product catalog.",
      overall_risk_score: 0.45,
      created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
      summary: {
        total_files: 4,
        completed_files: 4,
        total_vulnerabilities: 3,
        critical_count: 0,
        high_count: 2,
      },
    },
    {
      id: "33333333-3333-3333-3333-333333333333",
      name: "Data Processing Script",
      description: "Python ETL pipeline for CSV ingestion.",
      overall_risk_score: 0.18,
      created_at: new Date(Date.now() - 86400000 * 1).toISOString(),
      summary: {
        total_files: 1,
        completed_files: 1,
        total_vulnerabilities: 1,
        critical_count: 0,
        high_count: 0,
      },
    },
  ];

  const MOCK_FILE = {
    id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    project: "11111111-1111-1111-1111-111111111111",
    filename: "auth.py",
    language: "python",
    status: "complete",
    risk_score: 0.91,
    line_count: 34,
    size_bytes: 820,
    analysis_duration_ms: 312,
    uploaded_at: new Date().toISOString(),
    analyzed_at: new Date().toISOString(),
    vulnerabilities: [
      {
        id: "vv111111-1111-1111-1111-111111111111",
        line_start: 9,
        line_end: 9,
        title: "SQL Injection",
        description: "User-supplied input is concatenated directly into a SQL query string without sanitization. An attacker can bypass authentication, extract arbitrary data, or modify records.",
        category: "security",
        severity: "critical",
        confidence_score: 0.97,
        rule_id: "PY-SEC-001",
        recommendation: "Use parameterized queries. Replace with: cursor.execute('SELECT * FROM users WHERE username=?', (username,))",
        code_snippet: "query = \"SELECT * FROM users WHERE username='\" + username + \"'\"",
        fixed_snippet: "cursor.execute('SELECT * FROM users WHERE username=?', (username,))",
        cwe_id: "CWE-89",
        owasp_category: "A03:2021 – Injection",
      },
      {
        id: "vv222222-2222-2222-2222-222222222222",
        line_start: 16,
        line_end: 16,
        title: "Weak Cryptographic Hash (MD5)",
        description: "MD5 is cryptographically broken. Rainbow tables for common passwords are widely available. This provides almost no security for password storage.",
        category: "security",
        severity: "high",
        confidence_score: 0.99,
        rule_id: "PY-SEC-002",
        recommendation: "Use bcrypt, scrypt, or Argon2 for password hashing. In Python: use the 'bcrypt' library or Django's built-in password hashing.",
        code_snippet: "hashed = hashlib.md5(password.encode()).hexdigest()",
        fixed_snippet: "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        cwe_id: "CWE-916",
        owasp_category: "A02:2021 – Cryptographic Failures",
      },
      {
        id: "vv333333-3333-3333-3333-333333333333",
        line_start: 22,
        line_end: 22,
        title: "OS Command Injection",
        description: "User-controlled input is passed directly to os.system(). An attacker can inject shell metacharacters to execute arbitrary system commands.",
        category: "security",
        severity: "critical",
        confidence_score: 0.95,
        rule_id: "PY-SEC-003",
        recommendation: "Use subprocess.run() with a list of arguments and shell=False to prevent injection.",
        code_snippet: "os.system(\"echo \" + user_input)",
        fixed_snippet: "subprocess.run([\"echo\", user_input], shell=False, check=True)",
        cwe_id: "CWE-78",
        owasp_category: "A03:2021 – Injection",
      },
      {
        id: "vv444444-4444-4444-4444-444444444444",
        line_start: 31,
        line_end: 31,
        title: "Predictable Session Token",
        description: "Session tokens derived from an MD5 hash of the username are entirely predictable. An attacker who knows a valid username can forge a valid session token.",
        category: "security",
        severity: "high",
        confidence_score: 0.88,
        rule_id: "PY-SEC-004",
        recommendation: "Use a cryptographically secure random token: import secrets; token = secrets.token_hex(32)",
        code_snippet: "self.token = hashlib.md5(username.encode()).hexdigest()",
        fixed_snippet: "import secrets\nself.token = secrets.token_hex(32)",
        cwe_id: "CWE-330",
        owasp_category: "A07:2021 – Identification and Authentication Failures",
      },
    ],
  };

  const MOCK_SOURCE = `import sqlite3
import hashlib

def get_user(username, password):
    """Retrieve a user from the database by credentials."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # BUG: SQL injection — user input directly concatenated
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        # BUG: MD5 is cryptographically broken — do not use for passwords
        hashed = hashlib.md5(password.encode()).hexdigest()
        if user[2] == hashed:
            return user
    return None

def execute_command(user_input):
    """Run a system command based on user input."""
    # BUG: Command injection — user input passed directly to exec
    import os
    os.system("echo " + user_input)

class UserSession:
    def __init__(self):
        self.token = None
    
    def login(self, username, password):
        user = get_user(username, password)
        if user:
            # BUG: Weak token — predictable from username
            self.token = hashlib.md5(username.encode()).hexdigest()
            return True
        return False`;

  const MOCK_EXPLANATION = {
    id: "ee111111-1111-1111-1111-111111111111",
    method: "shap",
    summary: "The model flagged this as Critical SQL Injection because it detected direct string concatenation of user input into a SQL query string (top factor, +0.38). The absence of parameterized queries and input sanitization further increases the risk score.",
    top_feature_name: "SQL string concatenation detected",
    top_feature_importance: 0.38,
    explanation_data: {
      method: "shap",
      base_value: 0.35,
      prediction: 0.97,
      features: [
        { name: "sql_string_concat",  value: 1, shap_value:  0.38, display: "SQL string concatenation" },
        { name: "raw_execute_call",   value: 1, shap_value:  0.14, display: "Raw cursor.execute() call" },
        { name: "user_input_present", value: 1, shap_value:  0.22, display: "Unvalidated user input in scope" },
        { name: "parameterized_query",value: 0, shap_value: -0.10, display: "No parameterized query" },
        { name: "input_sanitization", value: 0, shap_value: -0.08, display: "No input sanitization" },
        { name: "orm_usage",          value: 0, shap_value: -0.05, display: "ORM not used" },
      ],
    },
  };

  // Monkey-patch the api object to return mock data
  api.health        = async () => ({ status: "mock", service: "Mock Mode" });
  api.listProjects  = async () => ({ count: MOCK_PROJECTS.length, results: MOCK_PROJECTS });
  api.getProject    = async () => MOCK_PROJECTS[0];
  api.createProject = async (data) => ({ ...MOCK_PROJECTS[0], ...data, id: crypto.randomUUID() });
  api.deleteProject = async () => ({});
  api.getFile       = async () => MOCK_FILE;
  api.analyzeFile   = async () => ({ status: "analyzing", message: "Analysis triggered (mock)" });
  api.getFileSource = async () => ({ filename: "auth.py", language: "python", source: MOCK_SOURCE });
  api.getVulnerability = async (id) => MOCK_FILE.vulnerabilities.find(v => v.id === id) || MOCK_FILE.vulnerabilities[0];
  api.getExplanation   = async () => MOCK_EXPLANATION;
  api.uploadFile    = async (_, file) => {
    await new Promise(r => setTimeout(r, 1200)); // simulate upload delay
    return { ...MOCK_FILE, filename: file.name, id: crypto.randomUUID() };
  };
}
