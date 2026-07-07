import axios from "axios";

const http = axios.create({ baseURL: "/api", timeout: 30000 });

export const ProjectApi = {
  create: (data: any) => http.post("/projects", data),
  upload: (data: FormData) => http.post("/projects/upload", data, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 120000,
  }),
  list: () => http.get("/projects"),
  parse: (id: string) => http.post(`/projects/${id}/parse`),
  tree: (id: string) => http.get(`/projects/${id}/tree`),
};

export const ScanApi = {
  create: (data: any) => http.post("/scans", data),
  get: (id: string) => http.get(`/scans/${id}`),
  findings: (id: string) => http.get(`/scans/${id}/findings`),
  agentMessages: (id: string, full = false) => http.get(`/scans/${id}/agent-messages`, { params: { full } }),
};

export const FindingApi = {
  detail: (id: string) => http.get(`/findings/${id}`),
  evidence: (id: string) => http.get(`/findings/${id}/evidence`),
  verify: (id: string, data: any) => http.post(`/findings/${id}/verify`, data),
};

export const ReportApi = {
  create: (data: any) => http.post("/reports", data),
  download: (id: string) => `${"/api"}/reports/${id}/download`,
};

export const AnalyticsApi = {
  overview: () => http.get("/analytics/overview"),
  projects: () => http.get("/analytics/projects"),
  benchmark: () => http.get("/analytics/benchmark"),
};

export default http;
