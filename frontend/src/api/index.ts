import axios from "axios";

const http = axios.create({ baseURL: "/api", timeout: 30000 });

export const ProjectApi = {
  create: (data: any) => http.post("/projects", data),
  list: () => http.get("/projects"),
  parse: (id: string) => http.post(`/projects/${id}/parse`),
  tree: (id: string) => http.get(`/projects/${id}/tree`),
};

export const ScanApi = {
  create: (data: any) => http.post("/scans", data),
  get: (id: string) => http.get(`/scans/${id}`),
  findings: (id: string) => http.get(`/scans/${id}/findings`),
};

export const FindingApi = {
  detail: (id: string) => http.get(`/findings/${id}`),
  evidence: (id: string) => http.get(`/findings/${id}/evidence`),
};

export const ReportApi = {
  create: (data: any) => http.post("/reports", data),
  download: (id: string) => `${"/api"}/reports/${id}/download`,
};

export default http;
