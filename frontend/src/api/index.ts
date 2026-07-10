import axios from "axios";
import { ElMessage } from "element-plus";

const http = axios.create({ baseURL: "/api", timeout: 30000 });

// 全局错误提示：此前接口报错（404/500/网络/超时）会静默失败，
// 用户点按钮后「一直没反应」。这里统一弹出可读错误，避免异常被吞。
http.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const detail = error?.response?.data?.detail;
    let msg = detail || error?.message || "请求失败";
    if (error?.code === "ECONNABORTED") msg = "请求超时，请检查后端服务是否运行";
    else if (status === 404) msg = detail || "未找到对应记录（可能已被清理或数据库已重置）";
    else if (status && status >= 500) msg = detail || "后端处理出错，请查看服务日志";
    else if (error?.request && !error?.response) msg = "无法连接后端服务，请确认后端已启动";
    ElMessage.error(String(msg));
    return Promise.reject(error);
  },
);

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
  list: (q?: string) => http.get("/scans", { params: q ? { q } : {} }),
  get: (id: string) => http.get(`/scans/${id}`),
  remove: (id: string) => http.delete(`/scans/${id}`),
  cancel: (id: string) => http.post(`/scans/${id}/cancel`),
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
