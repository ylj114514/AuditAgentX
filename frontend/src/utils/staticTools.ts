export const STATIC_TOOL_OPTIONS = [
  {
    value: "semgrep",
    label: "Semgrep",
    description: "SAST：注入、XSS、路径遍历与框架安全规则。",
  },
  {
    value: "bandit",
    label: "Bandit",
    description: "Python 安全扫描：危险 API、命令执行、反序列化与硬编码凭据。",
  },
  {
    value: "gitleaks",
    label: "Gitleaks",
    description: "敏感信息扫描：密钥、Token 与密码泄露。",
  },
  {
    value: "trivy",
    label: "Trivy",
    description: "SCA / Secret / IaC：依赖 CVE、密钥和基础设施配置风险。",
  },
] as const;

export type StaticTool = (typeof STATIC_TOOL_OPTIONS)[number]["value"];

export const DEFAULT_STATIC_TOOLS: StaticTool[] = ["semgrep", "bandit", "gitleaks", "trivy"];

export function normalizeStaticTools(values: readonly string[]): StaticTool[] {
  const selected = new Set(values);
  return DEFAULT_STATIC_TOOLS.filter((tool) => selected.has(tool));
}
