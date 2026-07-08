<template>
  <section class="dashboard-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Workbench</p>
        <h1>分析工作台</h1>
        <p>静态分析、动态分析和可利用漏洞代码分标签展示，支持历史记录查看。</p>
      </div>
      <el-button type="primary" @click="router.push('/projects/new')">新建审计</el-button>
    </div>

    <el-card shadow="never" class="query-card">
      <div class="query-row">
        <el-autocomplete
          v-model="searchText"
          class="project-search"
          :fetch-suggestions="querySearch"
          :trigger-on-focus="true"
          fit-input-width
          clearable
          placeholder="输入项目名称，例如 maccms"
          @select="selectSuggestion"
          @keyup.enter="load"
        >
          <template #default="{ item }">
            <div class="suggestion-option">
              <div class="suggestion-main">
                <strong>{{ item.projectName }}</strong>
                <span v-if="item.duplicatedName">项目 ID：{{ item.projectId || "-" }}</span>
              </div>
              <div class="suggestion-sub">
                <span>创建时间：{{ formatTime(item.createdAt) }}</span>
                <span>Scan ID：{{ item.scanId }}</span>
              </div>
            </div>
          </template>
        </el-autocomplete>
        <el-button type="primary" :loading="loading" @click="load">查询</el-button>
        <el-button @click="router.push('/history')">历史记录</el-button>
      </div>
    </el-card>

    <div v-if="status" class="summary-grid">
      <el-card shadow="never" class="summary-card">
        <span>任务状态</span><strong><el-tag :type="statusTagType(status.status)">{{ status.status || "unknown" }}</el-tag></strong><small>{{ status.current_stage || "等待阶段信息" }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>扫描进度</span><strong>{{ status.progress }}%</strong><el-progress :percentage="status.progress" :show-text="false" />
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>漏洞总数</span><strong>{{ findings.length }}</strong><small>高危 {{ highCount }} / 已验证 {{ verifiedCount }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>报告</span><strong>HTML</strong><el-button text type="primary" @click="genReport">生成报告</el-button>
      </el-card>
    </div>

    <el-alert
      v-if="status?.status === 'failed'"
      type="error"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描任务失败，请检查仓库地址、网络、分支或本地路径。'"
    />

    <el-card v-if="status" shadow="never" class="tabs-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro">
            <h2>静态分析结果</h2>
            <p>来自自定义规则、Semgrep、Gitleaks 等工具及候选漏洞归一化结果。</p>
          </div>
          <el-table :data="pagedStaticFindings" stripe empty-text="暂无静态分析结果">
            <el-table-column prop="type" label="类型" min-width="150" />
            <el-table-column label="严重级" width="110">
              <template #default="scope"><el-tag :type="severityType(scope.row.severity)">{{ scope.row.severity }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="file" label="文件" min-width="220" show-overflow-tooltip />
            <el-table-column prop="line" label="行" width="80" />
            <el-table-column label="置信度" width="100">
              <template #default="scope">{{ formatConfidence(scope.row.confidence) }}</template>
            </el-table-column>
            <el-table-column label="状态" width="130">
              <template #default="scope"><el-tag :type="findingStatusType(scope.row.status)">{{ scope.row.status || "unknown" }}</el-tag></template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">详情</el-button></template>
            </el-table-column>
          </el-table>
          <div v-if="staticFindings.length > pageSize" class="table-footer">
            <span>共 {{ staticFindings.length }} 条结果，当前显示 {{ pagedStaticFindings.length }} 条</span>
            <el-pagination
              v-model:current-page="currentPage"
              v-model:page-size="pageSize"
              :page-sizes="[20, 50, 100]"
              layout="sizes, prev, pager, next"
              :total="staticFindings.length"
              small
            />
          </div>
        </el-tab-pane>

        <el-tab-pane label="动态分析" name="dynamic">
          <div class="tab-intro">
            <h2>动态验证结果</h2>
            <p>展示已执行动态验证的漏洞、命中特征、响应状态和验证结论。</p>
          </div>
          <el-table v-loading="evidenceLoading" :data="dynamicRows" stripe empty-text="暂无动态验证结果，可在漏洞详情中执行按需验证">
            <el-table-column prop="type" label="漏洞类型" min-width="150" />
            <el-table-column prop="file" label="位置" min-width="220" show-overflow-tooltip />
            <el-table-column label="验证结论" width="120">
              <template #default="scope">
                <el-tag :type="runtimeTagType(scope.row.runtime)">
                  {{ runtimeStatusLabel(scope.row.runtime) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="命中特征" min-width="150">
              <template #default="scope">{{ scope.row.runtime?.matched_indicator || "-" }}</template>
            </el-table-column>
            <el-table-column label="状态码" width="90">
              <template #default="scope">{{ scope.row.runtime?.response_status || "-" }}</template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">证据链</el-button></template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="可利用漏洞代码" name="exploit">
          <div class="tab-intro">
            <h2>可利用漏洞代码</h2>
            <p>仅展示本地授权靶场用途的 PoC / exploit 代码骨架和触发路径。</p>
          </div>
          <el-empty v-if="!evidenceLoading && exploitRows.length === 0" description="暂无利用代码。可进入漏洞详情执行动态验证或启用 exploit 配置后重新扫描。" />
          <div v-else v-loading="evidenceLoading" class="exploit-list">
            <article v-for="row in exploitRows" :key="row.finding_id" class="exploit-card">
              <div class="exploit-head">
                <div>
                  <h3>{{ row.type }}</h3>
                  <p>{{ row.exploit?.trigger_location || row.file }}</p>
                </div>
                <el-button type="primary" link @click="openFinding(row.finding_id)">查看详情</el-button>
              </div>
              <p class="exploit-path">{{ row.exploit?.exploit_path }}</p>
              <pre><code>{{ row.exploit?.exploit_code }}</code></pre>
            </article>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Agent 通信流" name="agents">
          <div class="tab-intro">
            <h2>Agent 通信流</h2>
            <p>回放本次扫描保存的 ACP 消息，展示每个 Agent 的输入、输出、裁决和置信度。</p>
          </div>
          <el-empty v-if="!agentMessagesLoading && agentMessages.length === 0" description="暂无 Agent 通信记录，当前扫描未生成 ACP trace，可重新扫描生成。" />
          <el-timeline v-else v-loading="agentMessagesLoading" class="agent-timeline">
            <el-timeline-item
              v-for="msg in agentMessages"
              :key="msg.message_id"
              :timestamp="formatTime(msg.timestamp)"
              :type="agentTimelineType(msg)"
            >
              <div class="agent-message-card">
                <div class="agent-message-head">
                  <strong>{{ agentName(msg.sender) }} → {{ agentName(msg.receiver) }}</strong>
                  <el-tag size="small" :type="verdictTagType(msg.verdict)">{{ msg.verdict || msg.state }}</el-tag>
                </div>
                <p>{{ msg.intent || msg.message_type }}</p>
                <div class="agent-message-meta">
                  <span>{{ msg.message_type }}</span>
                  <span v-if="msg.confidence !== null && msg.confidence !== undefined">置信度 {{ msg.confidence }}</span>
                </div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { FindingApi, ReportApi, ScanApi } from "../api";
import { readHistory, upsertHistory, type AuditHistoryRecord } from "../api/history";

type SearchSuggestion = {
  value: string;
  record: AuditHistoryRecord;
  projectName: string;
  projectId?: string;
  scanId: string;
  createdAt: string;
  duplicatedName: boolean;
};

const route = useRoute();
const router = useRouter();
const scanId = ref((route.query.scanId as string) || "");
const searchText = ref((route.query.project as string) || scanId.value);
const historyRecords = ref<AuditHistoryRecord[]>([]);
const activeTab = ref((route.query.tab as string) || "static");
const loading = ref(false);
const evidenceLoading = ref(false);
const evidenceLoaded = ref(false);
const agentMessagesLoading = ref(false);
const agentMessagesLoaded = ref(false);
const status = ref<any>(null);
const findings = ref<any[]>([]);
const evidenceMap = ref<Record<string, any>>({});
const agentMessages = ref<any[]>([]);
const currentPage = ref(1);
const pageSize = ref(50);
let searchTimer: ReturnType<typeof setTimeout> | undefined;

const highCount = computed(() => findings.value.filter((item) => ["high", "critical"].includes(String(item.severity).toLowerCase())).length);
const verifiedCount = computed(() => findings.value.filter((item) => item.verified).length);
const staticFindings = computed(() => findings.value);
const pagedStaticFindings = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  return staticFindings.value.slice(start, start + pageSize.value);
});
const dynamicRows = computed(() => findings.value
  .map((item) => ({ ...item, runtime: evidenceMap.value[item.finding_id]?.runtime }))
  .filter((item) => item.runtime));
const exploitRows = computed(() => findings.value
  .map((item) => ({ ...item, exploit: evidenceMap.value[item.finding_id]?.exploit }))
  .filter((item) => item.exploit?.exploit_code));
const historySearchIndex = computed(() => historyRecords.value.map((record) => ({
  record,
  projectName: getProjectName(record),
  normalizedName: normalize(getProjectName(record)),
  normalizedProjectId: normalize(record.projectId),
  normalizedScanId: normalize(record.scanId),
})));

async function load() {
  const keyword = searchText.value.trim();
  if (!keyword) {
    ElMessage.warning("请输入项目名称");
    return;
  }
  refreshHistoryRecords();
  const record = resolveSearchRecord(keyword);
  if (record) {
    await loadRecord(record);
    return;
  }
  if (/^scan_/i.test(keyword)) {
    await loadByScanId(keyword);
    return;
  }
  ElMessage.warning("未找到该项目名称，请从推荐项中选择历史记录");
}

async function loadRecord(record: AuditHistoryRecord) {
  const duplicatedName = isDuplicatedProjectName(record);
  searchText.value = buildSuggestionValue(record, duplicatedName);
  await loadByScanId(record.scanId);
}

async function loadByScanId(nextScanId: string) {
  if (!nextScanId) return;
  scanId.value = nextScanId;
  loading.value = true;
  try {
    const { data } = await ScanApi.get(nextScanId);
    status.value = data;
    const { data: f } = await ScanApi.findings(nextScanId);
    findings.value = f.findings;
    currentPage.value = 1;
    evidenceMap.value = {};
    agentMessages.value = [];
    evidenceLoaded.value = false;
    agentMessagesLoaded.value = false;
    if (activeTab.value === "dynamic" || activeTab.value === "exploit") {
      await ensureEvidenceLoaded();
    }
    if (activeTab.value === "agents") {
      await ensureAgentMessagesLoaded();
    }
    upsertHistory({
      scanId: nextScanId,
      projectId: data.project_id,
      status: data.status,
      progress: data.progress,
      findingCount: findings.value.length,
      highCount: highCount.value,
      verifiedCount: verifiedCount.value,
    });
  } finally {
    loading.value = false;
  }
}

async function loadEvidence() {
  const pairs = await mapLimit(findings.value, 8, async (finding) => {
    try {
      const { data } = await FindingApi.evidence(finding.finding_id);
      return [finding.finding_id, data.evidence];
    } catch {
      return [finding.finding_id, null];
    }
  });
  evidenceMap.value = Object.fromEntries(pairs.filter(([, evidence]) => evidence));
}

async function ensureEvidenceLoaded() {
  if (evidenceLoaded.value || evidenceLoading.value) return;
  evidenceLoading.value = true;
  try {
    if (findings.value.length > 0) {
      await loadEvidence();
    }
    evidenceLoaded.value = true;
  } finally {
    evidenceLoading.value = false;
  }
}

async function loadAgentMessages(nextScanId: string) {
  try {
    const { data } = await ScanApi.agentMessages(nextScanId);
    agentMessages.value = data.messages || [];
  } catch {
    agentMessages.value = [];
  }
}

async function ensureAgentMessagesLoaded() {
  if (agentMessagesLoaded.value || agentMessagesLoading.value || !scanId.value) return;
  agentMessagesLoading.value = true;
  try {
    await loadAgentMessages(scanId.value);
    agentMessagesLoaded.value = true;
  } finally {
    agentMessagesLoading.value = false;
  }
}

async function genReport() {
  const { data } = await ReportApi.create({ scan_id: scanId.value, format: "html" });
  window.open(ReportApi.download(data.report_id));
  ElMessage.success("报告已生成");
}

function querySearch(queryString: string, cb: (items: SearchSuggestion[]) => void) {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    const keyword = normalize(queryString);
    const items = historySearchIndex.value
      .filter((item) => {
        if (!keyword) return true;
        return item.normalizedName.includes(keyword)
          || item.normalizedProjectId.includes(keyword)
          || item.normalizedScanId.includes(keyword);
      })
      .slice(0, 8)
      .map(({ record, projectName }) => {
        const duplicatedName = isDuplicatedProjectName(record);
      return {
        value: buildSuggestionValue(record, duplicatedName),
        record,
        projectName,
        projectId: record.projectId,
        scanId: record.scanId,
        createdAt: record.createdAt,
        duplicatedName,
      };
      });
    cb(items);
  }, 120);
}

function selectSuggestion(item: SearchSuggestion) {
  loadRecord(item.record);
}

function resolveSearchRecord(input: string) {
  const keyword = normalize(input);
  const byNameAndId = historySearchIndex.value.find((item) => {
    const ids = [item.normalizedProjectId, item.normalizedScanId].filter(Boolean);
    return item.normalizedName && keyword.includes(item.normalizedName) && ids.some((id) => keyword.includes(id));
  });
  if (byNameAndId) return byNameAndId.record;

  const exactNameMatches = historySearchIndex.value.filter((item) => item.normalizedName === keyword);
  if (exactNameMatches.length === 1) return exactNameMatches[0].record;
  if (exactNameMatches.length > 1) {
    ElMessage.warning("存在多个同名项目，请在推荐项中选择带项目 ID 的记录");
    return null;
  }

  const fuzzyNameMatches = historySearchIndex.value.filter((item) => item.normalizedName.includes(keyword));
  if (fuzzyNameMatches.length === 1) return fuzzyNameMatches[0].record;
  if (fuzzyNameMatches.length > 1) {
    ElMessage.warning("找到多个匹配项目，请在推荐项中选择具体记录");
    return null;
  }

  return historySearchIndex.value.find((item) => item.normalizedProjectId === keyword || item.normalizedScanId === keyword)?.record || null;
}

function refreshHistoryRecords() {
  historyRecords.value = readHistory();
}

function getProjectName(record: AuditHistoryRecord) {
  return record.projectName || record.projectId || record.scanId;
}

function isDuplicatedProjectName(record: AuditHistoryRecord) {
  const name = normalize(getProjectName(record));
  if (!name) return false;
  return historyRecords.value.filter((item) => normalize(getProjectName(item)) === name).length > 1;
}

function buildSuggestionValue(record: AuditHistoryRecord, duplicatedName: boolean) {
  const name = getProjectName(record);
  if (!duplicatedName) return name;
  return `${name}（${record.projectId || record.scanId}）`;
}

function normalize(value?: string) {
  return String(value || "").trim().toLowerCase();
}

function formatTime(value?: string) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function openFinding(id: string) { router.push(`/findings/${id}`); }
function severityType(severity: string) {
  const s = String(severity).toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

function statusTagType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value === "failed") return "danger";
  if (value === "done" || value === "finished") return "success";
  if (value === "running") return "warning";
  return "info";
}

function findingStatusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value.includes("false")) return "info";
  if (value.includes("confirm") || value.includes("verified")) return "success";
  if (value.includes("candidate")) return "warning";
  return "info";
}

function formatConfidence(value: any) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return num <= 1 ? `${Math.round(num * 100)}%` : String(num);
}

function runtimeStatusLabel(runtime: any) {
  const status = runtime?.reproduction_status;
  if (status === "dynamic_confirmed" || runtime?.reproducible) return "可复现";
  if (status === "not_reproduced") return "未复现";
  if (status === "not_executed") return "未执行";
  if (status === "not_runtime_verifiable") return "不适合动态验证";
  if (status === "connection_failed") return "连接失败";
  if (status === "request_timeout") return "请求超时";
  if (status === "endpoint_not_found") return "入口不存在";
  return status || "未执行";
}

function runtimeTagType(runtime: any) {
  const status = runtime?.reproduction_status;
  if (status === "dynamic_confirmed" || runtime?.reproducible) return "success";
  if (status === "not_reproduced") return "warning";
  if (status === "not_executed" || status === "not_runtime_verifiable") return "info";
  return "danger";
}

function agentName(value?: string) {
  return String(value || "unknown").replace(/_/g, " ");
}

function verdictTagType(verdict?: string) {
  const v = String(verdict || "").toLowerCase();
  if (v.includes("false") || v.includes("failed")) return "danger";
  if (v.includes("dynamic") || v.includes("confirmed") || v.includes("verified")) return "success";
  if (v.includes("exploit") || v.includes("harness")) return "warning";
  return "info";
}

function agentTimelineType(msg: any) {
  if (msg.state === "failed") return "danger";
  if (msg.verdict) return verdictTagType(msg.verdict);
  return msg.state === "success" ? "success" : "primary";
}

async function mapLimit<T, R>(items: T[], limit: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (nextIndex < items.length) {
      const current = nextIndex;
      nextIndex += 1;
      results[current] = await mapper(items[current]);
    }
  });
  await Promise.all(workers);
  return results;
}

watch(activeTab, async (tab) => {
  if (tab === "dynamic" || tab === "exploit") {
    await ensureEvidenceLoaded();
  }
  if (tab === "agents") {
    await ensureAgentMessagesLoaded();
  }
});

watch(pageSize, () => { currentPage.value = 1; });

onMounted(() => {
  refreshHistoryRecords();
  if (scanId.value) loadByScanId(scanId.value);
});
</script>

<style scoped>
.dashboard-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.query-card, .tabs-card, .summary-card { border-radius: 18px; }
.tabs-card { overflow: hidden; }
.query-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; }
.project-search { width: 100%; }
.suggestion-option { padding: 6px 0; line-height: 1.4; }
.suggestion-main { display: flex; align-items: center; justify-content: space-between; gap: 12px; color: #162235; }
.suggestion-main strong { font-weight: 700; }
.suggestion-main span { color: #2f80ed; font-size: 12px; white-space: nowrap; }
.suggestion-sub { display: flex; gap: 12px; margin-top: 4px; color: #667085; font-size: 12px; }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
.summary-card span { display: block; color: #667085; font-size: 13px; }
.summary-card strong { display: block; margin: 8px 0; font-size: 26px; color: #162235; }
.summary-card small { color: #667085; }
.error-alert { border-radius: 12px; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; color: #162235; }
.tab-intro p { margin: 6px 0 0; color: #667085; }
.exploit-list { display: grid; gap: 16px; }
.exploit-card { border: 1px solid #dce6f0; border-radius: 16px; padding: 16px; background: linear-gradient(180deg, #fff, #fbfdff); box-shadow: 0 8px 22px rgba(16,32,51,.04); }
.exploit-head { display: flex; justify-content: space-between; gap: 16px; }
.exploit-head h3 { margin: 0; }
.exploit-head p, .exploit-path { color: #667085; margin: 6px 0 12px; }
.agent-timeline { padding: 8px 0 0; }
.agent-message-card { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px 14px; background: #fbfdff; }
.agent-message-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; color: #162235; }
.agent-message-card p { margin: 8px 0; color: #475467; }
.agent-message-meta { display: flex; flex-wrap: wrap; gap: 10px; color: #667085; font-size: 12px; }
pre { background: #0b1220; color: #d7e3f1; padding: 14px; border-radius: 12px; overflow: auto; border: 1px solid rgba(255,255,255,.08); }
@media (max-width: 980px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 680px) { .query-row, .summary-grid { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>
