<template>
  <section class="dashboard-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Workbench</p>
        <h1>分析工作台</h1>
        <p>静态分析、动态分析和可利用漏洞代码分标签展示，支持历史记录查看。</p>
      </div>
      <div class="page-actions">
        <el-button
          v-if="status && !isTerminalStatus(status.status)"
          type="danger"
          plain
          :loading="cancelling"
          @click="cancelCurrentScan"
        >
          停止扫描
        </el-button>
        <el-button type="primary" @click="router.push('/projects/new')">新建审计</el-button>
      </div>
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
        <span>任务状态</span><strong><el-tag :type="statusTagType(status.status)">{{ statusLabel(status.status) }}</el-tag></strong><small>{{ status.current_stage || "等待阶段信息" }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>扫描进度</span><strong>{{ status.progress }}%</strong><el-progress :percentage="status.progress" :show-text="false" />
      </el-card>
      <el-card shadow="never" class="summary-card stage-summary-card">
        <span>阶段进度</span>
        <strong>{{ stageProgressLabel }}</strong>
        <small>{{ stageProgressHint }}</small>
        <el-progress
          v-if="stageProgressPercent !== null"
          :percentage="stageProgressPercent"
          :show-text="false"
        />
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>可处置漏洞</span><strong>{{ actionableFindings.length }}</strong><small>高危 {{ highCount }} / 已验证 {{ verifiedCount }} / 非处置结果 {{ informationalCount }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>报告</span><strong>HTML</strong><el-button text type="primary" @click="genReport">生成报告</el-button>
      </el-card>
    </div>

    <!-- Task 3/4：进度分区 + 候选计数分离 -->
    <el-card v-if="status" shadow="never" class="partition-card">
      <div class="partition-head">
        <h3>进度分区</h3>
        <el-tag v-if="verifyAllCandidates" type="warning" size="small" effect="light">本次将复核全部候选</el-tag>
      </div>
      <div class="partition-grid">
        <div v-for="p in progressPartitions" :key="p.key" class="partition-tile">
          <span class="partition-label">{{ p.label }}</span>
          <strong class="partition-value">{{ p.value }}</strong>
          <small class="partition-hint">{{ p.hint }}</small>
        </div>
      </div>
      <div class="partition-head partition-head--counts">
        <h3>候选计数</h3>
      </div>
      <div class="partition-grid partition-grid--counts">
        <div class="partition-tile">
          <span class="partition-label">原始静态发现</span>
          <strong class="partition-value">{{ candidateCounts.original }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">已送验证</span>
          <strong class="partition-value">{{ candidateCounts.sent }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">已完成验证</span>
          <strong class="partition-value">{{ candidateCounts.done }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">待人工复核</span>
          <strong class="partition-value">{{ candidateCounts.needsReview }}</strong>
        </div>
      </div>
    </el-card>

    <el-card v-if="scannerStatuses.length" shadow="never" class="partition-card">
      <div class="partition-head"><h3>扫描器真实运行状态</h3></div>
      <el-table :data="scannerStatuses" size="small" stripe>
        <el-table-column prop="tool" label="工具" width="130" />
        <el-table-column label="状态" width="130">
          <template #default="scope">
            <el-tag :type="scope.row.success ? 'success' : 'danger'">
              {{ scope.row.success ? '执行成功' : (scope.row.executed ? '执行失败' : '未启动') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="finding_count" label="原始命中" width="100" />
        <el-table-column prop="error" label="错误 / 降级原因" min-width="260" show-overflow-tooltip />
      </el-table>
    </el-card>

    <el-alert
      v-if="status?.status === 'failed'"
      type="error"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描任务失败，请检查仓库地址、网络、分支或本地路径。'"
    />

    <el-alert
      v-if="status?.status === 'partial_completed'"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描已部分完成（partial_completed）：部分阶段被跳过或未产出完整结果，以下为已获得的结果。'"
    />

    <el-alert
      v-if="staleWarning"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      title="任务疑似停滞"
    >
      <template #default>
        <div class="warning-action-row">
          <span>{{ staleWarning }}</span>
          <el-button type="primary" plain size="small" :loading="loading" @click="load">刷新状态</el-button>
        </div>
      </template>
    </el-alert>

    <el-alert
      v-if="longRunningWarning"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      :title="longRunningWarning"
    >
      <template #default>
        <div class="warning-action-row">
          <span>{{ longRunningHint }}</span>
          <el-button
            v-if="status && !isTerminalStatus(status.status)"
            type="warning"
            plain
            size="small"
            :loading="cancelling"
            @click="cancelCurrentScan"
          >
            停止扫描
          </el-button>
        </div>
      </template>
    </el-alert>

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
              <template #default="scope"><el-tag :type="findingStatusType(scope.row.status)">{{ findingStatusLabel(scope.row.status) }}</el-tag></template>
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

          <!-- Task 2：动态验证环境信息（从 stage_detail 读，缺字段显示 —） -->
          <el-descriptions
            v-if="hasDynamicInfo"
            :column="3"
            border
            class="dynamic-info-desc"
            title="动态验证环境"
          >
            <el-descriptions-item label="检测到的启动方式">{{ dynamicInfo.launchMethod }}</el-descriptions-item>
            <el-descriptions-item label="服务名">{{ dynamicInfo.serviceName }}</el-descriptions-item>
            <el-descriptions-item label="端口映射">{{ dynamicInfo.portMapping }}</el-descriptions-item>
            <el-descriptions-item label="健康检查结果">{{ dynamicInfo.healthCheck }}</el-descriptions-item>
            <el-descriptions-item label="回退 Harness 原因" :span="2">{{ dynamicInfo.harnessReason }}</el-descriptions-item>
          </el-descriptions>

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
            <el-table-column label="Docker" width="140">
              <template #default="scope">
                {{ scope.row.sandbox?.docker_engine?.status || scope.row.sandbox?.status || "-" }}
              </template>
            </el-table-column>
            <el-table-column label="说明" min-width="220" show-overflow-tooltip>
              <template #default="scope">{{ scope.row.runtime?.reason || scope.row.runtime?.error || "-" }}</template>
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
          <div class="agent-toolbar">
            <el-select v-model="agentFilters.actor" clearable filterable placeholder="按 Agent 过滤">
              <el-option v-for="item in agentActorOptions" :key="item" :label="agentName(item)" :value="item" />
            </el-select>
            <el-select v-model="agentFilters.messageType" clearable filterable placeholder="按消息类型过滤">
              <el-option v-for="item in agentMessageTypeOptions" :key="item" :label="item" :value="item" />
            </el-select>
            <el-checkbox v-model="agentFilters.onlyProblems">只看异常 / 待复核</el-checkbox>
            <el-checkbox v-model="agentFilters.collapse">折叠重复 Verify 消息</el-checkbox>
          </div>
          <div class="agent-stats">
            <el-tag size="small" type="info">原始 {{ agentMessages.length }}</el-tag>
            <el-tag size="small" type="primary">当前 {{ displayAgentMessages.length }}</el-tag>
            <el-tag size="small" type="warning">Verify 待返回 {{ stageDetail.verify_pending || 0 }}</el-tag>
          </div>
          <el-empty v-if="!agentMessagesLoading && agentMessages.length === 0" description="暂无 Agent 通信记录，当前扫描未生成 ACP trace，可重新扫描生成。" />
          <el-timeline v-else v-loading="agentMessagesLoading" class="agent-timeline">
            <el-timeline-item
              v-for="msg in displayAgentMessages"
              :key="msg.groupKey || msg.message_id"
              :timestamp="msg._group ? `${formatTime(msg.first_timestamp)} - ${formatTime(msg.last_timestamp)}` : formatTime(msg.timestamp)"
              :type="agentTimelineType(msg)"
            >
              <div class="agent-message-card">
                <div class="agent-message-head">
                  <strong>{{ agentName(msg.sender) }} → {{ agentName(msg.receiver) }}</strong>
                  <div class="agent-message-tags">
                    <el-tag v-if="msg._group" size="small" type="info">x{{ msg.count }}</el-tag>
                    <el-tag size="small" :type="agentMessageTagType(msg)">{{ agentMessageLabel(msg) }}</el-tag>
                  </div>
                </div>
                <p>{{ msg.intent || msg.message_type }}</p>
                <div class="agent-message-meta">
                  <span>{{ msg.message_type }}</span>
                  <span v-if="msg._group">折叠 {{ msg.count }} 条相邻重复消息</span>
                  <span v-if="msg.confidence !== null && msg.confidence !== undefined">置信度 {{ msg.confidence }}</span>
                </div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-tab-pane>

        <el-tab-pane label="项目结构" name="structure">
          <div class="tab-intro">
            <h2>目标项目结构</h2>
            <p>RepoParserAgent 解析出的文件结构、语言构成、框架、入口与依赖清单。</p>
          </div>
          <el-empty
            v-if="!projectMetaLoading && !projectMeta"
            description="暂无项目结构信息。该数据在扫描解析阶段生成，可重新扫描生成。"
          />
          <div v-else v-loading="projectMetaLoading" class="structure-block">
            <el-descriptions :column="4" border class="evidence-desc">
              <el-descriptions-item label="文件数">{{ projectMeta?.file_count ?? "-" }}</el-descriptions-item>
              <el-descriptions-item label="代码行数">{{ projectMeta?.loc ?? "-" }}</el-descriptions-item>
              <el-descriptions-item label="语言" :span="2">
                <el-tag v-for="l in projectMeta?.languages || []" :key="l" size="small" class="chip">{{ l }}</el-tag>
                <span v-if="!(projectMeta?.languages || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="框架" :span="2">
                <el-tag v-for="fw in projectMeta?.frameworks || []" :key="fw" size="small" type="success" class="chip">{{ fw }}</el-tag>
                <span v-if="!(projectMeta?.frameworks || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="依赖清单" :span="2">
                <el-tag v-for="d in projectMeta?.dependencies || []" :key="d" size="small" type="warning" class="chip">{{ d }}</el-tag>
                <span v-if="!(projectMeta?.dependencies || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="入口点" :span="4">
                <code v-for="e in projectMeta?.entrypoints || []" :key="e" class="entry-chip">{{ e }}</code>
                <span v-if="!(projectMeta?.entrypoints || []).length">-</span>
              </el-descriptions-item>
            </el-descriptions>

            <div class="file-tree-wrap">
              <h3>文件结构（{{ (projectMeta?.tree || []).length }} 个文件）</h3>
              <el-tree
                :data="fileTreeData"
                node-key="id"
                :props="{ label: 'label', children: 'children' }"
                :default-expand-all="fileTreeData.length <= 1"
                :filter-node-method="() => true"
              >
                <template #default="{ data }">
                  <span class="tree-node">
                    <span :class="data.isDir ? 'tree-dir' : 'tree-file'">{{ data.isDir ? "📁" : "📄" }} {{ data.label }}</span>
                    <el-tag v-if="!data.isDir && data.language && data.language !== 'Other'" size="small" class="tree-lang">{{ data.language }}</el-tag>
                  </span>
                </template>
              </el-tree>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { FindingApi, ProjectApi, ReportApi, ScanApi } from "../api";
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
const cancelling = ref(false);
const evidenceLoading = ref(false);
const evidenceLoaded = ref(false);
const agentMessagesLoading = ref(false);
const agentMessagesLoaded = ref(false);
const status = ref<any>(null);
const findings = ref<any[]>([]);
const evidenceMap = ref<Record<string, any>>({});
const agentMessages = ref<any[]>([]);
const projectMeta = ref<any>(null);
const projectMetaLoaded = ref(false);
const projectMetaLoading = ref(false);
const currentPage = ref(1);
const pageSize = ref(50);
let searchTimer: ReturnType<typeof setTimeout> | undefined;

// ---- 前端 watchdog：客户端侧 stale 检测，防止把已停滞任务永久显示成 running ----
const STALE_MS = 90_000;              // 90s 内无任何进度/阶段变化即判定疑似停滞
const lastActivityAt = ref<number>(Date.now());
const nowTick = ref<number>(Date.now());
let lastActivitySignature = "";
function statusActivitySignature(data: any) {
  const sd = data?.stage_detail || {};
  return [
    data?.status, data?.progress, data?.current_stage,
    sd.verify_results, sd.verify_requests, sd.dynamic_completed, sd.dynamic_phase,
  ].join("|");
}
// 每次拿到最新状态时调用：进度/阶段有变化就刷新活动时间，并推进 nowTick 让 stale 计算生效
function noteStatusActivity(data: any) {
  const sig = statusActivitySignature(data);
  if (sig !== lastActivitySignature) {
    lastActivitySignature = sig;
    lastActivityAt.value = Date.now();
  }
  nowTick.value = Date.now();
}

const agentFilters = reactive({
  actor: "",
  messageType: "",
  onlyProblems: false,
  collapse: true,
});

const NON_ACTIONABLE_STATUSES = new Set(["informational", "false_positive", "out_of_scope"]);
const actionableFindings = computed(() => findings.value.filter(
  (item) => !NON_ACTIONABLE_STATUSES.has(String(item.status || "").toLowerCase()),
));
const informationalCount = computed(() => findings.value.length - actionableFindings.value.length);
const highCount = computed(() => actionableFindings.value.filter((item) => ["high", "critical"].includes(String(item.severity).toLowerCase())).length);
const verifiedCount = computed(() => findings.value.filter((item) => item.verified).length);
const staticFindings = computed(() => findings.value);
const pagedStaticFindings = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  return staticFindings.value.slice(start, start + pageSize.value);
});
const dynamicRows = computed(() => findings.value
  .map((item) => ({
    ...item,
    runtime: evidenceMap.value[item.finding_id]?.runtime,
    sandbox: evidenceMap.value[item.finding_id]?.sandbox,
  }))
  .filter((item) => item.runtime));
const exploitRows = computed(() => findings.value
  .map((item) => ({ ...item, exploit: evidenceMap.value[item.finding_id]?.exploit }))
  .filter((item) => item.exploit?.exploit_code));

const stageDetail = computed<Record<string, any>>(() => status.value?.stage_detail || {});
const scannerStatuses = computed<any[]>(() => stageDetail.value.scanner_status || []);

const DASH = "—";
function numOrDash(value: any) {
  const n = Number(value);
  return Number.isFinite(n) && value !== null && value !== undefined && value !== "" ? n : DASH;
}

// 目标沙箱 / 健康检查状态 → 中文标签（供动态验证信息展示与回退原因用）
function targetStatusLabel(statusValue?: string) {
  const map: Record<string, string> = {
    started: "已启动，健康检查通过",
    not_available: "靶场不可用（回退 Harness）",
    not_web_target: "非 Web 项目，HTTP 不适用",
    sandbox_start_failed: "沙箱启动失败",
    health_check_failed: "健康检查失败",
    dependency_install_failed: "依赖安装失败",
    unsafe_project_config: "项目容器配置被安全策略阻止",
    not_installed: "Docker 未安装",
    unsupported: "当前环境不支持自启动 Docker",
    start_failed: "启动失败",
    start_timeout: "启动超时",
    launch_not_detected: "未识别启动方式",
  };
  return map[String(statusValue || "").toLowerCase()] || statusValue || DASH;
}

// Task 2：动态验证信息（从 stage_detail 读，读不到显示 —，不报错）
// launch_plan 来自后端 config.options.dynamic_target.launch_plan，通常仅在用户高级覆盖或后端回写后有值。
const launchPlan = computed<Record<string, any>>(() => stageDetail.value.launch_plan || {});
const dynamicInfo = computed(() => {
  const lp = launchPlan.value;
  const d = stageDetail.value;
  const targetStatus = d.dynamic_target_status;
  const isStarted = String(targetStatus || "").toLowerCase() === "started";
  return {
    // 检测到的启动方式：优先 launch_plan.source/framework，回退动态目标模式
    launchMethod: lp.source || lp.framework || lp.run_command || lp.command || d.dynamic_target_mode || DASH,
    // 服务名：compose / framework（后端暂无独立 service_name 字段）
    serviceName: lp.compose || lp.framework || DASH,
    // 端口映射：launch_plan.port（后端暂未把真实 host->container 映射写入 stage_detail）
    portMapping: lp.port ? String(lp.port) : DASH,
    // 健康检查结果：dynamic_target_status
    healthCheck: targetStatus ? targetStatusLabel(targetStatus) : DASH,
    // 回退到 Harness 的原因：非 started 时用 dynamic_detail / 状态标签
    harnessReason: targetStatus && !isStarted
      ? (d.dynamic_detail || targetStatusLabel(targetStatus))
      : DASH,
  };
});
const hasDynamicInfo = computed(() => {
  const d = stageDetail.value;
  return Boolean(
    d.dynamic_target_mode || d.dynamic_target_status || d.dynamic_phase ||
    d.dynamic_total || Object.keys(launchPlan.value).length,
  );
});

// Task 4：候选计数分离（从 findings 按 status 归类 + stage_detail 的验证收发计数）
const needsReviewCount = computed(() =>
  findings.value.filter((f) => String(f.status || "").toLowerCase().includes("review")).length);
const candidateCounts = computed(() => ({
  original: numOrDash(stageDetail.value.raw_finding_count),     // 工具原始静态发现数
  sent: numOrDash(stageDetail.value.verify_requests),          // 已送验证
  done: numOrDash(stageDetail.value.verify_results),           // 已完成验证
  needsReview: needsReviewCount.value,                         // 待人工复核
}));
// max_verify_candidates=0（或不限）时，明确显示"本次将复核全部候选"
const verifyAllCandidates = computed(() => {
  const raw = stageDetail.value.max_verify_candidates;
  return raw !== null && raw !== undefined && Number(raw) <= 0;
});

// Task 3：进度分区（静态扫描 / 静态复核 / 动态发现 / 动态验证 / 失败-跳过）
const progressPartitions = computed(() => {
  const d = stageDetail.value;
  const dynTotal = Number(d.dynamic_total || 0);
  const dynDone = Number(d.dynamic_completed || 0);
  const verReq = Number(d.verify_requests || 0);
  const verRes = Number(d.verify_results || 0);
  return [
    { key: "static", label: "静态扫描", value: String(numOrDash(d.raw_finding_count)), hint: "工具原始发现" },
    { key: "review", label: "静态复核", value: verReq > 0 ? `${verRes}/${verReq}` : String(verRes || 0), hint: "VerifyAgent" },
    { key: "discover", label: "动态发现", value: dynTotal > 0 ? String(dynTotal) : DASH, hint: "送验证候选" },
    { key: "dynamic", label: "动态验证", value: dynTotal > 0 ? `${dynDone}/${dynTotal}` : DASH, hint: d.dynamic_phase || "未开始" },
    { key: "skipped", label: "未自动定性", value: String(needsReviewCount.value), hint: "待人工复核" },
  ];
});

// Task 5：stale 检测——非终态且 90s 无变化时判定疑似停滞
const isStale = computed(() => {
  if (!status.value || isTerminalStatus(status.value.status)) return false;
  return nowTick.value - lastActivityAt.value >= STALE_MS;
});
const staleWarning = computed(() => {
  if (!isStale.value) return "";
  const secs = Math.floor((nowTick.value - lastActivityAt.value) / 1000);
  return `任务已 ${secs} 秒无任何进度或阶段变化，疑似停滞。后端可能已置为 partial_completed / failed，请点击"查询"刷新，或查看当前阶段日志。`;
});
const elapsedMinutes = computed(() => {
  const seconds = Number(stageDetail.value.elapsed_seconds || 0);
  return Math.floor(seconds / 60);
});
// ExploitAgent/DynamicVerify 是动态验证阶段，不应复用 VerifyAgent 的
// 静态复核计数；否则会把“已返回的静态复核数/配置上限”误显示成动态进度。
const isVerifyAgentStage = computed(() => /^verifyagent\b/i.test(
  String(status.value?.current_stage || "").trim(),
));
const isDynamicStage = computed(() => /dynamic|harness|exploit/i.test(
  String(status.value?.current_stage || ""),
));
const stageProgressPercent = computed(() => {
  if (!status.value) return null;
  const total = isVerifyAgentStage.value
    ? Number(stageDetail.value.max_verify_candidates || stageDetail.value.verify_requests || 0)
    : (isDynamicStage.value ? Number(stageDetail.value.dynamic_total || 0) : 0);
  const done = isVerifyAgentStage.value
    ? Number(stageDetail.value.verify_results || 0)
    : (isDynamicStage.value ? Number(stageDetail.value.dynamic_completed || 0) : 0);
  if (!Number.isFinite(total) || total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
});
const stageProgressLabel = computed(() => {
  const stage = status.value?.current_stage || "等待阶段信息";
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    const done = Number(detail.verify_results || 0);
    const total = Number(detail.max_verify_candidates || detail.verify_requests || 0);
    return total > 0 ? `${done}/${total}` : `${done}`;
  }
  if (isDynamicStage.value) {
    const done = Number(detail.dynamic_completed || 0);
    const total = Number(detail.dynamic_total || 0);
    const phase = String(detail.dynamic_phase || "动态验证");
    return total > 0 ? `${phase} ${done}/${total}` : phase;
  }
  return stage;
});
const stageProgressHint = computed(() => {
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    const pending = Number(detail.verify_pending || 0);
    const workers = Number(detail.max_verify_workers || 0);
    return `待返回 ${pending}，并发 ${workers || "-"}，已运行 ${elapsedMinutes.value} 分钟`;
  }
  if (isDynamicStage.value) {
    return detail.dynamic_detail || `已运行 ${elapsedMinutes.value} 分钟`;
  }
  return `已运行 ${elapsedMinutes.value} 分钟`;
});
const longRunningWarning = computed(() => {
  if (!status.value || isTerminalStatus(status.value.status)) return "";
  const stage = String(status.value.current_stage || "").toLowerCase();
  const minutes = elapsedMinutes.value;
  if (isVerifyAgentStage.value && minutes >= 10) return `VerifyAgent 已运行 ${minutes} 分钟，可能被 LLM 重试或候选数量拖慢`;
  if ((stage.includes("dynamic") || stage.includes("harness")) && minutes >= 15) return `动态验证阶段已运行 ${minutes} 分钟，可能卡在沙箱启动、健康检查或请求超时`;
  if (minutes >= 25) return `扫描已运行 ${minutes} 分钟，建议检查当前阶段日志或停止后调小候选数量`;
  return "";
});
const longRunningHint = computed(() => {
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    return `当前 Verify 请求 ${detail.verify_requests || 0}，结果 ${detail.verify_results || 0}，上限 ${detail.max_verify_candidates || "-"}`;
  }
  if (isDynamicStage.value) {
    return `动态阶段：${detail.dynamic_phase || "准备中"}，${detail.dynamic_completed || 0}/${detail.dynamic_total || 0}；${detail.dynamic_detail || "等待执行结果"}`;
  }
  return "可以先停止扫描，再降低候选上限或切换 Quick 模式复测。";
});

const agentActorOptions = computed(() => {
  const names = new Set<string>();
  agentMessages.value.forEach((msg) => {
    if (msg.sender) names.add(msg.sender);
    if (msg.receiver) names.add(msg.receiver);
  });
  return Array.from(names).sort();
});
const agentMessageTypeOptions = computed(() => Array.from(new Set(
  agentMessages.value.map((msg) => String(msg.message_type || "")).filter(Boolean),
)).sort());
const filteredAgentMessages = computed(() => agentMessages.value.filter((msg) => {
  if (agentFilters.actor && msg.sender !== agentFilters.actor && msg.receiver !== agentFilters.actor) return false;
  if (agentFilters.messageType && msg.message_type !== agentFilters.messageType) return false;
  if (agentFilters.onlyProblems && !isProblemAgentMessage(msg)) return false;
  return true;
}));
const displayAgentMessages = computed(() => {
  if (!agentFilters.collapse) return filteredAgentMessages.value;
  const grouped: any[] = [];
  for (const msg of filteredAgentMessages.value) {
    const prev = grouped[grouped.length - 1];
    const key = agentGroupKey(msg);
    if (prev?.groupKey === key) {
      prev.count += 1;
      prev.last_timestamp = msg.timestamp;
      prev.confidence = msg.confidence ?? prev.confidence;
      continue;
    }
    grouped.push({
      ...msg,
      _group: true,
      groupKey: key,
      count: 1,
      first_timestamp: msg.timestamp,
      last_timestamp: msg.timestamp,
    });
  }
  return grouped.map((msg) => (msg.count > 1 ? msg : { ...msg, _group: false }));
});

// 把扁平的 [{path, language}] 文件列表拼成 el-tree 的嵌套结构
const fileTreeData = computed(() => {
  const roots: any[] = [];
  const dirMap = new Map<string, any>();
  const files = (projectMeta.value?.tree || []) as Array<{ path: string; language?: string }>;
  for (const f of files) {
    const parts = String(f.path).split("/").filter(Boolean);
    let level = roots;
    let prefix = "";
    parts.forEach((part, idx) => {
      prefix = prefix ? `${prefix}/${part}` : part;
      const isLeaf = idx === parts.length - 1;
      if (isLeaf) {
        level.push({ id: prefix, label: part, isDir: false, language: f.language });
        return;
      }
      let dir = dirMap.get(prefix);
      if (!dir) {
        dir = { id: prefix, label: part, isDir: true, children: [] };
        dirMap.set(prefix, dir);
        level.push(dir);
      }
      level = dir.children;
    });
  }
  // 目录在前、同类按名排序
  const sortLevel = (nodes: any[]) => {
    nodes.sort((a, b) => (a.isDir === b.isDir ? a.label.localeCompare(b.label) : a.isDir ? -1 : 1));
    nodes.forEach((n) => n.children && sortLevel(n.children));
  };
  sortLevel(roots);
  return roots;
});

async function ensureProjectStructureLoaded() {
  if (projectMetaLoaded.value || projectMetaLoading.value) return;
  const pid = status.value?.project_id;
  if (!pid) return;
  projectMetaLoading.value = true;
  try {
    const { data } = await ProjectApi.tree(pid);
    projectMeta.value = data;
    projectMetaLoaded.value = true;
  } catch {
    projectMeta.value = null;
  } finally {
    projectMetaLoading.value = false;
  }
}
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
  // 浏览器 localStorage 未命中时，回退到后端按项目名/ID 查询（历史的真实数据源）。
  // 解决「清缓存/换浏览器/经脚本跑扫描」导致本地查不到的问题。
  loading.value = true;
  let matches: any[] = [];
  try {
    const { data } = await ScanApi.list(keyword);
    matches = data.scans || [];
  } finally {
    loading.value = false;
  }
  if (matches.length === 0) {
    ElMessage.warning("未找到该项目的扫描记录，请确认项目名称，或先发起一次审计");
    return;
  }
  if (matches.length > 1) {
    ElMessage.info(`找到 ${matches.length} 条匹配记录，已加载最近一条`);
  }
  const hit = matches[0];
  await loadByScanId(hit.scan_id);
  // 回写带真实项目名的历史，下次可直接本地命中
  upsertHistory({
    scanId: hit.scan_id,
    projectId: hit.project_id,
    projectName: hit.project_name,
    target: hit.target,
    sourceType: hit.source_type,
    status: hit.status,
    progress: hit.progress,
  });
}

async function loadRecord(record: AuditHistoryRecord) {
  const duplicatedName = isDuplicatedProjectName(record);
  searchText.value = buildSuggestionValue(record, duplicatedName);
  await loadByScanId(record.scanId);
}

async function loadByScanId(nextScanId: string) {
  if (!nextScanId) return;
  stopScanPolling();
  scanId.value = nextScanId;
  loading.value = true;
  try {
    const { data } = await ScanApi.get(nextScanId);
    status.value = data;
    lastActivitySignature = "";        // 切换扫描时重置活动基线，避免旧任务的 stale 误判
    noteStatusActivity(data);
    const { data: f } = await ScanApi.findings(nextScanId);
    findings.value = f.findings;
    currentPage.value = 1;
    evidenceMap.value = {};
    agentMessages.value = [];
    evidenceLoaded.value = false;
    agentMessagesLoaded.value = false;
    projectMeta.value = null;
    projectMetaLoaded.value = false;
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
    // 扫描仍在进行时启动轮询，实时刷新进度/状态/漏洞，无需手动重查
    startScanPolling();
  } finally {
    loading.value = false;
  }
}

const POLL_MS = 3000;
let pollTimer: ReturnType<typeof setInterval> | undefined;

function isTerminalStatus(s?: string) {
  const v = String(s || "").toLowerCase();
  return v === "done" || v === "finished" || v === "failed"
    || v === "cancelled" || v === "partial_completed";
}

function stopScanPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
}

async function cancelCurrentScan() {
  if (!scanId.value || cancelling.value) return;
  try {
    await ElMessageBox.confirm(
      "停止后，后端会尽快终止后续阶段和未开始的 Verify 任务；已经发出的单次请求可能需要等待返回。",
      "确认停止扫描",
      { confirmButtonText: "停止扫描", cancelButtonText: "继续扫描", type: "warning" },
    );
  } catch {
    return;
  }
  cancelling.value = true;
  try {
    await ScanApi.cancel(scanId.value);
    const { data } = await ScanApi.get(scanId.value);
    status.value = data;
    noteStatusActivity(data);
    stopScanPolling();
    upsertHistory({
      scanId: scanId.value,
      projectId: data.project_id,
      status: data.status,
      progress: data.progress,
      findingCount: findings.value.length,
      highCount: highCount.value,
      verifiedCount: verifiedCount.value,
    });
    ElMessage.success("已请求停止扫描");
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "停止扫描失败");
  } finally {
    cancelling.value = false;
  }
}

function startScanPolling() {
  stopScanPolling();
  if (!scanId.value || isTerminalStatus(status.value?.status)) return;
  pollTimer = setInterval(async () => {
    if (!scanId.value) { stopScanPolling(); return; }
    try {
      const { data } = await ScanApi.get(scanId.value);
      status.value = data;
      noteStatusActivity(data);
      const { data: f } = await ScanApi.findings(scanId.value);
      findings.value = f.findings;
      upsertHistory({
        scanId: scanId.value, projectId: data.project_id, status: data.status,
        progress: data.progress, findingCount: findings.value.length,
        highCount: highCount.value, verifiedCount: verifiedCount.value,
      });
      if (activeTab.value === "agents") {
        await loadAgentMessages(scanId.value);
        agentMessagesLoaded.value = true;
      }
      if (isTerminalStatus(data.status)) {
        stopScanPolling();
        // 扫描完成：让证据/Agent 消息在当前标签重新加载
        evidenceLoaded.value = false;
        agentMessagesLoaded.value = false;
        if (activeTab.value === "dynamic" || activeTab.value === "exploit") await ensureEvidenceLoaded();
        if (activeTab.value === "agents") await ensureAgentMessagesLoaded();
      }
    } catch {
      /* 瞬时网络错误忽略，下次轮询自动重试 */
    }
  }, POLL_MS);
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
  if (!scanId.value) {
    ElMessage.warning("请先查询一个扫描任务");
    return;
  }
  try {
    const { data } = await ReportApi.create({ scan_id: scanId.value, format: "html" });
    window.open(ReportApi.download(data.report_id));
    ElMessage.success("报告已生成");
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "报告生成失败");
  }
}

function querySearch(queryString: string, cb: (items: SearchSuggestion[]) => void) {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    // 每次输入都从 localStorage 重读，确保刚创建/仍在分析中的项目也能出现在下拉推荐里
    refreshHistoryRecords();
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
  if (value === "partial_completed") return "warning";
  if (value === "cancelled") return "info";
  if (value === "done" || value === "finished") return "success";
  if (value === "running") return "warning";
  return "info";
}

function statusLabel(status?: string) {
  const map: Record<string, string> = {
    queued: "排队中",
    running: "运行中",
    done: "已完成",
    finished: "已完成",
    failed: "失败",
    cancelled: "已取消",
    partial_completed: "部分完成",
  };
  return map[String(status || "").toLowerCase()] || status || "unknown";
}

function findingStatusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value.includes("false")) return "info";
  if (value === "out_of_scope") return "info";
  if (value === "unverified") return "info";           // 检出未验证：中性
  if (value.includes("review")) return "warning";      // needs_review 待人工复核
  if (value.includes("confirm") || value.includes("verified")) return "success";
  if (value.includes("candidate")) return "warning";
  return "info";
}

function findingStatusLabel(status?: string) {
  const map: Record<string, string> = {
    confirmed: "已确认",
    unverified: "检出未验证",
    needs_review: "需人工复核",
    informational: "低置信度线索",
    false_positive: "误报排除",
    out_of_scope: "范围外排除",
    candidate: "候选",
  };
  return map[String(status || "").toLowerCase()] || status || "unknown";
}

function formatConfidence(value: any) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return num <= 1 ? `${Math.round(num * 100)}%` : String(num);
}

function runtimeStatusLabel(runtime: any) {
  const status = runtime?.reproduction_status;
  if (status === "dynamic_confirmed" || runtime?.reproducible) return "可复现";
  if (runtime?.harness_confirmed) return "Harness 已复现";
  if (status === "not_reproduced") return "未复现";
  if (status === "function_reproduced") return "仅函数单元复现";
  if (status === "mechanism_confirmed") return "仅机理复现";
  if (status === "not_executed") return "未执行";
  if (status === "not_runtime_verifiable") return "不适合动态验证";
  if (status === "false_positive") return "误报排除";
  if (status === "connection_failed") return "连接失败";
  if (status === "request_timeout") return "请求超时";
  if (status === "endpoint_not_found") return "入口不存在";
  if (status === "launch_not_detected") return "未识别启动方式";
  if (status === "not_web_target") return "非 Web 项目（HTTP 不适用）";
  if (status === "unsafe_project_config") return "项目容器配置已被安全策略阻止";
  if (status === "sandbox_start_failed") return "沙箱启动失败";
  if (status === "health_check_failed") return "沙箱健康检查失败";
  if (status === "dependency_install_failed") return "沙箱依赖安装失败";
  return status || "未执行";
}

function runtimeTagType(runtime: any) {
  const status = runtime?.reproduction_status;
  if (status === "dynamic_confirmed" || runtime?.reproducible || runtime?.harness_confirmed) return "success";
  if (status === "not_reproduced") return "warning";
  if (status === "not_executed" || status === "not_runtime_verifiable" || status === "not_web_target" || status === "function_reproduced" || status === "mechanism_confirmed" || status === "false_positive") return "info";
  if (status === "connection_failed" || status === "request_timeout" || status === "endpoint_not_found" || status === "launch_not_detected" || status === "sandbox_start_failed" || status === "health_check_failed" || status === "dependency_install_failed") return "warning";
  return "info";
}

function agentName(value?: string) {
  return String(value || "unknown").replace(/_/g, " ");
}

function isProblemAgentMessage(msg: any) {
  const state = String(msg?.state || "").toLowerCase();
  const verdict = String(msg?.verdict || "").toLowerCase();
  const type = String(msg?.message_type || "").toLowerCase();
  return state === "failed"
    || state === "skipped"
    || verdict.includes("review")
    || verdict.includes("failed")
    || verdict.includes("timeout")
    || verdict.includes("not_reproduced")
    || verdict.includes("not_executed")
    || verdict.includes("not_found")
    || type === "error"
    || Boolean(msg?.error);
}

function agentGroupKey(msg: any) {
  const type = String(msg?.message_type || "");
  if (!agentFilters.collapse || !type.startsWith("verify.")) {
    return `${msg?.message_id || `${type}|${msg?.timestamp || ""}|${msg?.intent || ""}`}`;
  }
  return [
    msg?.sender || "",
    msg?.receiver || "",
    type,
    msg?.state || "",
    msg?.verdict || "",
  ].join("|");
}

function verdictLabel(verdict?: string, state?: string) {
  const v = String(verdict || "").toLowerCase();
  const labels: Record<string, string> = {
    false_positive: "误报排除",
    out_of_scope: "范围外排除",
    statically_verified: "静态确认",
    confirmed: "已确认",
    dynamic_confirmed: "动态复现",
    harness_confirmed: "Harness 复现",
    needs_review: "需人工复核",
    exploit_generated: "已生成利用方案",
    not_executed: "未执行",
    not_reproduced: "未复现",
    not_runtime_verifiable: "不适合动态验证",
    function_reproduced: "仅函数单元复现",
    mechanism_confirmed: "仅漏洞机理复现",
    connection_failed: "连接失败",
    endpoint_not_found: "入口不存在",
    request_timeout: "请求超时",
    launch_not_detected: "未识别启动方式",
    not_web_target: "非 Web 项目（HTTP 不适用）",
    unsafe_project_config: "项目容器配置被安全策略阻止",
    sandbox_start_failed: "沙箱启动失败",
    health_check_failed: "沙箱健康检查失败",
    dependency_install_failed: "沙箱依赖安装失败",
  };
  if (labels[v]) return labels[v];
  const s = String(state || "").toLowerCase();
  if (s === "success") return "执行成功";
  if (s === "failed") return "执行失败";
  if (s === "skipped") return "已跳过";
  return verdict || state || "unknown";
}

function agentMessageLabel(msg: any) {
  if (String(msg?.state || "").toLowerCase() === "failed") return "执行失败";
  return verdictLabel(msg?.verdict, msg?.state);
}

function verdictTagType(verdict?: string) {
  const v = String(verdict || "").toLowerCase();
  if (v === "false_positive" || v === "out_of_scope") return "info";
  if (v.includes("review")) return "warning";
  if (v.includes("dynamic_confirmed") || v.includes("harness_confirmed")) return "success";
  if (v.includes("confirmed") || v.includes("verified")) return "success";
  if (v.includes("not_reproduced")) return "warning";
  if (v.includes("failed") || v.includes("timeout") || v.includes("not_found")) return "warning";
  if (v.includes("exploit") || v.includes("harness")) return "warning";
  return "info";
}

function agentMessageTagType(msg: any) {
  if (String(msg?.state || "").toLowerCase() === "failed") return "danger";
  return verdictTagType(msg?.verdict);
}

function agentTimelineType(msg: any) {
  if (String(msg.state || "").toLowerCase() === "failed") return "danger";
  if (String(msg.verdict || "").toLowerCase() === "false_positive") return "primary";
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
  if (tab === "structure") {
    await ensureProjectStructureLoaded();
  }
});

watch(pageSize, () => { currentPage.value = 1; });

onMounted(() => {
  refreshHistoryRecords();
  // 历史记录被其他页面（如新建项目）更新时同步刷新，避免搜索用到过期快照
  window.addEventListener("audit-history-updated", refreshHistoryRecords);
  if (scanId.value) loadByScanId(scanId.value);
});

onUnmounted(() => {
  window.removeEventListener("audit-history-updated", refreshHistoryRecords);
  stopScanPolling();
});
</script>

<style scoped>
.dashboard-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.page-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
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
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }
.summary-card span { display: block; color: #667085; font-size: 13px; }
.summary-card strong { display: block; margin: 8px 0; font-size: 26px; color: #162235; }
.summary-card small { color: #667085; }
.stage-summary-card strong { font-size: 24px; }
.error-alert { border-radius: 12px; }
.partition-card { border-radius: 18px; }
.partition-head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.partition-head--counts { margin-top: 18px; }
.partition-head h3 { margin: 0; color: #162235; font-size: 15px; }
.partition-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.partition-grid--counts { grid-template-columns: repeat(4, 1fr); }
.partition-tile { border: 1px solid #e4ebf3; border-radius: 12px; padding: 12px 14px; background: #fbfdff; display: flex; flex-direction: column; gap: 4px; }
.partition-label { color: #667085; font-size: 13px; }
.partition-value { color: #162235; font-size: 22px; }
.partition-hint { color: #98a2b3; font-size: 12px; }
.dynamic-info-desc { margin-bottom: 16px; }
@media (max-width: 980px) { .partition-grid, .partition-grid--counts { grid-template-columns: repeat(2, 1fr); } }
.warning-action-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; color: #162235; }
.tab-intro p { margin: 6px 0 0; color: #667085; }
.exploit-list { display: grid; gap: 16px; }
.exploit-card { border: 1px solid #dce6f0; border-radius: 16px; padding: 16px; background: linear-gradient(180deg, #fff, #fbfdff); box-shadow: 0 8px 22px rgba(16,32,51,.04); }
.exploit-head { display: flex; justify-content: space-between; gap: 16px; }
.exploit-head h3 { margin: 0; }
.exploit-head p, .exploit-path { color: #667085; margin: 6px 0 12px; }
.agent-toolbar { display: grid; grid-template-columns: minmax(180px, 240px) minmax(180px, 260px) auto auto; align-items: center; gap: 12px; margin-bottom: 10px; }
.agent-stats { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.agent-timeline { padding: 8px 0 0; }
.agent-message-card { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px 14px; background: #fbfdff; }
.agent-message-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; color: #162235; }
.agent-message-tags { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.agent-message-card p { margin: 8px 0; color: #475467; }
.agent-message-meta { display: flex; flex-wrap: wrap; gap: 10px; color: #667085; font-size: 12px; }
.structure-block { display: flex; flex-direction: column; gap: 16px; }
.chip { margin: 0 6px 6px 0; }
.entry-chip { display: inline-block; margin: 0 8px 6px 0; padding: 2px 8px; background: #eef3fb; border-radius: 6px; color: #2f4a6b; font-size: 12px; }
.file-tree-wrap { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px 16px; background: #fbfdff; max-height: 520px; overflow: auto; }
.file-tree-wrap h3 { margin: 0 0 10px; color: #162235; }
.tree-node { display: inline-flex; align-items: center; gap: 8px; }
.tree-dir { font-weight: 600; color: #1f3350; }
.tree-file { color: #475467; }
.tree-lang { transform: scale(.9); }
pre { background: #0b1220; color: #d7e3f1; padding: 14px; border-radius: 12px; overflow: auto; border: 1px solid rgba(255,255,255,.08); }
@media (max-width: 980px) { .agent-toolbar { grid-template-columns: 1fr 1fr; } }
@media (max-width: 680px) { .query-row, .summary-grid, .agent-toolbar { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } .page-actions { justify-content: flex-start; } }
</style>
