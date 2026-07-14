<template>
  <section class="detail-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Finding</p>
        <h1>{{ detail?.type || "漏洞详情" }}</h1>
        <p v-if="detail">{{ detail.file }}:{{ detail.start_line }} · {{ detail.severity }}</p>
      </div>
      <div class="title-actions">
        <el-button type="success" plain :loading="labeling==='true_positive'" @click="labelFinding('true_positive')">标记为真漏洞</el-button>
        <el-button type="warning" plain :loading="labeling==='false_positive'" @click="labelFinding('false_positive')">标记为误报</el-button>
        <el-button :disabled="!evidence" @click="showEvidenceDialog = true">原始 JSON（审计用）</el-button>
        <el-button type="primary" plain :disabled="!evidence" @click="exportEvidence">导出证据链</el-button>
        <el-button @click="router.back()">返回</el-button>
      </div>
    </div>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="类型">{{ detail.type }}</el-descriptions-item>
        <el-descriptions-item label="严重级"><el-tag :type="severityType(detail.severity)">{{ detail.severity || "unknown" }}</el-tag></el-descriptions-item>
        <el-descriptions-item label="状态"><el-tag :type="findingStatusType(detail.verification.status)">{{ findingStatusLabel(detail.verification.status) }}</el-tag></el-descriptions-item>
        <el-descriptions-item label="文件位置">{{ detail.file }}:{{ detail.start_line }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ formatConfidence(detail.verification.confidence) }}</el-descriptions-item>
        <el-descriptions-item label="已验证"><el-tag :type="detail.verification.verified ? 'success' : 'info'">{{ detail.verification.verified ? "是" : "否" }}</el-tag></el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro"><h2>静态代码证据</h2><p>展示漏洞位置、代码片段、source/sink 和修复建议。</p></div>
          <pre class="code-block"><code>{{ detail.vulnerable_code || "暂无代码片段" }}</code></pre>

          <!-- 证据链：一句话叙述 + source→传播→sink 时间线，中文可读，不放 JSON -->
          <div class="chain-card">
            <h3 class="chain-title">漏洞证据链</h3>
            <p v-if="chainNarrative" class="chain-narrative">{{ chainNarrative }}</p>
            <div class="chain-endpoints">
              <div class="chain-endpoint source">
                <span class="chain-badge">污染源 Source</span>
                <span class="chain-text">{{ sourceText }}</span>
              </div>
              <div class="chain-arrow">↓ 数据流传播</div>
              <div class="chain-endpoint sink">
                <span class="chain-badge danger">危险汇聚 Sink</span>
                <span class="chain-text">{{ sinkText }}</span>
              </div>
            </div>

            <el-timeline v-if="flowSteps.length" class="chain-timeline">
              <el-timeline-item
                v-for="step in flowSteps"
                :key="step.index"
                :timestamp="step.location"
                placement="top"
              >
                <span class="step-stage">{{ step.stage }}</span>
                <span v-if="step.detail" class="step-detail">：{{ step.detail }}</span>
              </el-timeline-item>
            </el-timeline>
            <p v-else class="chain-empty">
              该 finding 暂无逐步数据流（可能是配置/密钥类漏洞，或静态跨过程分析未生成路径）。
            </p>
          </div>

          <el-descriptions :column="1" border class="evidence-desc fix-desc">
            <el-descriptions-item label="修复建议">{{ detail.fix_suggestion || "建议结合漏洞类型进行输入校验、参数化查询或最小权限加固。" }}</el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>

        <el-tab-pane label="知识增强" name="knowledge">
          <div class="tab-intro"><h2>RAG 安全知识增强</h2><p>展示 VerifyAgent 检索到的 CWE/OWASP、验证条件、误报判据和修复建议。</p></div>
          <el-empty v-if="!hasKnowledgeEvidence" description="暂无知识增强证据。启用 VerifyAgent 后重新扫描可生成。" />
          <div v-else class="knowledge-block">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="CWE">{{ evidence?.knowledge?.cwe_id || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="OWASP">{{ (evidence?.knowledge?.owasp || []).join("、") || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="动态策略" :span="2">{{ evidence?.knowledge?.dynamic_strategy || "N/A" }}</el-descriptions-item>
            </el-descriptions>

            <div v-if="evidence?.knowledge?.verification_checks?.length" class="flow-block">
              <h3>验证条件</h3>
              <ol>
                <li v-for="(item, index) in evidence.knowledge.verification_checks" :key="`check-${index}`">{{ item }}</li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.false_positive_signals?.length" class="flow-block warning-flow">
              <h3>误报信号</h3>
              <ol>
                <li v-for="(item, index) in evidence.knowledge.false_positive_signals" :key="`fp-${index}`">{{ item }}</li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.remediation?.length" class="flow-block fix-flow">
              <h3>修复建议</h3>
              <ol>
                <li v-for="(item, index) in evidence.knowledge.remediation" :key="`fix-${index}`">{{ item }}</li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.references?.length" class="tool-call-list">
              <h3>知识来源</h3>
              <p v-for="(ref, index) in evidence.knowledge.references" :key="`ref-${index}`"><code>{{ ref }}</code></p>
            </div>

            <div v-if="evidence?.knowledge?.retrieval" class="tool-call-list">
              <h3>原始检索结果</h3>
              <pre class="mini-pre">{{ JSON.stringify(evidence.knowledge.retrieval, null, 2) }}</pre>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="动态分析" name="dynamic">
          <div class="tab-intro"><h2>动态验证</h2><p>仅对本地授权靶场发起验证请求，保存响应摘要和命中特征。</p></div>
          <div class="verify-panel">
            <el-input v-model="verifyForm.base_url" placeholder="http://127.0.0.1:8080" />
            <el-input v-model="verifyForm.endpoints" placeholder="/user,/search" />
            <el-button type="primary" :loading="verifying" @click="runVerify">执行动态验证</el-button>
          </div>
          <el-alert type="warning" show-icon :closable="false" title="动态验证仅限本地授权靶场，不要对真实第三方系统使用。" />

          <el-descriptions v-if="evidence?.sandbox" :column="2" border class="evidence-desc" title="Docker 沙箱环境">
            <el-descriptions-item label="沙箱模式">{{ evidence.sandbox.mode || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="状态">
              <el-tag :type="sandboxStatusMeta(evidence.sandbox).tone">{{ sandboxStatusMeta(evidence.sandbox).label }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="镜像">{{ evidence.sandbox.image || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="容器 ID">{{ evidence.sandbox.container_id || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Base URL">{{ evidence.sandbox.base_url || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="健康检查">{{ evidence.sandbox.health_check || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Docker 引擎">{{ evidence.sandbox.docker_engine?.status || "未单独检查" }}</el-descriptions-item>
            <el-descriptions-item label="容器动作">
              构建 {{ evidence.sandbox.image_build_attempted ? "已尝试" : "未尝试" }} / 启动 {{ evidence.sandbox.container_start_attempted ? "已尝试" : "未尝试" }}
            </el-descriptions-item>
            <el-descriptions-item label="启动命令" :span="2"><code>{{ evidence.sandbox.launch_command || "N/A" }}</code></el-descriptions-item>
            <el-descriptions-item label="诊断" :span="2">{{ sandboxReason(evidence.sandbox, evidence.runtime) }}</el-descriptions-item>
            <el-descriptions-item label="容器日志摘要" :span="2"><pre class="mini-pre">{{ evidence.sandbox.logs_excerpt || "N/A" }}</pre></el-descriptions-item>
          </el-descriptions>

          <el-descriptions v-if="evidence?.runtime" :column="2" border class="evidence-desc">
            <el-descriptions-item label="HTTP 验证结论">
              <el-tag :type="runtimeTagType(evidence.runtime, detail)">{{ runtimeStatusLabel(evidence.runtime, detail) }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="HTTP 是否实际执行">{{ httpExecutionLabel(evidence.runtime) }}</el-descriptions-item>
            <el-descriptions-item label="最终证据等级">
              <el-tag :type="evidenceLevelMeta(evidence?.verification, detail, evidence?.runtime).tone">{{ evidenceLevelMeta(evidence?.verification, detail, evidence?.runtime).label }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="请求记录">
              攻击 {{ evidence.runtime.records?.length || 0 }} / 前置 {{ evidence.runtime.setup_records?.length || 0 }} / 确认 {{ evidence.runtime.confirmation_records?.length || 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="命中特征">{{ evidence.runtime.matched_indicator || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="请求 URL">{{ evidence.runtime.request?.url || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="状态码">{{ evidence.runtime.response_status || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="原因" :span="2">{{ evidence.runtime.reason || "N/A" }}</el-descriptions-item>
            <el-descriptions-item v-if="evidence.runtime.candidate_endpoints?.length" label="候选入口" :span="2">{{ evidence.runtime.candidate_endpoints.join(", ") }}</el-descriptions-item>
            <el-descriptions-item label="Payload" :span="2"><code>{{ evidence.runtime.request?.payload || "N/A" }}</code></el-descriptions-item>
            <el-descriptions-item label="响应摘要" :span="2"><pre class="mini-pre">{{ evidence.runtime.response_excerpt || "N/A" }}</pre></el-descriptions-item>
          </el-descriptions>
          <div v-if="evidence?.runtime?.evidence_flow?.length" class="flow-block">
            <h3>动态证据流</h3>
            <ol>
              <li v-for="(step, index) in evidence.runtime.evidence_flow" :key="index">
                <b>{{ step.stage }}</b>：{{ typeof step.detail === "string" ? step.detail : JSON.stringify(step.detail) }}
              </li>
            </ol>
          </div>

          <div v-if="evidence?.harness" class="harness-block">
            <h3>Fuzzing Harness 动态验证（DeepAudit 式）</h3>
            <p class="harness-note">对目标函数 mock 危险 sink + 恶意 payload 隔离测试，跑通触发才判可利用。</p>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="验证结论">
                <el-tag :type="harnessStatusMeta(evidence.harness).tone">
                  {{ harnessStatusMeta(evidence.harness).label }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="动态触发">{{ evidence.harness.dynamically_triggered ? "已触发" : "未触发" }}</el-descriptions-item>
              <el-descriptions-item label="执行后端">{{ evidence.harness.execution_backend || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="触发细节">{{ evidence.harness.trigger_detail || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="原因" :span="2">{{ evidence.harness.reason || "N/A" }}</el-descriptions-item>
            </el-descriptions>
            <pre v-if="canShowHarnessCode" class="code-block"><code>{{ evidence.harness.harness_code }}</code></pre>
            <p v-else class="harness-note">Harness 源码未展示；保留结论、类型、哈希与原因供审计。</p>
          </div>

          <el-empty v-if="!evidence?.runtime && !evidence?.harness" description="暂无动态验证结果" />
        </el-tab-pane>

        <el-tab-pane label="利用与复现代码" name="exploit">
          <div class="tab-intro"><h2>利用与复现代码</h2><p>仅展示已持久化的已确认 HTTP/目标入口代码，或已执行但未命中的 HTTP 请求复放代码。</p></div>
          <el-empty v-if="!attackPlan" description="暂无已持久化的确认代码或已执行请求复放代码。未确认内容不会生成可执行利用代码。" />
          <div v-else class="exploit-block">
            <div class="attack-plan-banner">
              <el-tag :type="attackPlanTagType(attackPlan)">{{ attackPlanLabel(attackPlan) }}</el-tag>
              <span>{{ attackPlanDescription(attackPlan) }}</span>
            </div>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="触发位置">{{ attackPlan.trigger_location || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="执行范围">{{ attackPlan.execution_scope === "localhost_only" ? "仅 localhost 授权靶场" : attackPlan.execution_scope || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="攻击向量">{{ attackPlan.attack_vector || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="利用路径">{{ attackPlan.exploit_path || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="验证方法" :span="2">{{ attackPlan.verification_method || "在一次性本地靶场中运行并观察成功判据" }}</el-descriptions-item>
            </el-descriptions>
            <div v-if="attackPlan.payloads?.length" class="attack-payloads"><b>Payload</b><code v-for="payload in attackPlan.payloads.slice(0, 6)" :key="payload">{{ payload }}</code></div>
            <div v-if="hasDisplayablePocCode(attackPlan.code)" class="attack-code-head"><span>{{ attackPlanCodeCaption(attackPlan) }}</span><el-button size="small" @click="copyAttackPlan">复制代码</el-button></div>
            <pre v-if="hasDisplayablePocCode(attackPlan.code)" class="code-block"><code>{{ attackPlan.code }}</code></pre>
            <p class="attack-safety">{{ attackPlan.safety_notes || "仅限本地授权靶场环境。" }}</p>
          </div>
          <section v-if="validationHypothesis" class="review-panel">
            <h3>验证假设 / 人工复核</h3>
            <el-alert type="warning" show-icon :closable="false" title="未确认，未生成可执行利用代码。" />
            <el-descriptions :column="2" border>
              <el-descriptions-item label="触发位置">{{ validationHypothesis.trigger_location || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="验证状态">{{ validationHypothesis.generation_status || "validation_pending" }}</el-descriptions-item>
              <el-descriptions-item label="攻击向量">{{ validationHypothesis.attack_vector || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="利用路径">{{ validationHypothesis.exploit_path || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="人工验证方法" :span="2">{{ validationHypothesis.verification_method || "请先确认 source→route/endpoint 绑定与实际 sink。" }}</el-descriptions-item>
            </el-descriptions>
            <div v-if="validationHypothesis.payloads?.length" class="attack-payloads"><b>Payload 候选</b><code v-for="payload in validationHypothesis.payloads.slice(0, 6)" :key="payload">{{ payload }}</code></div>
          </section>
          <section v-if="artifactStates.length" class="artifact-panel">
            <h3>复现制品状态</h3>
            <el-alert v-for="artifact in artifactStates" :key="artifact.kind" :type="artifact.alertType" show-icon :closable="false" :title="artifact.notice" />
            <el-descriptions v-for="artifact in artifactStates" :key="`${artifact.kind}-detail`" :title="artifact.label" :column="2" border>
              <el-descriptions-item label="generation_status">{{ artifact.generation_status }}</el-descriptions-item>
              <el-descriptions-item label="validation_status">{{ artifact.validation_status }}</el-descriptions-item>
              <el-descriptions-item label="persistence_status">{{ artifact.persistence_status }}</el-descriptions-item>
              <el-descriptions-item label="name">{{ artifact.name }}</el-descriptions-item>
              <el-descriptions-item label="sha256" :span="2"><code class="hash-value">{{ artifact.sha256 }}</code></el-descriptions-item>
              <el-descriptions-item label="failure_code" :span="2">{{ artifact.failure_code }}</el-descriptions-item>
            </el-descriptions>
          </section>
        </el-tab-pane>

        <el-tab-pane label="Agent/MCP 调用" name="agent">
          <div class="tab-intro"><h2>Agent 与 MCP 工具证据</h2><p>展示 VerifyAgent 使用的 Skill、MCP Server、工具调用和静态证据链。</p></div>
          <el-empty v-if="!hasAgentEvidence" description="暂无 Agent/MCP 调用证据。启用 VerifyAgent 后重新扫描可生成。" />
          <div v-else class="agent-evidence-block">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="MCP Server">{{ evidence?.verification?.mcp_server || evidence?.static_evidence_chain?.mcp_server || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="Skill">{{ evidence?.verification?.skill?.name || evidence?.verification?.skill || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="静态裁决">{{ evidence?.verification?.static_verdict || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="动态裁决">{{ evidence?.verification?.dynamic_verdict || evidence?.runtime?.reproduction_status || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="最终裁决" :span="2">{{ evidence?.verification?.final_verdict || detail.verification.status || "N/A" }}</el-descriptions-item>
              <el-descriptions-item v-if="evidence?.verification?.false_positive_reason" label="误报原因" :span="2">{{ evidence.verification.false_positive_reason }}</el-descriptions-item>
            </el-descriptions>

            <div v-if="evidence?.tool_calls?.length" class="tool-call-list">
              <h3>MCP / 本地工具调用</h3>
              <article v-for="(tool, index) in evidence.tool_calls" :key="index" class="tool-call-card">
                <div class="tool-call-head">
                  <strong>{{ tool.tool_name || tool.name || tool.tool || `tool_${index + 1}` }}</strong>
                  <el-tag size="small" :type="toolStatusType(tool)">{{ tool.status || (tool.success === false ? "failed" : "success") }}</el-tag>
                </div>
                <pre class="mini-pre">{{ JSON.stringify(tool, null, 2) }}</pre>
              </article>
            </div>

            <div v-if="evidence?.call_path?.length" class="flow-block">
              <h3>Source → Sink 调用路径</h3>
              <ol>
                <li v-for="(step, index) in evidence.call_path" :key="index">
                  <b>{{ step.stage || `step_${index + 1}` }}</b>：{{ step.detail || JSON.stringify(step) }}
                </li>
              </ol>
            </div>

            <div v-if="hasStaticEvidenceChain" class="tool-call-list">
              <h3>静态证据链原始结构</h3>
              <pre class="mini-pre">{{ JSON.stringify(evidence.static_evidence_chain, null, 2) }}</pre>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="showEvidenceDialog" title="漏洞证据链 JSON" width="78%" class="evidence-dialog">
      <p class="dialog-note">该内容来自当前漏洞的 evidence 接口，可用于答辩展示或随报告归档。</p>
      <pre class="code-block evidence-json"><code>{{ evidenceJson }}</code></pre>
      <template #footer>
        <el-button @click="copyEvidence">复制 JSON</el-button>
        <el-button type="primary" @click="exportEvidence">导出 JSON</el-button>
      </template>
    </el-dialog>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { FindingApi } from "../api";
import {
  evidenceLevelMeta,
  harnessStatusMeta,
  httpExecutionLabel,
  runtimeStatusMeta,
  sandboxReason,
  sandboxStatusMeta,
} from "../utils/dynamicStatus";
import {
  canDisplayDetailedPoc,
  hasDisplayablePocCode,
  isTargetHarnessConfirmedEvidence,
} from "../utils/pocDisplay";

const route = useRoute();
const router = useRouter();
const activeTab = ref("static");
const detail = ref<any>(null);
const evidence = ref<any>(null);
const showEvidenceDialog = ref(false);
const verifying = ref(false);
const verifyForm = reactive({ base_url: "http://127.0.0.1:8080", endpoints: "/user", timeout: 10 });
const labeling = ref<"" | "true_positive" | "false_positive">("");

async function labelFinding(label: "true_positive" | "false_positive") {
  const id = route.params.id as string;
  if (!id) return;
  labeling.value = label;
  try {
    const { data } = await FindingApi.label(id, label);
    ElMessage.success(
      (label === "true_positive" ? "已标记为真漏洞" : "已标记为误报") +
      (data.learned ? "，已录入 RAG 自进化知识库" : "（未满足录入条件）"),
    );
    if (label === "false_positive" && detail.value) {
      detail.value.status = "false_positive";
      detail.value.verification.status = "false_positive";
      detail.value.verification.verified = false;
      await load();
    }
  } finally {
    labeling.value = "";
  }
}

const evidenceJson = computed(() => safeStringify({ finding: detail.value, evidence: evidence.value }));
const pocDisplayAllowed = computed(() => canDisplayDetailedPoc({
  finding: detail.value,
  evidence: evidence.value,
}));
function legacyAttackPlan() {
  const legacy = evidence.value?.exploit;
  if (!legacy || !hasDisplayablePocCode(legacy.exploit_code)) return null;
  const artifact = evidence.value?.artifacts?.validated_poc || evidence.value?.poc_file || {};
  return {
    plan_status: "framework_confirmed_replay", label: "旧版已确认 PoC",
    code: legacy.exploit_code, trigger_location: legacy.trigger_location,
    attack_vector: legacy.attack_vector, exploit_path: legacy.exploit_path,
    payloads: legacy.payloads || [], verification_method: legacy.verification_method,
    execution_scope: "localhost_only", code_language: "python",
    safety_notes: "仅限本地授权靶场环境。",
    persistence_status: artifact.persistence_status,
    artifact_sha256: artifact.sha256,
  };
}
const attackPlan = computed(() => {
  if (!pocDisplayAllowed.value) return null;
  const plan = evidence.value?.attack_plan || legacyAttackPlan();
  return hasDisplayablePocCode(plan?.code) ? plan : null;
});
const validationHypothesis = computed(() => {
  const plan = evidence.value?.attack_plan || legacyAttackPlan();
  return plan && !pocDisplayAllowed.value ? plan : null;
});
function safeArtifactName(value: any) {
  const name = String(value || "");
  return name.split(/[\\/]/).pop() || "-";
}
const artifactStates = computed(() => {
  const artifacts = evidence.value?.artifacts || {};
  return [
    { kind: "validated_poc", label: "Primary PoC（端到端 / 目标入口）", value: artifacts.validated_poc, legacy: evidence.value?.poc_file },
  ].filter(({ value, legacy }) => value || legacy).map(({ kind, label, value, legacy }) => {
    const item = value || {};
    const persistence = String(item.persistence_status || (legacy?.sha256 ? "persisted" : "not_attempted"));
    const validation = String(item.validation_status || (legacy?.sha256 ? "validated" : "unknown"));
    const revoked = item.usable === false || Boolean(item.revoked_by_finding_status)
      || legacy?.usable === false || Boolean(legacy?.revoked_by_finding_status);
    const failed = persistence === "persistence_failed";
    const pending = validation === "validation_pending";
    return {
      kind, label,
      generation_status: item.generation_status || (legacy ? "generated" : "-"),
      validation_status: validation || "-",
      persistence_status: persistence || "-",
      name: safeArtifactName(item.name || legacy?.name),
      sha256: item.sha256 || legacy?.sha256 || "-",
      failure_code: item.failure_code || "-",
      alertType: revoked ? "warning" : failed ? "error" : pending ? "warning" : persistence === "persisted" ? "success" : "info",
      notice: revoked ? "finding 当前状态已撤销该制品；保留哈希仅供审计，不可复制或执行"
        : failed ? "已确认但制品保存失败 / 证据不完整" : pending ? "验证尚待完成：当前制品未确认" : persistence === "persisted" ? "已确认复现制品已安全保存" : "当前未形成已保存的确认制品",
    };
  });
});
const displayDataFlow = computed(() => {
  const value = detail.value?.data_flow?.length ? detail.value.data_flow : evidence.value?.data_flow;
  if (!value || (Array.isArray(value) && value.length === 0)) return "暂无结构化数据流";
  return typeof value === "string" ? value : safeStringify(value);
});

// ---------- 证据链：把 source/sink/数据流对象渲染成中文可读文字，不给用户看 JSON ----------
function fmtLoc(obj: any): string {
  if (!obj || typeof obj !== "object") return "";
  const file = obj.file || obj.path || obj.filename || "";
  const line = obj.line ?? obj.start_line ?? obj.lineno;
  if (file && line != null) return `${file} 第 ${line} 行`;
  if (file) return String(file);
  return line != null ? `第 ${line} 行` : "";
}
function locToText(v: any): string {
  if (v == null || v === "") return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const parts: string[] = [];
    if (v.variable) parts.push(`变量 ${v.variable}`);
    if (v.function) parts.push(`危险调用 ${String(v.function).replace(/\($/, "")}()`);
    if (v.parameter) parts.push(`参数 ${v.parameter}`);
    // 没有结构化字段时，退回展示代码片段/描述，避免只剩一个文件位置
    if (!v.variable && !v.function && !v.parameter && (v.code || v.detail)) {
      parts.push(String(v.code || v.detail));
    }
    const loc = fmtLoc(v);
    if (loc) parts.push(`（${loc}）`);
    return parts.join(" ").trim();
  }
  return String(v);
}
const sourceText = computed(() => locToText(detail.value?.source ?? evidence.value?.source) || "未标注污染源（source）");
const sinkText = computed(() => locToText(detail.value?.sink ?? evidence.value?.sink) || "未标注危险汇聚点（sink）");
const STAGE_LABELS: Record<string, string> = {
  source: "污染源", propagation: "传播", propagate: "传播", assignment: "赋值传播",
  call: "函数调用", sink: "危险汇聚", taint: "污点引入", return: "返回传播",
};
const flowSteps = computed(() => {
  const raw = detail.value?.data_flow?.length
    ? detail.value.data_flow
    : (evidence.value?.data_flow?.length ? evidence.value.data_flow : evidence.value?.call_path);
  if (!Array.isArray(raw) || raw.length === 0) return [] as any[];
  return raw.map((step: any, i: number) => ({
    index: i + 1,
    stage: STAGE_LABELS[String(step.stage || "").toLowerCase()] || step.stage || `步骤 ${i + 1}`,
    location: fmtLoc(step),
    detail: typeof step.detail === "string" ? step.detail
      : (step.code || step.variable || locToText(step) || ""),
  }));
});
const chainNarrative = computed(() => {
  const src = detail.value?.source ?? evidence.value?.source;
  const snk = detail.value?.sink ?? evidence.value?.sink;
  if (!src && !snk && flowSteps.value.length === 0) return "";
  const n = flowSteps.value.length;
  const hop = n > 0 ? `经 ${n} 步数据流传播` : "经数据流";
  return `用户可控输入（${sourceText.value}）${hop}，最终流入危险操作（${sinkText.value}）。`;
});

const hasStaticEvidenceChain = computed(() => {
  const chain = evidence.value?.static_evidence_chain;
  return !!chain && Object.keys(chain).length > 0;
});
const hasVerificationEvidence = computed(() => {
  const verification = evidence.value?.verification;
  return !!verification && Object.values(verification).some((value) => value !== null && value !== undefined && value !== "");
});
const hasKnowledgeEvidence = computed(() => {
  const knowledge = evidence.value?.knowledge;
  return !!knowledge && Object.values(knowledge).some((value) => {
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === "object") return Object.keys(value).length > 0;
    return value !== null && value !== undefined && value !== "";
  });
});
const hasAgentEvidence = computed(() => {
  return Boolean(
    hasVerificationEvidence.value
    || evidence.value?.tool_calls?.length
    || evidence.value?.call_path?.length
    || hasStaticEvidenceChain.value,
  );
});

const VERDICT_LABELS: Record<string, string> = {
  confirmed: "已确认",
  dynamic_confirmed: "动态复现",
  harness_confirmed: "Harness 复现",
  confirmed_dynamic: "动态复现",   // 兼容历史数据的旧拼写
  statically_verified: "静态确认",
  needs_review: "需人工复核",
  informational: "低置信度线索",
  not_reproduced: "未复现",
  false_positive: "误报排除",
  out_of_scope: "范围外排除",
  inconclusive: "无法判定",
  not_executed: "未执行",
  not_runtime_verifiable: "不适合动态验证",
  connection_failed: "连接失败",
  request_timeout: "请求超时",
  endpoint_not_found: "入口不存在",
  payload_not_matched: "载荷未命中",
  function_reproduced: "仅函数单元复现",
  mechanism_confirmed: "仅漏洞机理复现",
  launch_not_detected: "未识别启动方式",
  not_web_target: "非 Web 项目（HTTP 不适用）",
  unsafe_project_config: "项目容器配置被安全策略阻止",
  sandbox_start_failed: "沙箱启动失败",
  health_check_failed: "沙箱健康检查失败",
  dependency_install_failed: "依赖安装失败",
  sandbox_build_timeout: "沙箱构建超时",
  sandbox_cancelled: "沙箱执行已取消",
  cancelling: "正在取消",
  execution_error: "执行异常",
  blocked_by_environment: "受运行环境阻断",
};
function verdictLabel(v: string) {
  return VERDICT_LABELS[String(v || "").toLowerCase()] || v || "N/A";
}

function runtimeStatusLabel(runtime: any, finding?: any) {
  return runtimeStatusMeta(runtime, finding, evidence.value?.verification).label;
}

function runtimeTagType(runtime: any, finding?: any) {
  return runtimeStatusMeta(runtime, finding, evidence.value?.verification).tone;
}

function toolStatusType(tool: any) {
  const status = String(tool?.status || "").toLowerCase();
  if (tool?.success === false || status.includes("fail") || status.includes("error")) return "danger";
  if (status.includes("skip")) return "info";
  return "success";
}

function severityType(severity: string) {
  const s = String(severity || "").toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

function findingStatusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value.includes("false")) return "info";
  if (value === "unverified") return "info";        // 检出未验证：中性
  if (value.includes("review")) return "warning";
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
    candidate: "候选",
    statically_verified: "静态确认",
  };
  return map[String(status || "").toLowerCase()] || status || "unknown";
}

function formatConfidence(value: any) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return num <= 1 ? `${Math.round(num * 100)}%` : String(num);
}

function safeStringify(value: any) {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

async function copyEvidence() {
  await navigator.clipboard?.writeText(evidenceJson.value);
  ElMessage.success("证据链 JSON 已复制");
}

function attackPlanLabel(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return "候选测试草案";
  if (status === "static_confirmed_pending_runtime") return "静态确认待运行";
  if (status === "framework_confirmed_replay") return "已确认 HTTP PoC";
  if (status === "executed_not_reproduced_replay") return "已执行请求复放（未复现）";
  if (status === "target_harness_reproduction") return "目标 Harness 复现";
  if (plan?.plan_status === "manual_plan_required") return "需人工补充";
  return "利用与复现材料";
}
function attackPlanTagType(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (["framework_confirmed_replay", "executed_not_reproduced_replay", "target_harness_reproduction"].includes(status)) return "success";
  if (["candidate_plan_pending_review", "manual_plan_required"].includes(status)) return "warning";
  return "info";
}
function normalizedPlanStatus(plan: any) {
  const status = String(plan?.plan_status || "").toLowerCase();
  if (status === "validated_replay") return "framework_confirmed_replay";
  if (status === "validated_reproduction") return "target_harness_reproduction";
  return status;
}
const canShowHarnessCode = computed(() => {
  return pocDisplayAllowed.value
    && isTargetHarnessConfirmedEvidence(evidence.value)
    && Boolean(evidence.value?.harness?.harness_code);
});
function attackPlanDescription(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return "候选测试草案，尚待人工复核；不得计为已确认 PoC。";
  if (status === "static_confirmed_pending_runtime") return "静态证据已确认，代码仍待运行验证。";
  if (status === "framework_confirmed_replay") return "代码来自框架实际命中的本地 HTTP 请求。";
  if (status === "executed_not_reproduced_replay") return "代码来自已执行的本地 HTTP 请求；未命中成功判据，不声明漏洞命中。";
  if (status === "target_harness_reproduction") return "代码来自目标入口 Harness 的已确认复现。";
  return "当前材料不自动视为已确认 PoC。";
}
function attackPlanCodeCaption(plan: any) {
  const language = String(plan?.code_language || "python");
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return `${language} · 候选测试草案`;
  if (status === "static_confirmed_pending_runtime") return `${language} · 待运行测试计划`;
  if (status === "framework_confirmed_replay") return `${language} · 已确认 HTTP PoC`;
  if (status === "executed_not_reproduced_replay") return `${language} · 已执行请求复放（未复现）`;
  if (status === "target_harness_reproduction") return `${language} · 目标 Harness 复现代码`;
  return `${language} · 利用与复现代码`;
}
async function copyAttackPlan() {
  const code = attackPlan.value?.code;
  if (!pocDisplayAllowed.value || !hasDisplayablePocCode(code)) return;
  await navigator.clipboard?.writeText(code);
  ElMessage.success("利用与复现代码已复制");
}

function exportEvidence() {
  if (!evidence.value) return;
  const id = route.params.id as string;
  const blob = new Blob([evidenceJson.value], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${id || "finding"}_evidence_chain.json`;
  link.click();
  URL.revokeObjectURL(url);
  ElMessage.success("证据链 JSON 已导出");
}

async function load() {
  const id = route.params.id as string;
  detail.value = (await FindingApi.detail(id)).data;
  evidence.value = (await FindingApi.evidence(id)).data.evidence;
}

async function runVerify() {
  const id = route.params.id as string;
  verifying.value = true;
  try {
    const endpoints = verifyForm.endpoints.split(",").map((item) => item.trim()).filter(Boolean);
    const { data } = await FindingApi.verify(id, { mode: "url", base_url: verifyForm.base_url, endpoints, timeout: verifyForm.timeout });
    ElMessage.success(data.reproducible ? "动态验证成功，漏洞可复现" : data.message);
    activeTab.value = data.reproducible ? "dynamic" : activeTab.value;
    await load();
  } finally {
    verifying.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.detail-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.title-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 10px; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.panel-card { border-radius: 18px; overflow: hidden; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; }
.tab-intro p { color: #667085; margin: 6px 0 0; }
.code-block { background: #0b1220; color: #d7e3f1; padding: 16px; border-radius: 14px; overflow: auto; border: 1px solid rgba(255,255,255,.08); max-height: 520px; }
.mini-pre { margin: 0; padding: 12px; background: #f5f8fc; border: 1px solid #e4ebf3; border-radius: 10px; overflow: auto; max-height: 360px; }
.evidence-desc { margin-top: 16px; }
.harness-block { margin-top: 20px; }
.harness-block h3 { margin: 0 0 4px; color: #162235; }
.harness-note { color: #667085; margin: 0 0 12px; font-size: 13px; }
.chain-card { margin: 18px 0; padding: 18px 20px; border: 1px solid #dbe6f2; border-radius: 16px;
  background: linear-gradient(180deg, #f8fbff, #f2f7fd); }
.chain-title { margin: 0 0 10px; font-size: 16px; color: #162235; font-weight: 700; }
.chain-narrative { margin: 0 0 14px; color: #334155; line-height: 1.75; font-size: 14px;
  padding: 10px 14px; background: #eef4fb; border-left: 3px solid #3b82f6; border-radius: 8px; }
.chain-endpoints { display: flex; flex-direction: column; align-items: flex-start; gap: 6px; margin-bottom: 12px; }
.chain-endpoint { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.chain-badge { font-size: 12px; font-weight: 600; color: #fff; background: #3b82f6;
  padding: 3px 10px; border-radius: 999px; white-space: nowrap; }
.chain-badge.danger { background: #ef4444; }
.chain-text { color: #1e293b; font-size: 14px; font-family: "SFMono-Regular", Consolas, monospace; }
.chain-arrow { color: #64748b; font-size: 13px; margin-left: 6px; }
.chain-timeline { margin-top: 6px; padding-top: 6px; }
.step-stage { font-weight: 600; color: #1d4ed8; }
.step-detail { color: #475467; }
.chain-empty { color: #94a3b8; font-size: 13px; margin: 4px 0 0; }
.fix-desc { margin-top: 4px; }
@media (prefers-color-scheme: dark) {
  .chain-card { background: linear-gradient(180deg, #182234, #141d2c); border-color: #2b3a4f; }
  .chain-title { color: #e8eef6; }
  .chain-narrative { background: #1b2942; color: #cdd8e8; border-left-color: #3b82f6; }
  .chain-text { color: #dbe4f0; }
  .step-detail { color: #9fb0c6; }
}
.flow-block { margin-top: 16px; padding: 16px; border: 1px solid #dce6f0; border-radius: 14px; background: linear-gradient(180deg, #fff, #fbfdff); }
.flow-block h3 { margin: 0 0 8px; color: #162235; }
.flow-block ol { margin: 0; padding-left: 20px; color: #475467; line-height: 1.8; }
.agent-evidence-block { display: grid; gap: 16px; }
.knowledge-block { display: grid; gap: 16px; }
.warning-flow { border-color: #f59e0b; background: #fffbeb; }
.fix-flow { border-color: #10b981; background: #f0fdf4; }
.tool-call-list { display: grid; gap: 12px; }
.tool-call-list h3 { margin: 0; color: #162235; }
.tool-call-card { border: 1px solid #dce6f0; border-radius: 14px; padding: 14px; background: linear-gradient(180deg, #fff, #fbfdff); box-shadow: 0 8px 22px rgba(16,32,51,.04); }
.tool-call-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; }
.verify-panel { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; gap: 12px; margin-bottom: 14px; }
.exploit-block { display: grid; gap: 16px; }
.attack-plan-banner { display: flex; align-items: center; gap: 10px; padding: 11px 13px; color: #40536a; background: #eef5fb; border-left: 3px solid #2f80ed; border-radius: 8px; font-size: 13px; line-height: 1.55; }
.attack-payloads { display: flex; align-items: baseline; flex-wrap: wrap; gap: 7px; color: #526477; font-size: 13px; }
.attack-payloads code { max-width: 100%; padding: 2px 6px; color: #95421e; background: #fff3ed; border: 1px solid #fed7c3; border-radius: 5px; overflow-wrap: anywhere; }
.attack-code-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; color: #667085; font: 12px "SFMono-Regular", Consolas, monospace; }
.attack-safety { margin: -6px 0 0; color: #718096; font-size: 12px; line-height: 1.5; }
.review-panel { display: grid; gap: 14px; margin-top: 20px; padding: 16px; border: 1px solid #f3d19e; border-radius: 14px; background: #fffbf2; }
.review-panel h3 { margin: 0; color: #7a4a00; }
.artifact-panel { display: grid; gap: 12px; margin-top: 20px; }
.artifact-panel h3 { margin: 0; color: #162235; }
.hash-value { overflow-wrap: anywhere; }
.dialog-note { margin: 0 0 12px; color: #667085; }
.evidence-json { min-height: 360px; }
@media (max-width: 760px) { .verify-panel { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } .title-actions { width: 100%; justify-content: flex-start; } }
</style>
