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
                <li v-for="(item, index) in knowledgeVerificationChecks" :key="`check-${index}`">
                  <span class="knowledge-original">{{ item.original }}</span>
                  <span v-if="item.zh" class="knowledge-translation">{{ item.machine ? "机器翻译：" : "中文说明：" }}{{ item.zh }}</span>
                </li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.false_positive_signals?.length" class="flow-block warning-flow">
              <h3>误报信号</h3>
              <ol>
                <li v-for="(item, index) in knowledgeFalsePositiveSignals" :key="`fp-${index}`">
                  <span class="knowledge-original">{{ item.original }}</span>
                  <span v-if="item.zh" class="knowledge-translation">{{ item.machine ? "机器翻译：" : "中文说明：" }}{{ item.zh }}</span>
                </li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.remediation?.length" class="flow-block fix-flow">
              <h3>修复建议</h3>
              <ol>
                <li v-for="(item, index) in knowledgeRemediation" :key="`fix-${index}`">
                  <span class="knowledge-original">{{ item.original }}</span>
                  <span v-if="item.zh" class="knowledge-translation">{{ item.machine ? "机器翻译：" : "中文说明：" }}{{ item.zh }}</span>
                </li>
              </ol>
            </div>

            <div v-if="evidence?.knowledge?.references?.length" class="flow-block reference-flow">
              <h3>知识来源</h3>
              <ol>
                <li v-for="(ref, index) in evidence.knowledge.references" :key="`ref-${index}`">
                  <a
                    v-if="isHttpReference(ref)"
                    class="knowledge-reference-link"
                    :href="String(ref)"
                    target="_blank"
                    rel="noopener noreferrer"
                  >{{ ref }}</a>
                  <span v-else>{{ ref }}</span>
                </li>
              </ol>
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
          <el-alert
            type="warning"
            show-icon
            :closable="false"
            title="动态验证仅限本地授权靶场，不要对真实第三方系统使用。"
            class="dynamic-warning-alert"
          />

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
            <el-descriptions-item label="启动命令" :span="2"><span class="desc-text">{{ evidence.sandbox.launch_command || "N/A" }}</span></el-descriptions-item>
            <el-descriptions-item label="诊断" :span="2">{{ sandboxReason(evidence.sandbox, evidence.runtime) }}</el-descriptions-item>
            <el-descriptions-item label="容器日志摘要" :span="2"><pre class="mini-pre">{{ evidence.sandbox.logs_excerpt || "N/A" }}</pre></el-descriptions-item>
          </el-descriptions>

          <el-descriptions v-if="evidence?.runtime" :column="2" border class="evidence-desc">
            <el-descriptions-item label="HTTP 验证结论">
              <el-tag :type="runtimeTagType(evidence.runtime, detail)">{{ runtimeStatusLabel(evidence.runtime, detail) }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="HTTP 是否实际执行">{{ httpExecutionLabel(evidence.runtime) }}</el-descriptions-item>
            <el-descriptions-item label="最终证据等级">
              <el-tag :type="evidenceLevelMeta(evidence?.verification, detail).tone">{{ evidenceLevelMeta(evidence?.verification, detail).label }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="请求记录">
              攻击 {{ evidence.runtime.records?.length || 0 }} / 前置 {{ evidence.runtime.setup_records?.length || 0 }} / 确认 {{ evidence.runtime.confirmation_records?.length || 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="命中特征">{{ evidence.runtime.matched_indicator || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="请求 URL">{{ evidence.runtime.request?.url || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="状态码">{{ evidence.runtime.response_status || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="原因" :span="2">{{ evidence.runtime.reason || "N/A" }}</el-descriptions-item>
            <el-descriptions-item v-if="evidence.runtime.candidate_endpoints?.length" label="候选入口" :span="2">{{ evidence.runtime.candidate_endpoints.join(", ") }}</el-descriptions-item>
            <el-descriptions-item label="Payload" :span="2"><span class="desc-text">{{ evidence.runtime.request?.payload || "N/A" }}</span></el-descriptions-item>
            <el-descriptions-item label="响应摘要" :span="2"><div class="desc-text desc-text-block">{{ evidence.runtime.response_excerpt || "N/A" }}</div></el-descriptions-item>
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
          <div class="tab-intro"><h2>利用与复现代码</h2><p>仅展示已持久化且已确认的 HTTP/目标入口 PoC 代码。</p></div>
          <el-empty v-if="!attackPlan" description="暂无已持久化的端到端复现代码。未确认内容不会生成可执行利用代码。" />
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
import { ElMessage, ElMessageBox } from "element-plus";
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
  const isTruePositive = label === "true_positive";
  try {
    await ElMessageBox.confirm(
      isTruePositive
        ? "确认将该 finding 标记为真漏洞吗？该操作会更新本地 finding 状态，并可能写入 RAG 自进化反馈知识库。"
        : "确认将该 finding 标记为误报吗？该操作会更新本地 finding 状态、取消已验证标记，并可能写入 RAG 自进化反馈知识库。",
      isTruePositive ? "确认标记为真漏洞" : "确认标记为误报",
      {
        confirmButtonText: "确认",
        cancelButtonText: "取消",
        type: isTruePositive ? "success" : "warning",
      },
    );
  } catch {
    return;
  }
  labeling.value = label;
  try {
    const { data } = await FindingApi.label(id, label);
    ElMessage.success(
      (isTruePositive ? "已标记为真漏洞" : "已标记为误报") +
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
type KnowledgeDisplayItem = {
  original: string;
  zh?: string;
  machine?: boolean;
};

const KNOWLEDGE_ZH_NOTES: Record<string, string> = {
  "Confirm user-controlled input reaches SQL construction or execution.": "检查用户可控数据是否真的进入 SQL 拼接或执行位置。",
  "Confirm the query is built with string concatenation, interpolation, or formatting.": "判断 SQL 是否由拼接、模板插值或格式化字符串生成。",
  "Confirm no prepared statement, parameter binding, or strong type conversion separates data from SQL.": "确认没有用参数绑定、预编译语句或严格类型转换隔离用户数据。",
  "The sink uses parameter placeholders with a separate parameter tuple/list.": "如果代码已经用占位符和独立参数传值，通常不是 SQL 注入。",
  "The value is converted to a strict numeric type before reaching SQL.": "如果进入 SQL 前已经强制转成数字，风险通常会降低。",
  "The SQL statement is a static literal and user input is not interpolated.": "如果 SQL 是固定字面量且没有插入用户输入，通常不是注入点。",
  "Use prepared statements or parameterized queries.": "改用参数化查询或预编译语句。",
  "Do not concatenate user-controlled strings into SQL.": "不要把用户输入直接拼进 SQL 字符串。",
  "Run database users with least privilege and avoid detailed SQL errors in responses.": "数据库账号按最小权限配置，响应里不要暴露详细 SQL 错误。",
  "Confirm attacker-controlled input reaches a command execution sink.": "检查攻击者可控输入是否进入命令执行函数。",
  "Confirm a shell string is built from user input or shell=True is used.": "重点看是否用用户输入拼 shell 命令，或启用了 shell=True。",
  "Confirm input validation or argument separation does not remove command metacharacter impact.": "确认现有校验没有消除命令元字符带来的影响。",
  "Replace shell commands with library calls.": "优先用语言库 API 替代 shell 命令。",
  "Use argument arrays and shell=False.": "调用外部程序时使用参数数组，并关闭 shell 解释。",
  "Confirm the user-controlled value is concatenated or joined into a filesystem path.": "检查用户输入是否被拼进文件路径。",
  "Confirm traversal markers or absolute paths can influence the final path.": "确认 ../ 或绝对路径是否能改变最终访问位置。",
  "Confirm canonical path checks do not enforce an allowed base directory.": "确认规范化后的路径没有被限制在允许目录内。",
  "Canonicalize the path and confirm it stays under an allowlisted base directory.": "规范化路径后，必须校验它仍在允许目录下。",
  "Reject traversal sequences and use safe file APIs.": "拒绝目录穿越片段，并使用安全文件访问接口。",
  "Confirm untrusted input is written into an HTML, attribute, JS, or URL context.": "检查不可信输入是否输出到 HTML、属性、JS 或 URL 位置。",
  "Confirm output encoding matches the browser context.": "确认编码方式与实际浏览器上下文匹配。",
  "Confirm framework auto-escaping has not been disabled.": "确认模板或框架的自动转义没有被关闭。",
  "Apply context-aware output encoding.": "按 HTML、属性、JS、URL 等不同上下文分别编码。",
  "Keep template auto-escaping on and avoid safe/raw markers on untrusted data.": "保持模板自动转义开启，不要给不可信数据标记 safe/raw。",
  "Confirm user input controls URL, host, or scheme of a server-side request.": "检查用户输入是否能控制服务端请求的 URL、主机或协议。",
  "Check for an allowlist of schemes/hosts and blocking of internal ranges and cloud metadata endpoints.": "检查是否限制协议和主机，并阻止内网地址、云元数据地址。",
  "Confirm redirects and DNS rebinding are considered if network access is allowed.": "如果允许发起网络请求，还要考虑重定向和 DNS rebinding。",
  "Enforce a scheme/host allowlist and block internal ranges and metadata IPs.": "只允许可信协议和主机，同时阻止内网网段与元数据 IP。",
  "Resolve and validate the target host before requesting.": "请求前先解析并校验目标主机。",
  "Confirm untrusted input is passed to a deserialization sink.": "检查不可信数据是否进入反序列化函数。",
  "Confirm no integrity check (HMAC/signature) protects the serialized blob.": "确认序列化数据没有签名或 HMAC 保护。",
  "Prefer safe formats (JSON) and safe loaders (yaml.safe_load).": "优先使用 JSON 等安全格式，YAML 使用 safe_load。",
  "If unavoidable, sign+verify payloads and restrict allowed classes.": "无法避免时，对数据签名校验，并限制可反序列化的类型。",
  "Confirm user input reaches eval/exec-style execution.": "检查用户输入是否真的进入 eval、exec 或类似代码执行位置。",
  "Confirm attacker-controlled input reaches an eval/exec/code compilation sink.": "检查攻击者可控输入是否进入 eval、exec 或代码编译类函数。",
  "Confirm no safe evaluator (ast.literal_eval) or allowlist is used.": "确认没有使用 ast.literal_eval 这类安全解析器，也没有白名单限制。",
  "Confirm the evaluated expression is not restricted to a fixed allowlist or parsed by a safe data parser.": "确认被求值的表达式没有被固定白名单限制，也没有交给安全数据解析器处理。",
  "Prefer a function-level harness that feeds a harmless marker expression and observes whether evaluation occurs.": "更适合用函数级 harness 投入无害标记表达式，观察是否真的发生求值。",
  "ast.literal_eval is used instead of eval.": "如果已经用 ast.literal_eval 替代 eval，通常不是代码注入。",
  "ast.literal_eval or another data-only parser is used instead of eval/exec.": "如果已经用只解析数据的解析器替代 eval/exec，通常不是代码注入。",
  "The evaluated expression is a fixed literal.": "如果被求值内容是固定字面量，通常没有用户可控执行。",
  "The expression is a fixed literal or selected from a strict allowlist.": "如果表达式固定，或只能从严格白名单中选择，风险通常较低。",
  "The evaluator runs in a sandbox that blocks side effects and imports.": "如果求值器运行在阻止副作用和 import 的沙箱中，误报可能性更高。",
  "Avoid eval/exec on user input.": "避免对用户输入使用 eval 或 exec。",
  "Remove eval/exec on untrusted input.": "不要对不可信输入使用 eval 或 exec。",
  "Remove eval/exec/new Function on untrusted input.": "不要对不可信输入使用 eval、exec 或 new Function。",
  "Use ast.literal_eval or a safe parser.": "只需要解析数据时，改用 ast.literal_eval 或安全解析器。",
  "Use safe parsers or explicit allowlists for supported expressions.": "需要支持表达式时，使用专用安全解析器或明确白名单。",
  "Use safe data parsers or a purpose-built expression parser.": "使用安全数据解析器，或专门为业务设计的表达式解析器。",
  "Validate against a strict allowlist.": "把允许的值、字段或操作限制在严格白名单内。",
  "If dynamic behavior is required, restrict operations through an explicit allowlist and sandbox.": "如果业务必须支持动态行为，就用明确白名单限制可执行操作，并放进沙箱中运行。",
  "Confirm the redirect target or header value is user-controlled.": "检查重定向目标或响应头是否受用户输入控制。",
  "Confirm no allowlist restricts destinations to trusted hosts.": "确认没有把跳转目标限制到可信主机。",
  "Allowlist redirect destinations or require relative paths.": "只允许白名单目标，或只接受相对路径。",
  "Reject CR/LF and normalize hosts before validation.": "拒绝换行字符，并在校验前规范化主机名。",
};

const KNOWLEDGE_MACHINE_TERMS: Array<[RegExp, string]> = [
  [/\buser-controlled input\b/gi, "用户可控输入"],
  [/\battacker-controlled input\b/gi, "攻击者可控输入"],
  [/\buntrusted input\b/gi, "不可信输入"],
  [/\buser input\b/gi, "用户输入"],
  [/\bsource variable\b/gi, "source 变量"],
  [/\bsource\b/gi, "source"],
  [/\bsink\b/gi, "sink"],
  [/\bSQL construction\b/gi, "SQL 构造"],
  [/\bSQL execution\b/gi, "SQL 执行"],
  [/\bSQL sink\b/gi, "SQL sink"],
  [/\bSQL error\b/gi, "SQL 错误"],
  [/\bSQL string concatenation\b/gi, "SQL 字符串拼接"],
  [/\bquery template\b/gi, "查询模板"],
  [/\bexecutable sink\b/gi, "可执行 sink"],
  [/\bprepared statements?\b/gi, "预编译语句"],
  [/\bseparate parameter binding\b/gi, "独立参数绑定"],
  [/\bparameter binding\b/gi, "参数绑定"],
  [/\bparameterized queries\b/gi, "参数化查询"],
  [/\bparameterized query\b/gi, "参数化查询"],
  [/\bstring concatenation\b/gi, "字符串拼接"],
  [/\binterpolation\b/gi, "插值"],
  [/\bformatting\b/gi, "格式化"],
  [/\bcommand execution sink\b/gi, "命令执行 sink"],
  [/\bcommand execution\b/gi, "命令执行"],
  [/\bshell commands?\b/gi, "shell 命令"],
  [/\bshell string\b/gi, "shell 字符串"],
  [/\bshell=True\b/g, "shell=True"],
  [/\bshell=False\b/g, "shell=False"],
  [/\bcommand metacharacter impact\b/gi, "命令元字符影响"],
  [/\bargument arrays\b/gi, "参数数组"],
  [/\bargument separation\b/gi, "参数分离"],
  [/\binput validation\b/gi, "输入校验"],
  [/\blibrary calls\b/gi, "库 API 调用"],
  [/\bfilesystem path\b/gi, "文件系统路径"],
  [/\babsolute paths?\b/gi, "绝对路径"],
  [/\bfinal path\b/gi, "最终路径"],
  [/\bcanonical path checks?\b/gi, "规范化路径检查"],
  [/\ballowlisted base directory\b/gi, "白名单基础目录"],
  [/\bbase directory\b/gi, "基础目录"],
  [/\btraversal sequences?\b/gi, "目录穿越序列"],
  [/\btraversal markers?\b/gi, "目录穿越标记"],
  [/\bsafe file APIs\b/gi, "安全文件 API"],
  [/\bHTML, attribute, JS, or URL context\b/gi, "HTML、属性、JS 或 URL 上下文"],
  [/\bbrowser context\b/gi, "浏览器上下文"],
  [/\boutput encoding\b/gi, "输出编码"],
  [/\bauto-escaping\b/gi, "自动转义"],
  [/\bsafe\/raw markers?\b/gi, "safe/raw 标记"],
  [/\bserver-side request\b/gi, "服务端请求"],
  [/\bschemes?\/hosts?\b/gi, "协议/主机"],
  [/\bscheme\/host allowlist\b/gi, "协议/主机白名单"],
  [/\ballowlist\b/gi, "白名单"],
  [/\binternal ranges?\b/gi, "内网地址段"],
  [/\bcloud metadata endpoints?\b/gi, "云元数据端点"],
  [/\bmetadata IPs?\b/gi, "元数据 IP"],
  [/\bDNS rebinding\b/gi, "DNS rebinding"],
  [/\bredirects?\b/gi, "重定向"],
  [/\btarget host\b/gi, "目标主机"],
  [/\bdeserialization sink\b/gi, "反序列化 sink"],
  [/\bserialized blob\b/gi, "序列化数据"],
  [/\bintegrity check\b/gi, "完整性校验"],
  [/\bHMAC\/signature\b/gi, "HMAC/签名"],
  [/\bsafe loaders?\b/gi, "安全加载器"],
  [/\bsafe formats?\b/gi, "安全格式"],
  [/\ballowed classes\b/gi, "允许的类"],
  [/\bpayloads?\b/gi, "payload"],
  [/\bcode execution sinks?\b/gi, "代码执行 sink"],
  [/\bcode compilation sink\b/gi, "代码编译 sink"],
  [/\beval\/exec-style execution\b/gi, "eval/exec 类执行"],
  [/\bsafe evaluator\b/gi, "安全求值器"],
  [/\bevaluated expression\b/gi, "被求值表达式"],
  [/\bfixed literal\b/gi, "固定字面量"],
  [/\bstrict allowlist\b/gi, "严格白名单"],
  [/\bsafe data parser\b/gi, "安全数据解析器"],
  [/\bdata-only parser\b/gi, "只解析数据的解析器"],
  [/\bfunction-level harness\b/gi, "函数级 harness"],
  [/\bharmless marker expression\b/gi, "无害标记表达式"],
  [/\bevaluation occurs\b/gi, "发生求值"],
  [/\bside effects\b/gi, "副作用"],
  [/\bimports\b/gi, "import"],
  [/\btrusted hosts\b/gi, "可信主机"],
  [/\brelative paths\b/gi, "相对路径"],
  [/\bCR\/LF\b/g, "CR/LF"],
  [/\bhosts?\b/gi, "主机"],
  [/\bURL\b/g, "URL"],
  [/\bJSON\b/g, "JSON"],
];

const KNOWLEDGE_MACHINE_PATTERNS: Array<[RegExp, (...values: string[]) => string]> = [
  [/^Confirm (.+)$/i, (value) => `确认${translateKnowledgeClause(value)}`],
  [/^Check whether (.+)$/i, (value) => `检查是否${translateKnowledgeClause(value)}`],
  [/^Check for (.+)$/i, (value) => `检查是否存在${translateKnowledgeClause(value)}`],
  [/^Trace whether (.+)$/i, (value) => `跟踪确认是否${translateKnowledgeClause(value)}`],
  [/^Use (.+)$/i, (value) => `使用${translateKnowledgeClause(value)}`],
  [/^Avoid (.+)$/i, (value) => `避免${translateKnowledgeClause(value)}`],
  [/^Do not (.+)$/i, (value) => `不要${translateKnowledgeClause(value)}`],
  [/^Never (.+)$/i, (value) => `绝不要${translateKnowledgeClause(value)}`],
  [/^Remove (.+)$/i, (value) => `移除${translateKnowledgeClause(value)}`],
  [/^Replace (.+) with (.+)$/i, (from, to) => `用${translateKnowledgeClause(to)}替代${translateKnowledgeClause(from)}`],
  [/^Prefer (.+)$/i, (value) => `优先使用${translateKnowledgeClause(value)}`],
  [/^Reject (.+)$/i, (value) => `拒绝${translateKnowledgeClause(value)}`],
  [/^Apply (.+)$/i, (value) => `应用${translateKnowledgeClause(value)}`],
  [/^Keep (.+) on and avoid (.+)$/i, (first, second) => `保持${translateKnowledgeClause(first)}开启，并避免${translateKnowledgeClause(second)}`],
  [/^Enforce (.+)$/i, (value) => `强制实施${translateKnowledgeClause(value)}`],
  [/^Resolve and validate (.+) before requesting$/i, (value) => `发起请求前解析并校验${translateKnowledgeClause(value)}`],
  [/^If (.+), (.+)$/i, (condition, action) => `如果${translateKnowledgeClause(condition)}，则${translateKnowledgeClause(action)}`],
  [/^(.+) is used instead of (.+)$/i, (first, second) => `使用${translateKnowledgeClause(first)}替代${translateKnowledgeClause(second)}`],
  [/^(.+) are used on (.+)$/i, (first, second) => `在${translateKnowledgeClause(second)}上使用${translateKnowledgeClause(first)}`],
  [/^(.+) is present$/i, (value) => `已经存在${translateKnowledgeClause(value)}`],
  [/^(.+) is a (.+)$/i, (first, second) => `${translateKnowledgeClause(first)}是${translateKnowledgeClause(second)}`],
  [/^(.+) is (.+)$/i, (first, second) => `${translateKnowledgeClause(first)}是${translateKnowledgeClause(second)}`],
  [/^(.+) are (.+)$/i, (first, second) => `${translateKnowledgeClause(first)}是${translateKnowledgeClause(second)}`],
];

function translateKnowledgeClause(value: string) {
  let translated = value.trim();
  KNOWLEDGE_MACHINE_TERMS.forEach(([pattern, replacement]) => {
    translated = translated.replace(pattern, replacement);
  });
  translated = translated
    .replace(/\brather than\b/gi, "而不是")
    .replace(/\bwithout\b/gi, "且没有")
    .replace(/\bthrough\b/gi, "通过")
    .replace(/\bagainst\b/gi, "依据")
    .replace(/\bbefore\b/gi, "在...之前")
    .replace(/\bafter\b/gi, "在...之后")
    .replace(/\bfrom\b/gi, "来自")
    .replace(/\binto\b/gi, "进入")
    .replace(/\bto\b/gi, "到")
    .replace(/\bof\b/gi, "的")
    .replace(/\bwith\b/gi, "使用")
    .replace(/\bon\b/gi, "在")
    .replace(/\bin\b/gi, "在")
    .replace(/\bor\b/gi, "或")
    .replace(/\band\b/gi, "并且")
    .replace(/\bno longer\b/gi, "不再")
    .replace(/\bdoes not\b/gi, "不会")
    .replace(/\bdo not\b/gi, "不要")
    .replace(/\bnot\b/gi, "不")
    .replace(/\bno\b/gi, "没有")
    .replace(/\ba\b/gi, "")
    .replace(/\ban\b/gi, "")
    .replace(/\bthe\b/gi, "")
    .replace(/\s+/g, " ")
    .replace(/\s+([,.;])/g, "$1")
    .trim();
  return translated;
}

function machineTranslateKnowledgeText(original: string) {
  if (!original || /[\u4e00-\u9fff]/.test(original)) return "";
  const normalized = original.replace(/\s+/g, " ").trim().replace(/[.。]\s*$/, "");
  for (const [pattern, render] of KNOWLEDGE_MACHINE_PATTERNS) {
    const match = normalized.match(pattern);
    if (match) {
      const translated = render(...match.slice(1));
      return translated ? `${translated}。` : "";
    }
  }
  const translated = translateKnowledgeClause(normalized);
  return translated && translated !== normalized ? `${translated}。` : "";
}

function knowledgeDisplayList(values: unknown): KnowledgeDisplayItem[] {
  if (!Array.isArray(values)) return [];
  return values
    .map((value) => String(value ?? "").trim())
    .filter(Boolean)
    .map((original) => {
      const exact = KNOWLEDGE_ZH_NOTES[original];
      return exact
        ? { original, zh: exact }
        : { original, zh: machineTranslateKnowledgeText(original), machine: true };
    });
}

const knowledgeVerificationChecks = computed(() =>
  knowledgeDisplayList(evidence.value?.knowledge?.verification_checks));
const knowledgeFalsePositiveSignals = computed(() =>
  knowledgeDisplayList(evidence.value?.knowledge?.false_positive_signals));
const knowledgeRemediation = computed(() =>
  knowledgeDisplayList(evidence.value?.knowledge?.remediation));
function isHttpReference(value: unknown) {
  return /^https?:\/\//i.test(String(value ?? "").trim());
}
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
  return runtimeStatusMeta(runtime, finding).label;
}

function runtimeTagType(runtime: any, finding?: any) {
  return runtimeStatusMeta(runtime, finding).tone;
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
  if (status === "target_harness_reproduction") return "目标 Harness 复现";
  if (plan?.plan_status === "manual_plan_required") return "需人工补充";
  return "利用与复现材料";
}
function attackPlanTagType(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (["framework_confirmed_replay", "target_harness_reproduction"].includes(status)) return "success";
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
  if (status === "target_harness_reproduction") return "代码来自目标入口 Harness 的已确认复现。";
  return "当前材料不自动视为已确认 PoC。";
}
function attackPlanCodeCaption(plan: any) {
  const language = String(plan?.code_language || "python");
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return `${language} · 候选测试草案`;
  if (status === "static_confirmed_pending_runtime") return `${language} · 待运行测试计划`;
  if (status === "framework_confirmed_replay") return `${language} · 已确认 HTTP PoC`;
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
.desc-text {
  color: #475467;
  font-family: inherit;
  font-size: 14px;
  line-height: 1.6;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.desc-text-block {
  display: block;
  max-height: 220px;
  overflow: auto;
}
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
.flow-block li { margin: 4px 0; }
.knowledge-original { color: #344054; }
.knowledge-translation { display: inline; margin-left: 8px; color: #667085; font-size: 13px; }
.knowledge-reference-link { color: #2563eb; text-decoration: none; overflow-wrap: anywhere; }
.knowledge-reference-link:hover { text-decoration: underline; }
.agent-evidence-block { display: grid; gap: 16px; }
.knowledge-block { display: grid; gap: 16px; }
.warning-flow { border-color: #f59e0b; background: #fffbeb; }
.fix-flow { border-color: #10b981; background: #f0fdf4; }
.reference-flow { border-color: #93c5fd; background: #eff6ff; }
.tool-call-list { display: grid; gap: 12px; }
.tool-call-list h3 { margin: 0; color: #162235; }
.tool-call-card { border: 1px solid #dce6f0; border-radius: 14px; padding: 14px; background: linear-gradient(180deg, #fff, #fbfdff); box-shadow: 0 8px 22px rgba(16,32,51,.04); }
.tool-call-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; }
.verify-panel { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }
.verify-panel :deep(.el-input) { width: 260px; max-width: 100%; }
.dynamic-warning-alert {
  display: inline-flex;
  width: fit-content;
  max-width: 560px;
}
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
