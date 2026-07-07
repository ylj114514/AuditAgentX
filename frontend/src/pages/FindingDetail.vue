<template>
  <section class="detail-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Finding</p>
        <h1>{{ detail?.type || "漏洞详情" }}</h1>
        <p v-if="detail">{{ detail.file }}:{{ detail.start_line }} · {{ detail.severity }}</p>
      </div>
      <el-button @click="router.back()">返回</el-button>
    </div>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="类型">{{ detail.type }}</el-descriptions-item>
        <el-descriptions-item label="严重级">{{ detail.severity }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ detail.verification.status }}</el-descriptions-item>
        <el-descriptions-item label="文件位置">{{ detail.file }}:{{ detail.start_line }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ detail.verification.confidence }}</el-descriptions-item>
        <el-descriptions-item label="已验证">{{ detail.verification.verified ? "是" : "否" }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro"><h2>静态代码证据</h2><p>展示漏洞位置、代码片段、source/sink 和修复建议。</p></div>
          <pre class="code-block"><code>{{ detail.vulnerable_code || "暂无代码片段" }}</code></pre>
          <el-descriptions :column="2" border class="evidence-desc">
            <el-descriptions-item label="Source">{{ detail.source || evidence?.source || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Sink">{{ detail.sink || evidence?.sink || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="数据流" :span="2">
              <pre class="mini-pre">{{ JSON.stringify(detail.data_flow?.length ? detail.data_flow : evidence?.data_flow, null, 2) }}</pre>
            </el-descriptions-item>
            <el-descriptions-item label="修复建议" :span="2">{{ detail.fix_suggestion || "建议结合漏洞类型进行输入校验、参数化查询或最小权限加固。" }}</el-descriptions-item>
          </el-descriptions>
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
              <el-tag :type="evidence.sandbox.status === 'started' ? 'success' : 'danger'">{{ evidence.sandbox.status }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="镜像">{{ evidence.sandbox.image || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="容器 ID">{{ evidence.sandbox.container_id || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Base URL">{{ evidence.sandbox.base_url || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="健康检查">{{ evidence.sandbox.health_check || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="启动命令" :span="2"><code>{{ evidence.sandbox.launch_command || "N/A" }}</code></el-descriptions-item>
            <el-descriptions-item label="容器日志摘要" :span="2"><pre class="mini-pre">{{ evidence.sandbox.logs_excerpt || "N/A" }}</pre></el-descriptions-item>
          </el-descriptions>

          <el-descriptions v-if="evidence?.runtime" :column="2" border class="evidence-desc">
            <el-descriptions-item label="验证结论">
              <el-tag :type="runtimeTagType(evidence.runtime)">{{ runtimeStatusLabel(evidence.runtime) }}</el-tag>
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
                <el-tag :type="evidence.harness.dynamically_triggered ? 'success' : 'info'">
                  {{ verdictLabel(evidence.harness.verdict) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="动态触发">{{ evidence.harness.dynamically_triggered ? "已触发" : "未触发" }}</el-descriptions-item>
              <el-descriptions-item label="执行后端">{{ evidence.harness.execution_backend || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="触发细节">{{ evidence.harness.trigger_detail || "N/A" }}</el-descriptions-item>
            </el-descriptions>
            <pre class="code-block"><code>{{ evidence.harness.harness_code || "暂无 Harness 代码" }}</code></pre>
          </div>

          <el-empty v-if="!evidence?.runtime && !evidence?.harness" description="暂无动态验证结果" />
        </el-tab-pane>

        <el-tab-pane label="可利用漏洞代码" name="exploit">
          <div class="tab-intro"><h2>可利用漏洞代码</h2><p>展示 ExploitAgent 生成的本地授权 PoC 骨架和利用路径。</p></div>
          <el-empty v-if="!evidence?.exploit" description="暂无利用代码，执行动态验证或启用 exploit 扫描后生成。" />
          <div v-else class="exploit-block">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="触发位置">{{ evidence.exploit.trigger_location || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="攻击向量">{{ evidence.exploit.attack_vector || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="利用路径" :span="2">{{ evidence.exploit.exploit_path || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="验证方法" :span="2">{{ evidence.exploit.verification_method || "N/A" }}</el-descriptions-item>
            </el-descriptions>
            <pre class="code-block"><code>{{ evidence.exploit.exploit_code || "暂无代码" }}</code></pre>
          </div>
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
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { FindingApi } from "../api";

const route = useRoute();
const router = useRouter();
const activeTab = ref("static");
const detail = ref<any>(null);
const evidence = ref<any>(null);
const verifying = ref(false);
const verifyForm = reactive({ base_url: "http://127.0.0.1:8080", endpoints: "/user", timeout: 10 });

const hasStaticEvidenceChain = computed(() => {
  const chain = evidence.value?.static_evidence_chain;
  return !!chain && Object.keys(chain).length > 0;
});
const hasVerificationEvidence = computed(() => {
  const verification = evidence.value?.verification;
  return !!verification && Object.values(verification).some((value) => value !== null && value !== undefined && value !== "");
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
  confirmed_dynamic: "动态确认可利用",
  not_reproduced: "未复现",
  inconclusive: "无法判定",
};
function verdictLabel(v: string) {
  return VERDICT_LABELS[v] || v || "N/A";
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

function toolStatusType(tool: any) {
  const status = String(tool?.status || "").toLowerCase();
  if (tool?.success === false || status.includes("fail") || status.includes("error")) return "danger";
  if (status.includes("skip")) return "info";
  return "success";
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
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.panel-card { border-radius: 16px; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; }
.tab-intro p { color: #667085; margin: 6px 0 0; }
.code-block { background: #101828; color: #d7e3f1; padding: 16px; border-radius: 12px; overflow: auto; }
.mini-pre { margin: 0; padding: 10px; background: #f6f8fa; border-radius: 8px; }
.evidence-desc { margin-top: 16px; }
.harness-block { margin-top: 20px; }
.harness-block h3 { margin: 0 0 4px; color: #162235; }
.harness-note { color: #667085; margin: 0 0 12px; font-size: 13px; }
.flow-block { margin-top: 16px; padding: 14px; border: 1px solid #dce6f0; border-radius: 12px; background: #fbfdff; }
.flow-block h3 { margin: 0 0 8px; color: #162235; }
.flow-block ol { margin: 0; padding-left: 20px; color: #475467; line-height: 1.8; }
.agent-evidence-block { display: grid; gap: 16px; }
.tool-call-list { display: grid; gap: 12px; }
.tool-call-list h3 { margin: 0; color: #162235; }
.tool-call-card { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px; background: #fbfdff; }
.tool-call-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; }
.verify-panel { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; gap: 12px; margin-bottom: 14px; }
.exploit-block { display: grid; gap: 16px; }
@media (max-width: 760px) { .verify-panel { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>
