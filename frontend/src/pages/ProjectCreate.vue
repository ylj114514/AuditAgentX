<template>
  <section class="create-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">New Audit</p>
        <h1>新建审计项目</h1>
        <p>输入 Git 仓库或本地代码目录，选择静态分析、动态验证和利用代码生成配置。</p>
      </div>
      <el-button @click="router.push('/history')">查看历史</el-button>
    </div>

    <div class="create-grid">
      <el-card class="panel-card target-card" shadow="never">
        <template #header>目标项目</template>
        <el-form :model="form" label-position="top">
          <el-form-item label="项目名称">
            <el-input v-model="form.name" placeholder="例如 demo_flask_app" />
          </el-form-item>
          <el-form-item label="来源类型">
            <el-segmented v-model="form.source_type" :options="sourceOptions" />
          </el-form-item>
          <el-form-item label="仓库 URL" v-if="form.source_type === 'git'">
            <el-input v-model="form.url" placeholder="https://github.com/owner/repo" />
          </el-form-item>
          <el-form-item label="本地路径" v-else>
            <div class="local-input-row">
              <el-input v-model="form.local_path" placeholder="examples/vulnerable_projects/demo_app" />
              <el-button :disabled="submitting" @click="pickDirectory">上传目录</el-button>
            </div>
            <input
              ref="directoryInput"
              class="hidden-file-input"
              type="file"
              webkitdirectory
              multiple
              @change="handleDirectorySelect"
            />
            <p v-if="selectedDirectoryName" class="upload-hint">
              已选择：{{ selectedDirectoryName }}，创建时会上传 {{ selectedDirectoryFiles.length }} 个文件。
            </p>
          </el-form-item>
          <el-form-item label="分支" v-if="form.source_type === 'git'">
            <el-input v-model="form.branch" placeholder="留空则使用仓库默认分支；填错会自动回退" />
          </el-form-item>
        </el-form>
      </el-card>

      <el-card class="panel-card config-card" shadow="never">
        <template #header>扫描模式</template>
        <div class="mode-list">
          <div :class="['mode-row', scanMode === 'quick' && 'mode-active']" role="button" tabindex="0" @click="scanMode = 'quick'" @keyup.enter="scanMode = 'quick'">
            <div><span class="mode-kicker">Quick</span><b>快速扫描</b><p>仅静态扫描（Semgrep / Gitleaks / 污点规则），不调用 LLM，不动态验证。</p></div>
            <el-radio :model-value="scanMode" value="quick" />
          </div>
          <div :class="['mode-row', scanMode === 'standard' && 'mode-active']" role="button" tabindex="0" @click="scanMode = 'standard'" @keyup.enter="scanMode = 'standard'">
            <div><span class="mode-kicker">Standard</span><b>标准智能体审计</b><p>含 Quick + AuditAgent 语义审计 + VerifyAgent 复核去误报 + source→sink 证据链 + 报告。不主动发起动态请求。</p></div>
            <el-radio :model-value="scanMode" value="standard" />
          </div>
          <div :class="['mode-row', scanMode === 'deep' && 'mode-active']" role="button" tabindex="0" @click="scanMode = 'deep'" @keyup.enter="scanMode = 'deep'">
            <div><span class="mode-kicker">Deep Docker</span><b>沙箱验证</b><p>含 Standard + 在 Docker 沙箱中尝试启动 GitHub 项目，对本地容器服务执行授权动态验证 + Harness 验证。</p></div>
            <el-radio :model-value="scanMode" value="deep" />
          </div>
        </div>

        <el-alert
          v-if="scanMode !== 'quick'"
          type="info"
          show-icon
          :closable="false"
          title="Standard / Deep 会对候选漏洞调用 VerifyAgent 复核。建议先限制 Top 候选数量，避免大项目长时间卡住。"
          class="notice"
        />

        <el-form :model="scanScope" label-position="top" class="scope-form">
          <el-form-item label="审计范围">
            <div class="scope-option">
              <el-checkbox v-model="scanScope.include_test_findings">
                包含测试、样例、Demo、Fixture 和 Benchmark 资产
              </el-checkbox>
              <p class="deep-hint scope-hint">
                默认只审计生产代码。OWASP Benchmark 等故意包含漏洞的评测项目必须开启此项，
                否则其 findings 会标记为 out_of_scope，不会进入 Verify 或动态验证。
              </p>
            </div>
          </el-form-item>
        </el-form>

        <el-form :model="staticTools" label-position="top" class="static-tools-form">
          <el-form-item label="静态安全工具">
            <el-checkbox-group v-model="staticTools.selected" class="static-tools-list">
              <el-checkbox v-for="tool in STATIC_TOOL_OPTIONS" :key="tool.value" :label="tool.value">
                <span class="static-tool-label">{{ tool.label }}</span>
                <span class="static-tool-description">{{ tool.description }}</span>
              </el-checkbox>
            </el-checkbox-group>
            <p class="deep-hint">
              内置 Custom Rules 始终启用，作为离线兜底规则；取消勾选的外部工具不会在本次扫描中执行。
            </p>
          </el-form-item>
        </el-form>

        <el-alert
          v-if="scanScope.include_test_findings"
          type="warning"
          show-icon
          :closable="false"
          title="已包含非生产资产：测试/样例/Benchmark findings 将进入复核与动态候选池，扫描耗时会明显增加。"
          class="notice"
        />

        <el-form v-if="scanMode !== 'quick'" :model="verifyBudget" label-position="top" class="verify-budget-form">
          <div class="deep-inline">
            <el-form-item label="最大复核候选数 max_verify_candidates">
              <el-input-number
                v-model="verifyBudget.max_verify_candidates"
                :min="1"
                :max="100000"
                :step="10"
                :disabled="verifyBudget.unlimited_verify"
                controls-position="right"
              />
              <el-checkbox v-model="verifyBudget.unlimited_verify" style="margin-left: 12px;">
                不限（复核全部候选）
              </el-checkbox>
              <div v-if="verifyBudget.unlimited_verify" class="hint-text">
                将对全部候选逐条调用 VerifyAgent 复核——大项目会显著更慢、更耗 LLM token。
              </div>
            </el-form-item>
            <el-form-item label="Verify 并发 max_verify_workers">
              <el-input-number
                v-model="verifyBudget.max_verify_workers"
                :min="1"
                :max="16"
                :step="1"
                controls-position="right"
              />
            </el-form-item>
          </div>
        </el-form>

        <el-alert
          v-if="scanMode === 'deep'"
          type="warning"
          show-icon
          :closable="false"
          title="Deep 模式会自动识别项目 Docker/Compose 或 Web 启动方式；能启动时验证真实本地服务，不能启动时回退到目标函数 Harness。无需填写固定端口或 base_url。"
          class="notice"
        />

        <el-form v-if="scanMode === 'deep'" :model="deep" label-position="top" class="dynamic-form">
          <el-form-item>
            <div class="scope-option">
              <el-checkbox v-model="deep.trust_project_container_config">
                允许直接使用项目自带 Dockerfile（可选）
              </el-checkbox>
              <p class="deep-hint scope-hint">默认由系统自动识别并生成受限启动方案。Compose 始终先经过安全策略检查；只有你勾选此项，才会直接执行项目自己的 Dockerfile。</p>
            </div>
          </el-form-item>

          <el-form-item label="动态验证候选数上限 max_dynamic_candidates">
            <el-input-number
              v-model="deep.max_dynamic_candidates"
              :min="1"
              :max="500"
              :step="10"
              controls-position="right"
            />
            <p class="deep-hint">
              最多对多少条候选执行「生成利用代码 + 动态验证」。默认 20。调大可覆盖更多注入类
              候选（如 DVWA 的 SQLi/命令注入会拿到利用代码和动态结论），代价是每条都要起 Docker /
              发 HTTP / 跑 Harness，扫描更慢。建议按项目注入类漏洞数量设置（如 DVWA 设 60）。
            </p>
          </el-form-item>

          <el-collapse v-model="advancedOpen" class="advanced-collapse">
            <el-collapse-item name="override">
              <template #title>
                <span
                  class="advanced-title"
                  :class="{ 'is-open': advancedOpen.includes('override') }"
                >
                  高级覆盖（仅自动识别失败时使用）
                </span>
              </template>
              <p class="deep-hint">
                仅在自动识别启动方式失败时才需填写。留空即由系统自动识别 install / run 命令与端口；
                任意填写项会合并进 launch_plan 覆盖自动识别结果。
              </p>
              <el-form-item label="安装命令 install_command" class="override-input-item">
                <el-input v-model="deep.override.install_command" placeholder="例如 pip install -r requirements.txt（留空自动识别）" />
              </el-form-item>
              <el-form-item label="启动命令 run_command" class="override-input-item">
                <el-input v-model="deep.override.run_command" placeholder="例如 python app.py（留空自动识别）" />
              </el-form-item>
              <div class="override-inline">
                <el-form-item label="服务端口 port" class="override-input-item">
                  <el-input v-model="deep.override.port" placeholder="例如 8000（留空自动识别）" />
                </el-form-item>
                <el-form-item label="工作目录 working_dir" class="override-input-item">
                  <el-input v-model="deep.override.working_dir" placeholder="例如 . 或 src（留空为仓库根）" />
                </el-form-item>
              </div>
            </el-collapse-item>
          </el-collapse>
        </el-form>

        <el-button type="primary" size="large" :loading="submitting" class="submit-btn" @click="submit">
          创建并开始扫描
        </el-button>
      </el-card>
    </div>
  </section>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ProjectApi, ScanApi } from "../api";
import { upsertHistory } from "../api/history";
import { DEFAULT_STATIC_TOOLS, normalizeStaticTools, STATIC_TOOL_OPTIONS } from "../utils/staticTools";

const router = useRouter();
const submitting = ref(false);
const directoryInput = ref<HTMLInputElement | null>(null);
const selectedDirectoryName = ref("");
const selectedDirectoryFiles = ref<File[]>([]);

const sourceOptions = [
  { label: "Git 仓库", value: "git" },
  { label: "本地目录", value: "local" },
];

const form = reactive({
  name: "",
  source_type: "git",
  url: "",
  local_path: "",
  branch: "",
});

// 扫描模式：quick / standard / deep（Docker 沙箱）
const scanMode = ref<"quick" | "standard" | "deep">("standard");
const scanScope = reactive({
  include_test_findings: false,
});
const staticTools = reactive({
  selected: [...DEFAULT_STATIC_TOOLS],
});
const verifyBudget = reactive({
  max_verify_candidates: 50,
  max_verify_workers: 4,
  unlimited_verify: false,   // 勾选后提交 0 = 后端不设上限，复核全部候选
});
const advancedOpen = ref<string[]>([]); // 默认折叠「高级覆盖」，避免误导用户以为必填
const deep = reactive({
  trust_project_container_config: false,
  max_dynamic_candidates: 20,
  override: {
    install_command: "",
    run_command: "",
    port: "",
    working_dir: "",
  },
});

// 只把用户真正填写的覆盖项合并进 launch_plan；空串一律不发，保持后端自动识别。
function buildLaunchPlanOverride(): Record<string, any> {
  const o = deep.override;
  const plan: Record<string, any> = {};
  if (o.install_command.trim()) plan.install_command = o.install_command.trim();
  if (o.run_command.trim()) plan.run_command = o.run_command.trim();
  if (o.working_dir.trim()) plan.working_dir = o.working_dir.trim();
  const portNum = Number(o.port);
  if (o.port.trim() && Number.isFinite(portNum) && portNum > 0) plan.port = portNum;
  return plan;
}

function pickDirectory() {
  directoryInput.value?.click();
}

function handleDirectorySelect(event: Event) {
  const input = event.target as HTMLInputElement;
  const files = Array.from(input.files || []);
  selectedDirectoryFiles.value = files;
  const first = files[0] as (File & { webkitRelativePath?: string }) | undefined;
  const rootName = first?.webkitRelativePath?.split("/")[0] || first?.name || "";
  selectedDirectoryName.value = rootName;
  if (rootName) {
    form.local_path = rootName;
    if (!form.name.trim() || form.name === "maccms10") {
      form.name = rootName;
    }
  }
}

async function submit() {
  if (!form.name.trim()) {
    ElMessage.warning("请填写项目名称");
    return;
  }
  submitting.value = true;
  try {
    let proj: any;
    if (form.source_type === "local" && selectedDirectoryFiles.value.length > 0) {
      const upload = new FormData();
      upload.append("name", form.name.trim());
      for (const file of selectedDirectoryFiles.value) {
        const relativePath = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
        upload.append("files", file, relativePath);
      }
      const { data } = await ProjectApi.upload(upload);
      proj = data;
    } else {
      const payload = {
        ...form,
        branch: form.source_type === "git" ? (form.branch.trim() || null) : form.branch,
        url: form.url.trim(),
        local_path: form.local_path.trim(),
      };
      const { data } = await ProjectApi.create(payload);
      proj = data;
    }
    // Deep 模式固定使用项目 Docker 沙箱：后端负责识别启动方式和实际映射端口。
    const options: any = {
      enable_poc: false,
      include_test_findings: scanScope.include_test_findings,
    };
    if (scanMode.value !== "quick") {
      // 不限 -> 送 0：后端 _verify_candidate_limit 把 <=0 视为「复核全部候选」
      options.max_verify_candidates = verifyBudget.unlimited_verify
        ? 0
        : verifyBudget.max_verify_candidates;
      options.max_verify_workers = verifyBudget.max_verify_workers;
    }
    if (scanMode.value === "deep") {
      options.max_dynamic_candidates = deep.max_dynamic_candidates;
      options.dynamic_target = {
        mode: "docker_project",
        auto_start_docker: true,
        trust_project_container_config: deep.trust_project_container_config,
      };
      const launchOverride = buildLaunchPlanOverride();
      if (Object.keys(launchOverride).length > 0) {
        // 后端 pipeline 会把 launch_plan 覆盖项合并进自动识别结果
        options.dynamic_target.launch_plan = launchOverride;
      }
    }

    const { data: scan } = await ScanApi.create({
      project_id: proj.project_id,
      scan_mode: scanMode.value,
      scan_type: scanMode.value === "quick" ? "static" : "full",
      enabled_tools: normalizeStaticTools(staticTools.selected),
      options,
    });

    upsertHistory({
      scanId: scan.scan_id,
      projectId: proj.project_id,
      projectName: form.name,
      sourceType: form.source_type,
      target: form.source_type === "git" ? form.url : form.local_path,
      status: "queued",
      progress: 0,
      findingCount: 0,
    });

    ElMessage.success(`扫描任务已创建：${scan.scan_id}`);
    router.push({ path: "/scans", query: { scanId: scan.scan_id } });
  } catch (error: any) {
    const message = error?.response?.data?.detail || error?.message || "创建扫描任务失败";
    ElMessage.error(String(message));
  } finally {
    submitting.value = false;
  }
}
</script>

<style scoped>
.create-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.create-grid { display: grid; grid-template-columns: minmax(340px, 420px) minmax(0, 1fr); gap: 18px; align-items: start; }
.panel-card { border-radius: 18px; }
.target-card { order: 1; }
.config-card { order: 2; }
.local-input-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; width: 100%; }
.hidden-file-input { display: none; }
.upload-hint { margin: 8px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.switch-list { display: flex; flex-direction: column; gap: 14px; }
.switch-row { display: flex; justify-content: space-between; gap: 16px; padding: 14px; border: 1px solid #e4ebf3; border-radius: 12px; background: #fbfdff; }
.switch-row p { margin: 4px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.mode-list { display: flex; flex-direction: column; gap: 12px; }
.mode-row { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 16px; border: 1px solid #e4ebf3; border-radius: 16px; background: linear-gradient(180deg, #fff, #fbfdff); cursor: pointer; transition: all .15s; outline: none; }
.mode-row:hover, .mode-row:focus-visible { border-color: #2f80ed; box-shadow: 0 10px 24px rgba(47,128,237,.1); }
.mode-active { border-color: #2f80ed; background: linear-gradient(180deg, #eef6ff, #fff); box-shadow: inset 4px 0 0 #2f80ed, 0 14px 30px rgba(47,128,237,.12); }
.mode-kicker { display: inline-flex; margin-bottom: 5px; color: #2f80ed; font-size: 12px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase; }
.mode-row b { display: block; color: #162235; }
.mode-row p { margin: 4px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.deep-hint { color: #98a2b3; font-size: 13px; margin: 0 0 8px; }
.scope-option { display: flex; flex-direction: column; width: 100%; }
.scope-hint { margin-top: 4px; padding-left: 24px; line-height: 1.6; }
.deep-inline { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.notice { margin-top: 14px; }
.verify-budget-form { margin-top: 14px; }
.static-tools-form { margin-top: 14px; }
.static-tools-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; width: 100%; }
.static-tools-list :deep(.el-checkbox) { align-items: flex-start; height: auto; margin-right: 0; white-space: normal; }
.static-tool-label { display: block; color: #344054; font-weight: 700; }
.static-tool-description { display: block; color: #667085; font-size: 12px; line-height: 1.45; margin-top: 2px; }
.verify-budget-form :deep(.el-input-number) { width: 280px; max-width: 100%; }
.dynamic-form { margin-top: 14px; }
.advanced-collapse { margin-top: 6px; border-top: 1px dashed #e4ebf3; border-bottom: none; }
.advanced-collapse :deep(.el-collapse-item__header) {
  display: inline-flex;
  width: auto;
  height: auto;
  min-height: 34px;
  padding-top: 10px;
  border-bottom: none;
  background: transparent;
  pointer-events: none;
}
.advanced-collapse :deep(.el-collapse-item__arrow) { display: none; }
.advanced-collapse :deep(.el-collapse-item__wrap) { border-bottom: none; }
.advanced-title {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  width: fit-content;
  padding: 7px 11px;
  border: 1px solid #b9d7ff;
  border-radius: 8px;
  background: #f2f8ff;
  color: #175cd3;
  font-weight: 800;
  line-height: 1.2;
  cursor: pointer;
  pointer-events: auto;
  transition: border-color .15s ease, background .15s ease, box-shadow .15s ease;
}
.advanced-title::before {
  content: "";
  width: 7px;
  height: 7px;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(-45deg);
  transition: transform .15s ease;
}
.advanced-title.is-open::before { transform: rotate(45deg); }
.advanced-title:hover {
  border-color: #2f80ed;
  background: #eaf3ff;
  box-shadow: 0 6px 14px rgba(47, 128, 237, .12);
}
.override-input-item { max-width: 620px; }
.override-input-item :deep(.el-input) { width: 100%; }
.override-inline {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 304px));
  gap: 12px;
  max-width: 620px;
}
@media (max-width: 720px) {
  .override-inline, .static-tools-list { grid-template-columns: 1fr; }
  .override-input-item { max-width: 100%; }
}
.submit-btn { width: 100%; margin-top: 18px; }
@media (max-width: 980px) { .create-grid { grid-template-columns: 1fr; } }
@media (max-width: 720px) { .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>
