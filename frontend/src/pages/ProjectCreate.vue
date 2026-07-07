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
              <el-input v-model="form.local_path" placeholder="examples/vulnerable_projects/demo_flask_app" />
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
          <div :class="['mode-row', scanMode === 'quick' && 'mode-active']" @click="scanMode = 'quick'">
            <div><b>Quick 快速扫描</b><p>仅静态扫描（Semgrep / Gitleaks / 污点规则），不调用 LLM，不动态验证。</p></div>
            <el-radio :model-value="scanMode" value="quick" />
          </div>
          <div :class="['mode-row', scanMode === 'standard' && 'mode-active']" @click="scanMode = 'standard'">
            <div><b>Standard 标准智能体审计</b><p>含 Quick + AuditAgent 语义审计 + VerifyAgent 复核去误报 + source→sink 证据链 + 报告。不主动发起动态请求。</p></div>
            <el-radio :model-value="scanMode" value="standard" />
          </div>
          <div :class="['mode-row', scanMode === 'deep' && 'mode-active']" @click="scanMode = 'deep'">
            <div><b>Deep Docker 沙箱验证</b><p>含 Standard + 在 Docker 沙箱中尝试启动 GitHub 项目，对本地容器服务执行授权动态验证 + Harness 验证。</p></div>
            <el-radio :model-value="scanMode" value="deep" />
          </div>
        </div>

        <el-alert
          v-if="scanMode === 'deep'"
          type="warning"
          show-icon
          :closable="false"
          title="Deep 模式将在 Docker 沙箱中尝试启动 GitHub 项目，只对本地容器服务执行授权动态验证，不会攻击真实第三方系统。"
          class="notice"
        />

        <el-form v-if="scanMode === 'deep'" :model="deep" label-position="top" class="dynamic-form">
          <p class="deep-hint">高级配置可留空，后端 launch_detector 会自动推断启动方式。</p>
          <el-form-item label="安装命令 install_command">
            <el-input v-model="deep.install_command" placeholder="pip install -r requirements.txt" />
          </el-form-item>
          <el-form-item label="启动命令 run_command">
            <el-input v-model="deep.run_command" placeholder="python app.py" />
          </el-form-item>
          <div class="deep-inline">
            <el-form-item label="端口 port">
              <el-input v-model="deep.port" placeholder="5000" />
            </el-form-item>
            <el-form-item label="健康检查路径">
              <el-input v-model="deep.health_path" placeholder="/" />
            </el-form-item>
          </div>
          <el-form-item label="环境变量 env（每行 KEY=VALUE）">
            <el-input v-model="deep.env" type="textarea" :rows="2" placeholder="DEBUG=1" />
          </el-form-item>
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
  name: "maccms10",
  source_type: "git",
  url: "https://github.com/magicblack/maccms10",
  local_path: "examples/vulnerable_projects/demo_flask_app",
  branch: "",
});

// 扫描模式：quick / standard / deep（Docker 沙箱）
const scanMode = ref<"quick" | "standard" | "deep">("standard");
// Deep 模式可选高级配置（留空则由后端 launch_detector 自动推断）
const deep = reactive({ install_command: "", run_command: "", port: "", health_path: "/", env: "" });

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
    // Deep 模式：组装 docker_project 靶场 + 可选 launch_plan 覆盖项
    const options: any = { enable_poc: false };
    if (scanMode.value === "deep") {
      const launchPlan: any = {};
      if (deep.install_command.trim()) launchPlan.install_command = deep.install_command.trim();
      if (deep.run_command.trim()) launchPlan.run_command = deep.run_command.trim();
      if (deep.port.trim()) launchPlan.port = Number(deep.port.trim());
      if (deep.health_path.trim()) launchPlan.health_path = deep.health_path.trim();
      const env: Record<string, string> = {};
      deep.env.split(/[\n,]/).map((s) => s.trim()).filter(Boolean).forEach((kv) => {
        const i = kv.indexOf("="); if (i > 0) env[kv.slice(0, i)] = kv.slice(i + 1);
      });
      options.dynamic_target = {
        mode: "docker_project",
        ...(Object.keys(launchPlan).length ? { launch_plan: launchPlan } : {}),
        ...(Object.keys(env).length ? { env } : {}),
      };
    }

    const { data: scan } = await ScanApi.create({
      project_id: proj.project_id,
      scan_mode: scanMode.value,
      scan_type: scanMode.value === "quick" ? "static" : "full",
      enabled_tools: ["custom", "semgrep", "gitleaks"],
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
.create-grid { display: grid; grid-template-columns: 420px minmax(0, 1fr); gap: 18px; align-items: start; }
.panel-card { border-radius: 16px; }
.config-card { order: 1; }
.target-card { order: 2; }
.local-input-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; width: 100%; }
.hidden-file-input { display: none; }
.upload-hint { margin: 8px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.switch-list { display: flex; flex-direction: column; gap: 14px; }
.switch-row { display: flex; justify-content: space-between; gap: 16px; padding: 14px; border: 1px solid #e4ebf3; border-radius: 12px; background: #fbfdff; }
.switch-row p { margin: 4px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.mode-list { display: flex; flex-direction: column; gap: 12px; }
.mode-row { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 14px; border: 1px solid #e4ebf3; border-radius: 12px; background: #fbfdff; cursor: pointer; transition: all .15s; }
.mode-row:hover { border-color: #2f80ed; }
.mode-active { border-color: #2f80ed; background: #eef5ff; }
.mode-row p { margin: 4px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.deep-hint { color: #98a2b3; font-size: 13px; margin: 0 0 8px; }
.deep-inline { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.notice { margin-top: 14px; }
.dynamic-form { margin-top: 14px; }
.submit-btn { width: 100%; margin-top: 18px; }
@media (max-width: 980px) { .create-grid { grid-template-columns: 1fr; } }
@media (max-width: 720px) { .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>
