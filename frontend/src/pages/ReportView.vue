<template>
  <section class="report-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Report</p>
        <h1>审计报告导出</h1>
        <p>根据 scan_id 生成技术完整报告，支持 HTML / Markdown / JSON / PDF。</p>
      </div>
    </div>

    <el-card shadow="never" class="panel-card report-card">
      <div class="report-hint">
        <b>报告内容</b>
        <p>包含审计范围、工具状态、风险指标、完整漏洞证据、Source→Sink、调用链、动态请求对比、漏洞利用链、修复建议、限制和附录。</p>
      </div>
      <el-form label-position="top">
        <el-form-item label="Scan ID">
          <el-input v-model="scanId" placeholder="输入 scan_id" />
        </el-form-item>
        <el-form-item label="报告格式">
          <el-radio-group v-model="format">
            <el-radio-button label="html" />
            <el-radio-button label="markdown" />
            <el-radio-button label="json" />
            <el-radio-button label="pdf" />
          </el-radio-group>
        </el-form-item>
        <el-form-item label="内容选项">
          <div class="option-grid">
            <el-checkbox v-model="includePoc">包含 PoC / Payload / Harness 代码</el-checkbox>
            <el-checkbox v-model="includeFix">包含逐漏洞修复建议</el-checkbox>
          </div>
        </el-form-item>
        <el-alert
          v-if="format === 'pdf'"
          type="warning"
          :closable="false"
          title="PDF 导出依赖后端 WeasyPrint；不可用时会明确报错，不会伪装成 PDF。"
          class="format-alert"
        />
        <el-button type="primary" :loading="loading" @click="gen">生成并下载报告</el-button>
      </el-form>
      <el-alert v-if="msg" type="success" :closable="false" :title="msg" class="msg" />
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { ElMessage } from "element-plus";
import { ReportApi } from "../api";
import { readHistory } from "../api/history";

const route = useRoute();
const scanId = ref("");
const format = ref("html");
const includePoc = ref(true);
const includeFix = ref(true);
const msg = ref("");
const loading = ref(false);

async function gen() {
  if (!scanId.value) {
    ElMessage.warning("请先输入 scan_id");
    return;
  }
  loading.value = true;
  try {
    const { data } = await ReportApi.create({
      scan_id: scanId.value,
      format: format.value,
      include_poc: includePoc.value,
      include_fix: includeFix.value,
    });
    msg.value = `报告已生成：${data.report_id}`;
    window.open(ReportApi.download(data.report_id));
  } catch (error: any) {
    msg.value = "";
    ElMessage.error(error?.response?.data?.detail || error?.message || "报告生成失败");
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  const param = route.params.scanId as string;
  if (param && param !== "latest") {
    scanId.value = param;
    return;
  }
  scanId.value = readHistory()[0]?.scanId || "";
});
</script>

<style scoped>
.report-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.panel-card { width: 100%; border-radius: 18px; }
.report-card { background: linear-gradient(180deg, #fff, #f8fbff); }
.report-hint { max-width: 720px; margin-bottom: 18px; padding: 16px; border: 1px solid #dce6f0; border-radius: 14px; background: #fbfdff; }
.report-hint b { color: #162235; }
.report-hint p { margin: 6px 0 0; color: #667085; line-height: 1.7; }
.report-card :deep(.el-form-item) { max-width: 520px; }
.report-card :deep(.el-input) { max-width: 520px; }
.msg { margin-top: 16px; }
.option-grid { display: flex; flex-direction: column; gap: 8px; }
.format-alert { max-width: 520px; margin-bottom: 16px; }
</style>
