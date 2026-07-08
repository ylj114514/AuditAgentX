<template>
  <section class="report-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Report</p>
        <h1>审计报告导出</h1>
        <p>根据 scan_id 生成 HTML / Markdown / JSON 报告。</p>
      </div>
    </div>

    <el-card shadow="never" class="panel-card report-card">
      <div class="report-hint">
        <b>报告内容</b>
        <p>导出的报告会汇总漏洞列表、风险等级、证据链、动态验证状态和修复建议。</p>
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
          </el-radio-group>
        </el-form-item>
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
const msg = ref("");
const loading = ref(false);

async function gen() {
  if (!scanId.value) {
    ElMessage.warning("请先输入 scan_id");
    return;
  }
  loading.value = true;
  try {
    const { data } = await ReportApi.create({ scan_id: scanId.value, format: format.value });
    msg.value = `报告已生成：${data.report_id}`;
    window.open(ReportApi.download(data.report_id));
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
.panel-card { max-width: 760px; border-radius: 18px; }
.report-card { background: linear-gradient(180deg, #fff, #f8fbff); }
.report-hint { margin-bottom: 18px; padding: 16px; border: 1px solid #dce6f0; border-radius: 14px; background: #fbfdff; }
.report-hint b { color: #162235; }
.report-hint p { margin: 6px 0 0; color: #667085; line-height: 1.7; }
.msg { margin-top: 16px; }
</style>
