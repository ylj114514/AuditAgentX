<template>
  <el-card header="扫描看板">
    <el-input v-model="scanId" placeholder="输入 scan_id 查看进度与漏洞" style="width: 320px" />
    <el-button type="primary" @click="load" style="margin-left: 12px">查询</el-button>

    <div v-if="status" style="margin-top: 20px">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="状态">{{ status.status }}</el-descriptions-item>
        <el-descriptions-item label="阶段">{{ status.current_stage }}</el-descriptions-item>
        <el-descriptions-item label="进度">{{ status.progress }}%</el-descriptions-item>
      </el-descriptions>
      <el-progress :percentage="status.progress" style="margin-top: 12px" />

      <el-table :data="findings" style="margin-top: 20px" border>
        <el-table-column prop="type" label="类型" />
        <el-table-column prop="severity" label="严重级" width="100" />
        <el-table-column prop="file" label="文件" />
        <el-table-column prop="line" label="行" width="80" />
        <el-table-column prop="confidence" label="置信度" width="100" />
        <el-table-column prop="status" label="状态" width="120" />
      </el-table>
      <el-button type="success" @click="genReport" style="margin-top: 16px">生成报告</el-button>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import { ScanApi, ReportApi } from "../api";

const scanId = ref("");
const status = ref<any>(null);
const findings = ref<any[]>([]);

async function load() {
  const { data } = await ScanApi.get(scanId.value);
  status.value = data;
  const { data: f } = await ScanApi.findings(scanId.value);
  findings.value = f.findings;
}

async function genReport() {
  const { data } = await ReportApi.create({ scan_id: scanId.value, format: "html" });
  window.open(ReportApi.download(data.report_id));
  ElMessage.success("报告已生成");
}
</script>
