<template>
  <el-card header="报告">
    <el-button type="primary" @click="gen">生成并下载 HTML 报告</el-button>
    <p v-if="msg" style="margin-top: 12px">{{ msg }}</p>
  </el-card>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRoute } from "vue-router";
import { ReportApi } from "../api";

const route = useRoute();
const msg = ref("");

async function gen() {
  const scanId = route.params.scanId as string;
  const { data } = await ReportApi.create({ scan_id: scanId, format: "html" });
  msg.value = `报告 ID：${data.report_id}`;
  window.open(ReportApi.download(data.report_id));
}
</script>
