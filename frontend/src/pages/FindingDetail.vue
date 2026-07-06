<template>
  <el-card header="漏洞详情与证据链">
    <div v-if="detail">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="类型">{{ detail.type }}</el-descriptions-item>
        <el-descriptions-item label="严重级">{{ detail.severity }}</el-descriptions-item>
        <el-descriptions-item label="文件">{{ detail.file }}:{{ detail.start_line }}</el-descriptions-item>
        <el-descriptions-item label="已验证">{{ detail.verification.verified }}</el-descriptions-item>
      </el-descriptions>
      <pre style="background: #f6f8fa; padding: 12px; margin-top: 12px">{{ detail.vulnerable_code }}</pre>
      <p><b>修复建议：</b>{{ detail.fix_suggestion }}</p>

      <h3>证据链</h3>
      <pre style="background: #f6f8fa; padding: 12px">{{ JSON.stringify(evidence, null, 2) }}</pre>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useRoute } from "vue-router";
import { FindingApi } from "../api";

const route = useRoute();
const detail = ref<any>(null);
const evidence = ref<any>(null);

onMounted(async () => {
  const id = route.params.id as string;
  detail.value = (await FindingApi.detail(id)).data;
  evidence.value = (await FindingApi.evidence(id)).data.evidence;
});
</script>
