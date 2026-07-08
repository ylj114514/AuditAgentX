<template>
  <section class="page-stack">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Cache</p>
        <h1>历史分析记录</h1>
        <p>历史记录保存在浏览器本地缓存中，便于重新进入系统后继续查看扫描结果。</p>
      </div>
      <div class="title-actions">
        <el-button @click="refresh">刷新</el-button>
        <el-button type="danger" plain @click="clearAll">清空历史</el-button>
      </div>
    </div>

    <el-card shadow="never" class="panel-card">
      <el-empty v-if="records.length === 0" description="暂无历史记录" />
      <el-table v-else :data="records" stripe>
        <el-table-column prop="projectName" label="项目名称" min-width="160" />
        <el-table-column prop="projectId" label="项目 ID" min-width="160" />
        <el-table-column prop="scanId" label="Scan ID" min-width="190" />
        <el-table-column prop="target" label="目标" min-width="220" show-overflow-tooltip />
        <el-table-column label="状态" width="120">
          <template #default="scope"><el-tag :type="statusType(scope.row.status)">{{ scope.row.status || "unknown" }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="findingCount" label="漏洞" width="80" />
        <el-table-column prop="verifiedCount" label="已验证" width="90" />
        <el-table-column prop="updatedAt" label="更新时间" min-width="170">
          <template #default="scope">{{ formatTime(scope.row.updatedAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="scope">
            <el-button type="primary" link @click="open(scope.row.scanId)">查看</el-button>
            <el-button type="danger" link @click="remove(scope.row.scanId)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessageBox } from "element-plus";
import { clearHistory, readHistory, removeHistory, type AuditHistoryRecord } from "../api/history";

const router = useRouter();
const records = ref<AuditHistoryRecord[]>([]);

function refresh() { records.value = readHistory(); }
function open(scanId: string) { router.push({ path: "/scans", query: { scanId } }); }
function remove(scanId: string) { removeHistory(scanId); refresh(); }
async function clearAll() {
  await ElMessageBox.confirm("确认清空本地历史记录？", "清空历史", { type: "warning" });
  clearHistory();
  refresh();
}
function formatTime(value: string) { return value ? new Date(value).toLocaleString() : "-"; }
function statusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value === "failed") return "danger";
  if (value === "done" || value === "finished") return "success";
  if (value === "running") return "warning";
  return "info";
}

onMounted(refresh);
</script>

<style scoped>
.page-stack { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.title-actions { display: flex; gap: 10px; }
.panel-card { border-radius: 18px; overflow: hidden; }
@media (max-width: 720px) { .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>
