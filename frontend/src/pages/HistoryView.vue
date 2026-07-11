<template>
  <section class="page-stack">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">History</p>
        <h1>历史分析记录</h1>
        <p>历史记录以后端数据库为准（不再仅依赖浏览器缓存）；本地缓存仅用于补充漏洞/已验证等统计。</p>
      </div>
      <div class="title-actions">
        <el-button :loading="loading" @click="refresh">刷新</el-button>
        <el-button type="danger" plain @click="clearLocalCache">清空本地缓存</el-button>
      </div>
    </div>

    <el-card shadow="never" class="panel-card" v-loading="loading">
      <el-empty v-if="records.length === 0" description="暂无历史记录" />
      <el-table v-else :data="records" stripe>
        <el-table-column prop="projectName" label="项目名称" min-width="160" />
        <el-table-column prop="projectId" label="项目 ID" min-width="160" />
        <el-table-column prop="scanId" label="Scan ID" min-width="190" />
        <el-table-column prop="target" label="目标" min-width="220" show-overflow-tooltip />
        <el-table-column label="状态" width="110">
          <template #default="scope"><el-tag :type="statusType(scope.row.status)">{{ scope.row.status || "unknown" }}</el-tag></template>
        </el-table-column>
        <el-table-column label="来源" width="110">
          <template #default="scope">
            <el-tag :type="scope.row.source === 'local' ? 'info' : 'success'" effect="plain">
              {{ scope.row.source === 'local' ? '仅本地缓存' : '数据库' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="findingCount" label="漏洞" width="80" />
        <el-table-column prop="verifiedCount" label="已验证" width="90" />
        <el-table-column prop="updatedAt" label="更新时间" min-width="170">
          <template #default="scope">{{ formatTime(scope.row.updatedAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="scope">
            <el-button type="primary" link @click="open(scope.row.scanId)">查看</el-button>
            <el-button type="danger" link @click="remove(scope.row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { ScanApi } from "../api";
import { clearHistory, readHistory, removeHistory, type AuditHistoryRecord } from "../api/history";

type HistoryRow = AuditHistoryRecord & { source: "db" | "local" };

const router = useRouter();
const records = ref<HistoryRow[]>([]);
const loading = ref(false);

async function refresh() {
  loading.value = true;
  const local = readHistory();
  const localMap = new Map(local.map((r) => [r.scanId, r]));
  let backend: HistoryRow[] = [];
  try {
    const { data } = await ScanApi.list();
    backend = (data.scans || []).map((s: any): HistoryRow => {
      const l = localMap.get(s.scan_id);
      return {
        scanId: s.scan_id,
        projectId: s.project_id,
        projectName: s.project_name,
        target: s.target,
        sourceType: s.source_type,
        status: s.status,
        progress: s.progress,
        findingCount: l?.findingCount,
        verifiedCount: l?.verifiedCount,
        highCount: l?.highCount,
        createdAt: l?.createdAt ?? "",
        updatedAt: s.finished_at || s.started_at || l?.updatedAt || "",
        source: "db",
      };
    });
  } catch {
    // 后端不可用时至少展示本地缓存（错误提示已由 axios 拦截器统一弹出）
    backend = [];
  }
  // 仅存在于本地、后端已无的记录（如后端 DB 被重置前留下的旧缓存），单独标注展示
  const backendIds = new Set(backend.map((r) => r.scanId));
  const localOnly: HistoryRow[] = local
    .filter((r) => !backendIds.has(r.scanId))
    .map((r) => ({ ...r, source: "local" }));
  records.value = [...backend, ...localOnly];
  loading.value = false;
}

function open(scanId: string) { router.push({ path: "/scans", query: { scanId } }); }

async function remove(row: HistoryRow) {
  await ElMessageBox.confirm(
    row.source === "local"
      ? "该记录仅存在于本地缓存，确认移除？"
      : "将从数据库彻底删除该扫描及其全部漏洞、证据与报告，确认删除？",
    "删除记录",
    { type: "warning" },
  );
  if (row.source === "db") {
    try {
      await ScanApi.remove(row.scanId);
    } catch {
      return; // 删除失败：错误已由拦截器提示，保留该行不误导
    }
  }
  removeHistory(row.scanId);
  ElMessage.success("已删除");
  await refresh();
}

async function clearLocalCache() {
  await ElMessageBox.confirm(
    "仅清空浏览器本地缓存（不影响后端数据库中的扫描记录），确认？",
    "清空本地缓存",
    { type: "warning" },
  );
  clearHistory();
  ElMessage.success("本地缓存已清空");
  await refresh();
}

function formatTime(value?: string) { return value ? new Date(value).toLocaleString() : "-"; }
function statusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value === "failed") return "danger";
  if (value === "partial_completed") return "warning";
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
