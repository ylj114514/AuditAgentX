<template>
  <section class="home-shell">
    <div class="hero-panel">
      <div class="hero-copy">
        <p class="eyebrow">AuditAgentX</p>
        <h1>开源项目智能安全审计与验证系统</h1>
        <p class="hero-text">
          将仓库解析、静态扫描、LLM 智能体复核和证据链报告串成一条可查看的审计流程。
        </p>
        <div class="hero-actions">
          <el-button type="primary" size="large" @click="router.push('/projects/new')">新建审计项目</el-button>
          <el-button size="large" @click="router.push('/scans')">进入分析工作台</el-button>
          <el-button size="large" @click="router.push('/history')">查看历史项目</el-button>
        </div>
      </div>
      <div class="hero-metrics" aria-label="系统模块概览">
        <div class="metric-card"><strong>4</strong><span>核心模块</span></div>
        <div class="metric-card"><strong>3</strong><span>分析标签页</span></div>
        <div class="metric-card"><strong>50</strong><span>本地历史上限</span></div>
      </div>
    </div>

    <div class="quick-grid">
      <button class="quick-card" @click="router.push('/projects/new')">
        <span>01</span>
        <h2>创建项目</h2>
        <p>输入 Git 仓库或本地目录，自动解析语言、依赖和目录结构。</p>
      </button>
      <button class="quick-card" @click="router.push('/scans')">
        <span>02</span>
        <h2>静态分析</h2>
        <p>查看静态扫描、智能体复核和漏洞证据链，便于演示审计流程。</p>
      </button>
      <button class="quick-card" @click="router.push('/history')">
        <span>03</span>
        <h2>查看历史项目</h2>
        <p>本地缓存扫描记录，重新进入系统后可继续查看历史分析。</p>
      </button>
      <button class="quick-card" @click="router.push('/reports/latest')">
        <span>04</span>
        <h2>报告导出</h2>
        <p>生成包含漏洞列表、等级、证据链和修复建议的结构化报告。</p>
      </button>
    </div>

    <el-card class="history-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span>最近历史</span>
          <el-button text @click="router.push('/history')">全部记录</el-button>
        </div>
      </template>
      <el-empty v-if="history.length === 0" description="暂无历史记录，先创建一个审计任务" />
      <el-table v-else :data="history.slice(0, 5)" stripe>
        <el-table-column prop="projectName" label="项目" min-width="160" />
        <el-table-column prop="scanId" label="Scan ID" min-width="180" />
        <el-table-column prop="status" label="状态" width="110" />
        <el-table-column prop="findingCount" label="漏洞数" width="90" />
        <el-table-column label="操作" width="120">
          <template #default="scope">
            <el-button type="primary" link @click="openScan(scope.row.scanId)">查看</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import { readHistory, type AuditHistoryRecord } from "../api/history";

const router = useRouter();
const history = ref<AuditHistoryRecord[]>([]);

function refresh() {
  history.value = readHistory();
}

function openScan(scanId: string) {
  router.push({ path: "/scans", query: { scanId } });
}

onMounted(() => {
  refresh();
  window.addEventListener("audit-history-updated", refresh);
});

onUnmounted(() => window.removeEventListener("audit-history-updated", refresh));
</script>

<style scoped>
.home-shell { display: flex; flex-direction: column; gap: 24px; }
.hero-panel { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 24px; padding: 34px; background: #102033; color: #fff; border-radius: 18px; }
.eyebrow { margin: 0 0 10px; color: #8fd3ff; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
h1 { margin: 0; font-size: clamp(28px, 5vw, 46px); line-height: 1.1; }
.hero-text { max-width: 720px; color: #d8e6f3; font-size: 16px; line-height: 1.8; }
.hero-actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 22px; }
.hero-metrics { display: grid; gap: 12px; }
.metric-card { padding: 20px; border: 1px solid rgba(255,255,255,.18); border-radius: 14px; background: rgba(255,255,255,.08); }
.metric-card strong { display: block; font-size: 34px; }
.metric-card span { color: #d8e6f3; }
.quick-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
.quick-card { text-align: left; padding: 20px; border: 1px solid #d9e2ec; background: #fff; border-radius: 16px; cursor: pointer; transition: transform .16s ease, border-color .16s ease; }
.quick-card:hover { transform: translateY(-2px); border-color: #2f80ed; }
.quick-card span { color: #2f80ed; font-weight: 800; }
.quick-card h2 { margin: 12px 0 8px; font-size: 18px; color: #162235; }
.quick-card p { margin: 0; color: #667085; line-height: 1.7; }
.history-card { border-radius: 16px; }
.card-header { display: flex; align-items: center; justify-content: space-between; }
@media (max-width: 980px) { .hero-panel { grid-template-columns: 1fr; } .quick-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 560px) { .hero-panel { padding: 24px; } .quick-grid { grid-template-columns: 1fr; } }
</style>
