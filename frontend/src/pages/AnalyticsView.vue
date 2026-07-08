<template>
  <section class="analytics-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Analytics</p>
        <h1>对比分析与统计</h1>
        <p>跨项目漏洞统计、被测项目横向对比，以及与同类开源审计系统的能力对标。</p>
      </div>
      <el-button :loading="loading" @click="loadAll">刷新数据</el-button>
    </div>

    <!-- 全局概览 -->
    <div class="summary-grid" v-if="overview">
      <el-card shadow="never" class="summary-card">
        <span>项目总数</span><strong>{{ overview.projects }}</strong>
        <small>已完成扫描 {{ overview.scans_done }} / {{ overview.scans }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>漏洞总数</span><strong>{{ overview.findings_total }}</strong>
        <small>已验证 {{ overview.findings_verified }} / 确认 {{ overview.findings_confirmed }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>严重级分布</span>
        <div class="sev-bar">
          <el-tag type="danger">危 {{ overview.severity_distribution.critical }}</el-tag>
          <el-tag type="warning">高 {{ overview.severity_distribution.high }}</el-tag>
          <el-tag>中 {{ overview.severity_distribution.medium }}</el-tag>
          <el-tag type="info">低 {{ overview.severity_distribution.low }}</el-tag>
        </div>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>Top 漏洞类型</span>
        <div class="top-types">
          <div v-for="t in overview.top_vulnerability_types.slice(0, 4)" :key="t.type">
            {{ t.type }} <b>×{{ t.count }}</b>
          </div>
          <span v-if="!overview.top_vulnerability_types.length" class="muted">暂无数据</span>
        </div>
      </el-card>
    </div>

    <el-card shadow="never" class="tabs-card">
      <el-tabs v-model="activeTab">
        <!-- 项目横向对比 -->
        <el-tab-pane label="被测项目对比" name="projects">
          <div class="tab-intro">
            <h2>被测项目横向对比</h2>
            <p>每个项目取最新一次扫描，比较漏洞规模、严重级分布与风险评分（支撑 ≥20 款项目检测）。</p>
          </div>
          <el-table :data="projects" stripe empty-text="暂无项目数据，先创建并扫描项目">
            <el-table-column prop="name" label="项目" min-width="160" show-overflow-tooltip />
            <el-table-column label="语言" min-width="140">
              <template #default="s">{{ (s.row.languages || []).join(", ") || "-" }}</template>
            </el-table-column>
            <el-table-column prop="loc" label="代码行" width="100" />
            <el-table-column prop="findings_total" label="漏洞数" width="90" sortable />
            <el-table-column label="严重级(危/高/中/低)" min-width="170">
              <template #default="s">
                {{ s.row.severity_distribution.critical }}/{{ s.row.severity_distribution.high }}/{{ s.row.severity_distribution.medium }}/{{ s.row.severity_distribution.low }}
              </template>
            </el-table-column>
            <el-table-column prop="verified" label="已验证" width="90" />
            <el-table-column prop="risk_score" label="风险分" width="100" sortable>
              <template #default="s"><el-tag :type="riskType(s.row.risk_score)">{{ s.row.risk_score }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="scan_status" label="扫描状态" width="110" />
          </el-table>
        </el-tab-pane>

        <!-- 同类系统能力对标 -->
        <el-tab-pane label="同类系统对标" name="benchmark">
          <div class="tab-intro">
            <h2>与同类开源审计系统能力对标</h2>
            <p v-if="benchmark">{{ benchmark.disclaimer }}</p>
          </div>
          <el-table v-if="benchmark" :data="benchmarkRows" border size="small">
            <el-table-column prop="label" label="能力维度" fixed min-width="170" />
            <el-table-column v-for="sys in benchmark.systems" :key="sys.name" :label="shortName(sys.name)" min-width="120" align="center">
              <template #default="s">
                <span :class="'cap cap-' + s.row[sys.name]">{{ capIcon(s.row[sys.name]) }}</span>
              </template>
            </el-table-column>
          </el-table>
          <div class="legend">图例：✔ 支持　◐ 部分支持　? 资料未明确</div>

          <div class="innovations" v-if="benchmark">
            <h3>本系统创新点</h3>
            <ul><li v-for="(item, i) in benchmark.innovations" :key="i">{{ item }}</li></ul>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { AnalyticsApi } from "../api";

const loading = ref(false);
const activeTab = ref("projects");
const overview = ref<any>(null);
const projects = ref<any[]>([]);
const benchmark = ref<any>(null);

// 把对标数据转成「每行一个维度、每列一个系统」的表格
const benchmarkRows = computed(() => {
  if (!benchmark.value) return [];
  return benchmark.value.dimensions.map((dim: any) => {
    const row: any = { label: dim.label };
    benchmark.value.systems.forEach((sys: any) => {
      row[sys.name] = sys.caps[dim.key] || "unknown";
    });
    return row;
  });
});

function shortName(name: string) {
  return name.replace(" (本系统)", "*");
}
function capIcon(v: string) {
  return v === "yes" ? "✔" : v === "partial" ? "◐" : "?";
}
function riskType(score: number) {
  if (score >= 20) return "danger";
  if (score >= 8) return "warning";
  return "info";
}

async function loadAll() {
  loading.value = true;
  try {
    const [o, p, b] = await Promise.all([
      AnalyticsApi.overview(), AnalyticsApi.projects(), AnalyticsApi.benchmark(),
    ]);
    overview.value = o.data;
    projects.value = p.data.projects;
    benchmark.value = b.data;
  } finally {
    loading.value = false;
  }
}

onMounted(loadAll);
</script>

<style scoped>
.analytics-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
.summary-card { border-radius: 18px; background: linear-gradient(180deg, #fff, #f8fbff); }
.summary-card span { color: #667085; font-size: 13px; }
.summary-card strong { display: block; font-size: 28px; margin: 6px 0 2px; color: #162235; }
.summary-card small { color: #98a2b3; }
.sev-bar { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.top-types { margin-top: 8px; font-size: 13px; line-height: 1.8; }
.muted { color: #98a2b3; }
.tabs-card { border-radius: 18px; overflow: hidden; }
.tab-intro { margin-bottom: 14px; }
.tab-intro h2 { margin: 0; }
.tab-intro p { color: #667085; margin: 6px 0 0; }
.cap { font-weight: 700; }
.cap-yes { color: #21a366; }
.cap-partial { color: #e08600; }
.cap-unknown { color: #98a2b3; }
.legend { margin-top: 10px; color: #667085; font-size: 13px; }
.innovations { margin-top: 22px; padding: 18px; border: 1px solid #dce6f0; border-radius: 16px; background: linear-gradient(180deg, #fff, #fbfdff); }
.innovations h3 { margin: 0 0 8px; color: #162235; }
.innovations li { color: #344054; line-height: 1.9; }
@media (max-width: 980px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
</style>
