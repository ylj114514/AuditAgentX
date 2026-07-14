<template>
  <el-container class="app-shell">
    <el-aside class="sidebar" width="260px">
      <div class="brand" @click="router.push('/')" role="button" tabindex="0">
        <div class="brand-mark">AX</div>
        <div>
          <strong>AuditAgentX</strong>
          <span>智能安全审计平台</span>
        </div>
      </div>
      <el-menu router :default-active="$route.path" class="nav-menu">
        <el-menu-item index="/">首页</el-menu-item>
        <el-menu-item index="/projects/new">新建项目</el-menu-item>
        <el-menu-item index="/scans">分析工作台</el-menu-item>
        <el-menu-item index="/history">查看历史项目</el-menu-item>
      </el-menu>
      <div class="sidebar-note">
        <b>本地授权测试</b>
        <p>动态验证仅面向本地靶场或授权环境。</p>
      </div>
    </el-aside>

    <el-container>
      <el-header class="topbar">
        <div>
          <span class="topbar-kicker">LLM-Agent Security Audit</span>
          <h2>开源项目安全缺陷自动审计与验证</h2>
        </div>
        <div class="topbar-actions">
          <el-button @click="router.push('/history')">查看历史项目</el-button>
          <el-button type="primary" @click="router.push('/projects/new')">新建审计</el-button>
        </div>
      </el-header>
      <el-main class="main-view">
        <router-view v-slot="{ Component, route }">
          <keep-alive>
            <component :is="Component" :key="route.path" />
          </keep-alive>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { useRouter } from "vue-router";

const router = useRouter();
</script>

<style>
:root {
  color: #162235;
  background: #eef3f8;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
  --ax-bg: #eef3f8;
  --ax-bg-strong: #e5edf7;
  --ax-surface: rgba(255, 255, 255, .92);
  --ax-surface-solid: #fff;
  --ax-text: #162235;
  --ax-muted: #667085;
  --ax-border: #dce6f0;
  --ax-blue: #2f80ed;
  --ax-blue-dark: #163b68;
  --ax-green: #12b76a;
  --ax-orange: #f59e0b;
  --ax-red: #d92d20;
  --ax-shadow: 0 18px 42px rgba(16, 32, 51, .08);
}
body {
  margin: 0;
  background:
    radial-gradient(circle at top left, rgba(47, 128, 237, .14), transparent 34rem),
    linear-gradient(135deg, var(--ax-bg), #f8fbff 52%, var(--ax-bg-strong));
}
* { box-sizing: border-box; }
.app-shell { min-height: 100vh; background: transparent; }
.sidebar {
  background: linear-gradient(180deg, #0b1728 0%, #10233a 62%, #0b1728 100%);
  color: #fff;
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 18px;
  box-shadow: 12px 0 36px rgba(15, 27, 45, .18);
}
.brand { display: flex; gap: 12px; align-items: center; padding: 10px; cursor: pointer; border-radius: 16px; transition: background .18s ease, transform .18s ease; }
.brand:hover { background: rgba(255,255,255,.07); transform: translateY(-1px); }
.brand-mark { width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center; background: linear-gradient(135deg, #2f80ed, #56ccf2); font-weight: 900; box-shadow: 0 10px 24px rgba(47, 128, 237, .34); }
.brand strong { display: block; font-size: 17px; }
.brand span { display: block; color: #adc1d6; font-size: 12px; margin-top: 2px; }
.nav-menu { border-right: 0; background: transparent; }
.nav-menu .el-menu-item { color: #d7e3f1; border-radius: 12px; margin-bottom: 7px; height: 44px; line-height: 44px; }
.nav-menu .el-menu-item.is-active { background: linear-gradient(90deg, rgba(47,128,237,.95), rgba(47,128,237,.48)); color: #fff; box-shadow: inset 3px 0 0 #8fd3ff; }
.nav-menu .el-menu-item:hover { background: rgba(255,255,255,.08); color: #fff; }
.sidebar-note { margin-top: auto; border: 1px solid rgba(255,255,255,.14); border-radius: 14px; padding: 14px; color: #d7e3f1; background: rgba(255,255,255,.06); }
.sidebar-note p { margin: 6px 0 0; font-size: 13px; line-height: 1.6; }
.topbar { height: 82px; display: flex; align-items: center; justify-content: space-between; padding: 0 28px; background: rgba(255,255,255,.78); border-bottom: 1px solid rgba(219,229,239,.86); backdrop-filter: blur(14px); }
.topbar h2 { margin: 3px 0 0; font-size: 20px; color: #162235; }
.topbar-kicker { font-size: 12px; color: #667085; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.topbar-actions { display: flex; gap: 10px; }
.main-view { padding: 28px; }
.el-card { border: 1px solid var(--ax-border); box-shadow: 0 12px 32px rgba(16, 32, 51, .04); }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: var(--ax-text); letter-spacing: -.02em; }
.page-title-row p { margin: 6px 0 0; color: var(--ax-muted); }
.eyebrow { margin: 0 0 6px; color: var(--ax-blue); font-weight: 900; letter-spacing: .1em; text-transform: uppercase; font-size: 12px; }
.panel-card, .tabs-card, .query-card, .history-card { border-radius: 18px; background: var(--ax-surface); }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
.summary-card { border-radius: 18px; background: linear-gradient(180deg, #fff, #f8fbff); }
.summary-card span { color: var(--ax-muted); font-size: 13px; }
.summary-card strong { display: block; color: var(--ax-text); letter-spacing: -.02em; }
.code-block { background: #0b1220; color: #d7e3f1; padding: 16px; border-radius: 14px; overflow: auto; border: 1px solid rgba(255,255,255,.08); }
.mini-pre { margin: 0; padding: 12px; background: #f5f8fc; border: 1px solid #e4ebf3; border-radius: 10px; overflow: auto; }
.status-pill { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 700; }
pre { white-space: pre-wrap; word-break: break-word; }
@media (max-width: 860px) {
  .app-shell { display: block; }
  .sidebar { width: 100% !important; min-height: auto; padding: 14px; }
  .nav-menu { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
  .nav-menu .el-menu-item { margin: 0; }
  .topbar { height: auto; padding: 18px; align-items: flex-start; gap: 14px; flex-direction: column; }
  .main-view { padding: 18px; }
  .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 560px) {
  .nav-menu { grid-template-columns: 1fr; }
  .topbar-actions { width: 100%; display: grid; grid-template-columns: 1fr; }
  .page-title-row { align-items: flex-start; flex-direction: column; }
  .summary-grid { grid-template-columns: 1fr; }
}
</style>
