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
        <router-view />
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
}
body { margin: 0; background: #eef3f8; }
* { box-sizing: border-box; }
.app-shell { min-height: 100vh; background: #eef3f8; }
.sidebar { background: #0f1b2d; color: #fff; padding: 18px; display: flex; flex-direction: column; gap: 18px; }
.brand { display: flex; gap: 12px; align-items: center; padding: 8px; cursor: pointer; }
.brand-mark { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; background: #2f80ed; font-weight: 800; }
.brand strong { display: block; font-size: 17px; }
.brand span { display: block; color: #adc1d6; font-size: 12px; margin-top: 2px; }
.nav-menu { border-right: 0; background: transparent; }
.nav-menu .el-menu-item { color: #d7e3f1; border-radius: 10px; margin-bottom: 6px; }
.nav-menu .el-menu-item.is-active { background: #203755; color: #fff; }
.nav-menu .el-menu-item:hover { background: #172a44; }
.sidebar-note { margin-top: auto; border: 1px solid rgba(255,255,255,.14); border-radius: 14px; padding: 14px; color: #d7e3f1; background: rgba(255,255,255,.06); }
.sidebar-note p { margin: 6px 0 0; font-size: 13px; line-height: 1.6; }
.topbar { height: 82px; display: flex; align-items: center; justify-content: space-between; padding: 0 28px; background: rgba(255,255,255,.88); border-bottom: 1px solid #dbe5ef; backdrop-filter: blur(12px); }
.topbar h2 { margin: 3px 0 0; font-size: 20px; color: #162235; }
.topbar-kicker { font-size: 12px; color: #667085; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.topbar-actions { display: flex; gap: 10px; }
.main-view { padding: 28px; }
.el-card { border: 1px solid #dce6f0; }
pre { white-space: pre-wrap; word-break: break-word; }
@media (max-width: 860px) {
  .app-shell { display: block; }
  .sidebar { width: 100% !important; min-height: auto; }
  .topbar { height: auto; padding: 18px; align-items: flex-start; gap: 14px; flex-direction: column; }
  .main-view { padding: 18px; }
}
</style>
