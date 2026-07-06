<template>
  <el-container style="min-height: 100vh">
    <el-header style="display: flex; align-items: center; background: #2c3e50; color: #fff">
      <h2 style="margin: 0">AuditAgentX · 开源项目智能安全审计与验证系统</h2>
    </el-header>
    <el-container>
      <el-aside width="200px">
        <el-menu router :default-active="$route.path">
          <el-menu-item index="/">新建项目</el-menu-item>
          <el-menu-item index="/scans">扫描看板</el-menu-item>
        </el-menu>
      </el-aside>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts"></script>
