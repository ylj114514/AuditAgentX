<template>
  <el-card header="新建审计项目">
    <el-form :model="form" label-width="100px" style="max-width: 600px">
      <el-form-item label="项目名称">
        <el-input v-model="form.name" placeholder="例如 maccms-v10" />
      </el-form-item>
      <el-form-item label="来源类型">
        <el-select v-model="form.source_type">
          <el-option label="Git 仓库" value="git" />
          <el-option label="本地目录" value="local" />
        </el-select>
      </el-form-item>
      <el-form-item label="仓库 URL" v-if="form.source_type === 'git'">
        <el-input v-model="form.url" placeholder="https://github.com/..." />
      </el-form-item>
      <el-form-item label="本地路径" v-if="form.source_type === 'local'">
        <el-input v-model="form.local_path" />
      </el-form-item>
      <el-form-item label="分支">
        <el-input v-model="form.branch" placeholder="main" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="submit">创建并开始扫描</el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { reactive } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ProjectApi, ScanApi } from "../api";

const router = useRouter();
const form = reactive({
  name: "", source_type: "git", url: "", local_path: "", branch: "main",
});

async function submit() {
  const { data: proj } = await ProjectApi.create(form);
  await ProjectApi.parse(proj.project_id);
  const { data: scan } = await ScanApi.create({
    project_id: proj.project_id,
    enabled_tools: ["semgrep", "gitleaks", "custom"],
    enabled_agents: ["audit", "verify"],
    options: { enable_poc: false },
  });
  ElMessage.success(`扫描任务已创建：${scan.scan_id}`);
  router.push("/scans");
}
</script>
