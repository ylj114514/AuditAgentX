import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import App from "./App.vue";

import ProjectCreate from "./pages/ProjectCreate.vue";
import ScanDashboard from "./pages/ScanDashboard.vue";
import FindingDetail from "./pages/FindingDetail.vue";
import ReportView from "./pages/ReportView.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: ProjectCreate },
    { path: "/scans", component: ScanDashboard },
    { path: "/findings/:id", component: FindingDetail },
    { path: "/reports/:scanId", component: ReportView },
  ],
});

createApp(App).use(router).use(ElementPlus).mount("#app");
