<template>
  <section class="dashboard-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Workbench</p>
        <h1>分析工作台</h1>
        <p>静态分析、动态分析和利用与复现代码分标签展示，支持历史记录查看。</p>
      </div>
      <div class="page-actions">
        <el-button
          v-if="status && !isTerminalStatus(status.status)"
          type="danger"
          plain
          :loading="cancelling"
          @click="cancelCurrentScan"
        >
          停止扫描
        </el-button>
        <el-button type="primary" @click="router.push('/projects/new')">新建审计</el-button>
      </div>
    </div>

    <el-card shadow="never" class="query-card">
      <div class="query-row">
        <el-autocomplete
          v-model="searchText"
          class="project-search"
          :fetch-suggestions="querySearch"
          :trigger-on-focus="true"
          fit-input-width
          clearable
          placeholder="输入项目名称，例如 maccms"
          @select="selectSuggestion"
          @keyup.enter="load"
        >
          <template #default="{ item }">
            <div class="suggestion-option">
              <div class="suggestion-main">
                <strong>{{ item.projectName }}</strong>
                <span v-if="item.duplicatedName">项目 ID：{{ item.projectId || "-" }}</span>
              </div>
              <div class="suggestion-sub">
                <span>创建时间：{{ formatTime(item.createdAt) }}</span>
                <span>Scan ID：{{ item.scanId }}</span>
              </div>
            </div>
          </template>
        </el-autocomplete>
        <el-button type="primary" :loading="loading" @click="load">查询</el-button>
        <el-button @click="router.push('/history')">历史记录</el-button>
      </div>
    </el-card>

    <div v-if="status" class="summary-grid">
      <el-card shadow="never" class="summary-card">
        <span>任务状态</span><strong><el-tag :type="statusTagType(status.status)">{{ statusLabel(status.status) }}</el-tag></strong><small>{{ status.current_stage || "等待阶段信息" }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>扫描进度</span><strong>{{ status.progress }}%</strong><el-progress :percentage="status.progress" :show-text="false" />
      </el-card>
      <el-card shadow="never" class="summary-card stage-summary-card">
        <span>阶段进度</span>
        <strong>{{ stageProgressLabel }}</strong>
        <small>{{ stageProgressHint }}</small>
        <el-progress
          v-if="stageProgressPercent !== null"
          :percentage="stageProgressPercent"
          :show-text="false"
        />
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>可处置漏洞</span><strong>{{ actionableFindings.length }}</strong><small>高危 {{ highCount }} / 已验证 {{ verifiedCount }} / 非处置结果 {{ informationalCount }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>报告</span><strong>HTML</strong><el-button text type="primary" @click="genReport">生成报告</el-button>
      </el-card>
    </div>

    <!-- Task 3/4：进度分区 + 候选计数分离 -->
    <el-card v-if="status" shadow="never" class="partition-card">
      <div class="partition-head">
        <h3>进度分区</h3>
        <el-tag v-if="verifyAllCandidates" type="warning" size="small" effect="light">本次将复核全部候选</el-tag>
      </div>
      <div class="partition-grid">
        <div v-for="p in progressPartitions" :key="p.key" class="partition-tile">
          <span class="partition-label">{{ p.label }}</span>
          <strong class="partition-value">{{ p.value }}</strong>
          <small class="partition-hint">{{ p.hint }}</small>
        </div>
      </div>
      <div class="partition-head partition-head--counts">
        <h3>候选计数</h3>
      </div>
      <div class="partition-grid partition-grid--counts">
        <div class="partition-tile">
          <span class="partition-label">原始静态发现</span>
          <strong class="partition-value">{{ candidateCounts.original }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">已送验证</span>
          <strong class="partition-value">{{ candidateCounts.sent }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">已完成验证</span>
          <strong class="partition-value">{{ candidateCounts.done }}</strong>
        </div>
        <div class="partition-tile">
          <span class="partition-label">待人工复核</span>
          <strong class="partition-value">{{ candidateCounts.needsReview }}</strong>
        </div>
      </div>
    </el-card>

    <el-card v-if="scannerStatuses.length" shadow="never" class="partition-card">
      <div class="partition-head"><h3>扫描器真实运行状态</h3></div>
      <el-table :data="scannerStatuses" size="small" stripe>
        <el-table-column prop="tool" label="工具" width="130" />
        <el-table-column label="状态" width="130">
          <template #default="scope">
            <el-tag :type="scope.row.partial_results ? 'warning' : (scope.row.success ? 'success' : 'danger')">
              {{ scope.row.partial_results ? '部分完成' : (scope.row.success ? '执行成功' : (scope.row.executed ? '执行失败' : '未启动')) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="finding_count" label="原始命中" width="100" />
        <el-table-column label="未覆盖文件" width="120">
          <template #default="scope">{{ scannerCoverageGapCount(scope.row) || DASH }}</template>
        </el-table-column>
        <el-table-column prop="error" label="错误 / 降级原因" min-width="260" show-overflow-tooltip />
      </el-table>
    </el-card>

    <el-alert
      v-if="staticCoverageGaps.length"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      :title="`静态覆盖不完整：${staticCoverageGaps.length} 个文件未被 Semgrep 完整解析；这些文件已优先交给 Custom/LLM 审计，不等于已确认漏洞。`"
      :description="staticCoverageGapSummary"
    />

    <el-alert
      v-if="status?.status === 'failed'"
      type="error"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描任务失败，请检查仓库地址、网络、分支或本地路径。'"
    />

    <el-alert
      v-if="status?.status === 'partial_completed'"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描已部分完成（partial_completed）：部分阶段被跳过或未产出完整结果，以下为已获得的结果。'"
    />

    <el-alert
      v-if="staleWarning"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      title="任务疑似停滞"
    >
      <template #default>
        <div class="warning-action-row">
          <span>{{ staleWarning }}</span>
          <el-button type="primary" plain size="small" :loading="loading" @click="load">刷新状态</el-button>
        </div>
      </template>
    </el-alert>

    <el-alert
      v-if="longRunningWarning"
      type="warning"
      show-icon
      :closable="false"
      class="error-alert"
      :title="longRunningWarning"
    >
      <template #default>
        <div class="warning-action-row">
          <span>{{ longRunningHint }}</span>
          <el-button
            v-if="status && !isTerminalStatus(status.status)"
            type="warning"
            plain
            size="small"
            :loading="cancelling"
            @click="cancelCurrentScan"
          >
            停止扫描
          </el-button>
        </div>
      </template>
    </el-alert>

    <el-card v-if="status" shadow="never" class="tabs-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro">
            <h2>静态分析结果</h2>
            <p>来自自定义规则、Semgrep、Gitleaks 等工具及候选漏洞归一化结果。</p>
          </div>
          <el-table :data="pagedStaticFindings" stripe empty-text="暂无静态分析结果">
            <el-table-column prop="type" label="类型" min-width="150" />
            <el-table-column label="严重级" width="110">
              <template #default="scope"><el-tag :type="severityType(scope.row.severity)">{{ scope.row.severity }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="file" label="文件" min-width="220" show-overflow-tooltip />
            <el-table-column prop="line" label="行" width="80" />
            <el-table-column label="置信度" width="100">
              <template #default="scope">{{ formatConfidence(scope.row.confidence) }}</template>
            </el-table-column>
            <el-table-column label="状态" width="130">
              <template #default="scope"><el-tag :type="findingStatusType(scope.row.status)">{{ findingStatusLabel(scope.row.status) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">详情</el-button></template>
            </el-table-column>
          </el-table>
          <div v-if="staticFindings.length > pageSize" class="table-footer">
            <span>共 {{ staticFindings.length }} 条结果，当前显示 {{ pagedStaticFindings.length }} 条</span>
            <el-pagination
              v-model:current-page="currentPage"
              v-model:page-size="pageSize"
              :page-sizes="[20, 50, 100]"
              layout="sizes, prev, pager, next"
              :total="staticFindings.length"
              small
            />
          </div>
        </el-tab-pane>

        <el-tab-pane label="动态分析" name="dynamic">
          <div class="tab-intro">
            <h2>动态验证结果</h2>
            <p>分别展示 HTTP 是否执行、HTTP 结论、Harness 结论与最终证据等级；“未获得复现证据”不代表漏洞不存在。</p>
          </div>

          <!-- Task 2：动态验证环境信息（从 stage_detail 读，缺字段显示 —） -->
          <el-descriptions
            v-if="hasDynamicInfo"
            :column="3"
            border
            class="dynamic-info-desc"
            title="动态验证环境"
          >
            <el-descriptions-item label="检测到的启动方式">{{ dynamicInfo.launchMethod }}</el-descriptions-item>
            <el-descriptions-item label="服务名">{{ dynamicInfo.serviceName }}</el-descriptions-item>
            <el-descriptions-item label="端口映射">{{ dynamicInfo.portMapping }}</el-descriptions-item>
            <el-descriptions-item label="健康检查结果">{{ dynamicInfo.healthCheck }}</el-descriptions-item>
            <el-descriptions-item label="回退 Harness 原因" :span="2">{{ dynamicInfo.harnessReason }}</el-descriptions-item>
          </el-descriptions>

          <el-alert
            v-if="nonDynamicCount > 0"
            type="info"
            show-icon
            :closable="false"
            class="dynamic-scope-alert"
            :title="`${nonDynamicCount} 条 finding 未进入动态验证`"
            description="这些结果可能属于静态/配置类漏洞、动态策略不适用，或未进入本次动态候选；它们不会混入下方已执行结果，也不代表漏洞不存在。"
          />

          <el-table v-loading="evidenceLoading" :data="dynamicRows" stripe empty-text="本次没有 finding 真正进入 HTTP、Harness 或项目沙箱验证">
            <el-table-column prop="type" label="漏洞类型" min-width="150" />
            <el-table-column prop="file" label="位置" min-width="220" show-overflow-tooltip />
            <el-table-column label="HTTP 结论" min-width="210">
              <template #default="scope">
                <el-tag :type="runtimeTagType(scope.row.runtime, scope.row)">
                  {{ runtimeStatusLabel(scope.row.runtime, scope.row) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Harness 结论" min-width="220">
              <template #default="scope">
                <el-tag :type="harnessStatusMeta(scope.row.harness).tone">
                  {{ harnessStatusMeta(scope.row.harness).label }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="证据等级" min-width="160">
              <template #default="scope">
                <el-tag :type="evidenceLevelMeta(scope.row.verification, scope.row).tone">
                  {{ evidenceLevelMeta(scope.row.verification, scope.row).label }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="HTTP 执行" min-width="180">
              <template #default="scope">{{ httpExecutionLabel(scope.row.runtime) }}</template>
            </el-table-column>
            <el-table-column label="命中特征" min-width="150">
              <template #default="scope">{{ scope.row.runtime?.matched_indicator || "-" }}</template>
            </el-table-column>
            <el-table-column label="状态码" width="90">
              <template #default="scope">{{ scope.row.runtime?.response_status || "-" }}</template>
            </el-table-column>
            <el-table-column label="Docker 引擎" width="140">
              <template #default="scope">
                {{ scope.row.sandbox?.docker_engine?.status || "-" }}
              </template>
            </el-table-column>
            <el-table-column label="项目沙箱" min-width="150">
              <template #default="scope">
                <el-tag :type="sandboxStatusMeta(scope.row.sandbox).tone">
                  {{ sandboxStatusMeta(scope.row.sandbox).label }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="说明" min-width="220" show-overflow-tooltip>
              <template #default="scope">{{ sandboxReason(scope.row.sandbox, scope.row.runtime) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">证据链</el-button></template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="利用与复现代码" name="exploit">
          <div class="tab-intro">
            <h2>利用计划与复现代码</h2>
            <p>仅展示已持久化且已确认的 HTTP/目标入口 PoC 代码。未确认 finding 只提供验证假设，不生成可复制利用脚本。</p>
          </div>
          <div v-if="!evidenceLoading" class="exploit-summary" role="status">
            <span><b>{{ confirmedReproductionCount }}</b> 个已确认复现 / PoC</span>
            <span>脚本仅允许 localhost / 127.0.0.1 / ::1</span>
          </div>
          <el-empty v-if="!evidenceLoading && exploitRows.length === 0" description="该扫描没有已持久化的端到端复现代码。" />
          <div v-else v-loading="evidenceLoading" class="exploit-list">
            <section v-for="group in exploitGroups" :key="group.status" class="exploit-group">
              <div class="exploit-group-head">
                <h3>{{ group.label }}</h3><el-tag size="small" :type="group.tone">{{ group.rows.length }}</el-tag>
              </div>
            <article v-for="row in group.rows" :key="row.finding_id" class="exploit-card">
              <div class="exploit-head">
                <div>
                  <div class="exploit-title-line">
                    <h3>{{ row.type }}</h3>
                    <el-tag size="small" :type="attackPlanTagType(row.attackPlan)">{{ attackPlanLabel(row.attackPlan) }}</el-tag>
                    <el-tag size="small" effect="plain" :type="severityType(row.severity)">{{ row.severity }}</el-tag>
                  </div>
                  <p>{{ row.attackPlan?.trigger_location || row.file }}</p>
                </div>
                <el-button type="primary" link @click="openFinding(row.finding_id)">查看详情</el-button>
              </div>
              <div class="exploit-plan-note">
                <b>证据状态</b>
                <span>{{ attackPlanDescription(row.attackPlan) }}</span>
              </div>
              <dl class="exploit-facts">
                <div><dt>攻击向量</dt><dd>{{ row.attackPlan?.attack_vector || "根据静态 source → sink 证据生成" }}</dd></div>
                <div><dt>利用路径</dt><dd>{{ row.attackPlan?.exploit_path || "详见漏洞详情中的证据链" }}</dd></div>
                <div><dt>验证方法</dt><dd>{{ row.attackPlan?.verification_method || "在一次性本地靶场中运行并观察成功判据" }}</dd></div>
              </dl>
              <div v-if="row.attackPlan?.payloads?.length" class="payload-row">
                <b>Payload</b><code v-for="payload in row.attackPlan.payloads.slice(0, 4)" :key="payload">{{ payload }}</code>
              </div>
              <div v-if="canDisplayAttackPlanCode(row)" class="exploit-code-head">
                <span>{{ attackPlanCodeCaption(row.attackPlan) }}</span>
                <el-button size="small" @click="copyAttackPlan(row)">复制代码</el-button>
              </div>
              <pre v-if="canDisplayAttackPlanCode(row)"><code>{{ row.attackPlan?.code }}</code></pre>
              <div v-if="row.artifactRows.length" class="artifact-state-list">
                <div v-for="artifact in row.artifactRows" :key="artifact.kind" class="artifact-state-item">
                  <b>{{ artifact.label }}</b>
                  <el-tag size="small" :type="artifact.tone">{{ artifact.summary }}</el-tag>
                  <span v-if="artifact.reason">{{ artifact.reason }}</span>
                </div>
              </div>
              <p class="exploit-safety">{{ row.attackPlan?.safety_notes || "仅限本地授权靶场环境。" }}</p>
            </article>
            </section>
          </div>
          <section v-if="!evidenceLoading && validationHypothesisRows.length" class="validation-hypothesis-panel">
            <h3>验证假设 / 人工复核</h3>
            <el-alert type="warning" show-icon :closable="false" title="未确认，未生成可执行利用代码。" />
            <el-table :data="validationHypothesisRows" size="small" class="validation-hypothesis-table">
              <el-table-column prop="type" label="漏洞类型" min-width="150" />
              <el-table-column label="位置" min-width="180"><template #default="scope">{{ scope.row.attackPlan?.trigger_location || scope.row.file }}</template></el-table-column>
              <el-table-column label="验证方法" min-width="280"><template #default="scope">{{ scope.row.attackPlan?.verification_method || "请人工确认 source→route/endpoint 与 sink。" }}</template></el-table-column>
              <el-table-column label="人工复核" width="100"><template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">查看</el-button></template></el-table-column>
            </el-table>
          </section>
        </el-tab-pane>

        <el-tab-pane label="Agent 通信流" name="agents">
          <div class="tab-intro">
            <h2>Agent 通信流</h2>
            <p>回放本次扫描保存的 ACP 消息，展示每个 Agent 的输入、输出、裁决和置信度。</p>
          </div>
          <div class="agent-toolbar">
            <el-select v-model="agentFilters.actor" clearable filterable placeholder="按 Agent 过滤">
              <el-option v-for="item in agentActorOptions" :key="item" :label="agentName(item)" :value="item" />
            </el-select>
            <el-select v-model="agentFilters.messageType" clearable filterable placeholder="按消息类型过滤">
              <el-option v-for="item in agentMessageTypeOptions" :key="item" :label="item" :value="item" />
            </el-select>
            <el-checkbox v-model="agentFilters.onlyProblems">只看异常 / 待复核</el-checkbox>
            <el-checkbox v-model="agentFilters.collapse">折叠重复 Verify 消息</el-checkbox>
          </div>
          <div class="agent-stats">
            <el-tag size="small" type="info">原始 {{ agentMessages.length }}</el-tag>
            <el-tag size="small" type="primary">当前 {{ displayAgentMessages.length }}</el-tag>
            <el-tag size="small" type="warning">Verify 待返回 {{ stageDetail.verify_pending || 0 }}</el-tag>
          </div>
          <el-empty v-if="!agentMessagesLoading && agentMessages.length === 0" description="暂无 Agent 通信记录，当前扫描未生成 ACP trace，可重新扫描生成。" />
          <el-timeline v-else v-loading="agentMessagesLoading" class="agent-timeline">
            <el-timeline-item
              v-for="msg in displayAgentMessages"
              :key="msg.groupKey || msg.message_id"
              :timestamp="msg._group ? `${formatTime(msg.first_timestamp)} - ${formatTime(msg.last_timestamp)}` : formatTime(msg.timestamp)"
              :type="agentTimelineType(msg)"
            >
              <div class="agent-message-card">
                <div class="agent-message-head">
                  <strong>{{ agentName(msg.sender) }} → {{ agentName(msg.receiver) }}</strong>
                  <div class="agent-message-tags">
                    <el-tag v-if="msg._group" size="small" type="info">x{{ msg.count }}</el-tag>
                    <el-tag size="small" :type="agentMessageTagType(msg)">{{ agentMessageLabel(msg) }}</el-tag>
                  </div>
                </div>
                <p>{{ msg.intent || msg.message_type }}</p>
                <div class="agent-message-meta">
                  <span>{{ msg.message_type }}</span>
                  <span v-if="msg._group">折叠 {{ msg.count }} 条相邻重复消息</span>
                  <span v-if="msg.confidence !== null && msg.confidence !== undefined">置信度 {{ msg.confidence }}</span>
                </div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-tab-pane>

        <el-tab-pane label="项目结构" name="structure">
          <div class="tab-intro">
            <h2>目标项目结构</h2>
            <p>RepoParserAgent 解析出的文件结构、语言构成、框架、入口与依赖清单。</p>
          </div>
          <el-empty
            v-if="!projectMetaLoading && !projectMeta"
            description="暂无项目结构信息。该数据在扫描解析阶段生成，可重新扫描生成。"
          />
          <div v-else v-loading="projectMetaLoading" class="structure-block">
            <el-descriptions :column="4" border class="evidence-desc">
              <el-descriptions-item label="文件数">{{ projectMeta?.file_count ?? "-" }}</el-descriptions-item>
              <el-descriptions-item label="代码行数">{{ projectMeta?.loc ?? "-" }}</el-descriptions-item>
              <el-descriptions-item label="语言" :span="2">
                <el-tag v-for="l in projectMeta?.languages || []" :key="l" size="small" class="chip">{{ l }}</el-tag>
                <span v-if="!(projectMeta?.languages || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="框架" :span="2">
                <el-tag v-for="fw in projectMeta?.frameworks || []" :key="fw" size="small" type="success" class="chip">{{ fw }}</el-tag>
                <span v-if="!(projectMeta?.frameworks || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="依赖清单" :span="2">
                <el-tag v-for="d in projectMeta?.dependencies || []" :key="d" size="small" type="warning" class="chip">{{ d }}</el-tag>
                <span v-if="!(projectMeta?.dependencies || []).length">-</span>
              </el-descriptions-item>
              <el-descriptions-item label="入口点" :span="4">
                <code v-for="e in projectMeta?.entrypoints || []" :key="e" class="entry-chip">{{ e }}</code>
                <span v-if="!(projectMeta?.entrypoints || []).length">-</span>
              </el-descriptions-item>
            </el-descriptions>

            <div class="file-tree-wrap">
              <h3>文件结构（{{ (projectMeta?.tree || []).length }} 个文件）</h3>
              <el-tree
                :data="fileTreeData"
                node-key="id"
                :props="{ label: 'label', children: 'children' }"
                :default-expand-all="fileTreeData.length <= 1"
                :filter-node-method="() => true"
              >
                <template #default="{ data }">
                  <span class="tree-node">
                    <span :class="data.isDir ? 'tree-dir' : 'tree-file'">{{ data.isDir ? "📁" : "📄" }} {{ data.label }}</span>
                    <el-tag v-if="!data.isDir && data.language && data.language !== 'Other'" size="small" class="tree-lang">{{ data.language }}</el-tag>
                  </span>
                </template>
              </el-tree>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { FindingApi, ProjectApi, ReportApi, ScanApi } from "../api";
import { readHistory, upsertHistory, type AuditHistoryRecord } from "../api/history";
import {
  evidenceLevelMeta,
  harnessStatusMeta,
  httpExecutionLabel,
  httpWasExecuted,
  runtimeStatusMeta,
  sandboxReason,
  sandboxStatusMeta,
} from "../utils/dynamicStatus";
import { canDisplayDetailedPoc, hasDisplayablePocCode } from "../utils/pocDisplay";

type SearchSuggestion = {
  value: string;
  record: AuditHistoryRecord;
  projectName: string;
  projectId?: string;
  scanId: string;
  createdAt: string;
  duplicatedName: boolean;
};

const route = useRoute();
const router = useRouter();
const scanId = ref((route.query.scanId as string) || "");
const searchText = ref((route.query.project as string) || scanId.value);
const historyRecords = ref<AuditHistoryRecord[]>([]);
const activeTab = ref((route.query.tab as string) || "static");
const loading = ref(false);
const cancelling = ref(false);
const evidenceLoading = ref(false);
const evidenceLoaded = ref(false);
const agentMessagesLoading = ref(false);
const agentMessagesLoaded = ref(false);
const status = ref<any>(null);
const findings = ref<any[]>([]);
const evidenceMap = ref<Record<string, any>>({});
const agentMessages = ref<any[]>([]);
const projectMeta = ref<any>(null);
const projectMetaLoaded = ref(false);
const projectMetaLoading = ref(false);
const currentPage = ref(1);
const pageSize = ref(50);
let searchTimer: ReturnType<typeof setTimeout> | undefined;

// ---- 前端 watchdog：客户端侧 stale 检测，防止把已停滞任务永久显示成 running ----
const STALE_MS = 90_000;              // 90s 内无任何进度/阶段变化即判定疑似停滞
const lastActivityAt = ref<number>(Date.now());
const nowTick = ref<number>(Date.now());
let lastActivitySignature = "";
function statusActivitySignature(data: any) {
  const sd = data?.stage_detail || {};
  return [
    data?.status, data?.progress, data?.current_stage,
    sd.verify_results, sd.verify_requests, sd.dynamic_completed, sd.dynamic_phase,
  ].join("|");
}
// 每次拿到最新状态时调用：进度/阶段有变化就刷新活动时间，并推进 nowTick 让 stale 计算生效
function noteStatusActivity(data: any) {
  const sig = statusActivitySignature(data);
  if (sig !== lastActivitySignature) {
    lastActivitySignature = sig;
    lastActivityAt.value = Date.now();
  }
  nowTick.value = Date.now();
}

const agentFilters = reactive({
  actor: "",
  messageType: "",
  onlyProblems: false,
  collapse: true,
});

function findingEvidence(item: any) {
  return evidenceMap.value[item.finding_id] || item.evidence || {};
}
function isActionableFinding(item: any) {
  const evidence = findingEvidence(item);
  const status = String(item.status || "").toLowerCase();
  const complete = evidence.evidence_complete ?? evidence.verification?.evidence_complete;
  return status === "confirmed" && complete === true;
}
const actionableFindings = computed(() => findings.value.filter(
  (item) => isActionableFinding(item),
));
const informationalCount = computed(() => findings.value.length - actionableFindings.value.length);
const highCount = computed(() => actionableFindings.value.filter((item) => ["high", "critical"].includes(String(item.severity).toLowerCase())).length);
const verifiedCount = computed(() => findings.value.filter((item) => item.verified).length);
const staticFindings = computed(() => findings.value);
const pagedStaticFindings = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  return staticFindings.value.slice(start, start + pageSize.value);
});
const dynamicRows = computed(() => findings.value
  .map((item) => {
    const evidence = evidenceMap.value[item.finding_id] || {};
    return {
      ...item,
      runtime: evidence.runtime,
      sandbox: evidence.sandbox,
      harness: evidence.harness,
      verification: evidence.verification,
    };
  })
  .filter((item) => {
    const runtimeStatus = String(item.runtime?.reproduction_status || "not_executed").toLowerCase();
    const harnessVerdict = String(item.harness?.verdict || "not_executed").toLowerCase();
    return Boolean(
      httpWasExecuted(item.runtime)
      || item.runtime?.setup_records?.length
      || runtimeStatus !== "not_executed"
      || harnessVerdict !== "not_executed"
      || item.sandbox,
    );
  }));
const nonDynamicCount = computed(() => Math.max(0, findings.value.length - dynamicRows.value.length));
function legacyAttackPlan(item: any, evidence: any) {
  const legacy = evidence?.exploit;
  const artifact = evidence?.artifacts?.validated_poc || evidence?.poc_file || {};
  if (!hasDisplayablePocCode(legacy?.exploit_code)) return null;
  return {
    plan_status: "framework_confirmed_replay",
    label: "旧版已确认 PoC",
    code: legacy.exploit_code,
    trigger_location: legacy.trigger_location,
    attack_vector: legacy.attack_vector,
    exploit_path: legacy.exploit_path,
    payloads: legacy.payloads || [],
    verification_method: legacy.verification_method,
    safety_notes: "仅限本地授权靶场环境。",
    persistence_status: artifact.persistence_status,
    artifact_sha256: artifact.sha256,
  };
}
function artifactRows(evidence: any) {
  const artifacts = evidence?.artifacts || {};
  return [
    { kind: "validated_poc", label: "Primary PoC", value: artifacts.validated_poc },
  ].filter(({ value }) => value && Object.values(value).some((item) => item !== null && item !== undefined && item !== ""))
    .map(({ kind, label, value }) => {
      const persistence = String(value.persistence_status || "");
      const generation = String(value.generation_status || "");
      const failed = persistence === "persistence_failed";
      const pending = String(value.validation_status || "") === "validation_pending";
      return {
        kind, label, tone: failed ? "danger" : pending ? "warning" : persistence === "persisted" ? "success" : "info",
        summary: failed ? "制品保存失败 / 证据不完整" : pending ? "尚未确认" : persistence === "persisted" ? "制品已保存" : generation === "not_generated" ? "未生成" : "制品状态待定",
        reason: value.failure_code || value.error_summary || "",
      };
    });
}
const exploitRows = computed(() => findings.value
  .map((item) => {
    const evidence = findingEvidence(item);
    const attackPlan = evidence?.attack_plan || legacyAttackPlan(item, evidence);
    return { ...item, attackPlan, evidence, artifactRows: artifactRows(evidence) };
  })
  .filter((item) => canDisplayDetailedPoc({ finding: item, evidence: item.evidence })
    && hasDisplayablePocCode(item.attackPlan?.code)));
const validationHypothesisRows = computed(() => findings.value
  .map((item) => {
    const evidence = findingEvidence(item);
    return { ...item, evidence, attackPlan: evidence?.attack_plan || legacyAttackPlan(item, evidence) };
  })
  .filter((item) => item.attackPlan && !canDisplayDetailedPoc({ finding: item, evidence: item.evidence })));
function normalizedPlanStatus(plan: any) {
  const status = String(plan?.plan_status || "").toLowerCase();
  if (status === "validated_replay") return "framework_confirmed_replay";
  if (status === "validated_reproduction") return "target_harness_reproduction";
  return status || "unknown";
}
const confirmedReproductionCount = computed(() => exploitRows.value.length);
const exploitGroups = computed(() => {
  const order = ["framework_confirmed_replay", "target_harness_reproduction"];
  return order.map((status) => ({
    status,
    label: attackPlanLabel({ plan_status: status }),
    tone: attackPlanTagType({ plan_status: status }),
    rows: exploitRows.value.filter((row) => normalizedPlanStatus(row.attackPlan) === status || (status === "unknown" && !order.includes(normalizedPlanStatus(row.attackPlan)))),
  })).filter((group) => group.rows.length > 0);
});

const stageDetail = computed<Record<string, any>>(() => status.value?.stage_detail || {});
const scannerStatuses = computed<any[]>(() => stageDetail.value.scanner_status || []);
function scannerCoverageGaps(row: any): any[] {
  const workspace = Array.isArray(row?.workspace?.coverage_missing_files)
    ? row.workspace.coverage_missing_files : [];
  const batches = Array.isArray(row?.batches) ? row.batches : [];
  return [...workspace, ...batches.flatMap((batch: any) =>
    Array.isArray(batch?.coverage_missing_files) ? batch.coverage_missing_files : [])];
}
function scannerCoverageGapCount(row: any): number {
  return new Set(scannerCoverageGaps(row).map((item: any) => `${item?.file}:${item?.reason}`)).size;
}
const staticCoverageGaps = computed(() => {
  const unique = new Map<string, { file: string; reason: string }>();
  scannerStatuses.value.forEach((row) => scannerCoverageGaps(row).forEach((item: any) => {
    const file = String(item?.file || "");
    const reason = String(item?.reason || "unknown");
    if (file) unique.set(`${file}:${reason}`, { file, reason });
  }));
  return [...unique.values()];
});
const staticCoverageGapSummary = computed(() => staticCoverageGaps.value
  .slice(0, 8)
  .map((item) => `${item.file}（${item.reason === "parser_unsupported" ? "解析器不支持" : "文件过大"}）`)
  .join("；"));

const DASH = "—";
function numOrDash(value: any) {
  const n = Number(value);
  return Number.isFinite(n) && value !== null && value !== undefined && value !== "" ? n : DASH;
}

// 目标沙箱 / 健康检查状态 → 中文标签（供动态验证信息展示与回退原因用）
function targetStatusLabel(statusValue?: string) {
  const map: Record<string, string> = {
    started: "已启动，健康检查通过",
    not_available: "靶场不可用（回退 Harness）",
    not_web_target: "非 Web 项目，HTTP 不适用",
    sandbox_start_failed: "沙箱启动失败",
    sandbox_build_timeout: "沙箱构建超时",
    sandbox_cancelled: "沙箱执行已取消",
    cancelling: "正在取消",
    execution_error: "执行异常",
    blocked_by_environment: "受运行环境阻断",
    health_check_failed: "健康检查失败",
    dependency_install_failed: "依赖安装失败",
    unsafe_project_config: "项目容器配置被安全策略阻止",
    not_installed: "Docker 未安装",
    unsupported: "当前环境不支持自启动 Docker",
    start_failed: "启动失败",
    start_timeout: "启动超时",
    launch_not_detected: "未识别启动方式",
  };
  return map[String(statusValue || "").toLowerCase()] || statusValue || DASH;
}

// Task 2：动态验证信息（从 stage_detail 读，读不到显示 —，不报错）
// launch_plan 来自后端 config.options.dynamic_target.launch_plan，通常仅在用户高级覆盖或后端回写后有值。
const launchPlan = computed<Record<string, any>>(() => stageDetail.value.launch_plan || {});
const dynamicInfo = computed(() => {
  const lp = launchPlan.value;
  const d = stageDetail.value;
  const targetStatus = d.dynamic_target_status;
  const isStarted = String(targetStatus || "").toLowerCase() === "started";
  return {
    // 检测到的启动方式：优先 launch_plan.source/framework，回退动态目标模式
    launchMethod: lp.source || lp.framework || lp.run_command || lp.command || d.dynamic_target_mode || DASH,
    // 服务名：compose / framework（后端暂无独立 service_name 字段）
    serviceName: lp.compose || lp.framework || DASH,
    // 端口映射：launch_plan.port（后端暂未把真实 host->container 映射写入 stage_detail）
    portMapping: lp.port ? String(lp.port) : DASH,
    // 健康检查结果：dynamic_target_status
    healthCheck: targetStatus ? targetStatusLabel(targetStatus) : DASH,
    // 回退到 Harness 的原因：非 started 时用 dynamic_detail / 状态标签
    harnessReason: targetStatus && !isStarted
      ? (d.dynamic_detail || targetStatusLabel(targetStatus))
      : DASH,
  };
});
const hasDynamicInfo = computed(() => {
  const d = stageDetail.value;
  return Boolean(
    d.dynamic_target_mode || d.dynamic_target_status || d.dynamic_phase ||
    d.dynamic_total || Object.keys(launchPlan.value).length,
  );
});

// Task 4：候选计数分离（从 findings 按 status 归类 + stage_detail 的验证收发计数）
const needsReviewCount = computed(() =>
  findings.value.filter((f) => String(f.status || "").toLowerCase().includes("review")).length);
const candidateCounts = computed(() => ({
  original: numOrDash(stageDetail.value.raw_finding_count),     // 工具原始静态发现数
  sent: numOrDash(stageDetail.value.verify_requests),          // 已送验证
  done: numOrDash(stageDetail.value.verify_results),           // 已完成验证
  needsReview: needsReviewCount.value,                         // 待人工复核
}));
// max_verify_candidates=0（或不限）时，明确显示"本次将复核全部候选"
const verifyAllCandidates = computed(() => {
  const raw = stageDetail.value.max_verify_candidates;
  return raw !== null && raw !== undefined && Number(raw) <= 0;
});

// Task 3：进度分区（静态扫描 / 静态复核 / 动态发现 / 动态验证 / 失败-跳过）
const progressPartitions = computed(() => {
  const d = stageDetail.value;
  const dynTotal = Number(d.dynamic_total || 0);
  const dynDone = Number(d.dynamic_completed || 0);
  const verReq = Number(d.verify_requests || 0);
  const verRes = Number(d.verify_results || 0);
  return [
    { key: "static", label: "静态扫描", value: String(numOrDash(d.raw_finding_count)), hint: "工具原始发现" },
    { key: "review", label: "静态复核", value: verReq > 0 ? `${verRes}/${verReq}` : String(verRes || 0), hint: "VerifyAgent" },
    { key: "discover", label: "动态发现", value: dynTotal > 0 ? String(dynTotal) : DASH, hint: "送验证候选" },
    { key: "dynamic", label: "动态验证", value: dynTotal > 0 ? `${dynDone}/${dynTotal}` : DASH, hint: d.dynamic_phase || "未开始" },
    { key: "skipped", label: "未自动定性", value: String(needsReviewCount.value), hint: "待人工复核" },
  ];
});

// Task 5：stale 检测——非终态且 90s 无变化时判定疑似停滞
const isStale = computed(() => {
  if (!status.value || isTerminalStatus(status.value.status)) return false;
  return nowTick.value - lastActivityAt.value >= STALE_MS;
});
const staleWarning = computed(() => {
  if (!isStale.value) return "";
  const secs = Math.floor((nowTick.value - lastActivityAt.value) / 1000);
  return `任务已 ${secs} 秒无任何进度或阶段变化，疑似停滞。后端可能已置为 partial_completed / failed，请点击"查询"刷新，或查看当前阶段日志。`;
});
const elapsedMinutes = computed(() => {
  const seconds = Number(stageDetail.value.elapsed_seconds || 0);
  return Math.floor(seconds / 60);
});
// ExploitAgent/DynamicVerify 是动态验证阶段，不应复用 VerifyAgent 的
// 静态复核计数；否则会把“已返回的静态复核数/配置上限”误显示成动态进度。
const isVerifyAgentStage = computed(() => /^verifyagent\b/i.test(
  String(status.value?.current_stage || "").trim(),
));
const isDynamicStage = computed(() => /dynamic|harness|exploit/i.test(
  String(status.value?.current_stage || ""),
));
const stageProgressPercent = computed(() => {
  if (!status.value) return null;
  const total = isVerifyAgentStage.value
    ? Number(stageDetail.value.max_verify_candidates || stageDetail.value.verify_requests || 0)
    : (isDynamicStage.value ? Number(stageDetail.value.dynamic_total || 0) : 0);
  const done = isVerifyAgentStage.value
    ? Number(stageDetail.value.verify_results || 0)
    : (isDynamicStage.value ? Number(stageDetail.value.dynamic_completed || 0) : 0);
  if (!Number.isFinite(total) || total <= 0) return null;
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
});
const stageProgressLabel = computed(() => {
  const stage = status.value?.current_stage || "等待阶段信息";
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    const done = Number(detail.verify_results || 0);
    const total = Number(detail.max_verify_candidates || detail.verify_requests || 0);
    return total > 0 ? `${done}/${total}` : `${done}`;
  }
  if (isDynamicStage.value) {
    const done = Number(detail.dynamic_completed || 0);
    const total = Number(detail.dynamic_total || 0);
    const phase = String(detail.dynamic_phase || "动态验证");
    return total > 0 ? `${phase} ${done}/${total}` : phase;
  }
  return stage;
});
const stageProgressHint = computed(() => {
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    const pending = Number(detail.verify_pending || 0);
    const workers = Number(detail.max_verify_workers || 0);
    return `待返回 ${pending}，并发 ${workers || "-"}，已运行 ${elapsedMinutes.value} 分钟`;
  }
  if (isDynamicStage.value) {
    return detail.dynamic_detail || `已运行 ${elapsedMinutes.value} 分钟`;
  }
  return `已运行 ${elapsedMinutes.value} 分钟`;
});
const longRunningWarning = computed(() => {
  if (!status.value || isTerminalStatus(status.value.status)) return "";
  const stage = String(status.value.current_stage || "").toLowerCase();
  const minutes = elapsedMinutes.value;
  if (isVerifyAgentStage.value && minutes >= 10) return `VerifyAgent 已运行 ${minutes} 分钟，可能被 LLM 重试或候选数量拖慢`;
  if ((stage.includes("dynamic") || stage.includes("harness")) && minutes >= 15) return `动态验证阶段已运行 ${minutes} 分钟，可能卡在沙箱启动、健康检查或请求超时`;
  if (minutes >= 25) return `扫描已运行 ${minutes} 分钟，建议检查当前阶段日志或停止后调小候选数量`;
  return "";
});
const longRunningHint = computed(() => {
  const detail = stageDetail.value;
  if (isVerifyAgentStage.value) {
    return `当前 Verify 请求 ${detail.verify_requests || 0}，结果 ${detail.verify_results || 0}，上限 ${detail.max_verify_candidates || "-"}`;
  }
  if (isDynamicStage.value) {
    return `动态阶段：${detail.dynamic_phase || "准备中"}，${detail.dynamic_completed || 0}/${detail.dynamic_total || 0}；${detail.dynamic_detail || "等待执行结果"}`;
  }
  return "可以先停止扫描，再降低候选上限或切换 Quick 模式复测。";
});

const agentActorOptions = computed(() => {
  const names = new Set<string>();
  agentMessages.value.forEach((msg) => {
    if (msg.sender) names.add(msg.sender);
    if (msg.receiver) names.add(msg.receiver);
  });
  return Array.from(names).sort();
});
const agentMessageTypeOptions = computed(() => Array.from(new Set(
  agentMessages.value.map((msg) => String(msg.message_type || "")).filter(Boolean),
)).sort());
const filteredAgentMessages = computed(() => agentMessages.value.filter((msg) => {
  if (agentFilters.actor && msg.sender !== agentFilters.actor && msg.receiver !== agentFilters.actor) return false;
  if (agentFilters.messageType && msg.message_type !== agentFilters.messageType) return false;
  if (agentFilters.onlyProblems && !isProblemAgentMessage(msg)) return false;
  return true;
}));
const displayAgentMessages = computed(() => {
  if (!agentFilters.collapse) return filteredAgentMessages.value;
  const grouped: any[] = [];
  for (const msg of filteredAgentMessages.value) {
    const prev = grouped[grouped.length - 1];
    const key = agentGroupKey(msg);
    if (prev?.groupKey === key) {
      prev.count += 1;
      prev.last_timestamp = msg.timestamp;
      prev.confidence = msg.confidence ?? prev.confidence;
      continue;
    }
    grouped.push({
      ...msg,
      _group: true,
      groupKey: key,
      count: 1,
      first_timestamp: msg.timestamp,
      last_timestamp: msg.timestamp,
    });
  }
  return grouped.map((msg) => (msg.count > 1 ? msg : { ...msg, _group: false }));
});

// 把扁平的 [{path, language}] 文件列表拼成 el-tree 的嵌套结构
const fileTreeData = computed(() => {
  const roots: any[] = [];
  const dirMap = new Map<string, any>();
  const files = (projectMeta.value?.tree || []) as Array<{ path: string; language?: string }>;
  for (const f of files) {
    const parts = String(f.path).split("/").filter(Boolean);
    let level = roots;
    let prefix = "";
    parts.forEach((part, idx) => {
      prefix = prefix ? `${prefix}/${part}` : part;
      const isLeaf = idx === parts.length - 1;
      if (isLeaf) {
        level.push({ id: prefix, label: part, isDir: false, language: f.language });
        return;
      }
      let dir = dirMap.get(prefix);
      if (!dir) {
        dir = { id: prefix, label: part, isDir: true, children: [] };
        dirMap.set(prefix, dir);
        level.push(dir);
      }
      level = dir.children;
    });
  }
  // 目录在前、同类按名排序
  const sortLevel = (nodes: any[]) => {
    nodes.sort((a, b) => (a.isDir === b.isDir ? a.label.localeCompare(b.label) : a.isDir ? -1 : 1));
    nodes.forEach((n) => n.children && sortLevel(n.children));
  };
  sortLevel(roots);
  return roots;
});

async function ensureProjectStructureLoaded() {
  if (projectMetaLoaded.value || projectMetaLoading.value) return;
  const pid = status.value?.project_id;
  if (!pid) return;
  projectMetaLoading.value = true;
  try {
    const { data } = await ProjectApi.tree(pid);
    projectMeta.value = data;
    projectMetaLoaded.value = true;
  } catch {
    projectMeta.value = null;
  } finally {
    projectMetaLoading.value = false;
  }
}
const historySearchIndex = computed(() => historyRecords.value.map((record) => ({
  record,
  projectName: getProjectName(record),
  normalizedName: normalize(getProjectName(record)),
  normalizedProjectId: normalize(record.projectId),
  normalizedScanId: normalize(record.scanId),
})));

async function load() {
  const keyword = searchText.value.trim();
  if (!keyword) {
    ElMessage.warning("请输入项目名称");
    return;
  }
  refreshHistoryRecords();
  const record = resolveSearchRecord(keyword);
  if (record) {
    await loadRecord(record);
    return;
  }
  if (/^scan_/i.test(keyword)) {
    await loadByScanId(keyword);
    return;
  }
  // 浏览器 localStorage 未命中时，回退到后端按项目名/ID 查询（历史的真实数据源）。
  // 解决「清缓存/换浏览器/经脚本跑扫描」导致本地查不到的问题。
  loading.value = true;
  let matches: any[] = [];
  try {
    const { data } = await ScanApi.list(keyword);
    matches = data.scans || [];
  } finally {
    loading.value = false;
  }
  if (matches.length === 0) {
    ElMessage.warning("未找到该项目的扫描记录，请确认项目名称，或先发起一次审计");
    return;
  }
  if (matches.length > 1) {
    ElMessage.info(`找到 ${matches.length} 条匹配记录，已加载最近一条`);
  }
  const hit = matches[0];
  await loadByScanId(hit.scan_id);
  // 回写带真实项目名的历史，下次可直接本地命中
  upsertHistory({
    scanId: hit.scan_id,
    projectId: hit.project_id,
    projectName: hit.project_name,
    target: hit.target,
    sourceType: hit.source_type,
    status: hit.status,
    progress: hit.progress,
  });
}

async function loadRecord(record: AuditHistoryRecord) {
  const duplicatedName = isDuplicatedProjectName(record);
  searchText.value = buildSuggestionValue(record, duplicatedName);
  await loadByScanId(record.scanId);
}

async function loadByScanId(nextScanId: string) {
  if (!nextScanId) return;
  stopScanPolling();
  scanId.value = nextScanId;
  loading.value = true;
  try {
    const { data } = await ScanApi.get(nextScanId);
    status.value = data;
    lastActivitySignature = "";        // 切换扫描时重置活动基线，避免旧任务的 stale 误判
    noteStatusActivity(data);
    const { data: f } = await ScanApi.findings(nextScanId);
    findings.value = f.findings;
    currentPage.value = 1;
    evidenceMap.value = {};
    agentMessages.value = [];
    evidenceLoaded.value = false;
    agentMessagesLoaded.value = false;
    projectMeta.value = null;
    projectMetaLoaded.value = false;
    if (activeTab.value === "dynamic" || activeTab.value === "exploit") {
      await ensureEvidenceLoaded();
    }
    if (activeTab.value === "agents") {
      await ensureAgentMessagesLoaded();
    }
    upsertHistory({
      scanId: nextScanId,
      projectId: data.project_id,
      status: data.status,
      progress: data.progress,
      findingCount: findings.value.length,
      highCount: highCount.value,
      verifiedCount: verifiedCount.value,
    });
    // 扫描仍在进行时启动轮询，实时刷新进度/状态/漏洞，无需手动重查
    startScanPolling();
  } finally {
    loading.value = false;
  }
}

const POLL_MS = 3000;
const CANCELLING_POLL_MS = 6000;
let pollTimer: ReturnType<typeof setInterval> | undefined;
let pollInFlight = false;
let nextStatusRequestSequence = 0;
let appliedStatusRequestSequence = 0;

function applyFreshStatus(requestSequence: number, requestedScanId: string, data: any): boolean {
  if (requestedScanId !== scanId.value || requestSequence <= appliedStatusRequestSequence) return false;
  appliedStatusRequestSequence = requestSequence;
  status.value = data;
  noteStatusActivity(data);
  return true;
}

function isTerminalStatus(s?: string) {
  const v = String(s || "").toLowerCase();
  return v === "done" || v === "finished" || v === "failed"
    || v === "cancelled" || v === "partial_completed";
}

function stopScanPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
}

async function cancelCurrentScan() {
  if (!scanId.value || cancelling.value) return;
  try {
    await ElMessageBox.confirm(
      "停止后，后端会尽快终止后续阶段和未开始的 Verify 任务；已经发出的单次请求可能需要等待返回。",
      "确认停止扫描",
      { confirmButtonText: "停止扫描", cancelButtonText: "继续扫描", type: "warning" },
    );
  } catch {
    return;
  }
  cancelling.value = true;
  try {
    await ScanApi.cancel(scanId.value);
    const requestedScanId = scanId.value;
    const requestSequence = ++nextStatusRequestSequence;
    const { data } = await ScanApi.get(requestedScanId);
    if (!applyFreshStatus(requestSequence, requestedScanId, data)) return;
    // cancelling 是过渡态：继续低频轮询，直到后端收敛为 cancelled/done/failed 等终态。
    startScanPolling();
    upsertHistory({
      scanId: scanId.value,
      projectId: data.project_id,
      status: data.status,
      progress: data.progress,
      findingCount: findings.value.length,
      highCount: highCount.value,
      verifiedCount: verifiedCount.value,
    });
    ElMessage.success("已请求停止扫描");
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "停止扫描失败");
  } finally {
    cancelling.value = false;
  }
}

function startScanPolling() {
  stopScanPolling();
  if (!scanId.value || isTerminalStatus(status.value?.status)) return;
  pollTimer = setInterval(async () => {
    if (!scanId.value) { stopScanPolling(); return; }
    if (pollInFlight) return;
    const requestedScanId = scanId.value;
    const requestSequence = ++nextStatusRequestSequence;
    pollInFlight = true;
    try {
      const { data } = await ScanApi.get(requestedScanId);
      if (!applyFreshStatus(requestSequence, requestedScanId, data)) return;
      const { data: f } = await ScanApi.findings(requestedScanId);
      if (requestedScanId !== scanId.value || requestSequence !== appliedStatusRequestSequence) return;
      findings.value = f.findings;
      upsertHistory({
        scanId: scanId.value, projectId: data.project_id, status: data.status,
        progress: data.progress, findingCount: findings.value.length,
        highCount: highCount.value, verifiedCount: verifiedCount.value,
      });
      if (activeTab.value === "agents") {
        await loadAgentMessages(scanId.value);
        agentMessagesLoaded.value = true;
      }
      if (isTerminalStatus(data.status)) {
        stopScanPolling();
        // 扫描完成：让证据/Agent 消息在当前标签重新加载
        evidenceLoaded.value = false;
        agentMessagesLoaded.value = false;
        if (activeTab.value === "dynamic" || activeTab.value === "exploit") await ensureEvidenceLoaded();
        if (activeTab.value === "agents") await ensureAgentMessagesLoaded();
      }
    } catch {
      /* 瞬时网络错误忽略，下次轮询自动重试 */
    } finally {
      pollInFlight = false;
    }
  }, String(status.value?.status || "").toLowerCase() === "cancelling" ? CANCELLING_POLL_MS : POLL_MS);
}

async function loadEvidence() {
  const pairs = await mapLimit(findings.value, 8, async (finding) => {
    try {
      const { data } = await FindingApi.evidence(finding.finding_id);
      return [finding.finding_id, data.evidence];
    } catch {
      return [finding.finding_id, null];
    }
  });
  evidenceMap.value = Object.fromEntries(pairs.filter(([, evidence]) => evidence));
}

async function ensureEvidenceLoaded() {
  if (evidenceLoaded.value || evidenceLoading.value) return;
  evidenceLoading.value = true;
  try {
    if (findings.value.length > 0) {
      await loadEvidence();
    }
    evidenceLoaded.value = true;
  } finally {
    evidenceLoading.value = false;
  }
}

async function loadAgentMessages(nextScanId: string) {
  try {
    const { data } = await ScanApi.agentMessages(nextScanId);
    agentMessages.value = data.messages || [];
  } catch {
    agentMessages.value = [];
  }
}

async function ensureAgentMessagesLoaded() {
  if (agentMessagesLoaded.value || agentMessagesLoading.value || !scanId.value) return;
  agentMessagesLoading.value = true;
  try {
    await loadAgentMessages(scanId.value);
    agentMessagesLoaded.value = true;
  } finally {
    agentMessagesLoading.value = false;
  }
}

async function genReport() {
  if (!scanId.value) {
    ElMessage.warning("请先查询一个扫描任务");
    return;
  }
  try {
    const { data } = await ReportApi.create({ scan_id: scanId.value, format: "html" });
    window.open(ReportApi.download(data.report_id));
    ElMessage.success("报告已生成");
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "报告生成失败");
  }
}

function querySearch(queryString: string, cb: (items: SearchSuggestion[]) => void) {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    // 每次输入都从 localStorage 重读，确保刚创建/仍在分析中的项目也能出现在下拉推荐里
    refreshHistoryRecords();
    const keyword = normalize(queryString);
    const items = historySearchIndex.value
      .filter((item) => {
        if (!keyword) return true;
        return item.normalizedName.includes(keyword)
          || item.normalizedProjectId.includes(keyword)
          || item.normalizedScanId.includes(keyword);
      })
      .slice(0, 8)
      .map(({ record, projectName }) => {
        const duplicatedName = isDuplicatedProjectName(record);
      return {
        value: buildSuggestionValue(record, duplicatedName),
        record,
        projectName,
        projectId: record.projectId,
        scanId: record.scanId,
        createdAt: record.createdAt,
        duplicatedName,
      };
      });
    cb(items);
  }, 120);
}

function selectSuggestion(item: SearchSuggestion) {
  loadRecord(item.record);
}

function resolveSearchRecord(input: string) {
  const keyword = normalize(input);
  const byNameAndId = historySearchIndex.value.find((item) => {
    const ids = [item.normalizedProjectId, item.normalizedScanId].filter(Boolean);
    return item.normalizedName && keyword.includes(item.normalizedName) && ids.some((id) => keyword.includes(id));
  });
  if (byNameAndId) return byNameAndId.record;

  const exactNameMatches = historySearchIndex.value.filter((item) => item.normalizedName === keyword);
  if (exactNameMatches.length === 1) return exactNameMatches[0].record;
  if (exactNameMatches.length > 1) {
    ElMessage.warning("存在多个同名项目，请在推荐项中选择带项目 ID 的记录");
    return null;
  }

  const fuzzyNameMatches = historySearchIndex.value.filter((item) => item.normalizedName.includes(keyword));
  if (fuzzyNameMatches.length === 1) return fuzzyNameMatches[0].record;
  if (fuzzyNameMatches.length > 1) {
    ElMessage.warning("找到多个匹配项目，请在推荐项中选择具体记录");
    return null;
  }

  return historySearchIndex.value.find((item) => item.normalizedProjectId === keyword || item.normalizedScanId === keyword)?.record || null;
}

function refreshHistoryRecords() {
  historyRecords.value = readHistory();
}

function getProjectName(record: AuditHistoryRecord) {
  return record.projectName || record.projectId || record.scanId;
}

function isDuplicatedProjectName(record: AuditHistoryRecord) {
  const name = normalize(getProjectName(record));
  if (!name) return false;
  return historyRecords.value.filter((item) => normalize(getProjectName(item)) === name).length > 1;
}

function buildSuggestionValue(record: AuditHistoryRecord, duplicatedName: boolean) {
  const name = getProjectName(record);
  if (!duplicatedName) return name;
  return `${name}（${record.projectId || record.scanId}）`;
}

function normalize(value?: string) {
  return String(value || "").trim().toLowerCase();
}

function formatTime(value?: string) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function openFinding(id: string) { router.push(`/findings/${id}`); }
function severityType(severity: string) {
  const s = String(severity).toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

function attackPlanLabel(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return "候选测试草案";
  if (status === "static_confirmed_pending_runtime") return "静态确认待运行";
  if (status === "framework_confirmed_replay") return "已确认 HTTP PoC";
  if (status === "target_harness_reproduction") return "目标 Harness 复现";
  if (status === "manual_plan_required") return "需人工补充";
  return "其他利用与复现材料";
}

function attackPlanTagType(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (["framework_confirmed_replay", "target_harness_reproduction"].includes(status)) return "success";
  if (["candidate_plan_pending_review", "manual_plan_required"].includes(status)) return "warning";
  return "info";
}

function attackPlanDescription(plan: any) {
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return "候选测试草案，尚待人工复核；不得计为已确认 PoC。";
  if (status === "static_confirmed_pending_runtime") return "静态证据已确认，代码仍待运行验证。";
  if (status === "framework_confirmed_replay") return "代码来自框架实际命中的本地 HTTP 请求，可用于复放。";
  if (status === "target_harness_reproduction") return "代码来自目标入口 Harness 的已确认复现。";
  return "请结合证据状态人工判断，当前材料不自动视为已确认 PoC。";
}

function attackPlanCodeCaption(plan: any) {
  const language = String(plan?.code_language || "python");
  const status = normalizedPlanStatus(plan);
  if (status === "candidate_plan_pending_review") return `${language} · 候选测试草案`;
  if (status === "static_confirmed_pending_runtime") return `${language} · 待运行测试计划`;
  if (status === "framework_confirmed_replay") return `${language} · 已确认 HTTP PoC`;
  if (status === "target_harness_reproduction") return `${language} · 目标 Harness 复现代码`;
  return `${language} · 利用与复现代码`;
}

function canDisplayAttackPlanCode(row: any) {
  return canDisplayDetailedPoc({ finding: row, evidence: row.evidence })
    && hasDisplayablePocCode(row.attackPlan?.code);
}

async function copyAttackPlan(row: any) {
  if (!canDisplayAttackPlanCode(row)) return;
  const code = String(row.attackPlan?.code || "");
  await navigator.clipboard?.writeText(code);
  ElMessage.success("利用与复现代码已复制");
}

function statusTagType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value === "failed") return "danger";
  if (value === "partial_completed") return "warning";
  if (value === "cancelled") return "info";
  if (value === "done" || value === "finished") return "success";
  if (value === "running" || value === "cancelling") return "warning";
  return "info";
}

function statusLabel(status?: string) {
  const map: Record<string, string> = {
    queued: "排队中",
    running: "运行中",
    done: "已完成",
    finished: "已完成",
    failed: "失败",
    cancelling: "正在取消",
    cancelled: "已取消",
    partial_completed: "部分完成",
  };
  return map[String(status || "").toLowerCase()] || status || "unknown";
}

function findingStatusType(status?: string) {
  const value = String(status || "").toLowerCase();
  if (value.includes("false")) return "info";
  if (value === "out_of_scope") return "info";
  if (value === "unverified") return "info";           // 检出未验证：中性
  if (value.includes("review")) return "warning";      // needs_review 待人工复核
  if (value.includes("confirm") || value.includes("verified")) return "success";
  if (value.includes("candidate")) return "warning";
  return "info";
}

function findingStatusLabel(status?: string) {
  const map: Record<string, string> = {
    confirmed: "已确认",
    unverified: "检出未验证",
    needs_review: "需人工复核",
    informational: "低置信度线索",
    false_positive: "误报排除",
    out_of_scope: "范围外排除",
    candidate: "候选",
  };
  return map[String(status || "").toLowerCase()] || status || "unknown";
}

function formatConfidence(value: any) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return num <= 1 ? `${Math.round(num * 100)}%` : String(num);
}

function runtimeStatusLabel(runtime: any, finding?: any) {
  return runtimeStatusMeta(runtime, finding).label;
}

function runtimeTagType(runtime: any, finding?: any) {
  return runtimeStatusMeta(runtime, finding).tone;
}

function agentName(value?: string) {
  return String(value || "unknown").replace(/_/g, " ");
}

function isProblemAgentMessage(msg: any) {
  const state = String(msg?.state || "").toLowerCase();
  const verdict = String(msg?.verdict || "").toLowerCase();
  const type = String(msg?.message_type || "").toLowerCase();
  return state === "failed"
    || state === "skipped"
    || verdict.includes("review")
    || verdict.includes("failed")
    || verdict.includes("timeout")
    || verdict.includes("not_reproduced")
    || verdict.includes("not_executed")
    || verdict.includes("not_found")
    || type === "error"
    || Boolean(msg?.error);
}

function agentGroupKey(msg: any) {
  const type = String(msg?.message_type || "");
  if (!agentFilters.collapse || !type.startsWith("verify.")) {
    return `${msg?.message_id || `${type}|${msg?.timestamp || ""}|${msg?.intent || ""}`}`;
  }
  return [
    msg?.sender || "",
    msg?.receiver || "",
    type,
    msg?.state || "",
    msg?.verdict || "",
  ].join("|");
}

function verdictLabel(verdict?: string, state?: string) {
  const v = String(verdict || "").toLowerCase();
  const labels: Record<string, string> = {
    false_positive: "误报排除",
    out_of_scope: "范围外排除",
    statically_verified: "静态确认",
    confirmed: "已确认",
    dynamic_confirmed: "动态复现",
    harness_confirmed: "Harness 复现",
    needs_review: "需人工复核",
    exploit_generated: "已生成利用方案",
    not_executed: "未执行",
    not_reproduced: "未复现",
    not_runtime_verifiable: "不适合动态验证",
    function_reproduced: "仅函数单元复现",
    mechanism_confirmed: "仅漏洞机理复现",
    connection_failed: "连接失败",
    endpoint_not_found: "入口不存在",
    request_timeout: "请求超时",
    launch_not_detected: "未识别启动方式",
    not_web_target: "非 Web 项目（HTTP 不适用）",
    unsafe_project_config: "项目容器配置被安全策略阻止",
    sandbox_start_failed: "沙箱启动失败",
    health_check_failed: "沙箱健康检查失败",
    dependency_install_failed: "沙箱依赖安装失败",
    sandbox_build_timeout: "沙箱构建超时",
    sandbox_cancelled: "沙箱执行已取消",
    cancelling: "正在取消",
    execution_error: "执行异常",
    blocked_by_environment: "受运行环境阻断",
  };
  if (labels[v]) return labels[v];
  const s = String(state || "").toLowerCase();
  if (s === "success") return "执行成功";
  if (s === "failed") return "执行失败";
  if (s === "skipped") return "已跳过";
  return verdict || state || "unknown";
}

function agentMessageLabel(msg: any) {
  if (String(msg?.state || "").toLowerCase() === "failed") return "执行失败";
  return verdictLabel(msg?.verdict, msg?.state);
}

function verdictTagType(verdict?: string) {
  const v = String(verdict || "").toLowerCase();
  if (v === "false_positive" || v === "out_of_scope") return "info";
  if (v.includes("review")) return "warning";
  if (v.includes("dynamic_confirmed") || v.includes("harness_confirmed")) return "success";
  if (v.includes("confirmed") || v.includes("verified")) return "success";
  if (v.includes("not_reproduced")) return "warning";
  if (v.includes("failed") || v.includes("timeout") || v.includes("not_found")) return "warning";
  if (v.includes("exploit") || v.includes("harness")) return "warning";
  return "info";
}

function agentMessageTagType(msg: any) {
  if (String(msg?.state || "").toLowerCase() === "failed") return "danger";
  return verdictTagType(msg?.verdict);
}

function agentTimelineType(msg: any) {
  if (String(msg.state || "").toLowerCase() === "failed") return "danger";
  if (String(msg.verdict || "").toLowerCase() === "false_positive") return "primary";
  if (msg.verdict) return verdictTagType(msg.verdict);
  return msg.state === "success" ? "success" : "primary";
}

async function mapLimit<T, R>(items: T[], limit: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (nextIndex < items.length) {
      const current = nextIndex;
      nextIndex += 1;
      results[current] = await mapper(items[current]);
    }
  });
  await Promise.all(workers);
  return results;
}

watch(activeTab, async (tab) => {
  if (tab === "dynamic" || tab === "exploit") {
    await ensureEvidenceLoaded();
  }
  if (tab === "agents") {
    await ensureAgentMessagesLoaded();
  }
  if (tab === "structure") {
    await ensureProjectStructureLoaded();
  }
});

watch(pageSize, () => { currentPage.value = 1; });

onMounted(() => {
  refreshHistoryRecords();
  // 历史记录被其他页面（如新建项目）更新时同步刷新，避免搜索用到过期快照
  window.addEventListener("audit-history-updated", refreshHistoryRecords);
  if (scanId.value) loadByScanId(scanId.value);
});

onUnmounted(() => {
  window.removeEventListener("audit-history-updated", refreshHistoryRecords);
  stopScanPolling();
});
</script>

<style scoped>
.dashboard-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.page-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.query-card, .tabs-card, .summary-card { border-radius: 18px; }
.tabs-card { overflow: hidden; }
.query-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; }
.project-search { width: 100%; }
.suggestion-option { padding: 6px 0; line-height: 1.4; }
.suggestion-main { display: flex; align-items: center; justify-content: space-between; gap: 12px; color: #162235; }
.suggestion-main strong { font-weight: 700; }
.suggestion-main span { color: #2f80ed; font-size: 12px; white-space: nowrap; }
.suggestion-sub { display: flex; gap: 12px; margin-top: 4px; color: #667085; font-size: 12px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }
.summary-card span { display: block; color: #667085; font-size: 13px; }
.summary-card strong { display: block; margin: 8px 0; font-size: 26px; color: #162235; }
.summary-card small { color: #667085; }
.stage-summary-card strong { font-size: 24px; }
.error-alert { border-radius: 12px; }
.partition-card { border-radius: 18px; }
.partition-head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.partition-head--counts { margin-top: 18px; }
.partition-head h3 { margin: 0; color: #162235; font-size: 15px; }
.partition-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.partition-grid--counts { grid-template-columns: repeat(4, 1fr); }
.partition-tile { border: 1px solid #e4ebf3; border-radius: 12px; padding: 12px 14px; background: #fbfdff; display: flex; flex-direction: column; gap: 4px; }
.partition-label { color: #667085; font-size: 13px; }
.partition-value { color: #162235; font-size: 22px; }
.partition-hint { color: #98a2b3; font-size: 12px; }
.dynamic-info-desc { margin-bottom: 16px; }
@media (max-width: 980px) { .partition-grid, .partition-grid--counts { grid-template-columns: repeat(2, 1fr); } }
.warning-action-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; color: #162235; }
.tab-intro p { margin: 6px 0 0; color: #667085; }
.exploit-summary { display: flex; flex-wrap: wrap; gap: 8px 18px; margin: 0 0 14px; padding: 10px 14px; color: #526477; font-size: 13px; background: #f4f8fc; border: 1px solid #dce6f0; border-radius: 10px; }
.exploit-summary b { color: #162235; }
.validation-hypothesis-panel { display: grid; gap: 12px; margin-bottom: 16px; padding: 16px; border: 1px solid #f3d19e; border-radius: 12px; background: #fffbf2; }
.validation-hypothesis-panel h3 { margin: 0; color: #7a4a00; }
.exploit-list { display: grid; gap: 16px; }
.exploit-group { display: grid; gap: 12px; }
.exploit-group-head { display: flex; align-items: center; gap: 8px; }
.exploit-group-head h3 { margin: 0; color: #162235; font-size: 16px; }
.exploit-card { border: 1px solid #dce6f0; border-radius: 16px; padding: 18px; background: linear-gradient(180deg, #fff, #fbfdff); box-shadow: 0 8px 22px rgba(16,32,51,.04); }
.exploit-head { display: flex; justify-content: space-between; gap: 16px; }
.exploit-head h3 { margin: 0; }
.exploit-title-line { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.exploit-head p, .exploit-path { color: #667085; margin: 6px 0 12px; }
.exploit-plan-note { display: flex; gap: 8px; padding: 10px 12px; margin: 4px 0 14px; color: #40536a; background: #eef5fb; border-left: 3px solid #2f80ed; border-radius: 8px; font-size: 13px; line-height: 1.55; }
.exploit-plan-note b { color: #1c4d78; white-space: nowrap; }
.exploit-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 0 0 14px; }
.exploit-facts div { padding: 10px 12px; min-width: 0; border: 1px solid #e4ebf3; border-radius: 10px; background: #fff; }
.exploit-facts dt { margin-bottom: 5px; color: #718096; font-size: 12px; }
.exploit-facts dd { margin: 0; color: #334155; font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
.payload-row { display: flex; align-items: baseline; flex-wrap: wrap; gap: 7px; margin: 0 0 12px; font-size: 13px; color: #526477; }
.payload-row code { max-width: 100%; padding: 2px 6px; color: #95421e; background: #fff3ed; border: 1px solid #fed7c3; border-radius: 5px; overflow-wrap: anywhere; }
.exploit-code-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; color: #667085; font-size: 12px; }
.exploit-code-head span { font-family: "SFMono-Regular", Consolas, monospace; }
.exploit-card pre { margin: 0; max-height: 440px; }
.artifact-state-list { display: grid; gap: 8px; margin-top: 12px; }
.artifact-state-item { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 9px 11px; border: 1px solid #e4ebf3; border-radius: 10px; color: #526477; font-size: 13px; }
.exploit-safety { margin: 10px 0 0; color: #718096; font-size: 12px; line-height: 1.5; }
.agent-toolbar { display: grid; grid-template-columns: minmax(180px, 240px) minmax(180px, 260px) auto auto; align-items: center; gap: 12px; margin-bottom: 10px; }
.agent-stats { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.agent-timeline { padding: 8px 0 0; }
.agent-message-card { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px 14px; background: #fbfdff; }
.agent-message-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; color: #162235; }
.agent-message-tags { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.agent-message-card p { margin: 8px 0; color: #475467; }
.agent-message-meta { display: flex; flex-wrap: wrap; gap: 10px; color: #667085; font-size: 12px; }
.structure-block { display: flex; flex-direction: column; gap: 16px; }
.chip { margin: 0 6px 6px 0; }
.entry-chip { display: inline-block; margin: 0 8px 6px 0; padding: 2px 8px; background: #eef3fb; border-radius: 6px; color: #2f4a6b; font-size: 12px; }
.file-tree-wrap { border: 1px solid #dce6f0; border-radius: 12px; padding: 12px 16px; background: #fbfdff; max-height: 520px; overflow: auto; }
.file-tree-wrap h3 { margin: 0 0 10px; color: #162235; }
.tree-node { display: inline-flex; align-items: center; gap: 8px; }
.tree-dir { font-weight: 600; color: #1f3350; }
.tree-file { color: #475467; }
.tree-lang { transform: scale(.9); }
pre { background: #0b1220; color: #d7e3f1; padding: 14px; border-radius: 12px; overflow: auto; border: 1px solid rgba(255,255,255,.08); }
@media (max-width: 980px) { .agent-toolbar, .exploit-facts { grid-template-columns: 1fr 1fr; } }
@media (max-width: 680px) { .query-row, .summary-grid, .agent-toolbar, .exploit-facts { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } .page-actions { justify-content: flex-start; } .exploit-head { align-items: flex-start; flex-direction: column; } }
</style>
