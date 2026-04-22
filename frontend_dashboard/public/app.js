const ROLE_NORMAL = "normal";
const ROLE_ADMIN = "admin";

const DEMO_CREDENTIALS = {
  normal: { username: "user", password: "admin" },
  admin: { username: "admin", password: "admin" },
};

const ROLE_LABEL = {
  normal: "\u666e\u901a\u7528\u6237",
  admin: "\u7ba1\u7406\u5458",
};

const WEEKDAY_LABELS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];

const appEl = document.getElementById("app");
const tooltipEl = document.getElementById("tooltip");

const state = {
  token: localStorage.getItem("attack_demo_token") || "",
  profile: null,
  currentView: "",
  systemStatus: null,
  latestDataTime: "-",
  soundEnabled: localStorage.getItem("attack_sound_on") !== "0",
  intervals: {
    clock: null,
    system: null,
    view: null,
  },
  screenData: null,
  pro: {
    filters: {
      time_range: "24h",
      risk_level: "all",
      attack_type: "all",
      target_node: "all",
      process_status: "all",
      keyword: "",
      start_time: "",
      end_time: "",
    },
    options: {
      attackTypes: [],
      nodes: [],
    },
    listPage: 1,
    pageSize: 20,
    total: 0,
    items: [],
    selectedIds: new Set(),
    selectedEventId: "",
    selectedEventDetail: null,
    selectedNodeDetail: null,
  },
  admin: {
    summary: null,
    ranking: [],
    trend: [],
    machines: [],
    selectedMachineId: null,
    selectedMachineDetail: null,
    logs: [],
    logsPage: 1,
    logsPageSize: 25,
    logsTotal: 0,
    logsUsername: "",
    config: {},
    users: [],
  },
  rag: {
    page: 1,
    pageSize: 20,
    total: 0,
    q: "",
    attackType: "",
    items: [],
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindGlobalTooltip();
  bootstrap();
});

async function bootstrap() {
  if (state.token) {
    try {
      state.profile = await api("/api/v2/auth/profile");
      renderMainLayout();
      return;
    } catch (err) {
      console.warn("restore profile failed", err);
      state.token = "";
      localStorage.removeItem("attack_demo_token");
    }
  }
  renderLoginPage();
}

function renderLoginPage() {
  clearAllTimers();
  state.profile = null;
  state.currentView = "";

  appEl.innerHTML = `
    <section class="login-shell">
      <div class="login-card">
        <h1 class="login-title">AI攻击态势感知平台</h1>
        <p class="login-subtitle">请选择身份后自动填充账号，点击登录进入对应专属页面</p>

        <div class="form-row">
          <label for="loginUsername">用户名</label>
          <input id="loginUsername" type="text" autocomplete="username" />
        </div>
        <div class="form-row">
          <label for="loginPassword">密码</label>
          <input id="loginPassword" type="password" autocomplete="current-password" />
        </div>

        <div class="form-row">
          <label>身份快捷切换</label>
          <div class="role-switch">
            <button class="btn active" data-login-role="${ROLE_NORMAL}">普通用户</button>
            <button class="btn" data-login-role="${ROLE_ADMIN}">管理员</button>
          </div>
        </div>

        <button id="loginBtn" class="btn btn-primary" style="width:100%;">登录系统</button>
        <div id="loginError" class="login-error"></div>
      </div>
    </section>
  `;

  let selectedRole = ROLE_NORMAL;
  fillLoginCredential(selectedRole);

  appEl.querySelectorAll("[data-login-role]").forEach((btn) => {
    btn.addEventListener("click", () => {
      selectedRole = btn.getAttribute("data-login-role") || ROLE_NORMAL;
      appEl.querySelectorAll("[data-login-role]").forEach((x) => x.classList.remove("active"));
      btn.classList.add("active");
      fillLoginCredential(selectedRole);
    });
  });

  appEl.querySelector("#loginBtn")?.addEventListener("click", async () => {
    const username = String(appEl.querySelector("#loginUsername")?.value || "").trim();
    const password = String(appEl.querySelector("#loginPassword")?.value || "").trim();
    const errorEl = appEl.querySelector("#loginError");
    if (!username || !password) {
      if (errorEl) errorEl.textContent = "请输入用户名和密码";
      return;
    }

    const btn = appEl.querySelector("#loginBtn");
    if (btn) btn.disabled = true;
    if (errorEl) errorEl.textContent = "";
    try {
      const resp = await api("/api/v2/auth/login", {
        method: "POST",
        body: { username, password, role: selectedRole },
      });
      state.token = resp.token;
      localStorage.setItem("attack_demo_token", state.token);
      state.profile = await api("/api/v2/auth/profile");
      renderMainLayout();
      showToast(`登录成功，欢迎 ${state.profile.display_name || ""}`);
    } catch (err) {
      if (errorEl) errorEl.textContent = `登录失败：${err.message}`;
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

function fillLoginCredential(role) {
  const row = DEMO_CREDENTIALS[role] || DEMO_CREDENTIALS.normal;
  const usernameEl = appEl.querySelector("#loginUsername");
  const passwordEl = appEl.querySelector("#loginPassword");
  if (usernameEl) usernameEl.value = row.username;
  if (passwordEl) passwordEl.value = row.password;
}

function renderMainLayout() {
  appEl.innerHTML = `
    <div class="layout">
      <header class="status-bar">
        <div class="status-main">
          <span class="brand">AI攻击态势感知平台</span>
          <span class="pill">身份：${ROLE_LABEL[state.profile?.role] || "-"}</span>
          <span class="pill">用户：${escapeHtml(state.profile?.display_name || state.profile?.username || "-")}</span>
          <span class="pill">实时时钟：<strong id="statusClock">-</strong></span>
          <span class="pill">数据更新时间：<strong id="statusDataTime">-</strong></span>
          <span class="pill">
            <span id="statusDot" class="status-dot dot-green"></span>
            <strong id="statusText">系统状态：正常</strong>
          </span>
        </div>
        <div class="status-actions">
          <button id="btnFullscreen" class="btn btn-ghost">全屏</button>
          <button id="btnSound" class="btn btn-ghost">${state.soundEnabled ? "声音：开" : "声音：关"}</button>
          <button id="btnLogout" class="btn btn-danger">退出登录</button>
        </div>
      </header>
      <nav id="navTabs" class="nav-tabs"></nav>
      <main id="viewRoot" class="main-view"></main>
    </div>
  `;

  document.getElementById("btnFullscreen")?.addEventListener("click", toggleFullscreen);
  document.getElementById("btnSound")?.addEventListener("click", () => {
    state.soundEnabled = !state.soundEnabled;
    localStorage.setItem("attack_sound_on", state.soundEnabled ? "1" : "0");
    const btn = document.getElementById("btnSound");
    if (btn) btn.textContent = state.soundEnabled ? "声音：开" : "声音：关";
    showToast(state.soundEnabled ? "声音告警已开启" : "声音告警已关闭");
  });
  document.getElementById("btnLogout")?.addEventListener("click", logout);

  renderTabs();
  startGlobalTimers();

  switchView("screen");
}

function renderTabs() {
  const tabsEl = document.getElementById("navTabs");
  if (!tabsEl || !state.profile) return;
  tabsEl.innerHTML = "";

  const tabs = getTabsByRole(state.profile.role);
  tabs.forEach((tab) => {
    const btn = document.createElement("button");
    btn.className = `btn ${tab.id === state.currentView ? "active" : ""}`;
    btn.textContent = tab.label;
    btn.addEventListener("click", () => switchView(tab.id));
    tabsEl.appendChild(btn);
  });
}

function getTabsByRole(role) {
  if (role === ROLE_ADMIN) {
    return [
      { id: "screen", label: "\u6570\u636e\u5927\u5c4f" },
      { id: "pro-query", label: "\u8be6\u60c5\u4fe1\u606f" },
      { id: "user-center", label: "\u7528\u6237\u4e2d\u5fc3" },
      { id: "rag-settings", label: "\u77e5\u8bc6\u5e93\u8bbe\u7f6e\uff08RAG\uff09" },
      { id: "admin-overview", label: "\u5168\u5c40\u6982\u89c8" },
      { id: "admin-logs", label: "\u64cd\u4f5c\u65e5\u5fd7" },
      { id: "admin-config", label: "\u7cfb\u7edf\u914d\u7f6e" },
      { id: "admin-users", label: "\u7ba1\u7406\u7528\u6237" },
    ];
  }
  return [
    { id: "screen", label: "\u6570\u636e\u5927\u5c4f" },
    { id: "pro-query", label: "\u8be6\u60c5\u4fe1\u606f" },
    { id: "user-center", label: "\u7528\u6237\u4e2d\u5fc3" },
  ];
}

function switchView(viewId) {
  if (!viewId) return;
  state.currentView = viewId;
  renderTabs();
  clearIntervalSafe("view");

  if (viewId === "screen") {
    renderScreenView();
    setViewRefresh(5000, refreshScreenData);
    return;
  }
  if (viewId === "pro-query") {
    renderProQueryView();
    setViewRefresh(8000, loadProEvents);
    return;
  }
  if (viewId === "rag-settings") {
    renderRagSettingsView();
    setViewRefresh(15000, loadRagDocs);
    return;
  }
  if (viewId === "user-center") {
    renderUserCenterView();
    return;
  }
  if (viewId === "admin-overview") {
    renderAdminOverview();
    setViewRefresh(8000, refreshAdminOverview);
    return;
  }
  if (viewId === "admin-logs") {
    renderAdminLogsView();
    setViewRefresh(12000, loadAdminLogs);
    return;
  }
  if (viewId === "admin-config") {
    renderAdminConfigView();
    return;
  }
  if (viewId === "admin-users") {
    renderAdminUsersView();
    return;
  }
}

function setViewRefresh(ms, fn) {
  clearIntervalSafe("view");
  state.intervals.view = setInterval(() => {
    fn().catch((err) => console.warn("view refresh error", err));
  }, ms);
}

function startGlobalTimers() {
  clearAllTimers();

  updateClock();
  refreshSystemStatus().catch((err) => console.warn(err));

  state.intervals.clock = setInterval(updateClock, 1000);
  state.intervals.system = setInterval(() => refreshSystemStatus().catch((err) => console.warn(err)), 5000);
}

function updateClock() {
  const el = document.getElementById("statusClock");
  if (!el) return;
  el.textContent = formatDateTime(new Date(), false);
}

async function refreshSystemStatus() {
  if (!state.token) return;
  const data = await api("/api/v2/common/system-status");
  state.systemStatus = data;
  state.latestDataTime = data.latest_data_time || "-";

  const dataEl = document.getElementById("statusDataTime");
  if (dataEl) dataEl.textContent = state.latestDataTime;

  const dotEl = document.getElementById("statusDot");
  const textEl = document.getElementById("statusText");
  if (dotEl && textEl) {
    dotEl.classList.remove("dot-green", "dot-yellow", "dot-red");
    const color = data?.state?.color || "green";
    if (color === "red") {
      dotEl.classList.add("dot-red");
      textEl.textContent = "系统状态：异常";
    } else if (color === "yellow") {
      dotEl.classList.add("dot-yellow");
      textEl.textContent = "系统状态：告警";
    } else {
      dotEl.classList.add("dot-green");
      textEl.textContent = "系统状态：正常";
    }
  }
}

async function logout() {
  try {
    if (state.token) {
      await api("/api/v2/auth/logout", { method: "POST", body: {} });
    }
  } catch (err) {
    console.warn(err);
  } finally {
    state.token = "";
    localStorage.removeItem("attack_demo_token");
    renderLoginPage();
  }
}

function renderScreenView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="grid-6">
      <article class="kpi-card"><div class="kpi-label">今日遭遇攻击总数</div><div id="kpi_today_attack" class="kpi-value">0</div><div id="kpi_yoy" class="kpi-label">同比：-</div></article>
      <article class="kpi-card"><div class="kpi-label">当前活跃高危告警数</div><div id="kpi_high_alert" class="kpi-value">0</div></article>
      <article class="kpi-card"><div class="kpi-label">攻击拦截成功率</div><div id="kpi_intercept" class="kpi-value">0%</div></article>
      <article class="kpi-card"><div class="kpi-label">平均攻击响应时间</div><div id="kpi_response_ms" class="kpi-value">0ms</div></article>
      <article class="kpi-card"><div class="kpi-label">今日异常检测数</div><div id="kpi_anomaly" class="kpi-value">0</div></article>
      <article class="kpi-card"><div class="kpi-label">在线防护节点数</div><div id="kpi_nodes" class="kpi-value">0</div></article>
    </section>

    <section class="grid-2" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">近7天攻击趋势（总攻击 / 被拦截）</h3><span class="panel-sub">峰值红点标记</span></div>
        <div id="chartTrend7d" class="chart-box"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">攻击类型 TOP10</h3><span class="panel-sub">Top3 红色渐变</span></div>
        <div id="chartTopTypes" class="chart-box"></div>
      </article>
    </section>

    <section class="grid-3" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">攻击来源地区分布</h3></div>
        <div id="chartSourcePie" class="chart-box short"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">全天攻击热力图（小时×星期）</h3></div>
        <div id="chartHeatmap" class="chart-box short"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">攻击手段占比</h3></div>
        <div id="chartMethodDonut" class="chart-box short"></div>
      </article>
    </section>

    <section class="ticker">
      <div id="tickerTrack" class="ticker-track"></div>
    </section>
  `;
  refreshScreenData().catch((err) => showToast(`加载大屏失败：${err.message}`));
}

async function refreshScreenData() {
  const [kpis, trend7d, topTypes, sourceDist, heatmap, methodShare, ticker] = await Promise.all([
    api("/api/v2/user/dashboard/kpis"),
    api("/api/v2/user/dashboard/trend7d"),
    api("/api/v2/user/dashboard/top-attack-types"),
    api("/api/v2/user/dashboard/source-distribution"),
    api("/api/v2/user/dashboard/heatmap"),
    api("/api/v2/user/dashboard/method-share"),
    api("/api/v2/common/alerts/ticker?limit=3"),
  ]);

  animateTextNumber("kpi_today_attack", Number(kpis.today_attack_total || 0), "");
  animateTextNumber("kpi_high_alert", Number(kpis.active_high_alerts || 0), "");
  animateTextNumber("kpi_intercept", Number(kpis.intercept_success_rate || 0), "%");
  animateTextNumber("kpi_response_ms", Number(kpis.avg_attack_response_ms || 0), "ms");
  animateTextNumber("kpi_anomaly", Number(kpis.today_anomaly_detected || 0), "");
  animateTextNumber("kpi_nodes", Number(kpis.online_protection_nodes || 0), "");

  const yoy = Number(kpis.yoy_percent || 0);
  const yoyEl = document.getElementById("kpi_yoy");
  if (yoyEl) {
    if (yoy >= 0) {
      yoyEl.innerHTML = `同比：<span class="trend-up">▲ +${yoy.toFixed(2)}%</span>`;
    } else {
      yoyEl.innerHTML = `同比：<span class="trend-down">▼ ${yoy.toFixed(2)}%</span>`;
    }
  }

  renderTrendChart("chartTrend7d", Array.isArray(trend7d.items) ? trend7d.items : []);
  renderTopTypeBarChart("chartTopTypes", Array.isArray(topTypes.items) ? topTypes.items : []);
  renderPieChart("chartSourcePie", Array.isArray(sourceDist.items) ? sourceDist.items : [], "source_region", "total");
  renderHeatmapChart("chartHeatmap", Array.isArray(heatmap.items) ? heatmap.items : []);
  renderDonutChart("chartMethodDonut", Array.isArray(methodShare.items) ? methodShare.items : [], "attack_type", "ratio_percent");

  renderTicker(Array.isArray(ticker.items) ? ticker.items : []);
}

function renderTicker(items) {
  const el = document.getElementById("tickerTrack");
  if (!el) return;
  if (!items.length) {
    el.textContent = "暂无高危告警事件";
    return;
  }
  const text = items
    .map(
      (x) =>
        `【${x.occurred_at || "-"}】${x.event_id || "-"} ${x.attack_type || "-"} 来源IP ${x.source_ip || "-"} 目标 ${x.target_node || "-"}`
    )
    .join("  |  ");
  el.textContent = `${text}      ${text}`;
}

function renderProQueryView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const canHandle = state.profile?.role === ROLE_ADMIN;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">攻击详情信息</h3>
        <button id="btnSwitchToScreen" class="btn btn-primary">切换到数据大屏</button>
      </div>
      <div class="toolbar">
        <div class="filter-group">
          <select id="pro_time_range">
            <option value="1h">1小时</option>
            <option value="6h">6小时</option>
            <option value="24h" selected>24小时</option>
            <option value="7d">7天</option>
            <option value="30d">30天</option>
            <option value="custom">自定义</option>
          </select>
          <select id="pro_risk_level">
            <option value="all">全部风险</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          <select id="pro_attack_type"><option value="all">全部攻击类型</option></select>
          <select id="pro_target_node"><option value="all">全部防护节点</option></select>
          <input id="pro_keyword" placeholder="关键词（事件ID/IP/接口）" />
        </div>
        <div class="ops-group">
          <button id="pro_refresh" class="btn btn-success">刷新</button>
          <button id="pro_export" class="btn btn-ghost">导出表格（CSV）</button>
        </div>
      </div>
      <div id="pro_custom_time" class="filter-group hidden" style="margin-top:8px;grid-template-columns:repeat(2,minmax(220px,1fr));">
        <input id="pro_start_time" type="datetime-local" />
        <input id="pro_end_time" type="datetime-local" />
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-top:8px;">
        <select id="pro_batch_status" style="max-width:180px;" ${canHandle ? "" : "disabled"}>
          <option value="unprocessed">未处理</option>
          <option value="processing">处理中</option>
          <option value="done" selected>已处理</option>
          <option value="ignored">已忽略</option>
        </select>
        <button id="pro_apply_batch" class="btn btn-danger" ${canHandle ? "" : "disabled"}>批量标记状态</button>
        <span class="panel-sub">已选中 <strong id="pro_selected_count">0</strong> 条</span>
      </div>
    </section>

    <section class="split" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">攻击事件列表（按时间倒序）</h3><span class="panel-sub" id="pro_total_info">总计 0</span></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th><input id="pro_check_all" type="checkbox" /></th>
                <th>事件ID</th>
                <th>发生时间</th>
                <th>风险等级</th>
                <th>攻击类型</th>
                <th>来源IP</th>
                <th>目标节点</th>
                <th>攻击结果</th>
                <th>处理状态</th>
              </tr>
            </thead>
            <tbody id="pro_table_body"></tbody>
          </table>
        </div>
        <div style="margin-top:8px;display:flex;justify-content:flex-end;gap:8px;">
          <button id="pro_prev_page" class="btn btn-ghost">上一页</button>
          <button id="pro_next_page" class="btn btn-ghost">下一页</button>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">事件详情</h3><span class="panel-sub" id="pro_detail_hint">请选择左侧事件</span></div>
        <div id="pro_event_detail" class="detail-card">暂无详情</div>
        <div class="note-box">
          <textarea id="pro_note_text" rows="3" placeholder="处理备注" ${canHandle ? "" : "disabled"}></textarea>
          <button id="pro_save_note" class="btn btn-success" ${canHandle ? "" : "disabled"}>保存备注</button>
        </div>
        <div class="panel-head" style="margin-top:10px;"><h3 class="panel-title">节点详情</h3></div>
        <div id="pro_node_detail" class="detail-card">点击目标节点名称查看</div>
      </article>
    </section>
  `;

  document.getElementById("btnSwitchToScreen")?.addEventListener("click", () => switchView("screen"));
  document.getElementById("pro_refresh")?.addEventListener("click", () => loadProEvents(true));
  document.getElementById("pro_export")?.addEventListener("click", exportProEventsCsv);
  document.getElementById("pro_apply_batch")?.addEventListener("click", applyProBatchStatus);
  document.getElementById("pro_save_note")?.addEventListener("click", saveProEventNote);
  document.getElementById("pro_prev_page")?.addEventListener("click", () => {
    state.pro.listPage = Math.max(1, state.pro.listPage - 1);
    loadProEvents().catch((err) => showToast(err.message));
  });
  document.getElementById("pro_next_page")?.addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(state.pro.total / state.pro.pageSize));
    state.pro.listPage = Math.min(maxPage, state.pro.listPage + 1);
    loadProEvents().catch((err) => showToast(err.message));
  });

  const timeSelect = document.getElementById("pro_time_range");
  timeSelect?.addEventListener("change", () => {
    const customEl = document.getElementById("pro_custom_time");
    if (customEl) customEl.classList.toggle("hidden", timeSelect.value !== "custom");
  });

  [
    "pro_time_range",
    "pro_risk_level",
    "pro_attack_type",
    "pro_target_node",
    "pro_keyword",
    "pro_start_time",
    "pro_end_time",
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener("change", () => {
      state.pro.listPage = 1;
    });
  });
  document.getElementById("pro_keyword")?.addEventListener("keyup", (ev) => {
    if (ev.key === "Enter") {
      state.pro.listPage = 1;
      loadProEvents(true).catch((err) => showToast(err.message));
    }
  });

  document.getElementById("pro_check_all")?.addEventListener("change", (ev) => {
    const checked = Boolean(ev.target.checked);
    state.pro.selectedIds.clear();
    if (checked) {
      state.pro.items.forEach((x) => state.pro.selectedIds.add(x.event_id));
    }
    renderProTable();
  });

  initProOptions().catch((err) => showToast(`加载筛选项失败：${err.message}`));
  loadProEvents().catch((err) => showToast(`加载事件失败：${err.message}`));
}

async function initProOptions() {
  const [typeObj, eventObj] = await Promise.all([
    api("/api/v2/user/dashboard/top-attack-types"),
    api("/api/v2/pro/events?time_range=30d&page=1&page_size=200"),
  ]);
  const attackTypes = Array.from(new Set((typeObj.items || []).map((x) => x.attack_type))).filter(Boolean);
  const nodes = Array.from(new Set((eventObj.items || []).map((x) => x.target_node))).filter(Boolean);
  state.pro.options.attackTypes = attackTypes;
  state.pro.options.nodes = nodes;

  const typeSelect = document.getElementById("pro_attack_type");
  if (typeSelect) {
    typeSelect.innerHTML = `<option value="all">全部攻击类型</option>${attackTypes
      .map((x) => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`)
      .join("")}`;
  }
  const nodeSelect = document.getElementById("pro_target_node");
  if (nodeSelect) {
    nodeSelect.innerHTML = `<option value="all">全部防护节点</option>${nodes
      .map((x) => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`)
      .join("")}`;
  }
}

function collectProFilters() {
  state.pro.filters.time_range = String(document.getElementById("pro_time_range")?.value || "24h");
  state.pro.filters.risk_level = String(document.getElementById("pro_risk_level")?.value || "all");
  state.pro.filters.attack_type = String(document.getElementById("pro_attack_type")?.value || "all");
  state.pro.filters.target_node = String(document.getElementById("pro_target_node")?.value || "all");
  state.pro.filters.keyword = String(document.getElementById("pro_keyword")?.value || "").trim();
  state.pro.filters.start_time = String(document.getElementById("pro_start_time")?.value || "");
  state.pro.filters.end_time = String(document.getElementById("pro_end_time")?.value || "");
  return state.pro.filters;
}

async function loadProEvents(forcePageOne = false) {
  if (forcePageOne) {
    state.pro.listPage = 1;
  }
  const f = collectProFilters();
  const params = new URLSearchParams();
  params.set("time_range", f.time_range);
  params.set("risk_level", f.risk_level);
  params.set("attack_type", f.attack_type);
  params.set("target_node", f.target_node);
  params.set("process_status", f.process_status);
  if (f.keyword) params.set("keyword", f.keyword);
  if (f.time_range === "custom") {
    if (f.start_time) params.set("start_time", new Date(f.start_time).toISOString());
    if (f.end_time) params.set("end_time", new Date(f.end_time).toISOString());
  }
  params.set("page", String(state.pro.listPage));
  params.set("page_size", String(state.pro.pageSize));

  const data = await api(`/api/v2/pro/events?${params.toString()}`);
  state.pro.items = Array.isArray(data.items) ? data.items : [];
  state.pro.total = Number(data.total || 0);

  const validIds = new Set(state.pro.items.map((x) => x.event_id));
  state.pro.selectedIds = new Set([...state.pro.selectedIds].filter((x) => validIds.has(x)));
  if (state.pro.selectedEventId && !validIds.has(state.pro.selectedEventId)) {
    state.pro.selectedEventId = "";
    state.pro.selectedEventDetail = null;
  }

  renderProTable();
  if (state.pro.selectedEventId) {
    await loadProEventDetail(state.pro.selectedEventId);
  } else {
    renderProEventDetail();
  }
}

function renderProTable() {
  const bodyEl = document.getElementById("pro_table_body");
  if (!bodyEl) return;
  if (!state.pro.items.length) {
    bodyEl.innerHTML = `<tr><td colspan="9" class="panel-sub">暂无数据</td></tr>`;
  } else {
    bodyEl.innerHTML = state.pro.items
      .map((row) => {
        const checked = state.pro.selectedIds.has(row.event_id) ? "checked" : "";
        return `
          <tr class="${row.event_id === state.pro.selectedEventId ? "active" : ""}">
            <td><input type="checkbox" data-pro-check="${escapeHtml(row.event_id)}" ${checked} /></td>
            <td><span class="link-btn" data-pro-event="${escapeHtml(row.event_id)}">${escapeHtml(row.event_id)}</span></td>
            <td>${escapeHtml(row.occurred_at || "-")}</td>
            <td>${riskBadge(row.risk_level)}</td>
            <td>${escapeHtml(formatAttackType(row.attack_type || "-"))}</td>
            <td>${escapeHtml(row.source_ip || "-")}</td>
            <td><span class="link-btn" data-pro-node="${escapeHtml(row.target_node || "")}">${escapeHtml(row.target_node || "-")}</span></td>
            <td>${escapeHtml(formatAttackResult(row.attack_result || "-"))}</td>
            <td>${escapeHtml(formatProcessStatus(row.process_status || "-"))}</td>
          </tr>
        `;
      })
      .join("");
  }

  const totalInfo = document.getElementById("pro_total_info");
  if (totalInfo) {
    const maxPage = Math.max(1, Math.ceil(state.pro.total / state.pro.pageSize));
    totalInfo.textContent = `总计 ${state.pro.total} 条，当前第 ${state.pro.listPage}/${maxPage} 页`;
  }
  const selectedEl = document.getElementById("pro_selected_count");
  if (selectedEl) selectedEl.textContent = String(state.pro.selectedIds.size);

  bodyEl.querySelectorAll("[data-pro-check]").forEach((el) => {
    el.addEventListener("change", () => {
      const id = el.getAttribute("data-pro-check");
      if (!id) return;
      if (el.checked) state.pro.selectedIds.add(id);
      else state.pro.selectedIds.delete(id);
      renderProTable();
    });
  });
  bodyEl.querySelectorAll("[data-pro-event]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-pro-event");
      if (!id) return;
      loadProEventDetail(id).catch((err) => showToast(err.message));
    });
  });
  bodyEl.querySelectorAll("[data-pro-node]").forEach((el) => {
    el.addEventListener("click", () => {
      const nodeName = el.getAttribute("data-pro-node");
      if (!nodeName) return;
      loadProNodeDetail(nodeName).catch((err) => showToast(err.message));
    });
  });
}

async function loadProEventDetail(eventId) {
  state.pro.selectedEventId = eventId;
  state.pro.selectedEventDetail = await api(`/api/v2/pro/events/${encodeURIComponent(eventId)}`);
  renderProTable();
  renderProEventDetail();
}

function renderProEventDetail() {
  const detailEl = document.getElementById("pro_event_detail");
  const hintEl = document.getElementById("pro_detail_hint");
  const noteEl = document.getElementById("pro_note_text");
  if (!detailEl || !hintEl || !noteEl) return;
  const row = state.pro.selectedEventDetail;
  if (!row) {
    hintEl.textContent = "请选择左侧事件";
    detailEl.textContent = "暂无详情";
    noteEl.value = "";
    return;
  }
  hintEl.textContent = `当前事件：${row.event_id || "-"}`;
  noteEl.value = row.note || "";
  detailEl.innerHTML = `
    <div class="detail-grid">
      <div class="kv"><strong>事件ID：</strong>${escapeHtml(row.event_id || "-")}</div>
      <div class="kv"><strong>发生时间：</strong>${escapeHtml(row.occurred_at || "-")}</div>
      <div class="kv"><strong>风险等级：</strong>${riskBadge(row.risk_level)}</div>
      <div class="kv"><strong>攻击类型：</strong>${escapeHtml(formatAttackType(row.attack_type || "-"))}</div>
      <div class="kv"><strong>来源IP：</strong>${escapeHtml(row.source_ip || "-")} (${escapeHtml(row.source_region || "-")})</div>
      <div class="kv"><strong>目标节点：</strong>${escapeHtml(row.target_node || "-")}</div>
      <div class="kv"><strong>目标接口：</strong>${escapeHtml(row.target_interface || "-")}</div>
      <div class="kv"><strong>攻击结果：</strong>${escapeHtml(formatAttackResult(row.attack_result || "-"))}</div>
      <div class="kv"><strong>处理状态：</strong>${escapeHtml(formatProcessStatus(row.process_status || "-"))}</div>
      <div class="kv"><strong>响应耗时：</strong>${escapeHtml(String(row.response_ms || 0))} ms</div>
    </div>
    <div style="margin-top:8px;" class="kv"><strong>攻击载荷：</strong></div>
    <pre>${escapeHtml(row.attack_payload || "")}</pre>
    <div style="margin-top:8px;" class="kv"><strong>请求日志：</strong></div>
    <pre>${escapeHtml(row.request_log || "")}</pre>
    <div style="margin-top:8px;" class="kv"><strong>防护措施：</strong></div>
    <pre>${escapeHtml(row.protection_action || "")}</pre>
    <div style="margin-top:8px;" class="kv"><strong>处理建议：</strong></div>
    <pre>${escapeHtml(row.handling_suggestion || "")}</pre>
  `;
}

async function loadProNodeDetail(nodeName) {
  const detail = await api(`/api/v2/pro/nodes/${encodeURIComponent(nodeName)}/detail`);
  state.pro.selectedNodeDetail = detail;
  const box = document.getElementById("pro_node_detail");
  if (!box) return;
  const machine = detail.machine || {};
  const stats = detail.stats || {};
  const events = Array.isArray(detail.recent_events) ? detail.recent_events.slice(0, 8) : [];
  box.innerHTML = `
    <div class="detail-grid">
      <div class="kv"><strong>节点：</strong>${escapeHtml(machine.machine_name || "-")}</div>
      <div class="kv"><strong>IP：</strong>${escapeHtml(machine.ip_address || "-")}</div>
      <div class="kv"><strong>部署位置：</strong>${escapeHtml(machine.deploy_location || "-")}</div>
      <div class="kv"><strong>在线状态：</strong>${escapeHtml(machine.online_status || "-")}</div>
      <div class="kv"><strong>近7天攻击：</strong>${escapeHtml(String(stats.total_7d || 0))}</div>
      <div class="kv"><strong>近7天高危：</strong>${escapeHtml(String(stats.high_7d || 0))}</div>
      <div class="kv"><strong>CPU：</strong>${escapeHtml(String(machine.cpu_usage || 0))}%</div>
      <div class="kv"><strong>内存：</strong>${escapeHtml(String(machine.memory_usage || 0))}%</div>
      <div class="kv"><strong>GPU：</strong>${escapeHtml(String(machine.gpu_usage || 0))}%</div>
      <div class="kv"><strong>模型状态：</strong>${escapeHtml(machine.model_status || "-")}</div>
    </div>
    <div style="margin-top:8px;" class="kv"><strong>近期攻击记录</strong></div>
    <pre>${escapeHtml(events.map((x) => `${x.occurred_at} | ${x.risk_level} | ${x.attack_type} | ${x.source_ip} | ${x.attack_result}`).join("\n"))}</pre>
  `;
}

async function applyProBatchStatus() {
  if (!state.pro.selectedIds.size) {
    showToast("请先选择事件");
    return;
  }
  const status = String(document.getElementById("pro_batch_status")?.value || "done");
  try {
    const resp = await api("/api/v2/pro/events/batch-status", {
      method: "POST",
      body: {
        event_ids: [...state.pro.selectedIds],
        process_status: status,
      },
    });
    showToast(`批量更新成功，影响 ${resp.affected || 0} 条`);
    state.pro.selectedIds.clear();
    await loadProEvents();
  } catch (err) {
    showToast(`批量更新失败：${err.message}`);
  }
}

async function saveProEventNote() {
  const eventId = state.pro.selectedEventId;
  if (!eventId) {
    showToast("请先选择事件");
    return;
  }
  const note = String(document.getElementById("pro_note_text")?.value || "");
  try {
    await api(`/api/v2/pro/events/${encodeURIComponent(eventId)}/note`, { method: "POST", body: { note } });
    showToast("备注已保存");
    await loadProEventDetail(eventId);
  } catch (err) {
    showToast(`保存失败：${err.message}`);
  }
}

function exportProEventsCsv() {
  if (!state.pro.items.length) {
    showToast("暂无可导出数据");
    return;
  }
  const rows = state.pro.items.map((x) => ({
    event_id: x.event_id,
    occurred_at: x.occurred_at,
    risk_level: x.risk_level,
    attack_type: x.attack_type,
    source_ip: x.source_ip,
    target_node: x.target_node,
    attack_result: x.attack_result,
    process_status: x.process_status,
  }));
  downloadCsv("pro_events_export.csv", rows);
}

function renderRagSettingsView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const canRebuild = state.profile?.role === ROLE_ADMIN;

  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">知识库设置（RAG）</h3>
        <div style="display:flex;gap:8px;">
          <button id="rag_refresh" class="btn btn-success">刷新</button>
          <button id="rag_rebuild" class="btn btn-danger" ${canRebuild ? "" : "disabled"}>按种子重建</button>
        </div>
      </div>
      <div class="toolbar">
        <div class="filter-group">
          <input id="rag_q" placeholder="关键词检索（title/tags/content）" />
          <input id="rag_attack_type" placeholder="攻击类型（可选）" />
        </div>
      </div>
      <div style="margin-top:8px;" class="panel-sub">当前共 <strong id="rag_total">0</strong> 条知识</div>
    </section>

    <section class="split" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">知识列表</h3></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>文档ID</th>
                <th>标题</th>
                <th>攻击类型</th>
                <th>严重度</th>
                <th>来源</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="rag_table_body"></tbody>
          </table>
        </div>
        <div style="margin-top:8px;display:flex;justify-content:flex-end;gap:8px;">
          <button id="rag_prev_page" class="btn btn-ghost">上一页</button>
          <button id="rag_next_page" class="btn btn-ghost">下一页</button>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">新增知识</h3></div>
        <div class="detail-grid">
          <div><label class="panel-sub">标题</label><input id="rag_new_title" /></div>
          <div><label class="panel-sub">攻击类型</label><input id="rag_new_attack_type" placeholder="如 SQLi/XSS/DDoS" /></div>
          <div><label class="panel-sub">标签</label><input id="rag_new_tags" placeholder="空格分隔关键词" /></div>
          <div>
            <label class="panel-sub">严重度</label>
            <select id="rag_new_severity">
              <option value="low">低</option>
              <option value="medium" selected>中</option>
              <option value="high">高</option>
              <option value="critical">严重</option>
            </select>
          </div>
        </div>
        <div style="margin-top:8px;">
          <label class="panel-sub">正文内容</label>
          <textarea id="rag_new_content" rows="4" placeholder="知识正文"></textarea>
        </div>
        <div style="margin-top:8px;">
          <label class="panel-sub">判定证据</label>
          <textarea id="rag_new_evidence" rows="3" placeholder="命中依据"></textarea>
        </div>
        <div style="margin-top:8px;">
          <label class="panel-sub">处置建议</label>
          <textarea id="rag_new_mitigation" rows="3" placeholder="缓解与处置建议"></textarea>
        </div>
        <div style="margin-top:10px;display:flex;justify-content:flex-end;">
          <button id="rag_add_doc" class="btn btn-primary">新增到知识库</button>
        </div>
      </article>
    </section>
  `;

  document.getElementById("rag_refresh")?.addEventListener("click", () => loadRagDocs(true));
  document.getElementById("rag_rebuild")?.addEventListener("click", rebuildRagFromSeed);
  document.getElementById("rag_add_doc")?.addEventListener("click", addRagDoc);
  document.getElementById("rag_prev_page")?.addEventListener("click", () => {
    state.rag.page = Math.max(1, state.rag.page - 1);
    loadRagDocs().catch((err) => showToast(err.message));
  });
  document.getElementById("rag_next_page")?.addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(state.rag.total / state.rag.pageSize));
    state.rag.page = Math.min(maxPage, state.rag.page + 1);
    loadRagDocs().catch((err) => showToast(err.message));
  });
  document.getElementById("rag_q")?.addEventListener("keyup", (ev) => {
    if (ev.key === "Enter") loadRagDocs(true).catch((err) => showToast(err.message));
  });
  document.getElementById("rag_attack_type")?.addEventListener("keyup", (ev) => {
    if (ev.key === "Enter") loadRagDocs(true).catch((err) => showToast(err.message));
  });

  loadRagDocs(true).catch((err) => showToast(`加载RAG列表失败：${err.message}`));
}

async function loadRagDocs(forcePageOne = false) {
  if (forcePageOne) state.rag.page = 1;
  state.rag.q = String(document.getElementById("rag_q")?.value || "").trim();
  state.rag.attackType = String(document.getElementById("rag_attack_type")?.value || "").trim();
  const params = new URLSearchParams();
  params.set("page", String(state.rag.page));
  params.set("page_size", String(state.rag.pageSize));
  if (state.rag.q) params.set("q", state.rag.q);
  if (state.rag.attackType) params.set("attack_type", state.rag.attackType);
  const data = await api(`/api/v2/rag/docs?${params.toString()}`);
  state.rag.items = Array.isArray(data.items) ? data.items : [];
  state.rag.total = Number(data.total || 0);
  renderRagTable();
}

function renderRagTable() {
  const body = document.getElementById("rag_table_body");
  const total = document.getElementById("rag_total");
  if (total) total.textContent = String(state.rag.total || 0);
  if (!body) return;
  if (!state.rag.items.length) {
    body.innerHTML = `<tr><td colspan="6" class="panel-sub">暂无RAG知识</td></tr>`;
    return;
  }
  body.innerHTML = state.rag.items
    .map(
      (x) => `
      <tr>
        <td>${escapeHtml(x.doc_id || "-")}</td>
        <td title="${escapeHtml(x.title || "")}">${escapeHtml((x.title || "-").slice(0, 36))}</td>
        <td>${escapeHtml(x.attack_type || "-")}</td>
        <td>${escapeHtml(x.severity || "-")}</td>
        <td>${escapeHtml(x.source || "-")}</td>
        <td><button class="btn btn-danger" data-rag-del="${escapeHtml(x.doc_id || "")}">删除</button></td>
      </tr>
    `
    )
    .join("");
  body.querySelectorAll("[data-rag-del]").forEach((el) => {
    el.addEventListener("click", async () => {
      const docId = String(el.getAttribute("data-rag-del") || "");
      if (!docId) return;
      try {
        await api(`/api/v2/rag/docs/${encodeURIComponent(docId)}/delete`, { method: "POST", body: {} });
        showToast(`已删除 ${docId}`);
        await loadRagDocs();
      } catch (err) {
        showToast(`删除失败：${err.message}`);
      }
    });
  });
}

async function addRagDoc() {
  const payload = {
    title: String(document.getElementById("rag_new_title")?.value || "").trim(),
    attack_type: String(document.getElementById("rag_new_attack_type")?.value || "").trim(),
    tags: String(document.getElementById("rag_new_tags")?.value || "").trim(),
    severity: String(document.getElementById("rag_new_severity")?.value || "medium").trim().toLowerCase(),
    content: String(document.getElementById("rag_new_content")?.value || "").trim(),
    evidence: String(document.getElementById("rag_new_evidence")?.value || "").trim(),
    mitigation: String(document.getElementById("rag_new_mitigation")?.value || "").trim(),
  };
  if (!payload.title || !payload.content) {
    showToast("标题和正文内容必填");
    return;
  }
  const resp = await api("/api/v2/rag/docs", { method: "POST", body: payload });
  showToast(`新增成功：${resp.doc_id || ""}`);
  ["rag_new_title", "rag_new_attack_type", "rag_new_tags", "rag_new_content", "rag_new_evidence", "rag_new_mitigation"].forEach(
    (id) => {
      const el = document.getElementById(id);
      if (el) el.value = "";
    }
  );
  await loadRagDocs(true);
}

async function rebuildRagFromSeed() {
  try {
    const resp = await api("/api/v2/rag/rebuild", { method: "POST", body: {} });
    showToast(`重建完成，装载 ${resp.rows || 0} 条`);
    await loadRagDocs(true);
  } catch (err) {
    showToast(`重建失败：${err.message}`);
  }
}

function renderProModelView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">模型性能页面</h3>
        <button id="pro_model_refresh" class="btn btn-success">刷新</button>
      </div>
      <div class="grid-3">
        <article class="panel">
          <div class="panel-head"><h3 class="panel-title">数据漂移趋势</h3></div>
          <div id="chartModelDrift" class="chart-box short"></div>
        </article>
        <article class="panel">
          <div class="panel-head"><h3 class="panel-title">准确率/召回率趋势</h3></div>
          <div id="chartModelAccRecall" class="chart-box short"></div>
        </article>
        <article class="panel">
          <div class="panel-head"><h3 class="panel-title">推理耗时分布</h3></div>
          <div id="chartModelLatency" class="chart-box short"></div>
        </article>
      </div>
    </section>
  `;
  document.getElementById("pro_model_refresh")?.addEventListener("click", () => refreshProModelPerformance());
  refreshProModelPerformance().catch((err) => showToast(`加载模型性能失败：${err.message}`));
}

async function refreshProModelPerformance() {
  const data = await api("/api/v2/pro/model/performance");
  const trend = Array.isArray(data.trend) ? data.trend : [];
  const dist = Array.isArray(data.inference_distribution) ? data.inference_distribution : [];

  renderSimpleLineChart("chartModelDrift", trend, "d", [{ key: "drift_score", color: "#ff6f6f", name: "漂移" }], 0, 0.3);
  renderSimpleLineChart(
    "chartModelAccRecall",
    trend,
    "d",
    [
      { key: "accuracy", color: "#2ca7ff", name: "准确率" },
      { key: "recall_rate", color: "#16d88b", name: "召回率" },
    ],
    0.75,
    1.0
  );
  renderTopTypeBarChart("chartModelLatency", dist.map((x) => ({ attack_type: x.bucket, total: x.count })));
}

function renderAdminOverview() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="metric-cards">
      <article class="metric-item"><div class="label">在线防护机器总数</div><div id="adm_online_total" class="value">0</div></article>
      <article class="metric-item"><div class="label">今日所有机器总攻击数</div><div id="adm_today_total" class="value">0</div></article>
      <article class="metric-item"><div class="label">存在告警的机器数</div><div id="adm_alert_machine" class="value">0</div></article>
      <article class="metric-item"><div class="label">异常离线机器数</div><div id="adm_offline_machine" class="value">0</div></article>
    </section>

    <section class="grid-2" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">各机器攻击数量排名</h3></div>
        <div id="chartAdminRanking" class="chart-box"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">近7天全平台攻击趋势</h3></div>
        <div id="chartAdminTrend7d" class="chart-box"></div>
      </article>
    </section>

    <section class="split" style="margin-top:10px;">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">机器运行状态列表</h3><button id="adm_refresh" class="btn btn-success">刷新</button></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>机器名称</th>
                <th>IP地址</th>
                <th>部署位置</th>
                <th>在线状态</th>
                <th>今日攻击数</th>
                <th>当前告警数</th>
                <th>最后心跳</th>
              </tr>
            </thead>
            <tbody id="adm_machine_body"></tbody>
          </table>
        </div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">机器详情</h3></div>
        <div id="adm_machine_detail" class="detail-card">点击左侧机器查看详情</div>
      </article>
    </section>
  `;

  document.getElementById("adm_refresh")?.addEventListener("click", () => refreshAdminOverview());
  refreshAdminOverview().catch((err) => showToast(`加载管理员概览失败：${err.message}`));
}

async function refreshAdminOverview() {
  const [summary, ranking, trend7d, machines] = await Promise.all([
    api("/api/v2/admin/summary"),
    api("/api/v2/admin/machines/ranking"),
    api("/api/v2/admin/trend7d"),
    api("/api/v2/admin/machines"),
  ]);
  state.admin.summary = summary;
  state.admin.ranking = Array.isArray(ranking.items) ? ranking.items : [];
  state.admin.trend = Array.isArray(trend7d.items) ? trend7d.items : [];
  state.admin.machines = Array.isArray(machines.items) ? machines.items : [];

  animateTextNumber("adm_online_total", Number(summary.online_machine_total || 0), "");
  animateTextNumber("adm_today_total", Number(summary.today_attack_total || 0), "");
  animateTextNumber("adm_alert_machine", Number(summary.alert_machine_count || 0), "");
  animateTextNumber("adm_offline_machine", Number(summary.offline_machine_count || 0), "");

  renderTopTypeBarChart(
    "chartAdminRanking",
    state.admin.ranking.map((x) => ({ attack_type: x.machine_name, total: x.attack_total }))
  );
  renderSimpleLineChart(
    "chartAdminTrend7d",
    state.admin.trend,
    "d",
    [{ key: "total", color: "#2ca7ff", name: "总攻击" }],
    0,
    undefined
  );
  renderAdminMachineTable();
  if (state.admin.selectedMachineId) {
    await loadAdminMachineDetail(state.admin.selectedMachineId);
  }
}

function renderAdminMachineTable() {
  const body = document.getElementById("adm_machine_body");
  if (!body) return;
  if (!state.admin.machines.length) {
    body.innerHTML = `<tr><td colspan="7" class="panel-sub">暂无机器数据</td></tr>`;
    return;
  }
  body.innerHTML = state.admin.machines
    .map(
      (x) => `
      <tr class="${x.id === state.admin.selectedMachineId ? "active" : ""}">
        <td><span class="link-btn" data-adm-machine="${x.id}">${escapeHtml(x.machine_name || "-")}</span></td>
        <td>${escapeHtml(x.ip_address || "-")}</td>
        <td>${escapeHtml(x.deploy_location || "-")}</td>
        <td>${escapeHtml(formatOnlineStatus(x.online_status || "-"))}</td>
        <td>${escapeHtml(String(x.today_attack_count || 0))}</td>
        <td>${escapeHtml(String(x.current_alert_count || 0))}</td>
        <td>${escapeHtml(x.last_heartbeat || "-")}</td>
      </tr>
    `
    )
    .join("");

  body.querySelectorAll("[data-adm-machine]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = Number(el.getAttribute("data-adm-machine") || 0);
      if (!id) return;
      loadAdminMachineDetail(id).catch((err) => showToast(err.message));
    });
  });
}

async function loadAdminMachineDetail(machineId) {
  state.admin.selectedMachineId = machineId;
  state.admin.selectedMachineDetail = await api(`/api/v2/admin/machines/${machineId}`);
  renderAdminMachineTable();

  const box = document.getElementById("adm_machine_detail");
  if (!box) return;
  const machine = state.admin.selectedMachineDetail.machine || {};
  const events = (state.admin.selectedMachineDetail.events || []).slice(0, 8);
  box.innerHTML = `
    <div class="detail-grid">
      <div class="kv"><strong>机器：</strong>${escapeHtml(machine.machine_name || "-")}</div>
      <div class="kv"><strong>IP：</strong>${escapeHtml(machine.ip_address || "-")}</div>
      <div class="kv"><strong>部署位置：</strong>${escapeHtml(machine.deploy_location || "-")}</div>
      <div class="kv"><strong>在线状态：</strong>${escapeHtml(formatOnlineStatus(machine.online_status || "-"))}</div>
      <div class="kv"><strong>CPU：</strong>${escapeHtml(String(machine.cpu_usage || 0))}%</div>
      <div class="kv"><strong>内存：</strong>${escapeHtml(String(machine.memory_usage || 0))}%</div>
      <div class="kv"><strong>GPU：</strong>${escapeHtml(String(machine.gpu_usage || 0))}%</div>
      <div class="kv"><strong>模型状态：</strong>${escapeHtml(formatModelStatus(machine.model_status || "-"))}</div>
    </div>
    <div style="margin-top:8px;"><button id="adm_restart_service" class="btn btn-danger">远程重启防护服务</button></div>
    <div style="margin-top:8px;" class="kv"><strong>近期攻击记录：</strong></div>
    <pre>${escapeHtml(events.map((x) => `${x.occurred_at} | ${x.risk_level} | ${x.attack_type} | ${x.source_ip} | ${x.attack_result}`).join("\n"))}</pre>
  `;
  document.getElementById("adm_restart_service")?.addEventListener("click", async () => {
    try {
      await api(`/api/v2/admin/machines/${machineId}/restart-service`, { method: "POST", body: {} });
      showToast("已触发远程重启（demo）");
      await refreshAdminOverview();
    } catch (err) {
      showToast(`重启失败：${err.message}`);
    }
  });
}

function renderAdminLogsView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">管理员 - 用户操作日志</h3>
        <div class="ops-group">
          <input id="adm_log_user" placeholder="按用户名筛选" style="max-width:160px;" />
          <button id="adm_log_search" class="btn btn-success">查询</button>
        </div>
      </div>
      <div class="table-shell">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>用户名</th>
              <th>角色</th>
              <th>动作</th>
              <th>目标</th>
              <th>详情</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody id="adm_log_body"></tbody>
        </table>
      </div>
      <div style="margin-top:8px;display:flex;justify-content:flex-end;gap:8px;">
        <button id="adm_log_prev" class="btn btn-ghost">上一页</button>
        <button id="adm_log_next" class="btn btn-ghost">下一页</button>
      </div>
      <div class="panel-sub" id="adm_log_info" style="margin-top:6px;">-</div>
    </section>
  `;
  document.getElementById("adm_log_search")?.addEventListener("click", () => {
    state.admin.logsUsername = String(document.getElementById("adm_log_user")?.value || "").trim();
    state.admin.logsPage = 1;
    loadAdminLogs().catch((err) => showToast(err.message));
  });
  document.getElementById("adm_log_prev")?.addEventListener("click", () => {
    state.admin.logsPage = Math.max(1, state.admin.logsPage - 1);
    loadAdminLogs().catch((err) => showToast(err.message));
  });
  document.getElementById("adm_log_next")?.addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(state.admin.logsTotal / state.admin.logsPageSize));
    state.admin.logsPage = Math.min(maxPage, state.admin.logsPage + 1);
    loadAdminLogs().catch((err) => showToast(err.message));
  });
  loadAdminLogs().catch((err) => showToast(`加载日志失败：${err.message}`));
}

async function loadAdminLogs() {
  const params = new URLSearchParams();
  params.set("page", String(state.admin.logsPage));
  params.set("page_size", String(state.admin.logsPageSize));
  if (state.admin.logsUsername) params.set("username", state.admin.logsUsername);
  const data = await api(`/api/v2/admin/user-op-logs?${params.toString()}`);
  state.admin.logs = Array.isArray(data.items) ? data.items : [];
  state.admin.logsTotal = Number(data.total || 0);

  const body = document.getElementById("adm_log_body");
  if (!body) return;
  if (!state.admin.logs.length) {
    body.innerHTML = `<tr><td colspan="7" class="panel-sub">暂无日志</td></tr>`;
  } else {
    body.innerHTML = state.admin.logs
      .map(
        (x) => `
      <tr>
        <td>${escapeHtml(String(x.id || ""))}</td>
        <td>${escapeHtml(x.username || "-")}</td>
        <td>${escapeHtml(ROLE_LABEL[x.role] || x.role || "-")}</td>
        <td>${escapeHtml(x.action || "-")}</td>
        <td>${escapeHtml(x.target || "-")}</td>
        <td>${escapeHtml(x.detail || "-")}</td>
        <td>${escapeHtml(x.created_at || "-")}</td>
      </tr>
    `
      )
      .join("");
  }
  const info = document.getElementById("adm_log_info");
  if (info) {
    const maxPage = Math.max(1, Math.ceil(state.admin.logsTotal / state.admin.logsPageSize));
    info.textContent = `总计 ${state.admin.logsTotal} 条，当前第 ${state.admin.logsPage}/${maxPage} 页`;
  }
}

function renderAdminConfigView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">管理员 - 全局配置</h3>
        <div class="ops-group">
          <button id="adm_cfg_refresh" class="btn btn-success">刷新配置</button>
          <button id="adm_export_report" class="btn btn-danger">导出全平台攻击统计报告</button>
        </div>
      </div>
      <div class="filter-group" style="grid-template-columns:repeat(3,minmax(220px,1fr));">
        <div>
          <label>高危告警阈值</label>
          <input id="cfg_alert_threshold_high" type="number" min="1" />
        </div>
        <div>
          <label>自动刷新间隔(秒)</label>
          <input id="cfg_auto_refresh_seconds" type="number" min="1" />
        </div>
        <div>
          <label>声音告警开关(1开/0关)</label>
          <input id="cfg_sound_alert_enabled" type="number" min="0" max="1" />
        </div>
        <div>
          <label>数据包分组数量</label>
          <input id="cfg_capture_batch_size" type="number" min="1" />
        </div>
        <div>
          <label>监测端口(逗号分隔)</label>
          <input id="cfg_monitor_ports" placeholder="80,443,8080" />
        </div>
      </div>
      <div style="margin-top:10px;display:flex;justify-content:flex-end;">
        <button id="adm_cfg_save" class="btn btn-primary">保存全局配置</button>
      </div>
    </section>
  `;
  document.getElementById("adm_cfg_refresh")?.addEventListener("click", () => loadAdminConfig());
  document.getElementById("adm_cfg_save")?.addEventListener("click", () => saveAdminConfig());
  document.getElementById("adm_export_report")?.addEventListener("click", () => exportAdminReport());
  loadAdminConfig().catch((err) => showToast(`加载配置失败：${err.message}`));
}

async function loadAdminConfig() {
  const data = await api("/api/v2/admin/config");
  const items = Array.isArray(data.items) ? data.items : [];
  const map = {};
  items.forEach((x) => {
    map[x.config_key] = x.config_value;
  });
  state.admin.config = map;
  setInputValue("cfg_alert_threshold_high", map.alert_threshold_high || "10");
  setInputValue("cfg_auto_refresh_seconds", map.auto_refresh_seconds || "5");
  setInputValue("cfg_sound_alert_enabled", map.sound_alert_enabled || "1");
  setInputValue("cfg_capture_batch_size", map.capture_batch_size || "4");
  setInputValue("cfg_monitor_ports", map.monitor_ports || "80,443,8080");
}

async function saveAdminConfig() {
  const payload = {
    alert_threshold_high: String(document.getElementById("cfg_alert_threshold_high")?.value || "10"),
    auto_refresh_seconds: String(document.getElementById("cfg_auto_refresh_seconds")?.value || "5"),
    sound_alert_enabled: String(document.getElementById("cfg_sound_alert_enabled")?.value || "1"),
    capture_batch_size: String(document.getElementById("cfg_capture_batch_size")?.value || "4"),
    monitor_ports: String(document.getElementById("cfg_monitor_ports")?.value || "80,443,8080"),
  };
  await api("/api/v2/admin/config", { method: "PUT", body: payload });
  showToast("配置保存成功");
  await loadAdminConfig();
}

async function exportAdminReport() {
  const blob = await api("/api/v2/admin/reports/export", { responseType: "blob" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "platform_report_30d.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast("报表导出成功");
}

function renderUserCenterView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head"><h3 class="panel-title">\u7528\u6237\u4e2d\u5fc3</h3></div>
      <div class="detail-grid">
        <div><label class="panel-sub">\u5f53\u524d\u8d26\u53f7</label><input value="${escapeHtml(state.profile?.username || "-")}" disabled /></div>
        <div><label class="panel-sub">\u5f53\u524d\u89d2\u8272</label><input value="${escapeHtml(ROLE_LABEL[state.profile?.role] || state.profile?.role || "-")}" disabled /></div>
        <div><label class="panel-sub">\u65e7\u5bc6\u7801</label><input id="uc_old_password" type="password" autocomplete="current-password" /></div>
        <div><label class="panel-sub">\u65b0\u5bc6\u7801</label><input id="uc_new_password" type="password" autocomplete="new-password" /></div>
        <div><label class="panel-sub">\u786e\u8ba4\u65b0\u5bc6\u7801</label><input id="uc_confirm_password" type="password" autocomplete="new-password" /></div>
      </div>
      <div style="margin-top:10px;display:flex;justify-content:flex-end;">
        <button id="uc_save_password" class="btn btn-primary">\u4fee\u6539\u5bc6\u7801</button>
      </div>
    </section>
  `;
  document.getElementById("uc_save_password")?.addEventListener("click", () => updateSelfPassword());
}

async function updateSelfPassword() {
  const oldPassword = String(document.getElementById("uc_old_password")?.value || "").trim();
  const newPassword = String(document.getElementById("uc_new_password")?.value || "").trim();
  const confirmPassword = String(document.getElementById("uc_confirm_password")?.value || "").trim();
  if (!oldPassword || !newPassword || !confirmPassword) {
    showToast("\u8bf7\u5b8c\u6574\u586b\u5199\u5bc6\u7801\u4fe1\u606f");
    return;
  }
  if (newPassword !== confirmPassword) {
    showToast("\u4e24\u6b21\u8f93\u5165\u7684\u65b0\u5bc6\u7801\u4e0d\u4e00\u81f4");
    return;
  }
  if (newPassword.length < 4) {
    showToast("\u65b0\u5bc6\u7801\u81f3\u5c114\u4f4d");
    return;
  }
  await api("/api/v2/auth/change-password", {
    method: "POST",
    body: { old_password: oldPassword, new_password: newPassword },
  });
  setInputValue("uc_old_password", "");
  setInputValue("uc_new_password", "");
  setInputValue("uc_confirm_password", "");
  showToast("\u5bc6\u7801\u4fee\u6539\u6210\u529f");
}

function renderAdminUsersView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="panel">
      <div class="panel-head">
        <h3 class="panel-title">\u7ba1\u7406\u5458 - \u7528\u6237\u7ba1\u7406</h3>
        <button id="adm_users_refresh" class="btn btn-success">\u5237\u65b0\u7528\u6237</button>
      </div>
      <div class="table-shell">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>\u7528\u6237\u540d</th>
              <th>\u89d2\u8272</th>
              <th>\u663e\u793a\u540d</th>
              <th>\u66f4\u65b0\u65f6\u95f4</th>
              <th>\u91cd\u7f6e\u5bc6\u7801</th>
            </tr>
          </thead>
          <tbody id="adm_users_body"></tbody>
        </table>
      </div>
    </section>
  `;
  document.getElementById("adm_users_refresh")?.addEventListener("click", () => loadAdminUsers());
  loadAdminUsers().catch((err) => showToast(`\u52a0\u8f7d\u7528\u6237\u5931\u8d25\uff1a${err.message}`));
}

async function loadAdminUsers() {
  const data = await api("/api/v2/admin/users");
  state.admin.users = Array.isArray(data.items) ? data.items : [];
  const body = document.getElementById("adm_users_body");
  if (!body) return;
  if (!state.admin.users.length) {
    body.innerHTML = `<tr><td colspan="6" class="panel-sub">\u6682\u65e0\u7528\u6237</td></tr>`;
    return;
  }
  body.innerHTML = state.admin.users
    .map(
      (x) => `
      <tr>
        <td>${escapeHtml(String(x.id || ""))}</td>
        <td>${escapeHtml(x.username || "-")}</td>
        <td>${escapeHtml(ROLE_LABEL[x.role] || x.role || "-")}</td>
        <td>${escapeHtml(x.display_name || "-")}</td>
        <td>${escapeHtml(x.updated_at || "-")}</td>
        <td>
          <div style="display:flex;gap:8px;">
            <input type="password" data-adm-user-pass="${escapeHtml(x.username || "")}" placeholder="\u65b0\u5bc6\u7801" style="max-width:160px;" />
            <button class="btn btn-danger" data-adm-user-save="${escapeHtml(x.username || "")}">\u66f4\u65b0</button>
          </div>
        </td>
      </tr>
    `
    )
    .join("");
  body.querySelectorAll("[data-adm-user-save]").forEach((el) => {
    el.addEventListener("click", async () => {
      const username = String(el.getAttribute("data-adm-user-save") || "");
      if (!username) return;
      const input = el.closest("tr")?.querySelector("[data-adm-user-pass]");
      const newPassword = String(input?.value || "").trim();
      if (!newPassword) {
        showToast("\u8bf7\u8f93\u5165\u65b0\u5bc6\u7801");
        return;
      }
      if (newPassword.length < 4) {
        showToast("\u65b0\u5bc6\u7801\u81f3\u5c114\u4f4d");
        return;
      }
      await api(`/api/v2/admin/users/${encodeURIComponent(username)}/password`, {
        method: "PUT",
        body: { new_password: newPassword },
      });
      if (input) input.value = "";
      showToast(`\u5df2\u66f4\u65b0 ${username} \u5bc6\u7801`);
    });
  });
}

function renderTrendChart(containerId, rows) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 640);
  const height = Math.max(container.clientHeight, 280);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无趋势数据</div>`;
    return;
  }
  const margin = { l: 48, r: 20, t: 20, b: 40 };
  const cw = width - margin.l - margin.r;
  const ch = height - margin.t - margin.b;
  const maxY = Math.max(...rows.map((x) => Number(x.total_attack || 0)), 1);
  const xStep = rows.length > 1 ? cw / (rows.length - 1) : cw;
  const x = (idx) => margin.l + idx * xStep;
  const y = (v) => margin.t + ch - (Number(v) / maxY) * ch;

  const totalPts = rows.map((row, idx) => `${x(idx)},${y(row.total_attack || 0)}`).join(" ");
  const blockedPts = rows.map((row, idx) => `${x(idx)},${y(row.blocked_attack || 0)}`).join(" ");

  const circles = rows
    .map((row, idx) => {
      const isPeak = row.is_peak;
      return `<circle cx="${x(idx)}" cy="${y(row.total_attack || 0)}" r="${isPeak ? 5 : 3}" fill="${
        isPeak ? "#ff4965" : "#2ca7ff"
      }" data-tip="日期: ${row.date}\n总攻击: ${row.total_attack}\n拦截: ${row.blocked_attack}" />`;
    })
    .join("");

  const xLabels = rows
    .map((row, idx) => `<text x="${x(idx)}" y="${height - 10}" fill="#8fbadf" font-size="11" text-anchor="middle">${row.date.slice(5)}</text>`)
    .join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <line x1="${margin.l}" y1="${margin.t + ch}" x2="${margin.l + cw}" y2="${margin.t + ch}" stroke="#4c7fae" stroke-width="1" />
      <line x1="${margin.l}" y1="${margin.t}" x2="${margin.l}" y2="${margin.t + ch}" stroke="#4c7fae" stroke-width="1" />
      <polyline fill="none" stroke="#2ca7ff" stroke-width="2.2" points="${totalPts}" />
      <polyline fill="none" stroke="#16d88b" stroke-width="2.2" points="${blockedPts}" />
      ${circles}
      ${xLabels}
      <text x="${width - 130}" y="18" fill="#9ec6e6" font-size="12">蓝:总攻击  绿:拦截</text>
    </svg>
  `;
}

function renderTopTypeBarChart(containerId, rows) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 520);
  const height = Math.max(container.clientHeight, 260);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无柱状图数据</div>`;
    return;
  }
  const data = rows.slice(0, 10);
  const margin = { l: 110, r: 26, t: 16, b: 20 };
  const cw = width - margin.l - margin.r;
  const ch = height - margin.t - margin.b;
  const maxV = Math.max(...data.map((x) => Number(x.total || 0)), 1);
  const barH = Math.max(14, ch / data.length - 6);
  const gap = 6;
  const parts = [];
  data.forEach((row, idx) => {
    const y = margin.t + idx * (barH + gap);
    const ratio = Number(row.total || 0) / maxV;
    const bw = Math.max(2, cw * ratio);
    const color = idx < 3 ? `url(#hotGrad${idx})` : "url(#coolGrad)";
    parts.push(
      `<text x="${margin.l - 8}" y="${y + barH * 0.74}" text-anchor="end" fill="#9ec6e6" font-size="12">${escapeHtml(
        String(row.attack_type || row.bucket || "-")
      )}</text>`
    );
    parts.push(
      `<rect x="${margin.l}" y="${y}" width="${bw}" height="${barH}" rx="6" fill="${color}" data-tip="${
        row.attack_type || row.bucket || "-"
      }: ${row.total}" />`
    );
    parts.push(`<text x="${margin.l + bw + 6}" y="${y + barH * 0.74}" fill="#d9f1ff" font-size="12">${row.total}</text>`);
  });

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="coolGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#2b9bff"/>
          <stop offset="100%" stop-color="#16d88b"/>
        </linearGradient>
        <linearGradient id="hotGrad0" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#ff4965"/>
          <stop offset="100%" stop-color="#ff8547"/>
        </linearGradient>
        <linearGradient id="hotGrad1" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#ff5f63"/>
          <stop offset="100%" stop-color="#ff9b4a"/>
        </linearGradient>
        <linearGradient id="hotGrad2" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#ff7667"/>
          <stop offset="100%" stop-color="#ffad53"/>
        </linearGradient>
      </defs>
      ${parts.join("")}
    </svg>
  `;
}

function renderPieChart(containerId, rows, labelKey, valueKey) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 360);
  const height = Math.max(container.clientHeight, 230);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无饼图数据</div>`;
    return;
  }
  const cx = width * 0.32;
  const cy = height * 0.52;
  const r = Math.min(width, height) * 0.28;
  const total = rows.reduce((acc, x) => acc + Number(x[valueKey] || 0), 0) || 1;
  const colors = ["#2ca7ff", "#16d88b", "#ffb020", "#ff4965", "#8f7dff", "#3dd3d1", "#d984ff", "#4cd9a6", "#ffd166", "#f88"];

  let start = 0;
  const slices = [];
  const legends = [];
  rows.slice(0, 8).forEach((row, idx) => {
    const val = Number(row[valueKey] || 0);
    const ratio = val / total;
    const end = start + ratio * Math.PI * 2;
    const path = arcPath(cx, cy, r, start, end);
    const color = colors[idx % colors.length];
    slices.push(
      `<path d="${path}" fill="${color}" stroke="#0b1e31" stroke-width="1" data-tip="${escapeHtml(
        String(row[labelKey] || "-")
      )}: ${val}" />`
    );
    legends.push(
      `<rect x="${width * 0.58}" y="${18 + idx * 23}" width="10" height="10" fill="${color}" />
       <text x="${width * 0.58 + 16}" y="${27 + idx * 23}" fill="#cce6ff" font-size="12">${escapeHtml(
         String(row[labelKey] || "-")
       )} (${val})</text>`
    );
    start = end;
  });

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      ${slices.join("")}
      ${legends.join("")}
    </svg>
  `;
}

function renderDonutChart(containerId, rows, labelKey, valueKey) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 360);
  const height = Math.max(container.clientHeight, 230);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无环图数据</div>`;
    return;
  }
  const cx = width * 0.32;
  const cy = height * 0.5;
  const rOuter = Math.min(width, height) * 0.28;
  const rInner = rOuter * 0.58;
  const total = rows.reduce((acc, x) => acc + Number(x[valueKey] || 0), 0) || 1;
  const colors = ["#ff4965", "#2ca7ff", "#16d88b", "#ffb020", "#8f7dff", "#3dd3d1", "#f48fff"];
  let start = 0;
  const parts = [];
  const legends = [];

  rows.slice(0, 8).forEach((row, idx) => {
    const val = Number(row[valueKey] || 0);
    const ratio = val / total;
    const end = start + ratio * Math.PI * 2;
    const path = donutArcPath(cx, cy, rOuter, rInner, start, end);
    const color = colors[idx % colors.length];
    parts.push(
      `<path d="${path}" fill="${color}" stroke="#081b2c" stroke-width="1" data-tip="${escapeHtml(
        String(row[labelKey] || "-")
      )}: ${Number(val).toFixed(2)}%" />`
    );
    legends.push(
      `<rect x="${width * 0.58}" y="${18 + idx * 23}" width="10" height="10" fill="${color}" />
       <text x="${width * 0.58 + 16}" y="${27 + idx * 23}" fill="#cce6ff" font-size="12">${escapeHtml(
         String(row[labelKey] || "-")
       )} (${Number(val).toFixed(1)}%)</text>`
    );
    start = end;
  });

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      ${parts.join("")}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="#e9f5ff" font-size="14">占比</text>
      <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="#7ec7ff" font-size="12">${Number(total).toFixed(1)}%</text>
      ${legends.join("")}
    </svg>
  `;
}

function renderHeatmapChart(containerId, rows) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 360);
  const height = Math.max(container.clientHeight, 230);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无热力图数据</div>`;
    return;
  }
  const margin = { l: 36, r: 10, t: 10, b: 24 };
  const cw = width - margin.l - margin.r;
  const ch = height - margin.t - margin.b;
  const cellW = cw / 24;
  const cellH = ch / 7;
  const maxV = Math.max(...rows.map((x) => Number(x.total || 0)), 1);
  const map = new Map(rows.map((x) => [`${x.weekday_idx}-${x.hour_idx}`, Number(x.total || 0)]));
  const rects = [];
  for (let d = 0; d < 7; d++) {
    for (let h = 0; h < 24; h++) {
      const v = map.get(`${d}-${h}`) || 0;
      const ratio = v / maxV;
      const color = `rgba(44, 167, 255, ${0.1 + ratio * 0.85})`;
      const x = margin.l + h * cellW;
      const y = margin.t + d * cellH;
      rects.push(
        `<rect x="${x + 0.5}" y="${y + 0.5}" width="${Math.max(cellW - 1, 1)}" height="${Math.max(
          cellH - 1,
          1
        )}" fill="${color}" stroke="rgba(57,99,136,0.35)" data-tip="${WEEKDAY_LABELS[d]} ${h}:00  攻击: ${v}" />`
      );
    }
  }
  const xLabels = [0, 3, 6, 9, 12, 15, 18, 21, 23]
    .map((h) => `<text x="${margin.l + h * cellW + cellW / 2}" y="${height - 8}" fill="#9ec6e6" font-size="10" text-anchor="middle">${h}</text>`)
    .join("");
  const yLabels = WEEKDAY_LABELS.map(
    (d, idx) =>
      `<text x="${margin.l - 6}" y="${margin.t + idx * cellH + cellH * 0.68}" fill="#9ec6e6" font-size="10" text-anchor="end">${d}</text>`
  ).join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      ${rects.join("")}
      ${xLabels}
      ${yLabels}
    </svg>
  `;
}

function renderSimpleLineChart(containerId, rows, labelKey, series, minY = 0, maxYOverride) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const width = Math.max(container.clientWidth, 420);
  const height = Math.max(container.clientHeight, 230);
  if (!rows.length) {
    container.innerHTML = `<div class="panel-sub" style="padding:12px;">暂无折线数据</div>`;
    return;
  }
  const margin = { l: 38, r: 16, t: 14, b: 28 };
  const cw = width - margin.l - margin.r;
  const ch = height - margin.t - margin.b;
  const flatVals = [];
  series.forEach((s) => rows.forEach((r) => flatVals.push(Number(r[s.key] || 0))));
  let maxY = Math.max(...flatVals, minY + 1e-6);
  if (typeof maxYOverride === "number") {
    maxY = maxYOverride;
  }
  const xStep = rows.length > 1 ? cw / (rows.length - 1) : cw;
  const x = (idx) => margin.l + idx * xStep;
  const y = (v) => margin.t + ch - ((Number(v) - minY) / Math.max(maxY - minY, 1e-6)) * ch;

  const seriesSvg = series
    .map((s) => {
      const pts = rows.map((r, idx) => `${x(idx)},${y(r[s.key] || 0)}`).join(" ");
      const circles = rows
        .map(
          (r, idx) =>
            `<circle cx="${x(idx)}" cy="${y(r[s.key] || 0)}" r="2.8" fill="${s.color}" data-tip="${escapeHtml(
              `${r[labelKey]} ${s.name}: ${Number(r[s.key] || 0).toFixed(4)}`
            )}" />`
        )
        .join("");
      return `<polyline fill="none" stroke="${s.color}" stroke-width="2" points="${pts}" />${circles}`;
    })
    .join("");

  const labelStep = Math.max(1, Math.floor(rows.length / 6));
  const xLabels = rows
    .map((r, idx) =>
      idx % labelStep === 0 || idx === rows.length - 1
        ? `<text x="${x(idx)}" y="${height - 8}" fill="#9ec6e6" font-size="10" text-anchor="middle">${String(r[labelKey]).slice(5)}</text>`
        : ""
    )
    .join("");
  const legends = series
    .map((s, idx) => `<text x="${width - 140}" y="${16 + idx * 14}" fill="${s.color}" font-size="11">${s.name}</text>`)
    .join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <line x1="${margin.l}" y1="${margin.t + ch}" x2="${margin.l + cw}" y2="${margin.t + ch}" stroke="#4c7fae" />
      <line x1="${margin.l}" y1="${margin.t}" x2="${margin.l}" y2="${margin.t + ch}" stroke="#4c7fae" />
      ${seriesSvg}
      ${xLabels}
      ${legends}
    </svg>
  `;
}

function arcPath(cx, cy, r, start, end) {
  const large = end - start > Math.PI ? 1 : 0;
  const x1 = cx + r * Math.cos(start);
  const y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end);
  const y2 = cy + r * Math.sin(end);
  return `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`;
}

function donutArcPath(cx, cy, rOuter, rInner, start, end) {
  const large = end - start > Math.PI ? 1 : 0;
  const x1 = cx + rOuter * Math.cos(start);
  const y1 = cy + rOuter * Math.sin(start);
  const x2 = cx + rOuter * Math.cos(end);
  const y2 = cy + rOuter * Math.sin(end);
  const x3 = cx + rInner * Math.cos(end);
  const y3 = cy + rInner * Math.sin(end);
  const x4 = cx + rInner * Math.cos(start);
  const y4 = cy + rInner * Math.sin(start);
  return `M ${x1} ${y1} A ${rOuter} ${rOuter} 0 ${large} 1 ${x2} ${y2} L ${x3} ${y3} A ${rInner} ${rInner} 0 ${large} 0 ${x4} ${y4} Z`;
}

function animateTextNumber(id, value, suffix = "") {
  const el = document.getElementById(id);
  if (!el) return;
  const start = Number((el.getAttribute("data-value") || "0").replace(/[^\d.-]/g, "")) || 0;
  const end = Number(value || 0);
  const startAt = performance.now();
  const duration = 500;
  function frame(ts) {
    const p = Math.min((ts - startAt) / duration, 1);
    const cur = start + (end - start) * p;
    const text = Math.abs(end) >= 1000 ? Math.round(cur).toLocaleString("zh-CN") : cur.toFixed(2).replace(/\.00$/, "");
    el.textContent = `${text}${suffix}`;
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  el.setAttribute("data-value", String(end));
}

function riskBadge(level) {
  const safe = escapeHtml(formatRiskLevel(level || "-"));
  if (level === "high") return `<span class="badge badge-high">${safe}</span>`;
  if (level === "medium") return `<span class="badge badge-medium">${safe}</span>`;
  return `<span class="badge badge-low">${safe}</span>`;
}

function formatRiskLevel(level) {
  const map = {
    high: "高危",
    medium: "中危",
    low: "低危",
    critical: "严重",
  };
  return map[String(level || "").toLowerCase()] || level || "-";
}

function formatProcessStatus(status) {
  const map = {
    unprocessed: "未处理",
    processing: "处理中",
    done: "已处理",
    ignored: "已忽略",
  };
  return map[String(status || "").toLowerCase()] || status || "-";
}

function formatAttackResult(result) {
  const map = {
    blocked: "已拦截",
    intercepted: "已拦截",
    success: "攻击成功",
    failed: "攻击失败",
    timeout: "请求超时",
  };
  return map[String(result || "").toLowerCase()] || result || "-";
}

function formatOnlineStatus(status) {
  const map = {
    online: "在线",
    offline: "离线",
    warning: "告警",
    abnormal: "异常",
  };
  return map[String(status || "").toLowerCase()] || status || "-";
}

function formatModelStatus(status) {
  const map = {
    running: "运行中",
    stopped: "已停止",
    healthy: "健康",
    unhealthy: "异常",
    degraded: "退化",
  };
  return map[String(status || "").toLowerCase()] || status || "-";
}

function formatAttackType(attackType) {
  const key = String(attackType || "").trim().toLowerCase();
  const map = {
    sqli: "SQL注入",
    sql_injection: "SQL注入",
    "sql injection": "SQL注入",
    xss: "XSS跨站脚本",
    ddos: "DDoS攻击",
    "brute force": "暴力破解",
    brute_force: "暴力破解",
    bruteforce: "暴力破解",
    port_scan: "端口扫描",
    "port scan": "端口扫描",
    "command injection": "命令注入",
    command_injection: "命令注入",
    rce: "远程代码执行",
  };
  return map[key] || attackType || "-";
}

function bindGlobalTooltip() {
  document.addEventListener("mousemove", (ev) => {
    const target = ev.target instanceof HTMLElement ? ev.target.closest("[data-tip]") : null;
    if (!target) {
      tooltipEl.classList.add("hidden");
      return;
    }
    tooltipEl.textContent = target.getAttribute("data-tip") || "";
    tooltipEl.style.left = `${ev.clientX + 12}px`;
    tooltipEl.style.top = `${ev.clientY + 12}px`;
    tooltipEl.classList.remove("hidden");
  });

  document.addEventListener("mouseleave", () => {
    tooltipEl.classList.add("hidden");
  });
}

function toggleFullscreen() {
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen().catch((err) => showToast(`全屏失败：${err.message}`));
  } else {
    document.exitFullscreen().catch((err) => showToast(`退出全屏失败：${err.message}`));
  }
}

function showToast(message) {
  const div = document.createElement("div");
  div.className = "toast";
  div.textContent = message;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 2400);
}

function clearIntervalSafe(key) {
  if (state.intervals[key]) {
    clearInterval(state.intervals[key]);
    state.intervals[key] = null;
  }
}

function clearAllTimers() {
  Object.keys(state.intervals).forEach(clearIntervalSafe);
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  const body = options.body;
  const responseType = options.responseType || "json";
  const headers = {
    Accept: "application/json",
  };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const fetchOptions = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    fetchOptions.body = JSON.stringify(body);
  }

  const resp = await fetch(path, fetchOptions);
  if (responseType === "blob") {
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    return resp.blob();
  }

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(parseApiError(text, resp.status));
  }
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

function parseApiError(text, status) {
  try {
    const obj = JSON.parse(text);
    return obj.message || obj.error || `HTTP ${status}`;
  } catch {
    return `HTTP ${status}`;
  }
}

function formatDateTime(dt, withMs = true) {
  const d = dt instanceof Date ? dt : new Date(dt);
  if (Number.isNaN(d.getTime())) return "-";
  const base = d.toLocaleString("zh-CN", { hour12: false });
  if (!withMs) return base;
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${base}.${ms}`;
}

function setInputValue(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function downloadCsv(filename, rows) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(",")];
  rows.forEach((row) => {
    const vals = headers.map((h) => `"${String(row[h] ?? "").replaceAll('"', '""')}"`);
    lines.push(vals.join(","));
  });
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
