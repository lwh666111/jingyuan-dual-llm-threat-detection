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

const WEEKDAY_LABELS = [
  "\u5468\u4e00",
  "\u5468\u4e8c",
  "\u5468\u4e09",
  "\u5468\u56db",
  "\u5468\u4e94",
  "\u5468\u516d",
  "\u5468\u65e5",
];

const appEl = document.getElementById("app");
const tooltipEl = document.getElementById("tooltip");
const chartRegistry = {};
let viewTransitionSeq = 0;

const state = {
  token: "",
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
    blocked: {
      q: "",
      page: 1,
      pageSize: 10,
      total: 0,
      items: [],
    },
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
  plugins: {
    activeTool: "phishing",
    phishing: {
      url: "",
      token: "",
      result: null,
      checkedAt: "",
    },
    ipAnalyze: {
      ip: "",
      result: null,
      checkedAt: "",
    },
    localStatus: {
      result: null,
      checkedAt: "",
      loading: false,
    },
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindGlobalTooltip();
  bootstrap();
});

window.addEventListener("resize", () => {
  Object.values(chartRegistry).forEach((ins) => {
    try {
      ins?.resize?.();
    } catch {}
  });
});

function disposeAllCharts() {
  Object.keys(chartRegistry).forEach((k) => {
    try {
      chartRegistry[k]?.dispose?.();
    } catch {}
    delete chartRegistry[k];
  });
}

function animateViewRoot(direction = "right") {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const token = ++viewTransitionSeq;
  root.classList.remove("page-enter", "page-enter-left");
  void root.offsetWidth;
  root.classList.add(direction === "left" ? "page-enter-left" : "page-enter");
  setTimeout(() => {
    if (token === viewTransitionSeq) {
      root.classList.remove("page-enter", "page-enter-left");
    }
  }, 560);
}

function getEchartsInstance(containerId) {
  const el = document.getElementById(containerId);
  if (!el || typeof window.echarts === "undefined") return null;
  if (chartRegistry[containerId] && !chartRegistry[containerId].isDisposed?.()) {
    return chartRegistry[containerId];
  }
  const ins = window.echarts.init(el, null, { renderer: "canvas" });
  chartRegistry[containerId] = ins;
  return ins;
}

async function bootstrap() {
  // Move to cookie-based session persistence. Drop legacy local token cache.
  localStorage.removeItem("attack_demo_token");
  try {
    state.profile = await api("/api/v2/auth/profile");
    renderMainLayout();
    return;
  } catch (err) {
    console.warn("restore profile failed", err);
    state.token = "";
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
        <h1 class="login-title">AI\u653b\u51fb\u6001\u52bf\u611f\u77e5\u5e73\u53f0</h1>
        <p class="login-subtitle">\u8bf7\u9009\u62e9\u8eab\u4efd\u540e\u81ea\u52a8\u586b\u5145\u8d26\u53f7\uff0c\u70b9\u51fb\u767b\u5f55\u8fdb\u5165\u5bf9\u5e94\u9875\u9762</p>

        <div class="form-row">
          <label for="loginUsername">\u7528\u6237\u540d</label>
          <input id="loginUsername" type="text" autocomplete="username" />
        </div>
        <div class="form-row">
          <label for="loginPassword">\u5bc6\u7801</label>
          <input id="loginPassword" type="password" autocomplete="current-password" />
        </div>

        <div class="form-row">
          <label>\u8eab\u4efd\u5feb\u6377\u5207\u6362</label>
          <div class="role-switch">
            <button class="btn active" data-login-role="${ROLE_NORMAL}">\u666e\u901a\u7528\u6237</button>
            <button class="btn" data-login-role="${ROLE_ADMIN}">\u7ba1\u7406\u5458</button>
          </div>
        </div>

        <button id="loginBtn" class="btn btn-primary" style="width:100%;">\u767b\u5f55\u7cfb\u7edf</button>
        <button id="toggleRegisterBtn" class="btn btn-ghost" style="width:100%;margin-top:8px;">\u6ce8\u518c\u65b0\u8d26\u53f7</button>
        <div id="loginError" class="login-error"></div>

        <div id="registerPanel" class="hidden" style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(95,152,206,0.25);">
          <div class="form-row">
            <label for="registerDisplayName">\u663e\u793a\u540d\u79f0</label>
            <input id="registerDisplayName" type="text" autocomplete="nickname" />
          </div>
          <div class="form-row">
            <label for="registerUsername">\u6ce8\u518c\u7528\u6237\u540d\uff08\u5b57\u6bcd/\u6570\u5b57/\u4e0b\u5212\u7ebf\uff09</label>
            <input id="registerUsername" type="text" autocomplete="username" />
          </div>
          <div class="form-row">
            <label for="registerPassword">\u6ce8\u518c\u5bc6\u7801\uff08\u81f3\u5c116\u4f4d\uff09</label>
            <input id="registerPassword" type="password" autocomplete="new-password" />
          </div>
          <div class="form-row">
            <label for="registerPassword2">\u786e\u8ba4\u5bc6\u7801</label>
            <input id="registerPassword2" type="password" autocomplete="new-password" />
          </div>
          <button id="registerBtn" class="btn btn-success" style="width:100%;">\u63d0\u4ea4\u6ce8\u518c</button>
          <div id="registerError" class="login-error"></div>
        </div>
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
      if (errorEl) errorEl.textContent = "\u8bf7\u8f93\u5165\u7528\u6237\u540d\u548c\u5bc6\u7801";
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
      state.token = resp.token || "";
      localStorage.removeItem("attack_demo_token");
      state.profile = await api("/api/v2/auth/profile");
      renderMainLayout();
      showToast(`\u767b\u5f55\u6210\u529f\uff0c\u6b22\u8fce ${state.profile.display_name || ""}`);
    } catch (err) {
      if (errorEl) errorEl.textContent = `\u767b\u5f55\u5931\u8d25\uff1a${err.message}`;
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  appEl.querySelector("#toggleRegisterBtn")?.addEventListener("click", () => {
    const panel = appEl.querySelector("#registerPanel");
    if (!panel) return;
    panel.classList.toggle("hidden");
  });

  appEl.querySelector("#registerBtn")?.addEventListener("click", async () => {
    const displayName = String(appEl.querySelector("#registerDisplayName")?.value || "").trim();
    const username = String(appEl.querySelector("#registerUsername")?.value || "").trim();
    const password = String(appEl.querySelector("#registerPassword")?.value || "").trim();
    const password2 = String(appEl.querySelector("#registerPassword2")?.value || "").trim();
    const errorEl = appEl.querySelector("#registerError");
    if (errorEl) errorEl.textContent = "";
    if (!username || !password) {
      if (errorEl) errorEl.textContent = "\u8bf7\u8f93\u5165\u6ce8\u518c\u7528\u6237\u540d\u548c\u5bc6\u7801";
      return;
    }
    if (password !== password2) {
      if (errorEl) errorEl.textContent = "\u4e24\u6b21\u8f93\u5165\u5bc6\u7801\u4e0d\u4e00\u81f4";
      return;
    }

    const btn = appEl.querySelector("#registerBtn");
    if (btn) btn.disabled = true;
    try {
      const resp = await api("/api/v2/auth/register", {
        method: "POST",
        body: {
          username,
          password,
          display_name: displayName || username,
        },
      });
      state.token = resp.token || "";
      localStorage.removeItem("attack_demo_token");
      state.profile = await api("/api/v2/auth/profile");
      renderMainLayout();
      showToast(`\u6ce8\u518c\u5e76\u767b\u5f55\u6210\u529f\uff0c\u6b22\u8fce ${state.profile.display_name || ""}`);
    } catch (err) {
      if (errorEl) errorEl.textContent = `\u6ce8\u518c\u5931\u8d25\uff1a${err.message}`;
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
  if (passwordEl) passwordEl.value = "";
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
      { id: "plugins", label: "\u6269\u5c55\u63d2\u4ef6" },
      { id: "user-center", label: "\u7528\u6237\u4e2d\u5fc3" },
      { id: "rag-settings", label: "\u77e5\u8bc6\u5e93\u8bbe\u7f6e\uff08RAG\uff09" },
      { id: "admin-logs", label: "\u64cd\u4f5c\u65e5\u5fd7" },
      { id: "admin-config", label: "\u7cfb\u7edf\u914d\u7f6e" },
      { id: "admin-users", label: "\u7ba1\u7406\u7528\u6237" },
    ];
  }
  return [
    { id: "screen", label: "\u6570\u636e\u5927\u5c4f" },
    { id: "pro-query", label: "\u8be6\u60c5\u4fe1\u606f" },
    { id: "plugins", label: "\u6269\u5c55\u63d2\u4ef6" },
    { id: "user-center", label: "\u7528\u6237\u4e2d\u5fc3" },
  ];
}

function switchView(viewId) {
  if (!viewId) return;
  const prevView = state.currentView;
  state.currentView = viewId;
  renderTabs();
  clearIntervalSafe("view");
  disposeAllCharts();
  const tabs = getTabsByRole(state.profile?.role || ROLE_NORMAL);
  const prevIdx = tabs.findIndex((x) => x.id === prevView);
  const nextIdx = tabs.findIndex((x) => x.id === viewId);
  const direction = prevIdx >= 0 && nextIdx >= 0 && nextIdx < prevIdx ? "left" : "right";

  if (viewId === "screen") {
    renderScreenView();
    setViewRefresh(5000, refreshScreenData);
    animateViewRoot(direction);
    return;
  }
  if (viewId === "pro-query") {
    renderProQueryView();
    setViewRefresh(8000, refreshProWorkspace);
    animateViewRoot(direction);
    return;
  }
  if (viewId === "rag-settings") {
    renderRagSettingsView();
    setViewRefresh(15000, loadRagDocs);
    animateViewRoot(direction);
    return;
  }
  if (viewId === "plugins") {
    renderPluginHubView();
    animateViewRoot(direction);
    return;
  }
  if (viewId === "user-center") {
    renderUserCenterView();
    animateViewRoot(direction);
    return;
  }
  if (viewId === "admin-logs") {
    renderAdminLogsView();
    setViewRefresh(12000, loadAdminLogs);
    animateViewRoot(direction);
    return;
  }
  if (viewId === "admin-config") {
    renderAdminConfigView();
    animateViewRoot(direction);
    return;
  }
  if (viewId === "admin-users") {
    renderAdminUsersView();
    animateViewRoot(direction);
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
    <section class="grid-6 dashboard-kpi-grid">
      <article class="kpi-card"><div class="kpi-label">今日遭遇攻击总数</div><div id="kpi_today_attack" class="kpi-value">0</div><div id="kpi_yoy" class="kpi-label">同比：-</div></article>
      <article class="kpi-card"><div class="kpi-label">当前活跃高危告警数</div><div id="kpi_high_alert" class="kpi-value">0</div></article>
      <article class="kpi-card"><div class="kpi-label">攻击拦截成功率</div><div id="kpi_intercept" class="kpi-value">0%</div></article>
      <article class="kpi-card"><div class="kpi-label">平均攻击响应时间</div><div id="kpi_response_ms" class="kpi-value">0ms</div></article>
      <article class="kpi-card"><div class="kpi-label">今日异常检测数</div><div id="kpi_anomaly" class="kpi-value">0</div></article>
      <article class="kpi-card"><div class="kpi-label">在线防护节点数</div><div id="kpi_nodes" class="kpi-value">0</div></article>
    </section>

    <section class="grid-2 dashboard-main-grid">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">近7天攻击趋势（总攻击 / 被拦截）</h3><span class="panel-sub">鼠标悬停查看明细</span></div>
        <div id="chartTrend7d" class="chart-box"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">攻击类型 TOP10</h3><span class="panel-sub">按数量降序</span></div>
        <div id="chartTopTypes" class="chart-box"></div>
      </article>
    </section>

    <section class="grid-3 dashboard-sub-grid">
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
        <div class="ops-group">
          <button id="btnSwitchToScreen" class="btn btn-primary">切换到数据大屏</button>
          <button id="pro_refresh" class="btn btn-success">刷新</button>
          <button id="pro_export" class="btn btn-ghost">导出表格（CSV）</button>
        </div>
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
          <select id="pro_batch_status" style="min-width:180px;" ${canHandle ? "" : "disabled"}>
            <option value="unprocessed">未处理</option>
            <option value="processing">处理中</option>
            <option value="done" selected>已处理</option>
            <option value="ignored">已忽略</option>
          </select>
          <button id="pro_apply_batch" class="btn btn-danger" ${canHandle ? "" : "disabled"}>批量标记状态</button>
          <span class="panel-sub">已选中 <strong id="pro_selected_count">0</strong> 条</span>
        </div>
      </div>
      <div id="pro_custom_time" class="filter-group hidden pro-custom-time">
        <input id="pro_start_time" type="datetime-local" />
        <input id="pro_end_time" type="datetime-local" />
      </div>
    </section>

    <section class="pro-workspace">
      <article class="panel pro-events-panel">
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
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="pro_table_body"></tbody>
          </table>
        </div>
        <div class="table-pager">
          <button id="pro_prev_page" class="btn btn-ghost">上一页</button>
          <button id="pro_next_page" class="btn btn-ghost">下一页</button>
        </div>
      </article>

      <article class="panel pro-detail-panel">
        <div class="panel-head"><h3 class="panel-title">事件详情</h3><span class="panel-sub" id="pro_detail_hint">请选择左侧事件</span></div>
        <div id="pro_event_detail" class="detail-card">暂无详情</div>
        <div class="note-box">
          <textarea id="pro_note_text" rows="3" placeholder="处理备注" ${canHandle ? "" : "disabled"}></textarea>
          <button id="pro_save_note" class="btn btn-success" ${canHandle ? "" : "disabled"}>保存备注</button>
        </div>
        <div class="panel-head pro-node-head"><h3 class="panel-title">节点详情</h3></div>
        <div id="pro_node_detail" class="detail-card">点击目标节点名称查看</div>
      </article>
    </section>

    <section class="panel blocked-ip-panel">
      <div class="panel-head">
        <h3 class="panel-title">已封禁IP列表</h3>
        <div class="ops-group">
          <input id="blocked_ip_q" placeholder="按IP/事件ID/操作人搜索" />
          <button id="blocked_ip_refresh" class="btn btn-success">刷新列表</button>
        </div>
      </div>
      <div class="table-shell blocked-table-shell">
        <table>
          <thead>
            <tr>
              <th>IP地址</th>
              <th>来源事件ID</th>
              <th>封禁原因</th>
              <th>操作人</th>
              <th>封禁时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="blocked_ip_table_body"></tbody>
        </table>
      </div>
      <div class="table-pager">
        <span class="panel-sub" id="blocked_ip_total">总计 0 条</span>
        <div class="ops-group">
          <button id="blocked_ip_prev" class="btn btn-ghost">上一页</button>
          <button id="blocked_ip_next" class="btn btn-ghost">下一页</button>
        </div>
      </div>
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
  document.getElementById("blocked_ip_refresh")?.addEventListener("click", () => loadBlockedIpList(true));
  document.getElementById("blocked_ip_q")?.addEventListener("keyup", (ev) => {
    if (ev.key === "Enter") loadBlockedIpList(true).catch((err) => showToast(err.message));
  });
  document.getElementById("blocked_ip_prev")?.addEventListener("click", () => {
    state.pro.blocked.page = Math.max(1, state.pro.blocked.page - 1);
    loadBlockedIpList().catch((err) => showToast(err.message));
  });
  document.getElementById("blocked_ip_next")?.addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(state.pro.blocked.total / state.pro.blocked.pageSize));
    state.pro.blocked.page = Math.min(maxPage, state.pro.blocked.page + 1);
    loadBlockedIpList().catch((err) => showToast(err.message));
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
  loadBlockedIpList(true).catch((err) => showToast(`加载封禁列表失败：${err.message}`));
}

async function refreshProWorkspace() {
  await loadProEvents();
  await loadBlockedIpList();
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
    bodyEl.innerHTML = `<tr><td colspan="10" class="panel-sub">暂无数据</td></tr>`;
  } else {
    bodyEl.innerHTML = state.pro.items
      .map((row) => {
        const checked = state.pro.selectedIds.has(row.event_id) ? "checked" : "";
        const ipBlocked = Number(row.ip_blocked || 0) === 1;
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
            <td><button type="button" class="btn ${ipBlocked ? "btn-ghost" : "btn-danger"}" data-pro-ipaction="${escapeHtml(row.event_id)}" data-pro-ipblocked="${ipBlocked ? "1" : "0"}">${ipBlocked ? "解封IP" : "封禁IP"}</button></td>
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
  bodyEl.querySelectorAll("[data-pro-ipaction]").forEach((el) => {
    el.addEventListener("click", () => {
      const eventId = el.getAttribute("data-pro-ipaction");
      const ipBlocked = el.getAttribute("data-pro-ipblocked") === "1";
      if (!eventId) return;
      if (ipBlocked) {
        unblockProEventIp(eventId).catch((err) => showToast(err.message));
      } else {
        blockProEventIp(eventId).catch((err) => showToast(err.message));
      }
    });
  });
}

async function loadBlockedIpList(forcePageOne = false) {
  if (forcePageOne) state.pro.blocked.page = 1;
  state.pro.blocked.q = String(document.getElementById("blocked_ip_q")?.value || "").trim();
  const params = new URLSearchParams();
  params.set("page", String(state.pro.blocked.page));
  params.set("page_size", String(state.pro.blocked.pageSize));
  if (state.pro.blocked.q) params.set("q", state.pro.blocked.q);
  const data = await api(`/api/v2/pro/blocked-ips?${params.toString()}`);
  state.pro.blocked.items = Array.isArray(data.items) ? data.items : [];
  state.pro.blocked.total = Number(data.total || 0);
  renderBlockedIpTable();
}

function renderBlockedIpTable() {
  const bodyEl = document.getElementById("blocked_ip_table_body");
  const totalEl = document.getElementById("blocked_ip_total");
  if (totalEl) {
    const maxPage = Math.max(1, Math.ceil(state.pro.blocked.total / state.pro.blocked.pageSize));
    totalEl.textContent = `总计 ${state.pro.blocked.total} 条，当前第 ${state.pro.blocked.page}/${maxPage} 页`;
  }
  if (!bodyEl) return;
  if (!state.pro.blocked.items.length) {
    bodyEl.innerHTML = `<tr><td colspan="6" class="panel-sub">暂无封禁记录</td></tr>`;
    return;
  }
  bodyEl.innerHTML = state.pro.blocked.items
    .map(
      (x) => `
      <tr>
        <td>${escapeHtml(x.ip_address || "-")}</td>
        <td>${escapeHtml(x.source_event_id || "-")}</td>
        <td>${escapeHtml(x.reason || "-")}</td>
        <td>${escapeHtml(x.blocked_by || "-")} (${escapeHtml(x.blocked_role || "-")})</td>
        <td>${escapeHtml(x.blocked_at || "-")}</td>
        <td><button class="btn btn-ghost" data-unblock-ip="${escapeHtml(x.ip_address || "")}">解封该IP</button></td>
      </tr>
    `
    )
    .join("");
  bodyEl.querySelectorAll("[data-unblock-ip]").forEach((el) => {
    el.addEventListener("click", async () => {
      const ip = String(el.getAttribute("data-unblock-ip") || "").trim();
      if (!ip) return;
      try {
        await api("/api/v2/pro/blocked-ips/unblock", {
          method: "POST",
          body: { ip_address: ip, reason: "manual_unblock_from_blocked_list" },
        });
        showToast(`已解封IP：${ip}`);
        await loadProEvents();
        await loadBlockedIpList();
      } catch (err) {
        showToast(`解封失败：${err.message}`);
      }
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
      <div class="kv"><strong>IP\u5c01\u7981\u72b6\u6001\uff1a</strong>${Number(row.ip_blocked || 0) === 1 ? "\u5df2\u5c01\u7981" : "\u672a\u5c01\u7981"}</div>
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


async function blockProEventIp(eventId) {
  const btn = document.querySelector(`[data-pro-ipaction="${escapeHtml(eventId)}"]`);
  if (btn) {
    btn.disabled = true;
    btn.textContent = "封禁中...";
  }
  try {
    const resp = await api(`/api/v2/pro/events/${encodeURIComponent(eventId)}/block-ip`, {
      method: "POST",
      body: { reason: "manual_block_from_ui", block_mode: "source" },
    });
    const ips = Array.isArray(resp.blocked_ips) ? resp.blocked_ips : [];
    const tip = ips.length ? ips.join(", ") : (resp.source_ip || "-");
    showToast(`已封禁来源IP（双向）：${tip}`);
    await loadProEvents();
    await loadBlockedIpList();
    if (state.pro.selectedEventId) {
      await loadProEventDetail(state.pro.selectedEventId);
    }
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.includes("管理员权限") || msg.includes("firewall")) {
      showToast("封禁失败：请用管理员权限启动 app.py 后重试");
    } else {
      showToast(`封禁失败：${msg || "未知错误"}`);
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function unblockProEventIp(eventId) {
  const btn = document.querySelector(`[data-pro-ipaction="${escapeHtml(eventId)}"]`);
  if (btn) {
    btn.disabled = true;
    btn.textContent = "解封中...";
  }
  try {
    const resp = await api(`/api/v2/pro/events/${encodeURIComponent(eventId)}/unblock-ip`, {
      method: "POST",
      body: { reason: "manual_unblock_from_ui", block_mode: "source" },
    });
    const ips = Array.isArray(resp.unblocked_ips) ? resp.unblocked_ips : [];
    const tip = ips.length ? ips.join(", ") : (resp.source_ip || "-");
    showToast(`已解封来源IP：${tip}`);
    await loadProEvents();
    await loadBlockedIpList();
    if (state.pro.selectedEventId) {
      await loadProEventDetail(state.pro.selectedEventId);
    }
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.includes("管理员权限") || msg.includes("firewall")) {
      showToast("解封失败：请用管理员权限启动 app.py 后重试");
    } else {
      showToast(`解封失败：${msg || "未知错误"}`);
    }
  } finally {
    if (btn) btn.disabled = false;
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
        <div class="ops-group">
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
      <div class="panel-sub top-gap-sm">当前共 <strong id="rag_total">0</strong> 条知识</div>
    </section>

    <section class="split">
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
        <div class="table-pager">
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
        <div class="top-gap-sm">
          <label class="panel-sub">正文内容</label>
          <textarea id="rag_new_content" rows="4" placeholder="知识正文"></textarea>
        </div>
        <div class="top-gap-sm">
          <label class="panel-sub">判定证据</label>
          <textarea id="rag_new_evidence" rows="3" placeholder="命中依据"></textarea>
        </div>
        <div class="top-gap-sm">
          <label class="panel-sub">处置建议</label>
          <textarea id="rag_new_mitigation" rows="3" placeholder="缓解与处置建议"></textarea>
        </div>
        <div class="row-actions">
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


function renderPluginHubView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const active = String(state.plugins.activeTool || "phishing");
  root.innerHTML = `
    <section class="split">
      <article class="panel plugin-tools-panel">
        <div class="panel-head">
          <h3 class="panel-title">\u6269\u5c55\u63d2\u4ef6</h3>
          <span class="panel-sub">\u5b9e\u7528\u5de5\u5177\u5217\u8868</span>
        </div>
        <div class="plugin-tool-list">
          <button id="pluginToolPhishing" class="plugin-tool-item ${active === "phishing" ? "active" : ""}">
            <div class="plugin-tool-name">\u9493\u9c7c\u7f51\u7ad9\u68c0\u6d4b\u5de5\u5177</div>
            <div class="plugin-tool-desc">\u68c0\u6d4b\u76ee\u6807URL\u662f\u5426\u5b58\u5728\u9493\u9c7c\u98ce\u9669\u5e76\u8fd4\u56de\u8bc1\u636e\u94fe</div>
          </button>
          <button id="pluginToolIpAnalyze" class="plugin-tool-item ${active === "ip_analyze" ? "active" : ""}">
            <div class="plugin-tool-name">IP地址分析工具</div>
            <div class="plugin-tool-desc">输入IP地址，返回归属地区与公网/内网判定</div>
          </button>
          <button id="pluginToolLocalStatus" class="plugin-tool-item ${active === "local_status" ? "active" : ""}">
            <div class="plugin-tool-name">本机状态工具</div>
            <div class="plugin-tool-desc">查看本机CPU、内存、磁盘和运行时长状态</div>
          </button>
        </div>
      </article>

      <article class="panel plugin-detail-panel">
        <div class="panel-head">
          <h3 class="panel-title">\u5b9e\u7528\u5de5\u5177</h3>
          <span class="panel-sub">\u8bf7\u8f93\u5165\u53c2\u6570\u540e\u6267\u884c\u68c0\u6d4b</span>
        </div>
        <div id="pluginDetailBody"></div>
      </article>
    </section>
  `;
  document.getElementById("pluginToolPhishing")?.addEventListener("click", () => {
    activatePluginTool("phishing");
  });
  document.getElementById("pluginToolIpAnalyze")?.addEventListener("click", () => {
    activatePluginTool("ip_analyze");
  });
  document.getElementById("pluginToolLocalStatus")?.addEventListener("click", () => {
    activatePluginTool("local_status");
    if (!state.plugins.localStatus.result && !state.plugins.localStatus.loading) {
      loadPluginLocalStatus().catch((err) => showToast(`加载本机状态失败：${err.message}`));
    }
  });
  renderPluginDetailBody();
}

function activatePluginTool(toolName) {
  state.plugins.activeTool = toolName;
  renderPluginHubView();
}

function renderPluginDetailBody() {
  const box = document.getElementById("pluginDetailBody");
  if (!box) return;
  const activeTool = String(state.plugins.activeTool || "phishing");
  if (activeTool === "phishing") {
    renderPluginPhishingDetail(box);
    return;
  }
  if (activeTool === "ip_analyze") {
    renderPluginIpAnalyzeDetail(box);
    return;
  }
  if (activeTool === "local_status") {
    renderPluginLocalStatusDetail(box);
    return;
  }
  box.innerHTML = `<div class="panel-sub">\u6682\u65e0\u5de5\u5177</div>`;
}

function renderPluginPhishingDetail(box) {
  const p = state.plugins.phishing;
  const result = p.result || {};
  const evidence = Array.isArray(result.evidence) ? result.evidence : [];
  const verdict = String(result.verdict || "").toLowerCase();
  let verdictClass = "badge-gray";
  if (verdict === "phishing") verdictClass = "badge-red";
  else if (verdict === "safe") verdictClass = "badge-green";
  else if (verdict) verdictClass = "badge-yellow";

  box.innerHTML = `
    <div class="detail-grid">
      <div>
        <label class="panel-sub">\u68c0\u6d4b URL\uff08\u5fc5\u987b http/https\uff09</label>
        <input id="pluginPhishingUrl" value="${escapeHtml(p.url || "")}" placeholder="https://example.com/login" />
      </div>
      <div>
        <label class="panel-sub">Token</label>
        <input id="pluginPhishingToken" value="${escapeHtml(p.token || "")}" placeholder="\u8bf7\u8f93\u5165\u68c0\u6d4b token" />
      </div>
    </div>
    <div class="plugin-actions-row">
      <button id="pluginPhishingSubmit" class="btn btn-primary">\u5f00\u59cb\u68c0\u6d4b</button>
      <span class="panel-sub" id="pluginPhishingHint">${escapeHtml(p.checkedAt ? `\u6700\u8fd1\u68c0\u6d4b\uff1a${p.checkedAt}` : "\u5c1a\u672a\u68c0\u6d4b")}</span>
    </div>
    <div class="plugin-result-shell">
      <div class="plugin-result-row"><span>\u52a8\u4f5c</span><strong>${escapeHtml(result.action || "-")}</strong></div>
      <div class="plugin-result-row"><span>\u5224\u5b9a\u7ed3\u679c</span><strong class="${verdictClass}">${escapeHtml(result.verdict || "-")}</strong></div>
      <div class="plugin-result-row"><span>\u7f6e\u4fe1\u5ea6</span><strong>${result.confidence === undefined || result.confidence === null ? "-" : escapeHtml(String(result.confidence))}</strong></div>
      <div class="plugin-result-row"><span>\u5224\u5b9a\u4f9d\u636e</span><strong>${escapeHtml(result.reason || "-")}</strong></div>
      <div class="plugin-result-evidence">
        <div class="panel-sub">\u8bc1\u636e\u94fe</div>
        <ul>
          ${evidence.length ? evidence.map((x) => `<li>${escapeHtml(String(x))}</li>`).join("") : "<li>-</li>"}
        </ul>
      </div>
    </div>
  `;
  document.getElementById("pluginPhishingSubmit")?.addEventListener("click", runPluginPhishingCheck);
}

function renderPluginIpAnalyzeDetail(box) {
  const p = state.plugins.ipAnalyze;
  const result = p.result || {};
  const isPublic = result.is_public === undefined ? "-" : (result.is_public ? "公网IP" : "内网/保留地址");
  box.innerHTML = `
    <div class="detail-grid">
      <div>
        <label class="panel-sub">IP地址</label>
        <input id="pluginIpInput" value="${escapeHtml(p.ip || "")}" placeholder="例如：8.8.8.8 或 192.168.1.10" />
      </div>
    </div>
    <div class="plugin-actions-row">
      <button id="pluginIpSubmit" class="btn btn-primary">开始分析</button>
      <span class="panel-sub">${escapeHtml(p.checkedAt ? `最近分析：${p.checkedAt}` : "尚未分析")}</span>
    </div>
    <div class="plugin-result-shell">
      <div class="plugin-result-row"><span>IP地址</span><strong>${escapeHtml(result.ip || "-")}</strong></div>
      <div class="plugin-result-row"><span>地区</span><strong>${escapeHtml(result.region || "-")}</strong></div>
      <div class="plugin-result-row"><span>网络类型</span><strong>${escapeHtml(isPublic)}</strong></div>
      <div class="plugin-result-row"><span>数据来源</span><strong>${escapeHtml(result.source || "-")}</strong></div>
      <div class="plugin-result-row"><span>更新时间</span><strong>${escapeHtml(result.updated_at || "-")}</strong></div>
    </div>
  `;
  document.getElementById("pluginIpSubmit")?.addEventListener("click", runPluginIpAnalyze);
}

function renderPluginLocalStatusDetail(box) {
  const p = state.plugins.localStatus;
  const s = p.result || {};
  const mem = s.memory || {};
  const disk = s.disk || {};
  const loadingText = p.loading ? "加载中..." : "刷新";
  box.innerHTML = `
    <div class="plugin-actions-row">
      <button id="pluginLocalStatusRefresh" class="btn btn-success">${loadingText}</button>
      <span class="panel-sub">${escapeHtml(p.checkedAt ? `最近刷新：${p.checkedAt}` : "尚未刷新")}</span>
    </div>
    <div class="plugin-status-grid">
      <div class="plugin-status-card"><span>主机名</span><strong>${escapeHtml(s.hostname || "-")}</strong></div>
      <div class="plugin-status-card"><span>本机IP</span><strong>${escapeHtml(s.local_ip || "-")}</strong></div>
      <div class="plugin-status-card"><span>操作系统</span><strong>${escapeHtml(s.os || "-")}</strong></div>
      <div class="plugin-status-card"><span>CPU占用</span><strong>${s.cpu_percent === undefined || s.cpu_percent === null ? "-" : `${escapeHtml(String(s.cpu_percent))}%`}</strong></div>
      <div class="plugin-status-card"><span>内存占用</span><strong>${mem.used_percent === undefined || mem.used_percent === null ? "-" : `${escapeHtml(String(mem.used_percent))}%`}</strong></div>
      <div class="plugin-status-card"><span>磁盘占用</span><strong>${disk.used_percent === undefined || disk.used_percent === null ? "-" : `${escapeHtml(String(disk.used_percent))}%`}</strong></div>
      <div class="plugin-status-card"><span>内存(已用/总量)</span><strong>${formatBytes(mem.used_bytes)} / ${formatBytes(mem.total_bytes)}</strong></div>
      <div class="plugin-status-card"><span>磁盘(已用/总量)</span><strong>${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)}</strong></div>
      <div class="plugin-status-card"><span>运行时长</span><strong>${s.uptime_hours === undefined || s.uptime_hours === null ? "-" : `${escapeHtml(String(s.uptime_hours))} 小时`}</strong></div>
    </div>
  `;
  document.getElementById("pluginLocalStatusRefresh")?.addEventListener("click", () => {
    loadPluginLocalStatus().catch((err) => showToast(`加载本机状态失败：${err.message}`));
  });
}

async function runPluginPhishingCheck() {
  const url = String(document.getElementById("pluginPhishingUrl")?.value || "").trim();
  const token = String(document.getElementById("pluginPhishingToken")?.value || "").trim();
  if (!/^https?:\/\//i.test(url)) {
    showToast("URL \u5fc5\u987b\u4ee5 http:// \u6216 https:// \u5f00\u5934");
    return;
  }
  if (!token) {
    showToast("\u8bf7\u8f93\u5165 token");
    return;
  }
  const btn = document.getElementById("pluginPhishingSubmit");
  if (btn) btn.disabled = true;
  try {
    const resp = await api("/api/v2/plugins/phishing/check", {
      method: "POST",
      body: { url, token },
    });
    state.plugins.phishing.url = url;
    state.plugins.phishing.token = token;
    state.plugins.phishing.result = resp || {};
    state.plugins.phishing.checkedAt = formatDateTime(new Date(), false);
    renderPluginDetailBody();
    showToast("\u68c0\u6d4b\u5b8c\u6210");
  } catch (err) {
    showToast(`\u68c0\u6d4b\u5931\u8d25\uff1a${err.message}`);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function runPluginIpAnalyze() {
  const ip = String(document.getElementById("pluginIpInput")?.value || "").trim();
  if (!ip) {
    showToast("请输入IP地址");
    return;
  }
  const btn = document.getElementById("pluginIpSubmit");
  if (btn) btn.disabled = true;
  try {
    const resp = await api("/api/v2/plugins/ip-analyze", {
      method: "POST",
      body: { ip },
    });
    state.plugins.ipAnalyze.ip = ip;
    state.plugins.ipAnalyze.result = resp || {};
    state.plugins.ipAnalyze.checkedAt = formatDateTime(new Date(), false);
    renderPluginDetailBody();
    showToast("IP分析完成");
  } catch (err) {
    showToast(`IP分析失败：${err.message}`);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadPluginLocalStatus() {
  state.plugins.localStatus.loading = true;
  renderPluginDetailBody();
  try {
    const resp = await api("/api/v2/plugins/local-status");
    state.plugins.localStatus.result = resp || {};
    state.plugins.localStatus.checkedAt = formatDateTime(new Date(), false);
  } finally {
    state.plugins.localStatus.loading = false;
    renderPluginDetailBody();
  }
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let idx = 0;
  while (v >= 1024 && idx < units.length - 1) {
    v /= 1024;
    idx += 1;
  }
  return `${v.toFixed(v >= 100 || idx === 0 ? 0 : 2)} ${units[idx]}`;
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

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">各机器攻击数量排名</h3></div>
        <div id="chartAdminRanking" class="chart-box"></div>
      </article>
      <article class="panel">
        <div class="panel-head"><h3 class="panel-title">近7天全平台攻击趋势</h3></div>
        <div id="chartAdminTrend7d" class="chart-box"></div>
      </article>
    </section>

    <section class="split">
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
    <div class="top-gap-sm"><button id="adm_restart_service" class="btn btn-danger">远程重启防护服务</button></div>
    <div class="top-gap-sm kv"><strong>近期攻击记录：</strong></div>
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
          <input id="adm_log_user" placeholder="按用户名筛选" class="input-sm" />
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
      <div class="table-pager">
        <button id="adm_log_prev" class="btn btn-ghost">上一页</button>
        <button id="adm_log_next" class="btn btn-ghost">下一页</button>
      </div>
      <div class="panel-sub top-gap-xs" id="adm_log_info">-</div>
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
      <div class="form-grid-3">
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
      <div class="row-actions">
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
      <div class="row-actions">
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
          <div class="inline-pass-reset">
            <input type="password" data-adm-user-pass="${escapeHtml(x.username || "")}" placeholder="\u65b0\u5bc6\u7801" class="input-sm" />
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
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = Array.isArray(rows) ? rows : [];
  const x = data.map((x) => String(x.date || "").slice(5));
  const total = data.map((x) => Number(x.total_attack || 0));
  const blocked = data.map((x) => Number(x.blocked_attack || 0));
  const peakIndex = data.findIndex((x) => Boolean(x.is_peak));

  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 700,
      tooltip: { trigger: "axis" },
      legend: {
        top: 8,
        right: 10,
        textStyle: { color: "#d7ebff" },
        data: ["\u603b\u653b\u51fb", "\u5df2\u62e6\u622a"],
      },
      grid: { left: 46, right: 26, top: 48, bottom: 34 },
      xAxis: {
        type: "category",
        data: x,
        boundaryGap: false,
        axisLabel: { color: "#9ec6e6" },
        axisLine: { lineStyle: { color: "rgba(130,180,225,.45)" } },
      },
      yAxis: {
        type: "value",
        axisLabel: { color: "#9ec6e6" },
        splitLine: { lineStyle: { color: "rgba(130,180,225,.18)" } },
      },
      series: [
        {
          name: "\u603b\u653b\u51fb",
          type: "line",
          smooth: true,
          data: total,
          symbolSize: 8,
          lineStyle: { width: 3, color: "#2ca7ff" },
          itemStyle: { color: "#2ca7ff" },
          areaStyle: { color: "rgba(44,167,255,.16)" },
          markPoint:
            peakIndex >= 0
              ? {
                  data: [{ coord: [x[peakIndex], total[peakIndex]], value: total[peakIndex] }],
                  itemStyle: { color: "#ff4965" },
                }
              : undefined,
        },
        {
          name: "\u5df2\u62e6\u622a",
          type: "line",
          smooth: true,
          data: blocked,
          symbolSize: 7,
          lineStyle: { width: 2.4, color: "#16d88b" },
          itemStyle: { color: "#16d88b" },
          areaStyle: { color: "rgba(22,216,139,.12)" },
        },
      ],
    },
    true
  );
}

function renderTopTypeBarChart(containerId, rows) {
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = (Array.isArray(rows) ? rows : []).slice(0, 10);
  const names = data.map((x) => formatAttackType(String(x.attack_type || x.bucket || "-")));
  const vals = data.map((x) => Number(x.total || x.count || 0));

  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 700,
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: 30, right: 18, top: 18, bottom: 56, containLabel: true },
      xAxis: {
        type: "category",
        data: names,
        axisLabel: { color: "#9ec6e6", rotate: 24 },
        axisLine: { lineStyle: { color: "rgba(130,180,225,.45)" } },
      },
      yAxis: {
        type: "value",
        axisLabel: { color: "#9ec6e6" },
        splitLine: { lineStyle: { color: "rgba(130,180,225,.16)" } },
      },
      series: [
        {
          type: "bar",
          data: vals.map((v, idx) => ({
            value: v,
            itemStyle:
              idx < 3
                ? {
                    color: new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: ["#ff4965", "#ff6a5c", "#ff8a47"][idx] || "#ff4965" },
                      { offset: 1, color: ["#ff8547", "#ff9b4a", "#ffad53"][idx] || "#ff8547" },
                    ]),
                  }
                : {
                    color: new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: "#2ca7ff" },
                      { offset: 1, color: "#16d88b" },
                    ]),
                  },
          })),
          barWidth: "56%",
          label: { show: true, position: "top", color: "#d9f1ff" },
        },
      ],
    },
    true
  );
}

function renderPieChart(containerId, rows, labelKey, valueKey) {
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = (Array.isArray(rows) ? rows : []).slice(0, 10).map((x) => ({
    name: String(x[labelKey] || "-"),
    value: Number(x[valueKey] || 0),
  }));
  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 650,
      tooltip: { trigger: "item" },
      legend: {
        type: "scroll",
        orient: "vertical",
        right: 8,
        top: 12,
        bottom: 12,
        textStyle: { color: "#cce6ff" },
      },
      series: [
        {
          type: "pie",
          radius: ["0%", "66%"],
          center: ["32%", "52%"],
          data,
          label: { color: "#dff1ff" },
          itemStyle: { borderColor: "#081c2e", borderWidth: 1 },
        },
      ],
    },
    true
  );
}

function renderDonutChart(containerId, rows, labelKey, valueKey) {
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = (Array.isArray(rows) ? rows : []).slice(0, 10).map((x) => ({
    name: formatAttackType(String(x[labelKey] || "-")),
    value: Number(x[valueKey] || 0),
  }));
  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 650,
      tooltip: { trigger: "item" },
      legend: {
        type: "scroll",
        orient: "vertical",
        right: 8,
        top: 12,
        bottom: 12,
        textStyle: { color: "#cce6ff" },
      },
      series: [
        {
          type: "pie",
          radius: ["42%", "70%"],
          center: ["34%", "52%"],
          data,
          avoidLabelOverlap: true,
          label: { color: "#dff1ff" },
          itemStyle: { borderColor: "#081c2e", borderWidth: 1 },
        },
      ],
    },
    true
  );
}

function renderHeatmapChart(containerId, rows) {
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = Array.isArray(rows) ? rows : [];
  const heat = data.map((x) => [Number(x.hour_idx || 0), Number(x.weekday_idx || 0), Number(x.total || 0)]);
  const maxVal = Math.max(1, ...heat.map((x) => x[2]));
  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 650,
      tooltip: {
        position: "top",
        formatter: (p) => `${WEEKDAY_LABELS[p.data[1]] || "-"} ${p.data[0]}:00<br/>\u653b\u51fb: ${p.data[2]}`,
      },
      grid: { left: 48, right: 18, top: 18, bottom: 30 },
      xAxis: {
        type: "category",
        data: Array.from({ length: 24 }, (_, i) => String(i)),
        splitArea: { show: true },
        axisLabel: { color: "#9ec6e6" },
      },
      yAxis: {
        type: "category",
        data: WEEKDAY_LABELS,
        splitArea: { show: true },
        axisLabel: { color: "#9ec6e6" },
      },
      visualMap: {
        min: 0,
        max: maxVal,
        calculable: true,
        orient: "horizontal",
        left: "center",
        bottom: 0,
        inRange: { color: ["#0c2033", "#1e5c94", "#2ca7ff", "#7ed9ff"] },
        textStyle: { color: "#dff1ff" },
      },
      series: [
        {
          name: "\u653b\u51fb\u6d3b\u8dc3\u5ea6",
          type: "heatmap",
          data: heat,
          label: { show: false },
          emphasis: { itemStyle: { shadowBlur: 10, shadowColor: "rgba(0,0,0,.4)" } },
        },
      ],
    },
    true
  );
}

function renderSimpleLineChart(containerId, rows, labelKey, series, minY = 0, maxYOverride) {
  const chart = getEchartsInstance(containerId);
  if (!chart) return;
  const data = Array.isArray(rows) ? rows : [];
  const x = data.map((r) => String(r[labelKey] || "").slice(5));
  const yMax =
    typeof maxYOverride === "number"
      ? maxYOverride
      : Math.max(
          minY + 1,
          ...series.flatMap((s) => data.map((r) => Number(r[s.key] || 0)))
        );

  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 650,
      tooltip: { trigger: "axis" },
      legend: {
        top: 8,
        right: 10,
        textStyle: { color: "#d7ebff" },
        data: series.map((s) => s.name),
      },
      grid: { left: 44, right: 18, top: 42, bottom: 30 },
      xAxis: {
        type: "category",
        data: x,
        axisLabel: { color: "#9ec6e6" },
        axisLine: { lineStyle: { color: "rgba(130,180,225,.45)" } },
      },
      yAxis: {
        type: "value",
        min: minY,
        max: yMax,
        axisLabel: { color: "#9ec6e6" },
        splitLine: { lineStyle: { color: "rgba(130,180,225,.18)" } },
      },
      series: series.map((s) => ({
        name: s.name,
        type: "line",
        smooth: true,
        showSymbol: false,
        data: data.map((r) => Number(r[s.key] || 0)),
        lineStyle: { width: 2.2, color: s.color },
        itemStyle: { color: s.color },
        areaStyle: { color: `${s.color}33` },
      })),
    },
    true
  );
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
  fetchOptions.credentials = "same-origin";
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
