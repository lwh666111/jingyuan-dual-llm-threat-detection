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

const BEIJING_COORD = [116.4074, 39.9042];
const WORLD_MAP_NAME = "world";
const WORLD_MAP_SCRIPT_URLS = [
  "/assets/echarts-world-lonlat.js",
  "https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/js/world.js",
];
const REGION_COORDS = {
  beijing: { label: "北京", coord: [116.4074, 39.9042] },
  "\u5317\u4eac": { label: "北京", coord: [116.4074, 39.9042] },
  shanghai: { label: "上海", coord: [121.4737, 31.2304] },
  "\u4e0a\u6d77": { label: "上海", coord: [121.4737, 31.2304] },
  guangdong: { label: "广东", coord: [113.2665, 23.1322] },
  "\u5e7f\u4e1c": { label: "广东", coord: [113.2665, 23.1322] },
  zhejiang: { label: "浙江", coord: [120.1551, 30.2741] },
  "\u6d59\u6c5f": { label: "浙江", coord: [120.1551, 30.2741] },
  jiangsu: { label: "江苏", coord: [118.7969, 32.0603] },
  "\u6c5f\u82cf": { label: "江苏", coord: [118.7969, 32.0603] },
  shandong: { label: "山东", coord: [117.1201, 36.6512] },
  "\u5c71\u4e1c": { label: "山东", coord: [117.1201, 36.6512] },
  henan: { label: "河南", coord: [113.6254, 34.7466] },
  "\u6cb3\u5357": { label: "河南", coord: [113.6254, 34.7466] },
  hunan: { label: "湖南", coord: [112.9823, 28.1941] },
  "\u6e56\u5357": { label: "湖南", coord: [112.9823, 28.1941] },
  hubei: { label: "湖北", coord: [114.3054, 30.5928] },
  "\u6e56\u5317": { label: "湖北", coord: [114.3054, 30.5928] },
  sichuan: { label: "四川", coord: [104.0668, 30.5728] },
  "\u56db\u5ddd": { label: "四川", coord: [104.0668, 30.5728] },
  hongkong: { label: "香港", coord: [114.1694, 22.3193] },
  "hong kong": { label: "香港", coord: [114.1694, 22.3193] },
  "\u9999\u6e2f": { label: "香港", coord: [114.1694, 22.3193] },
  china: { label: "中国", coord: [104.1954, 35.8617] },
  "\u4e2d\u56fd": { label: "中国", coord: [104.1954, 35.8617] },
  poland: { label: "波兰", coord: [19.1451, 51.9194] },
  "\u6ce2\u5170": { label: "波兰", coord: [19.1451, 51.9194] },
  turkey: { label: "土耳其", coord: [35.2433, 38.9637] },
  "\u571f\u8033\u5176": { label: "土耳其", coord: [35.2433, 38.9637] },
  netherlands: { label: "荷兰", coord: [5.2913, 52.1326] },
  "\u8377\u5170": { label: "荷兰", coord: [5.2913, 52.1326] },
  "united states": { label: "美国", coord: [-98.5795, 39.8283] },
  usa: { label: "美国", coord: [-98.5795, 39.8283] },
  us: { label: "美国", coord: [-98.5795, 39.8283] },
  america: { label: "美国", coord: [-98.5795, 39.8283] },
  "\u7f8e\u56fd": { label: "美国", coord: [-98.5795, 39.8283] },
  germany: { label: "德国", coord: [10.4515, 51.1657] },
  "\u5fb7\u56fd": { label: "德国", coord: [10.4515, 51.1657] },
  singapore: { label: "新加坡", coord: [103.8198, 1.3521] },
  "\u65b0\u52a0\u5761": { label: "新加坡", coord: [103.8198, 1.3521] },
  russia: { label: "俄罗斯", coord: [105.3188, 61.524] },
  "\u4fc4\u7f57\u65af": { label: "俄罗斯", coord: [105.3188, 61.524] },
  india: { label: "印度", coord: [78.9629, 20.5937] },
  "\u5370\u5ea6": { label: "印度", coord: [78.9629, 20.5937] },
  france: { label: "法国", coord: [2.2137, 46.2276] },
  "\u6cd5\u56fd": { label: "法国", coord: [2.2137, 46.2276] },
  "united kingdom": { label: "英国", coord: [-3.436, 55.3781] },
  uk: { label: "英国", coord: [-3.436, 55.3781] },
  britain: { label: "英国", coord: [-3.436, 55.3781] },
  "\u82f1\u56fd": { label: "英国", coord: [-3.436, 55.3781] },
  japan: { label: "日本", coord: [138.2529, 36.2048] },
  "\u65e5\u672c": { label: "日本", coord: [138.2529, 36.2048] },
  "south korea": { label: "韩国", coord: [127.7669, 35.9078] },
  korea: { label: "韩国", coord: [127.7669, 35.9078] },
  "\u97e9\u56fd": { label: "韩国", coord: [127.7669, 35.9078] },
  vietnam: { label: "越南", coord: [108.2772, 14.0583] },
  "\u8d8a\u5357": { label: "越南", coord: [108.2772, 14.0583] },
  brazil: { label: "巴西", coord: [-51.9253, -14.235] },
  "\u5df4\u897f": { label: "巴西", coord: [-51.9253, -14.235] },
  canada: { label: "加拿大", coord: [-106.3468, 56.1304] },
  "\u52a0\u62ff\u5927": { label: "加拿大", coord: [-106.3468, 56.1304] },
  australia: { label: "澳大利亚", coord: [133.7751, -25.2744] },
  "\u6fb3\u5927\u5229\u4e9a": { label: "澳大利亚", coord: [133.7751, -25.2744] },
  anhui: { label: "安徽", coord: [117.283, 31.8612] },
  "\u5b89\u5fbd": { label: "安徽", coord: [117.283, 31.8612] },
  fujian: { label: "福建", coord: [119.2965, 26.0745] },
  "\u798f\u5efa": { label: "福建", coord: [119.2965, 26.0745] },
  jiangxi: { label: "江西", coord: [115.8582, 28.6829] },
  "\u6c5f\u897f": { label: "江西", coord: [115.8582, 28.6829] },
  tianjin: { label: "天津", coord: [117.2009, 39.0842] },
  "\u5929\u6d25": { label: "天津", coord: [117.2009, 39.0842] },
  chongqing: { label: "重庆", coord: [106.5516, 29.563] },
  "\u91cd\u5e86": { label: "重庆", coord: [106.5516, 29.563] },
  hainan: { label: "海南", coord: [110.3312, 20.031] },
  "\u6d77\u5357": { label: "海南", coord: [110.3312, 20.031] },
  guizhou: { label: "贵州", coord: [106.6302, 26.647] },
  "\u8d35\u5dde": { label: "贵州", coord: [106.6302, 26.647] },
  yunnan: { label: "云南", coord: [102.8329, 24.8801] },
  "\u4e91\u5357": { label: "云南", coord: [102.8329, 24.8801] },
  shaanxi: { label: "陕西", coord: [108.9542, 34.2655] },
  "\u9655\u897f": { label: "陕西", coord: [108.9542, 34.2655] },
  xinjiang: { label: "新疆", coord: [87.6168, 43.8256] },
  "\u65b0\u7586": { label: "新疆", coord: [87.6168, 43.8256] },
  bulgaria: { label: "保加利亚", coord: [25.4858, 42.7339] },
  "\u4fdd\u52a0\u5229\u4e9a": { label: "保加利亚", coord: [25.4858, 42.7339] },
  slovenia: { label: "斯洛文尼亚", coord: [14.9955, 46.1512] },
  "\u65af\u6d1b\u6587\u5c3c\u4e9a": { label: "斯洛文尼亚", coord: [14.9955, 46.1512] },
  andorra: { label: "安道尔", coord: [1.6016, 42.5462] },
  "\u5b89\u9053\u5c14": { label: "安道尔", coord: [1.6016, 42.5462] },
};

const appEl = document.getElementById("app");
const tooltipEl = document.getElementById("tooltip");
const chartRegistry = {};
const loadedScriptPromises = {};
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
    alarm: null,
  },
  alarmAudio: {
    initialized: false,
    seenKeys: new Set(),
    lastAlarmAt: 0,
    audioContext: null,
    primed: false,
  },
  screenData: null,
  pro: {
    filters: {
      time_range: "24h",
      risk_level: "all",
      attack_type: "all",
      target_port: "all",
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
    candidates: {
      q: "",
      page: 1,
      pageSize: 8,
      total: 0,
      items: [],
    },
    blocked: {
      q: "",
      page: 1,
      pageSize: 10,
      total: 0,
      items: [],
    },
    defense: {
      enabled: false,
      minimumRisk: "critical",
      blockedCount: 0,
      enforcement: "windows_firewall_bidirectional",
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
    modelCandidates: [],
    captureInterfaces: [],
    runtimeCheck: null,
  },
  rag: {
    page: 1,
    pageSize: 20,
    total: 0,
    q: "",
    attackType: "",
    items: [],
    selectedDocId: "",
    selectedDoc: null,
  },
  llmSettings: {
    activePanel: "rag",
    prompt: "",
    promptPath: "",
    promptUpdatedAt: "",
    promptMaxChars: 0,
    reportPrompt: "",
    reportPromptPath: "",
    reportPromptUpdatedAt: "",
    reportPromptMaxChars: 0,
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
  situations: {
    items: [],
    selectedId: "",
    detail: null,
    graph: null,
    status: "",
    chainMode: "aggregate",
    scopeMode: "single_ip",
    clusterWindowMinutes: 60,
    professionalReport: null,
    professionalReportPoll: null,
    clusterLookbackHours: 720,
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindGlobalTooltip();
  document.addEventListener("pointerdown", primeAlarmAudio, { once: true });
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
  await loadHomepageBackground();
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

function normalizeBackgroundUrl(url) {
  const text = String(url || "").trim();
  if (!text || text.includes('"') || text.includes("\\") || text.startsWith("//")) {
    return "/assets/bg-main.jpg";
  }
  if (!text.startsWith("/")) {
    return "/assets/bg-main.jpg";
  }
  return text;
}

function applyHomepageBackground(url) {
  const safeUrl = normalizeBackgroundUrl(url);
  document.documentElement.style.setProperty("--homepage-bg-url", `url("${safeUrl}")`);
  const preview = document.getElementById("cfg_home_bg_preview");
  if (preview) {
    preview.style.setProperty("--homepage-bg-url", `url("${safeUrl}")`);
  }
  const text = document.getElementById("cfg_home_bg_current");
  if (text) {
    text.textContent = `当前背景：${safeUrl}`;
  }
}

async function loadHomepageBackground() {
  try {
    const data = await api("/api/v2/common/home-background");
    applyHomepageBackground(data.url || "/assets/bg-main.jpg");
  } catch (err) {
    console.warn("load homepage background failed", err);
    applyHomepageBackground("/assets/bg-main.jpg");
  }
}

function loginStaticPieMarkup(rows, centerValue = "4", centerLabel = "\u7ef4\u80fd\u529b") {
  const total = rows.reduce((sum, x) => sum + Number(x.value || 0), 0) || 1;
  let cursor = 0;
  const stops = rows
    .map((row) => {
      const start = cursor;
      const end = cursor + (Number(row.value || 0) / total) * 100;
      cursor = end;
      return `${row.color} ${start.toFixed(2)}% ${end.toFixed(2)}%`;
    })
    .join(", ");
  const legend = rows
    .map((row) => {
      const pct = Math.round((Number(row.value || 0) / total) * 100);
      return `<span><i style="background:${escapeHtml(row.color)}"></i>${escapeHtml(row.name)} <b>${pct}%</b></span>`;
    })
    .join("");
  return `
    <div class="static-pie-wrap">
      <div class="static-pie" style="--pie-stops:${stops};">
        <div><strong>${escapeHtml(centerValue)}</strong><span>${escapeHtml(centerLabel)}</span></div>
      </div>
      <div class="static-pie-legend">${legend}</div>
    </div>
  `;
}

function renderLoginPage() {
  clearAllTimers();
  disposeAllCharts();
  state.profile = null;
  state.currentView = "";

  appEl.innerHTML = `
    <div class="login-page">
      <section class="login-shell">
        <div class="login-orb orb-a"></div>
        <div class="login-orb orb-b"></div>
        <div class="login-topline">
          <div class="login-brand">
            <span class="brand-mark">智</span>
            <div>
              <strong>智御态势</strong>
              <small>AI Security Situation Center</small>
            </div>
          </div>
          <div class="login-top-actions">
            <span>本地模型研判</span>
            <span>RAG 知识增强</span>
            <span>自动化处置</span>
          </div>
        </div>

        <div class="login-stage">
          <div class="login-hero-copy">
            <div class="hero-kicker"><i></i> AI-Powered Security Console</div>
            <h1 class="login-title">AI攻击态势感知平台</h1>
            <p class="login-subtitle">
              面向 Web 服务与靶场验证的轻量级态势感知系统，融合抓包、分层检测、LLM/RAG 研判、数据大屏与封禁处置。
            </p>
            <div class="login-hero-stats">
              <article><strong>4 层</strong><span>Payload / POC / 行为 / LLM</span></article>
              <article><strong>3 类</strong><span>raw_only / candidate / attack</span></article>
              <article><strong>1 键</strong><span>启动检测链路与前端大屏</span></article>
            </div>
            <div class="login-flow-card">
              <span>Capture</span>
              <b></b>
              <span>AI Gate</span>
              <b></b>
              <span>LLM/RAG</span>
              <b></b>
              <span>Response</span>
            </div>
          </div>

          <div class="login-card auth-card">
            <div class="auth-card-head">
              <div>
                <p class="panel-sub">安全登录</p>
                <h2>进入控制台</h2>
              </div>
              <span class="auth-live-dot">在线</span>
            </div>
            <p class="auth-hint">首次打开不会预填账号密码；需要演示账号时可主动点击身份按钮。普通用户仅查看大屏与详情，管理员可维护模型、用户和系统配置。</p>

            <div class="form-row">
              <label for="loginUsername">用户名</label>
              <input id="loginUsername" type="text" autocomplete="off" data-form-type="other" readonly />
            </div>
            <div class="form-row">
              <label for="loginPassword">密码</label>
              <input id="loginPassword" type="password" autocomplete="new-password" data-form-type="other" readonly />
            </div>

            <div class="form-row">
              <label>身份快捷切换</label>
              <div class="role-switch">
                <button class="btn active" data-login-role="${ROLE_NORMAL}">普通用户</button>
                <button class="btn" data-login-role="${ROLE_ADMIN}">管理员</button>
              </div>
            </div>

            <div class="auth-action-row">
              <button id="loginBtn" class="btn btn-primary">登录系统</button>
              <button id="toggleRegisterBtn" class="btn btn-ghost">注册新账号</button>
            </div>
            <div id="loginError" class="login-error"></div>

            <div id="registerPanel" class="register-panel hidden">
              <div class="register-panel-head">
                <strong>创建普通用户</strong>
                <span>注册账号默认普通用户，管理员可在用户管理中调整角色。</span>
              </div>
              <div class="form-row">
                <label for="registerDisplayName">显示名称</label>
                <input id="registerDisplayName" type="text" autocomplete="nickname" />
              </div>
              <div class="form-row">
                <label for="registerUsername">注册用户名（字母/数字/下划线）</label>
                <input id="registerUsername" type="text" autocomplete="username" />
              </div>
              <div class="register-grid">
                <div class="form-row">
                  <label for="registerPassword">注册密码（至少6位）</label>
                  <input id="registerPassword" type="password" autocomplete="new-password" />
                </div>
                <div class="form-row">
                  <label for="registerPassword2">确认密码</label>
                  <input id="registerPassword2" type="password" autocomplete="new-password" />
                </div>
              </div>
              <button id="registerBtn" class="btn btn-success">提交注册</button>
              <div id="registerError" class="login-error"></div>
            </div>

            <div class="scroll-cue" aria-hidden="true">
              <span>向下滑动了解平台能力</span>
              <b></b>
            </div>
          </div>
        </div>
      </section>

      <section class="intro-section intro-overview intro-reveal">
        <div class="intro-kicker">\u4f5c\u54c1\u6982\u89c8</div>
        <h2>\u4e0d\u53ea\u662f\u770b\u5230\u653b\u51fb\uff0c\u800c\u662f\u628a\u653b\u51fb\u8bb2\u6e05\u695a\u3001\u7ba1\u8d77\u6765\u3002</h2>
        <p class="intro-lead">
          \u667a\u5fa1\u6001\u52bf\u9762\u5411 Web \u670d\u52a1\u548c\u8f7b\u91cf\u5b9e\u6218\u9632\u62a4\u573a\u666f\uff0c\u5c06\u6293\u5305\u7559\u75d5\u3001AI \u5206\u5c42\u68c0\u6d4b\u3001LLM/RAG \u7814\u5224\u3001\u6570\u636e\u5927\u5c4f\u548c IP \u5904\u7f6e\u4e32\u6210\u4e00\u6761\u5b8c\u6574\u95ed\u73af\u3002
        </p>
        <div class="intro-stat-grid">
          <article><strong>raw_only</strong><span>\u6b63\u5e38\u8bbf\u95ee\u4ec5\u7559\u5b58</span></article>
          <article><strong>candidate</strong><span>\u4f4e\u4e2d\u7f6e\u4fe1\u8fdb\u5165\u590d\u6838</span></article>
          <article><strong>attack_event</strong><span>\u9ad8\u7f6e\u4fe1\u4e8b\u4ef6\u89e6\u53d1\u7814\u5224</span></article>
          <article><strong>RAG + LLM</strong><span>\u8f93\u51fa\u8bc1\u636e\u548c\u5904\u7f6e\u5efa\u8bae</span></article>
        </div>
      </section>

      <section class="intro-section intro-charts intro-reveal">
        <div class="intro-copy">
          <div class="intro-kicker">\u5e73\u53f0\u4f18\u52bf</div>
          <h2>\u7528\u591a\u6a21\u578b\u878d\u5408\u964d\u4f4e\u8bef\u62a5\uff0c\u7528\u884c\u4e3a\u7a97\u53e3\u6355\u6349\u626b\u63cf\u548c\u7206\u7834\u3002</h2>
          <p>
            \u7cfb\u7edf\u4e0d\u628a\u201c\u8bbf\u95ee\u8def\u5f84\u201d\u7b80\u5355\u7b49\u540c\u4e8e\u653b\u51fb\uff0c\u800c\u662f\u540c\u65f6\u89c2\u5bdf Payload\u3001POC \u89c4\u5219\u3001\u884c\u4e3a\u9891\u7387\u548c\u4e0a\u4e0b\u6587\u8bc1\u636e\u3002\u8fd9\u4f7f\u666e\u901a\u8bbf\u95ee\u4e0d\u88ab\u8f7b\u6613\u63a8\u5230\u544a\u8b66\u533a\uff0c\u4e5f\u8ba9\u5b57\u5178\u626b\u63cf\u3001\u5f31\u53e3\u4ee4\u7206\u7834\u7b49\u884c\u4e3a\u578b\u5a01\u80c1\u53ef\u4ee5\u88ab\u805a\u5408\u8bc6\u522b\u3002
          </p>
          <div class="intro-feature-list">
            <span>\u8bc1\u636e\u94fe\u6e05\u6670</span>
            <span>\u544a\u8b66\u805a\u5408</span>
            <span>\u672c\u5730\u5927\u6a21\u578b</span>
            <span>\u652f\u6301\u5c01\u7981 / \u89e3\u5c01</span>
          </div>
        </div>
        <div class="intro-chart-grid">
          <article class="intro-chart-card">
            <h3>\u68c0\u6d4b\u80fd\u529b\u6784\u6210</h3>
            <div id="loginChartCapability" class="intro-chart-box">
              ${loginStaticPieMarkup([
                { name: "Payload\u68c0\u6d4b", value: 35, color: "#3bb7ff" },
                { name: "\u884c\u4e3a\u7a97\u53e3", value: 25, color: "#18d99a" },
                { name: "POC\u89c4\u5219", value: 22, color: "#ffbf4d" },
                { name: "LLM/RAG\u7814\u5224", value: 18, color: "#8a7cff" },
              ])}
            </div>
          </article>
          <article class="intro-chart-card">
            <h3>\u544a\u8b66\u964d\u566a\u6548\u679c</h3>
            <div id="loginChartNoise" class="intro-chart-box">
              ${loginStaticPieMarkup([
                { name: "\u539f\u59cb\u65e5\u5fd7\u7559\u5b58", value: 62, color: "#5fb4ff" },
                { name: "\u5019\u9009\u590d\u6838", value: 24, color: "#ffbf4d" },
                { name: "\u9ad8\u7f6e\u4fe1\u544a\u8b66", value: 14, color: "#ff5b73" },
              ], "3", "\u7ea7\u5206\u6d41")}
            </div>
          </article>
        </div>
      </section>

      <section class="intro-section intro-flow intro-reveal">
        <div class="intro-kicker">\u4f7f\u7528\u65b9\u6cd5</div>
        <h2>\u4ece\u90e8\u7f72\u5230\u5904\u7f6e\uff0c\u6f14\u793a\u8def\u5f84\u6e05\u6670\u53ef\u590d\u73b0\u3002</h2>
        <div class="intro-step-grid">
          <article><b>01</b><strong>\u542f\u52a8\u76d1\u542c</strong><span>\u914d\u7f6e\u7aef\u53e3\u548c\u7f51\u5361\uff0capp.py \u62c9\u8d77\u6293\u5305\u3001\u68c0\u6d4b\u3001API \u548c\u524d\u7aef\u3002</span></article>
          <article><b>02</b><strong>\u89c2\u5bdf\u5927\u5c4f</strong><span>\u67e5\u770b\u653b\u51fb\u7c7b\u578b\u3001\u6765\u6e90\u5730\u533a\u3001\u8d8b\u52bf\u548c\u9ad8\u5371\u4e8b\u4ef6\u3002</span></article>
          <article><b>03</b><strong>\u8fdb\u5165\u8be6\u60c5</strong><span>\u5c55\u5f00\u8bf7\u6c42\u4f53\u3001\u54cd\u5e94\u4f53\u3001\u89c4\u5219\u8bc1\u636e\u548c LLM \u7814\u5224\u7ed3\u679c\u3002</span></article>
          <article><b>04</b><strong>\u8f85\u52a9\u5904\u7f6e</strong><span>\u5bf9\u786e\u8ba4\u653b\u51fb\u7684\u6765\u6e90 IP \u8fdb\u884c\u5c01\u7981\uff0c\u4e5f\u53ef\u5728\u5217\u8868\u4e2d\u89e3\u5c01\u3002</span></article>
        </div>
      </section>

      <section class="intro-section intro-architecture intro-reveal">
        <div class="intro-card-stack">
          <article>
            <small>01</small>
            <strong>\u539f\u59cb\u8bf7\u6c42\u5168\u91cf\u7559\u5b58</strong>
            <span>\u8bf7\u6c42\u3001\u54cd\u5e94\u548c\u5206\u6790\u7ed3\u679c\u5165\u5e93\uff0c\u4fbf\u4e8e\u590d\u76d8\u548c\u7b54\u8fa9\u5c55\u793a\u3002</span>
          </article>
          <article>
            <small>02</small>
            <strong>\u591a\u7ea7\u5019\u9009\u4e8b\u4ef6\u7b5b\u9009</strong>
            <span>\u901a\u8fc7 raw_only / candidate / attack_event \u5206\u7ea7\u51cf\u5c11\u544a\u8b66\u566a\u58f0\u3002</span>
          </article>
          <article>
            <small>03</small>
            <strong>\u77e5\u8bc6\u5e93\u53ef\u7ef4\u62a4</strong>
            <span>\u7ba1\u7406\u5458\u53ef\u5728\u524d\u7aef\u589e\u5220\u6539 RAG \u77e5\u8bc6\uff0c\u8ba9\u7814\u5224\u8bdd\u672f\u8ddf\u968f\u573a\u666f\u8fdb\u5316\u3002</span>
          </article>
        </div>
        <div class="intro-chart-card intro-wide-chart">
          <h3>\u5b9e\u6218\u4ef7\u503c\u5206\u5e03</h3>
          <div id="loginChartValue" class="intro-chart-box wide">
            ${loginStaticPieMarkup([
              { name: "\u964d\u4f4e\u8bef\u62a5", value: 28, color: "#3bb7ff" },
              { name: "\u8bc6\u522b\u626b\u63cf\u7206\u7834", value: 24, color: "#18d99a" },
              { name: "\u8bc1\u636e\u94fe\u89e3\u91ca", value: 21, color: "#ffbf4d" },
              { name: "\u8f85\u52a9\u5904\u7f6e", value: 16, color: "#ff6b8a" },
              { name: "\u90e8\u7f72\u6f14\u793a", value: 11, color: "#8a7cff" },
            ], "5", "\u7c7b\u4ef7\u503c")}
          </div>
        </div>
      </section>
    </div>
  `;

  let selectedRole = ROLE_NORMAL;

  ["#loginUsername", "#loginPassword"].forEach((selector) => {
    const input = appEl.querySelector(selector);
    if (!input) return;
    const enableManualInput = () => {
      input.readOnly = false;
    };
    input.addEventListener("pointerdown", enableManualInput, { once: true });
    input.addEventListener("focus", enableManualInput, { once: true });
    input.addEventListener("keydown", enableManualInput, { once: true });
  });

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

  initLoginIntro();
}

function initLoginIntro() {
  requestAnimationFrame(() => {
    const revealItems = Array.from(document.querySelectorAll(".intro-reveal"));
    const revealNow = () => {
      const bottomLine = window.innerHeight * 0.88;
      revealItems.forEach((el) => {
        if (el.classList.contains("is-visible")) return;
        const rect = el.getBoundingClientRect();
        if (rect.top < bottomLine && rect.bottom > 0) {
          el.classList.add("is-visible");
        }
      });
    };
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add("is-visible");
              observer.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.18, rootMargin: "0px 0px -8% 0px" }
      );
      revealItems.forEach((el) => observer.observe(el));
    } else {
      revealItems.forEach((el) => el.classList.add("is-visible"));
    }
    window.addEventListener("scroll", revealNow, { passive: true });
    window.addEventListener("resize", revealNow, { passive: true });
    revealNow();
    setTimeout(revealNow, 180);
    renderLoginIntroCharts();
  });
}

function renderLoginIntroCharts() {
  renderLoginPieChart("loginChartCapability", [
    { name: "Payload检测", value: 35, color: "#3bb7ff" },
    { name: "行为窗口", value: 25, color: "#18d99a" },
    { name: "POC规则", value: 22, color: "#ffbf4d" },
    { name: "LLM/RAG研判", value: 18, color: "#8a7cff" },
  ]);
  renderLoginPieChart("loginChartNoise", [
    { name: "原始日志留存", value: 62, color: "#5fb4ff" },
    { name: "候选复核", value: 24, color: "#ffbf4d" },
    { name: "高置信告警", value: 14, color: "#ff5b73" },
  ]);
  renderLoginPieChart("loginChartValue", [
    { name: "降低误报", value: 28, color: "#3bb7ff" },
    { name: "识别扫描爆破", value: 24, color: "#18d99a" },
    { name: "证据链解释", value: 21, color: "#ffbf4d" },
    { name: "辅助处置", value: 16, color: "#ff6b8a" },
    { name: "部署演示", value: 11, color: "#8a7cff" },
  ]);
}

function renderLoginPieChart(containerId, rows) {
  const chart = getEchartsInstance(containerId);
  if (!chart) {
    renderStaticLoginPieChart(containerId, rows);
    return;
  }
  chart.setOption({
    backgroundColor: "transparent",
    animationDuration: 1000,
    animationEasing: "cubicOut",
    color: rows.map((x) => x.color),
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(8, 22, 36, 0.94)",
      borderColor: "rgba(146, 206, 255, 0.34)",
      textStyle: { color: "#edf6ff", fontFamily: "Microsoft YaHei UI" },
      formatter: "{b}<br/>占比：{d}%",
    },
    legend: {
      bottom: 2,
      left: "center",
      itemWidth: 10,
      itemHeight: 10,
      textStyle: { color: "#c7dcf0", fontSize: 11 },
    },
    series: [
      {
        type: "pie",
        radius: ["44%", "70%"],
        center: ["50%", "43%"],
        minAngle: 8,
        avoidLabelOverlap: true,
        itemStyle: {
          borderColor: "rgba(6, 17, 30, 0.92)",
          borderWidth: 3,
          shadowBlur: 14,
          shadowColor: "rgba(0, 0, 0, 0.22)",
        },
        label: {
          color: "#f4fbff",
          fontSize: 11,
          formatter: "{b}\n{d}%",
        },
        labelLine: {
          length: 13,
          length2: 8,
          lineStyle: { color: "rgba(232, 246, 255, 0.72)" },
        },
        emphasis: {
          scale: true,
          scaleSize: 8,
          label: { fontSize: 13, fontWeight: 700 },
        },
        data: rows.map((x) => ({ name: x.name, value: x.value })),
      },
    ],
  });
}

function renderStaticLoginPieChart(containerId, rows) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const total = rows.reduce((sum, x) => sum + Number(x.value || 0), 0) || 1;
  let cursor = 0;
  const stops = rows
    .map((row) => {
      const start = cursor;
      const end = cursor + (Number(row.value || 0) / total) * 100;
      cursor = end;
      return `${row.color} ${start.toFixed(2)}% ${end.toFixed(2)}%`;
    })
    .join(", ");
  const legend = rows
    .map((row) => {
      const pct = Math.round((Number(row.value || 0) / total) * 100);
      return `<span><i style="background:${escapeHtml(row.color)}"></i>${escapeHtml(row.name)} <b>${pct}%</b></span>`;
    })
    .join("");
  el.innerHTML = `
    <div class="static-pie-wrap">
      <div class="static-pie" style="--pie-stops:${stops};">
        <div><strong>${rows.length}</strong><span>维能力</span></div>
      </div>
      <div class="static-pie-legend">${legend}</div>
    </div>
  `;
}

function fillLoginCredential(role) {
  const row = DEMO_CREDENTIALS[role] || DEMO_CREDENTIALS.normal;
  const usernameEl = appEl.querySelector("#loginUsername");
  const passwordEl = appEl.querySelector("#loginPassword");
  if (usernameEl) {
    usernameEl.readOnly = false;
    usernameEl.value = row.username;
  }
  if (passwordEl) {
    passwordEl.readOnly = false;
    passwordEl.value = row.password;
  }
}

function getProfileName(profile = state.profile) {
  return profile?.nickname || profile?.display_name || profile?.username || "-";
}

function getProfileInitial(profile = state.profile) {
  const text = getProfileName(profile);
  const chars = Array.from(String(text || "-").trim());
  return chars[0] || "-";
}

function renderUserAvatar(profile = state.profile, extraClass = "") {
  const avatarUrl = String(profile?.avatar_url || "").trim();
  const initial = escapeHtml(getProfileInitial(profile));
  const cls = `user-avatar ${extraClass || ""}`.trim();
  if (avatarUrl) {
    return `<span class="${cls}"><img src="${escapeHtml(avatarUrl)}" alt="用户头像" loading="lazy" /><span class="avatar-initial">${initial}</span></span>`;
  }
  return `<span class="${cls}"><span class="avatar-initial">${initial}</span></span>`;
}

function bindProfileMenu() {
  const menu = document.getElementById("profileMenu");
  const btn = document.getElementById("profileAvatarBtn");
  const dropdown = document.getElementById("profileDropdown");
  if (!menu || !btn || !dropdown) return;
  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const willOpen = dropdown.classList.contains("hidden");
    dropdown.classList.toggle("hidden", !willOpen);
    btn.setAttribute("aria-expanded", willOpen ? "true" : "false");
  });
  dropdown.querySelectorAll("[data-profile-action]").forEach((el) => {
    el.addEventListener("click", () => {
      const action = el.getAttribute("data-profile-action");
      dropdown.classList.add("hidden");
      btn.setAttribute("aria-expanded", "false");
      if (action === "center") switchView("user-center");
      if (action === "admin-users") switchView("admin-users");
      if (action === "logout") logout();
    });
  });
  document.addEventListener("click", (ev) => {
    if (!menu.contains(ev.target)) {
      dropdown.classList.add("hidden");
      btn.setAttribute("aria-expanded", "false");
    }
  });
}

function refreshHeaderProfile() {
  const headerName = document.getElementById("headerProfileName");
  const dropdownName = document.getElementById("dropdownProfileName");
  if (headerName) headerName.textContent = getProfileName(state.profile);
  if (dropdownName) dropdownName.textContent = getProfileName(state.profile);
  const btn = document.getElementById("profileAvatarBtn");
  const head = document.querySelector(".profile-dropdown-head");
  if (btn) {
    const avatar = btn.querySelector(".user-avatar");
    if (avatar) avatar.outerHTML = renderUserAvatar(state.profile, "avatar-sm");
  }
  if (head) {
    const avatar = head.querySelector(".user-avatar");
    if (avatar) avatar.outerHTML = renderUserAvatar(state.profile, "avatar-md");
  }
}

function renderMainLayout() {
  appEl.innerHTML = `
    <div class="layout">
      <header class="status-bar">
        <div class="status-main">
          <span class="brand">
            <span class="brand-icon">智</span>
            <span>
              <strong>AI攻击态势感知平台</strong>
              <small>Jingyuan Threat Intelligence</small>
            </span>
          </span>
          <span class="pill">身份：${ROLE_LABEL[state.profile?.role] || "-"}</span>
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
          <div class="profile-menu" id="profileMenu">
            <button id="profileAvatarBtn" class="avatar-button" type="button" aria-haspopup="true" aria-expanded="false">
              ${renderUserAvatar(state.profile, "avatar-sm")}
              <span class="avatar-button-text">
                <strong id="headerProfileName">${escapeHtml(getProfileName(state.profile))}</strong>
                <small>${escapeHtml(ROLE_LABEL[state.profile?.role] || "-")}</small>
              </span>
            </button>
            <div id="profileDropdown" class="profile-dropdown hidden">
              <div class="profile-dropdown-head">
                ${renderUserAvatar(state.profile, "avatar-md")}
                <div>
                  <strong id="dropdownProfileName">${escapeHtml(getProfileName(state.profile))}</strong>
                  <span>${escapeHtml(state.profile?.username || "-")} · ${escapeHtml(ROLE_LABEL[state.profile?.role] || "-")}</span>
                </div>
              </div>
              <button class="profile-menu-item" type="button" data-profile-action="center"><span>个人资料</span><small>头像、昵称与密码</small></button>
              ${
                state.profile?.role === ROLE_ADMIN
                  ? `<button class="profile-menu-item" type="button" data-profile-action="admin-users"><span>管理用户</span><small>角色、密码与账号资料</small></button>`
                  : ""
              }
              <button class="profile-menu-item danger" type="button" data-profile-action="logout"><span>退出登录</span><small>返回登录页</small></button>
            </div>
          </div>
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
    if (state.soundEnabled) {
      state.alarmAudio.initialized = false;
      state.alarmAudio.seenKeys = new Set();
      primeAlarmAudio();
      pollAudioAlerts().catch((err) => console.warn("alarm poll error", err));
    }
    showToast(state.soundEnabled ? "声音告警已开启" : "声音告警已关闭");
  });
  bindProfileMenu();

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
      { id: "situations", label: "态势感知展示" },
      { id: "pro-query", label: "\u8be6\u60c5\u4fe1\u606f" },
      { id: "plugins", label: "\u6269\u5c55\u63d2\u4ef6" },
      { id: "rag-settings", label: "\u5927\u6a21\u578b\u8bbe\u7f6e" },
      { id: "admin-logs", label: "\u64cd\u4f5c\u65e5\u5fd7" },
      { id: "admin-config", label: "\u7cfb\u7edf\u914d\u7f6e" },
    ];
  }
  return [
    { id: "screen", label: "\u6570\u636e\u5927\u5c4f" },
    { id: "situations", label: "态势感知展示" },
    { id: "pro-query", label: "\u8be6\u60c5\u4fe1\u606f" },
    { id: "plugins", label: "\u6269\u5c55\u63d2\u4ef6" },
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
  if (viewId === "situations") {
    renderSituationView();
    setViewRefresh(8000, () => refreshSituationData({ preserveSelection: true }));
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
  pollAudioAlerts().catch((err) => console.warn("alarm poll error", err));
  state.intervals.alarm = setInterval(() => pollAudioAlerts().catch((err) => console.warn("alarm poll error", err)), 5000);
}

async function pollAudioAlerts() {
  if (!state.profile || !state.soundEnabled) return;
  const data = await api("/api/v2/common/alerts/ticker?limit=3");
  handleAudioAlertItems(Array.isArray(data.items) ? data.items : []);
}

function getAudioAlertKey(item) {
  return String(
    item?.event_id ||
      item?.case_id ||
      `${item?.occurred_at || ""}|${item?.source_ip || ""}|${item?.attack_type || ""}|${item?.target_node || ""}`
  );
}

function handleAudioAlertItems(items) {
  const keys = items.map(getAudioAlertKey).filter(Boolean);
  if (!state.alarmAudio.initialized) {
    keys.forEach((key) => state.alarmAudio.seenKeys.add(key));
    state.alarmAudio.initialized = true;
    return;
  }
  const hasNewAlert = keys.some((key) => !state.alarmAudio.seenKeys.has(key));
  keys.forEach((key) => state.alarmAudio.seenKeys.add(key));
  if (hasNewAlert) {
    playAbnormalTrafficAlarm();
  }
}

function primeAlarmAudio() {
  try {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (AudioContextCtor && !state.alarmAudio.audioContext) {
      state.alarmAudio.audioContext = new AudioContextCtor();
    }
    state.alarmAudio.audioContext?.resume?.();
    state.alarmAudio.primed = true;
  } catch (err) {
    console.warn("audio prime failed", err);
  }
}

function playAbnormalTrafficAlarm() {
  if (!state.soundEnabled) return;
  const now = Date.now();
  if (now - state.alarmAudio.lastAlarmAt < 8000) return;
  state.alarmAudio.lastAlarmAt = now;

  primeAlarmAudio();
  playMechanicalTone();
  speakMechanicalWarning();
  showToast("检测到异常流量，已触发声音告警");
}

function playMechanicalTone() {
  try {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    const ctx = state.alarmAudio.audioContext || (AudioContextCtor ? new AudioContextCtor() : null);
    if (!ctx) return;
    state.alarmAudio.audioContext = ctx;

    const start = ctx.currentTime;
    [0, 0.18, 0.36].forEach((offset, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "square";
      osc.frequency.setValueAtTime(idx === 1 ? 680 : 520, start + offset);
      gain.gain.setValueAtTime(0.0001, start + offset);
      gain.gain.exponentialRampToValueAtTime(0.18, start + offset + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + offset + 0.14);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(start + offset);
      osc.stop(start + offset + 0.15);
    });
  } catch (err) {
    console.warn("mechanical tone failed", err);
  }
}

function speakMechanicalWarning() {
  try {
    if (!("speechSynthesis" in window)) return;
    const utterance = new SpeechSynthesisUtterance("注意异常流量");
    utterance.lang = "zh-CN";
    utterance.rate = 0.82;
    utterance.pitch = 0.55;
    utterance.volume = 1;
    const voices = window.speechSynthesis.getVoices?.() || [];
    const zhVoice = voices.find((voice) => /zh|chinese|mandarin/i.test(`${voice.lang} ${voice.name}`));
    if (zhVoice) utterance.voice = zhVoice;
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
  } catch (err) {
    console.warn("speech warning failed", err);
  }
}

function updateClock() {
  const el = document.getElementById("statusClock");
  if (!el) return;
  // The platform is deployed in Beijing; do not let a remote browser's host
  // timezone shift the status clock or situation timestamps.
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
      <article class="kpi-card"><div class="kpi-label">今日识别态势数</div><div id="kpi_situations" class="kpi-value">0</div></article>
      <article class="kpi-card"><div class="kpi-label">自动防御平均封禁时间</div><div id="kpi_defense_seconds" class="kpi-value">0s</div></article>
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
        <div class="panel-head">
          <div>
            <h3 class="panel-title">攻击来源地区 TOP7</h3>
            <span class="panel-sub">按占比最多展示</span>
          </div>
          <button id="btnAttackMapShow" class="btn btn-ghost btn-mini" type="button">动态展示</button>
        </div>
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
  document.getElementById("btnAttackMapShow")?.addEventListener("click", () => openAttackMapModal());
  // Re-entering the dashboard should feel instant: paint the last successful
  // snapshot first, then reconcile it with fresh server data in the background.
  if (state.screenData) applyScreenData(state.screenData);
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

  const snapshot = { kpis, trend7d, topTypes, sourceDist, heatmap, methodShare, ticker };
  state.screenData = snapshot;
  applyScreenData(snapshot);
}

function applyScreenData(snapshot) {
  const { kpis, trend7d, topTypes, sourceDist, heatmap, methodShare, ticker } = snapshot;
  animateTextNumber("kpi_today_attack", Number(kpis.today_attack_total || 0), "");
  animateTextNumber("kpi_high_alert", Number(kpis.active_high_alerts || 0), "");
  animateTextNumber("kpi_situations", Number(kpis.today_situation_total || 0), "");
  animateTextNumber("kpi_defense_seconds", Number(kpis.avg_auto_defense_block_seconds || 0), "s");
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

function normalizeRegionLookupKey(value) {
  return String(value || "")
    .trim()
    .replace(/ Province$/i, "")
    .replace(/ province$/i, "")
    .replace(/ City$/i, "")
    .replace(/ city$/i, "")
    .replace(/省|市|自治区|特别行政区/g, "")
    .toLowerCase();
}

function getRegionInfo(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "-" || raw === "未知" || raw === "内网") {
    return { label: raw || "未知", coord: null };
  }
  const candidates = [raw];
  raw
    .split(/[\/|,，]+/)
    .map((x) => x.trim())
    .filter(Boolean)
    .forEach((x) => candidates.push(x));

  for (const item of candidates) {
    const direct = REGION_COORDS[item] || REGION_COORDS[normalizeRegionLookupKey(item)];
    if (direct) return direct;
  }
  return { label: raw, coord: null };
}

function formatSourceRegionLabel(value) {
  return getRegionInfo(value).label || String(value || "-");
}

function loadScriptOnce(src) {
  if (!loadedScriptPromises[src]) {
    loadedScriptPromises[src] = new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[src="${src}"]`);
      if (existing) {
        existing.addEventListener("load", () => resolve(true), { once: true });
        existing.addEventListener("error", reject, { once: true });
        if (existing.dataset.loaded === "1") resolve(true);
        return;
      }
      const script = document.createElement("script");
      script.src = src;
      script.async = true;
      script.onload = () => {
        script.dataset.loaded = "1";
        resolve(true);
      };
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }
  return loadedScriptPromises[src];
}

function getLoadedWorldMapName() {
  if (!window.echarts || typeof echarts.getMap !== "function") return "";
  if (echarts.getMap(WORLD_MAP_NAME)) return WORLD_MAP_NAME;
  return "";
}

async function ensureWorldMapReady() {
  if (!window.echarts || typeof echarts.getMap !== "function") return "";
  let mapName = getLoadedWorldMapName();
  if (mapName) return mapName;
  for (const src of WORLD_MAP_SCRIPT_URLS) {
    try {
      await loadScriptOnce(src);
      mapName = getLoadedWorldMapName();
      if (mapName) return mapName;
    } catch (err) {
      console.warn("world map load failed", src, err);
    }
  }
  return "";
}

function buildAttackMapItems(rows) {
  const bucket = new Map();
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const info = getRegionInfo(row.source_region || row.region || row.name);
    if (!info.coord) return;
    const total = Math.max(0, Number(row.total || row.count || row.value || 0));
    if (!total) return;
    const key = info.label;
    const old = bucket.get(key) || { label: info.label, coord: info.coord, total: 0 };
    old.total += total;
    bucket.set(key, old);
  });
  return Array.from(bucket.values())
    .sort((a, b) => b.total - a.total)
    .slice(0, 10);
}

function getAttackMapPreviewRows() {
  return [
    { source_region: "United States", total: 46 },
    { source_region: "Turkey", total: 37 },
    { source_region: "Bulgaria", total: 28 },
    { source_region: "United Kingdom", total: 22 },
    { source_region: "India", total: 18 },
    { source_region: "Anhui", total: 16 },
    { source_region: "Hong Kong", total: 13 },
    { source_region: "Singapore", total: 11 },
    { source_region: "Germany", total: 9 },
    { source_region: "Slovenia", total: 7 },
  ];
}

async function loadAttackMapPayload() {
  try {
    return await api("/api/v2/user/dashboard/source-map?days=30&limit=10");
  } catch (err) {
    const items = state.screenData?.sourceDist?.items || [];
    return {
      items,
      fallback_client: true,
      fallback_reason: err.message,
      period_days: 30,
      limit: 10,
    };
  }
}

async function openAttackMapModal() {
  document.querySelector(".attack-map-overlay")?.remove();
  const overlay = document.createElement("div");
  overlay.className = "attack-map-overlay";
  overlay.innerHTML = `
    <div class="attack-map-modal">
      <div class="attack-map-topbar">
        <div>
          <div class="panel-sub">动态攻击态势</div>
          <h2>近 30 天 TOP10 攻击来源飞线图</h2>
          <p id="attackMapSummary">正在加载攻击来源数据...</p>
        </div>
        <button id="attackMapClose" class="btn btn-ghost" type="button">关闭</button>
      </div>
      <div class="attack-map-body">
        <div class="attack-map-stage">
          <div id="attackMapChart" class="attack-map-chart"></div>
          <div id="attackMapEmpty" class="attack-map-empty hidden">暂无可定位的攻击来源数据</div>
        </div>
        <aside class="attack-map-side">
          <div class="attack-map-server">
            <span class="server-pulse"></span>
            <div><strong>防护节点</strong><small>北京 · 本机服务器</small></div>
          </div>
          <div id="attackMapList" class="attack-map-list"></div>
        </aside>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  document.body.classList.add("modal-open");
  requestAnimationFrame(() => overlay.classList.add("is-open"));

  let chart = null;
  const close = () => {
    if (chart) {
      chart.dispose();
      chart = null;
    }
    document.body.classList.remove("modal-open");
    overlay.classList.remove("is-open");
    setTimeout(() => overlay.remove(), 180);
    document.removeEventListener("keydown", onKeyDown);
  };
  const onKeyDown = (ev) => {
    if (ev.key === "Escape") close();
  };
  overlay.addEventListener("click", (ev) => {
    if (ev.target === overlay) close();
  });
  overlay.querySelector("#attackMapClose")?.addEventListener("click", close);
  document.addEventListener("keydown", onKeyDown);

  try {
    const payload = await loadAttackMapPayload();
    let items = buildAttackMapItems(payload.items);
    let mode = "真实数据";
    if (items.length < 2) {
      items = buildAttackMapItems(getAttackMapPreviewRows());
      mode = "动画预览数据";
    } else if (payload.fallback_all_time) {
      mode = "历史数据";
    } else if (payload.fallback_client) {
      mode = "当前大屏数据";
    }

    const total = items.reduce((sum, item) => sum + item.total, 0);
    const summary = overlay.querySelector("#attackMapSummary");
    if (summary) {
      summary.textContent = `${mode} · ${items.length} 个来源 · 共 ${total.toLocaleString("zh-CN")} 次攻击，线条频率随攻击次数增强`;
    }
    renderAttackMapList(overlay.querySelector("#attackMapList"), items);

    const chartEl = overlay.querySelector("#attackMapChart");
    const emptyEl = overlay.querySelector("#attackMapEmpty");
    if (!items.length || !chartEl) {
      emptyEl?.classList.remove("hidden");
      return;
    }

    const worldMapName = await ensureWorldMapReady();
    if (worldMapName) {
      chart = renderAttackMapEcharts(chartEl, items, worldMapName);
    } else {
      renderAttackMapSvg(chartEl, items);
    }
  } catch (err) {
    const summary = overlay.querySelector("#attackMapSummary");
    if (summary) summary.textContent = `加载失败：${err.message}`;
    overlay.querySelector("#attackMapEmpty")?.classList.remove("hidden");
  }
}

function renderAttackMapList(container, items) {
  if (!container) return;
  const max = Math.max(1, ...items.map((x) => x.total));
  container.innerHTML = items
    .map((item, idx) => {
      const width = Math.max(8, Math.round((item.total / max) * 100));
      return `
        <div class="attack-map-rank" style="--bar-width:${width}%">
          <b>${String(idx + 1).padStart(2, "0")}</b>
          <span>${escapeHtml(item.label)}</span>
          <strong>${Number(item.total || 0).toLocaleString("zh-CN")}</strong>
        </div>
      `;
    })
    .join("");
}

function renderAttackMapEcharts(container, items, mapName) {
  const chart = echarts.init(container);
  const colors = ["#ff5d7a", "#ffb84d", "#35d9ff", "#55f0b2", "#8d7cff", "#f56bdc"];
  const max = Math.max(1, ...items.map((x) => x.total));
  const lineSeries = items.map((item, idx) => ({
    name: item.label,
    type: "lines",
    coordinateSystem: "geo",
    zlevel: 3,
    effect: {
      show: true,
      period: Math.max(2.4, 8 - (item.total / max) * 4.8),
      trailLength: 0.28,
      color: "#ffffff",
      symbol: "arrow",
      symbolSize: 8 + (item.total / max) * 5,
    },
    lineStyle: {
      color: colors[idx % colors.length],
      width: 1.2 + (item.total / max) * 2.6,
      opacity: 0.78,
      curveness: 0.28,
      shadowColor: colors[idx % colors.length],
      shadowBlur: 8,
    },
    data: [{ fromName: item.label, toName: "北京", coords: [item.coord, BEIJING_COORD], value: item.total }],
  }));

  chart.setOption(
    {
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item",
        formatter: (params) => {
          const data = params.data || {};
          if (params.seriesType === "lines") return `${escapeHtml(params.seriesName)} → 北京<br/>攻击次数：${data.value || 0}`;
          const value = Array.isArray(data.value) ? data.value[2] : data.value;
          return `${escapeHtml(data.name || params.name || "-")}<br/>攻击次数：${value || 0}`;
        },
      },
      geo: {
        map: mapName,
        roam: false,
        zoom: 1.18,
        center: [45, 25],
        silent: true,
        label: { show: false },
        itemStyle: {
          areaColor: "rgba(22, 66, 103, 0.72)",
          borderColor: "rgba(144, 213, 255, 0.45)",
          borderWidth: 0.7,
          shadowColor: "rgba(36, 194, 255, 0.22)",
          shadowBlur: 16,
        },
        emphasis: {
          label: { show: false },
          itemStyle: { areaColor: "rgba(48, 119, 169, 0.9)" },
        },
        select: { label: { show: false } },
        blur: { label: { show: false } },
      },
      series: [
        ...lineSeries,
        {
          name: "攻击来源",
          type: "effectScatter",
          coordinateSystem: "geo",
          zlevel: 4,
          rippleEffect: { brushType: "stroke", scale: 4 },
          symbolSize: (val) => 8 + (Number(val[2] || 0) / max) * 16,
          itemStyle: { color: "#ffbf4d", shadowBlur: 14, shadowColor: "#ffbf4d" },
          data: items.map((item) => ({ name: item.label, value: [...item.coord, item.total] })),
        },
        {
          name: "北京防护节点",
          type: "effectScatter",
          coordinateSystem: "geo",
          zlevel: 5,
          rippleEffect: { brushType: "stroke", scale: 5 },
          symbolSize: 18,
          itemStyle: { color: "#ffffff", shadowBlur: 24, shadowColor: "#35d9ff" },
          label: { show: true, formatter: "北京", position: "right", color: "#fff", fontWeight: 800 },
          data: [{ name: "北京", value: [...BEIJING_COORD, max] }],
        },
      ],
    },
    true
  );
  setTimeout(() => chart.resize(), 60);
  return chart;
}

function projectMapCoord(coord, width = 1000, height = 520) {
  const lon = Number(coord[0] || 0);
  const lat = Number(coord[1] || 0);
  return {
    x: ((lon + 180) / 360) * width,
    y: ((90 - lat) / 180) * height,
  };
}

function renderAttackMapSvg(container, items) {
  const width = 1000;
  const height = 520;
  const target = projectMapCoord(BEIJING_COORD, width, height);
  const max = Math.max(1, ...items.map((x) => x.total));
  const paths = items
    .map((item, idx) => {
      const from = projectMapCoord(item.coord, width, height);
      const lift = 54 + idx * 8 + Math.min(90, (item.total / max) * 120);
      const cx = (from.x + target.x) / 2;
      const cy = Math.min(from.y, target.y) - lift;
      const d = `M ${from.x.toFixed(1)} ${from.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${target.x.toFixed(1)} ${target.y.toFixed(1)}`;
      const dur = Math.max(2.4, 8 - (item.total / max) * 4.8).toFixed(2);
      return `
        <path class="attack-svg-line line-${idx % 6}" d="${d}" />
        <circle class="attack-svg-source" cx="${from.x.toFixed(1)}" cy="${from.y.toFixed(1)}" r="${(5 + (item.total / max) * 8).toFixed(1)}" />
        <text class="attack-svg-label" x="${(from.x + 10).toFixed(1)}" y="${(from.y - 8).toFixed(1)}">${escapeHtml(item.label)}</text>
        <circle class="attack-svg-missile" r="${(3.5 + (item.total / max) * 2).toFixed(1)}">
          <animateMotion dur="${dur}s" repeatCount="indefinite" path="${d}" />
        </circle>
      `;
    })
    .join("");

  container.innerHTML = `
    <svg class="attack-map-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="攻击来源飞线地图">
      <defs>
        <radialGradient id="mapGlow" cx="50%" cy="50%" r="65%">
          <stop offset="0%" stop-color="rgba(53,217,255,.26)" />
          <stop offset="70%" stop-color="rgba(53,217,255,.08)" />
          <stop offset="100%" stop-color="rgba(53,217,255,0)" />
        </radialGradient>
      </defs>
      <rect width="${width}" height="${height}" rx="28" fill="url(#mapGlow)" />
      ${[-120, -60, 0, 60, 120].map((lon) => {
        const x = projectMapCoord([lon, 0], width, height).x;
        return `<line class="attack-svg-grid" x1="${x}" y1="34" x2="${x}" y2="${height - 34}" />`;
      }).join("")}
      ${[-45, 0, 45].map((lat) => {
        const y = projectMapCoord([0, lat], width, height).y;
        return `<line class="attack-svg-grid" x1="36" y1="${y}" x2="${width - 36}" y2="${y}" />`;
      }).join("")}
      <path class="attack-svg-land" d="M142 158c58-56 129-72 217-42 60 20 96 15 147-8 77-34 155-23 231 25 56 36 101 37 154 18 30-11 56-12 84 7v205c-61-19-119-20-174-3-66 20-131 25-199-3-70-29-138-32-214-5-82 30-163 24-246-19z" />
      ${paths}
      <circle class="attack-svg-target-halo" cx="${target.x.toFixed(1)}" cy="${target.y.toFixed(1)}" r="24" />
      <circle class="attack-svg-target" cx="${target.x.toFixed(1)}" cy="${target.y.toFixed(1)}" r="8" />
      <text class="attack-svg-target-label" x="${(target.x + 15).toFixed(1)}" y="${(target.y + 4).toFixed(1)}">北京</text>
    </svg>
  `;
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
        `【${x.occurred_at || "-"}】${x.event_id || "-"} ${x.attack_type || "-"} 来源IP ${x.source_ip || "-"} 攻击端口 ${x.target_port || "-"}`
    )
    .join("  |  ");
  el.textContent = `${text}      ${text}`;
}

function renderSituationView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  root.innerHTML = `
    <section class="situation-hero">
      <div>
        <span class="situation-eyebrow"><i></i> CROSS-SENSOR CORRELATION</span>
        <h2>攻击者连续态势</h2>
        <p>将同一来源在短时间内的扫描、凭据攻击与漏洞利用关联为一条可解释攻击链。</p>
      </div>
      <div class="situation-hero-actions">
        <button id="btnSituationScope" class="situation-scope-toggle" type="button" aria-pressed="false">
          <span class="scope-toggle-icon">◎</span><span><b>多代理聚合</b><small>识别高频换 IP</small></span>
        </button>
        <label id="situationClusterWindowWrap" class="situation-filter hidden">聚合时间
          <select id="situationClusterWindow">
            <option value="30">30 分钟</option>
            <option value="60">1 小时</option>
            <option value="180">3 小时</option>
            <option value="360">6 小时</option>
            <option value="1440">24 小时</option>
          </select>
        </label>
        <label class="situation-filter">状态
          <select id="situationStatusFilter">
            <option value="">全部</option>
            <option value="open">进行中</option>
            <option value="closed">已结束</option>
            <option value="handled">已处置</option>
            <option value="observing">观察中</option>
          </select>
        </label>
        <button id="btnSituationRefresh" class="btn btn-primary" type="button">刷新态势</button>
      </div>
    </section>

    <section class="situation-workspace">
      <aside class="situation-list-panel">
        <div class="situation-panel-title">
          <div><span id="situationListTitle">最近攻击者</span><small id="situationCount">正在加载</small></div>
          <span class="live-pulse" aria-label="实时更新"></span>
        </div>
        <div id="situationList" class="situation-list">
          ${renderSituationSkeleton(4)}
        </div>
      </aside>

      <article class="situation-chain-panel">
        <div class="situation-panel-title">
          <div><span id="situationChainTitle">攻击链路</span><small id="situationChainSubtitle">选择一个攻击者查看动作推进</small></div>
          <div class="situation-chain-tools">
            <div class="situation-view-switch" role="group" aria-label="链路视图">
              <button type="button" data-chain-mode="aggregate">聚合视图</button>
              <button type="button" data-chain-mode="evidence">证据视图</button>
            </div>
            <div id="situationStagePills" class="situation-stage-pills"></div>
          </div>
        </div>
        <div id="situationChainChart" class="situation-chain-chart"></div>
        <div id="situationChainEmpty" class="situation-empty hidden"></div>
      </article>

      <aside class="situation-risk-panel">
        <div class="situation-panel-title"><div><span>态势研判</span><small>融合风险概览</small></div></div>
        <div id="situationRiskSummary" class="situation-risk-summary">
          <div class="situation-risk-orbit"><strong>-</strong><span>等待选择</span></div>
        </div>
      </aside>
    </section>

    <section class="situation-report-grid">
      <article class="situation-report-panel">
        <div class="situation-panel-title">
          <div><span>AI 态势报告</span><small id="situationAiMeta">Ollama + RAG 可解释研判</small></div>
          <div class="situation-report-actions">
            <button id="btnProfessionalSituationReport" class="btn btn-primary btn-mini" type="button">获取专业态势报告</button>
            <button id="btnSituationReanalyze" class="btn btn-ghost btn-mini ${state.profile?.role === ROLE_ADMIN ? "" : "hidden"}" type="button">重新研判</button>
          </div>
        </div>
        <div id="situationAiReport" class="situation-ai-report">
          <div class="situation-report-placeholder">报告将在攻击链形成后自动生成</div>
        </div>
      </article>
      <article class="situation-evidence-panel">
        <div class="situation-panel-title"><div><span>证据序列</span><small>所有结论可回溯到原始传感器</small></div></div>
        <div id="situationEvidence" class="situation-evidence-list"></div>
      </article>
    </section>
  `;

  const statusFilter = document.getElementById("situationStatusFilter");
  if (statusFilter) statusFilter.value = state.situations.status;
  statusFilter?.addEventListener("change", async (event) => {
    state.situations.status = event.target.value;
    state.situations.selectedId = "";
    await refreshSituationData({ preserveSelection: false });
  });
  document.getElementById("btnSituationRefresh")?.addEventListener("click", () => refreshSituationData({ preserveSelection: true }));
  const clusterWindow = document.getElementById("situationClusterWindow");
  if (clusterWindow) clusterWindow.value = String(state.situations.clusterWindowMinutes);
  clusterWindow?.addEventListener("change", async (event) => {
    state.situations.clusterWindowMinutes = Number(event.target.value || 60);
    state.situations.selectedId = "";
    await refreshSituationData({ preserveSelection: false });
  });
  document.getElementById("btnSituationScope")?.addEventListener("click", async () => {
    state.situations.scopeMode = state.situations.scopeMode === "single_ip" ? "cross_ip" : "single_ip";
    state.situations.selectedId = "";
    syncSituationScopeMode();
    await refreshSituationData({ preserveSelection: false });
  });
  document.getElementById("btnSituationReanalyze")?.addEventListener("click", reanalyzeSelectedSituation);
  document.getElementById("btnProfessionalSituationReport")?.addEventListener("click", startProfessionalSituationReport);
  document.querySelectorAll("[data-chain-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      state.situations.chainMode = button.dataset.chainMode || "aggregate";
      syncSituationChainMode();
      if (state.situations.graph) drawSituationChain(state.situations.graph);
    });
  });
  syncSituationChainMode();
  syncSituationScopeMode();
  refreshSituationData({ preserveSelection: true }).catch((err) => renderSituationFailure(err));
}

function syncSituationScopeMode() {
  const crossIp = state.situations.scopeMode === "cross_ip";
  const button = document.getElementById("btnSituationScope");
  button?.classList.toggle("active", crossIp);
  button?.setAttribute("aria-pressed", crossIp ? "true" : "false");
  if (button) {
    button.querySelector("b").textContent = crossIp ? "返回单 IP 态势" : "多代理聚合";
    button.querySelector("small").textContent = crossIp ? "当前汇总多个来源" : "识别高频换 IP";
  }
  document.getElementById("situationClusterWindowWrap")?.classList.toggle("hidden", !crossIp);
  const heading = document.querySelector(".situation-hero h2");
  const description = document.querySelector(".situation-hero p");
  if (heading) heading.textContent = crossIp ? "多代理协同态势" : "攻击者连续态势";
  const listTitle = document.getElementById("situationListTitle");
  if (listTitle) listTitle.textContent = crossIp ? "最近代理集群" : "最近攻击者";
  if (description) description.textContent = crossIp
    ? "跨来源关联同一目标在时间窗内的攻击动作，识别代理池轮换与分布式协同行为。"
    : "将同一来源在短时间内的扫描、凭据攻击与漏洞利用关联为一条可解释攻击链。";
}

function syncSituationChainMode() {
  document.querySelectorAll("[data-chain-mode]").forEach((button) => {
    const active = button.dataset.chainMode === state.situations.chainMode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function renderSituationSkeleton(count) {
  return Array.from({ length: count }, () => `<div class="situation-list-skeleton"><i></i><span></span><b></b></div>`).join("");
}

async function refreshSituationData({ preserveSelection = true } = {}) {
  const crossIp = state.situations.scopeMode === "cross_ip";
  const query = new URLSearchParams(crossIp
    ? { window_minutes: String(state.situations.clusterWindowMinutes), lookback_hours: String(state.situations.clusterLookbackHours) }
    : { limit: "80" });
  if (state.situations.status) query.set("status", state.situations.status);
  const data = await api(`${crossIp ? "/api/v2/situation-clusters" : "/api/v2/situations"}?${query.toString()}`);
  if (state.currentView !== "situations") return;
  state.situations.items = Array.isArray(data.items) ? data.items : [];
  const selectedStillExists = state.situations.items.some((item) => situationItemId(item) === state.situations.selectedId);
  if (!preserveSelection || !selectedStillExists) {
    state.situations.selectedId = situationItemId(state.situations.items[0]);
  }
  renderSituationList();
  if (state.situations.selectedId) {
    await loadSituationDetail(state.situations.selectedId);
  } else {
    renderSituationEmptyState();
  }
}

function situationItemId(item) {
  return String(item?.cluster_id || item?.situation_id || "");
}

function renderSituationList() {
  const container = document.getElementById("situationList");
  const count = document.getElementById("situationCount");
  const crossIp = state.situations.scopeMode === "cross_ip";
  if (count) count.textContent = `${state.situations.items.length} 条${crossIp ? "代理集群" : "关联会话"}`;
  if (!container) return;
  if (!state.situations.items.length) {
    container.innerHTML = `<div class="situation-list-empty"><b>${crossIp ? "暂无多代理协同态势" : "暂无连续攻击态势"}</b><span>${crossIp ? "同一目标在时间窗内至少出现两个来源和三类动作后才会聚合，避免误拼无关攻击。" : "单一请求仍会保留在详情信息中；至少三种不同动作才会形成攻击链。"}</span></div>`;
    return;
  }
  container.innerHTML = state.situations.items
    .map((item, index) => {
      const itemId = situationItemId(item);
      const active = itemId === state.situations.selectedId;
      return `
        <button class="situation-list-item ${active ? "active" : ""}" data-situation-id="${escapeHtml(itemId)}" type="button" style="--delay:${Math.min(index, 8) * 38}ms">
          <span class="situation-list-index">${String(index + 1).padStart(2, "0")}</span>
          <span class="situation-list-copy">
            <strong>${escapeHtml(crossIp ? `${Number(item.source_ips?.length || 0)} 个来源 IP` : (item.source_ip || "未知来源"))}</strong>
            <small>${escapeHtml(formatSituationStage(item.current_stage))} · ${Number(item.distinct_action_types || 0)} 类动作 · ${Number(item.total_action_count || 0)} 次${crossIp && item.proxy_rotation_suspected ? " · 疑似代理轮换" : ""}</small>
            <time>${escapeHtml(formatDateTime(item.last_action_at, false))}</time>
          </span>
          <span class="situation-risk-tag ${escapeHtml(item.risk_level || "low")}">${escapeHtml(formatRiskLevel(item.risk_level))}</span>
        </button>`;
    })
    .join("");
  container.querySelectorAll("[data-situation-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.situations.selectedId = button.dataset.situationId || "";
      renderSituationList();
      await loadSituationDetail(state.situations.selectedId);
    });
  });
}

async function loadSituationDetail(situationId) {
  const crossIp = state.situations.scopeMode === "cross_ip";
  let detailData;
  let graphData;
  if (crossIp) {
    const query = new URLSearchParams({
      window_minutes: String(state.situations.clusterWindowMinutes),
      lookback_hours: String(state.situations.clusterLookbackHours),
    });
    const response = await api(`/api/v2/situation-clusters/${encodeURIComponent(situationId)}?${query.toString()}`);
    detailData = response;
    graphData = response.graph || {};
  } else {
    [detailData, graphData] = await Promise.all([
      api(`/api/v2/situations/${encodeURIComponent(situationId)}`),
      api(`/api/v2/situations/${encodeURIComponent(situationId)}/graph`),
    ]);
  }
  if (state.currentView !== "situations" || situationId !== state.situations.selectedId) return;
  state.situations.detail = detailData.item || null;
  state.situations.graph = graphData || null;
  renderSituationDetail();
}

function renderSituationDetail() {
  const detail = state.situations.detail;
  const graph = state.situations.graph;
  if (!detail || !graph) return renderSituationEmptyState();
  const title = document.getElementById("situationChainTitle");
  const subtitle = document.getElementById("situationChainSubtitle");
  if (title) title.textContent = state.situations.scopeMode === "cross_ip"
    ? `${Number(detail.source_ips?.length || 0)} 个代理来源融合链路`
    : `${detail.source_ip} 攻击链路`;
  if (subtitle) subtitle.textContent = `${formatDateTime(detail.started_at, false)} 至 ${formatDateTime(detail.last_action_at, false)}`;
  renderSituationStagePills(graph.nodes || []);
  renderSituationRisk(detail);
  renderSituationAiReport(detail);
  renderSituationEvidence(detail.actions || []);
  drawSituationChain(graph);
  refreshProfessionalReportStatus(false).catch(() => {});
}

function renderSituationStagePills(nodes) {
  const container = document.getElementById("situationStagePills");
  if (!container) return;
  const stages = [...new Set(nodes.map((node) => node.stage))];
  container.innerHTML = stages.map((stage) => `<span class="stage-${escapeHtml(stage)}">${escapeHtml(formatSituationStage(stage))}</span>`).join("");
}

function renderSituationRisk(detail) {
  const container = document.getElementById("situationRiskSummary");
  if (!container) return;
  const score = Math.round(Number(detail.risk_score || 0) * 100);
  const statusMap = { open: "进行中", closed: "已结束", handled: "已处置", ignored: "已忽略", observing: "观察中" };
  container.innerHTML = `
    <div class="situation-risk-orbit risk-${escapeHtml(detail.risk_level || "low")}" style="--score:${score * 3.6}deg">
      <strong>${score}</strong><span>风险指数</span>
    </div>
    <div class="situation-risk-facts">
      <div><span>攻击阶段</span><strong>${escapeHtml(formatSituationStage(detail.current_stage))}</strong></div>
      <div><span>动作种类</span><strong>${Number(detail.distinct_action_types || 0)}</strong></div>
      <div><span>累计频次</span><strong>${Number(detail.total_action_count || 0)}</strong></div>
      <div><span>${detail.mode === "cross_ip" ? "来源 IP" : "会话状态"}</span><strong>${detail.mode === "cross_ip" ? Number(detail.source_ips?.length || 0) : escapeHtml(statusMap[detail.status] || detail.status || "-")}</strong></div>
    </div>
    ${detail.mode === "cross_ip" ? `<div class="situation-proxy-indicator ${detail.proxy_rotation_suspected ? "alert" : ""}"><i></i><span>${detail.proxy_rotation_suspected ? "疑似代理池轮换" : "多来源时间关联"}</span></div>` : ""}
    <div class="situation-risk-actions ${state.profile?.role === ROLE_ADMIN && detail.mode !== "cross_ip" ? "" : "hidden"}">
      <button class="btn btn-ghost btn-mini" data-situation-status="handled" type="button">标记已处置</button>
      <button class="btn btn-ghost btn-mini" data-situation-status="ignored" type="button">忽略</button>
    </div>`;
  container.querySelectorAll("[data-situation-status]").forEach((button) => {
    button.addEventListener("click", () => updateSelectedSituationStatus(button.dataset.situationStatus));
  });
}

function renderSituationAiReport(detail) {
  const container = document.getElementById("situationAiReport");
  const meta = document.getElementById("situationAiMeta");
  if (!container) return;
  const report = detail.ai_report;
  if (meta) {
    meta.textContent = detail.mode === "cross_ip" && report?.generated_by === "cross_ip_correlation_engine"
      ? "跨 IP 融合引擎 · 证据可回溯"
      : formatAiStatus(detail.ai_status, report);
  }
  if (!report) {
    container.innerHTML = `<div class="situation-report-placeholder"><i class="live-pulse"></i> 研判任务已入队，Ollama 完成后将自动刷新</div>`;
    return;
  }
  container.innerHTML = `
    <header class="situation-report-lead">
      <span>执行摘要</span>
      <p>${escapeHtml(normalizeSituationReportTime(report.executive_summary || report.narrative || "暂无摘要", report))}</p>
      <div class="situation-report-intent"><b>可能意图</b><span>${escapeHtml(normalizeSituationReportTime(report.likely_intent || "待确认", report))}</span></div>
    </header>
    <div class="situation-report-reading">
      ${renderSituationReportSection("事件叙述", report.narrative, "", report)}
      ${renderSituationReportSection("时间线分析", report.timeline_analysis, "", report)}
      ${renderSituationReportSection("技术手法分析", report.technique_analysis, "", report)}
      ${renderSituationReportSection("证据强度", report.evidence_assessment || report.analysis, "", report)}
      ${renderSituationReportSection("影响评估", report.impact_assessment, "", report)}
      ${renderSituationReportSection("失陷判断", report.compromise_assessment || report.conclusion, "critical", report)}
      ${renderSituationReportSection("综合结论", report.conclusion, "conclusion", report)}
    </div>
    <div class="situation-response-plan">
      <section><h4>调查步骤</h4>${renderSituationAdvice(report.investigation_steps, report)}</section>
      <section><h4>即时防护</h4>${renderSituationAdvice(report.protection_measures, report)}</section>
      <section><h4>检测优化</h4>${renderSituationAdvice(report.detection_improvements, report)}</section>
      <section><h4>长期改进</h4>${renderSituationAdvice(report.improvement_suggestions, report)}</section>
    </div>
    <details class="situation-evidence-limits">
      <summary>证据边界与不确定性</summary>
      ${renderSituationAdvice(report.evidence_limitations, report)}
    </details>`;
}

function normalizeSituationReportTime(value, report = {}) {
  const text = String(value || "");
  if (String(report.time_zone || report.timezone || "").toLowerCase() === "asia/shanghai") return text;
  return text.replace(/\b(20\d{2}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)?\b/g, (_, date, time) => {
    const parsed = new Date(`${date}T${time}Z`);
    if (Number.isNaN(parsed.getTime())) return `${date} ${time}`;
    return parsed.toLocaleString("sv-SE", { hour12: false, timeZone: "Asia/Shanghai" });
  });
}

function renderSituationReportSection(title, content, className = "", report = {}) {
  if (!content) return "";
  return `<section class="${escapeHtml(className)}"><h4>${escapeHtml(title)}</h4><p>${escapeHtml(normalizeSituationReportTime(content, report))}</p></section>`;
}

function renderSituationAdvice(items, report = {}) {
  const rows = Array.isArray(items) ? items : [];
  return rows.length ? `<ol>${rows.map((item) => `<li>${escapeHtml(normalizeSituationReportTime(item, report))}</li>`).join("")}</ol>` : `<p>暂无建议</p>`;
}

function professionalReportButtonLabel(job) {
  if (!job) return "获取专业态势报告";
  if (job.status === "completed") return "查看专业态势报告";
  if (job.status === "failed") return "重新生成专业报告";
  return `报告生成中 ${Number(job.progress || 0)}%`;
}

async function refreshProfessionalReportStatus(openModal = false) {
  if (state.situations.scopeMode !== "single_ip" || !state.situations.selectedId) return null;
  const response = await api(`/api/v2/situations/${encodeURIComponent(state.situations.selectedId)}/professional-report`);
  state.situations.professionalReport = response.job || null;
  const button = document.getElementById("btnProfessionalSituationReport");
  if (button) button.textContent = professionalReportButtonLabel(state.situations.professionalReport);
  if (openModal && state.situations.professionalReport) renderProfessionalReportModal();
  return state.situations.professionalReport;
}

async function startProfessionalSituationReport() {
  if (state.situations.scopeMode !== "single_ip" || !state.situations.selectedId) {
    showToast("请先切换到单 IP 态势并选择一条记录");
    return;
  }
  const current = await refreshProfessionalReportStatus(false).catch(() => null);
  if (current?.status === "completed" || current?.status === "running" || current?.status === "queued") {
    renderProfessionalReportModal();
    beginProfessionalReportPolling();
    return;
  }
  const response = await api(`/api/v2/situations/${encodeURIComponent(state.situations.selectedId)}/professional-report`, { method: "POST", body: {} });
  state.situations.professionalReport = response.job || null;
  renderProfessionalReportModal();
  beginProfessionalReportPolling();
}

function closeProfessionalReportModal() {
  document.getElementById("professionalReportOverlay")?.remove();
  if (state.situations.professionalReportPoll) {
    clearTimeout(state.situations.professionalReportPoll);
    state.situations.professionalReportPoll = null;
  }
}

function renderProfessionalReportModal() {
  const job = state.situations.professionalReport || {};
  let root = document.getElementById("professionalReportOverlay");
  if (!root) {
    root = document.createElement("div");
    root.id = "professionalReportOverlay";
    root.className = "professional-report-overlay";
    document.body.appendChild(root);
  }
  const done = job.status === "completed";
  const failed = job.status === "failed";
  const progress = Math.max(2, Math.min(100, Number(job.progress || 2)));
  root.innerHTML = `
    <section class="professional-report-modal" role="dialog" aria-modal="true" aria-labelledby="professionalReportTitle">
      <button class="professional-report-close" type="button" aria-label="关闭">×</button>
      <span class="section-eyebrow">PROFESSIONAL SITUATION REPORT</span>
      <div class="professional-report-mark ${done ? "done" : failed ? "failed" : ""}"><i></i><i></i><i></i></div>
      <h3 id="professionalReportTitle">${done ? "专业态势报告已生成" : failed ? "专业态势报告生成失败" : "正在生成专业态势报告"}</h3>
      <p>${done ? "报告已完成事实核验、知识增强与 PDF 排版，可以立即下载。" : failed ? escapeHtml(job.error_message || "生成服务暂时不可用，请稍后重试。") : "大约需要一分钟，退出此界面也可以"}</p>
      <div class="professional-report-progress"><span style="width:${progress}%"></span></div>
      <div class="professional-report-stage"><span>${escapeHtml(job.stage || "任务已创建")}</span><strong>${progress}%</strong></div>
      <footer>
        <button class="btn btn-ghost" data-professional-close type="button">${done || failed ? "关闭" : "退出此界面"}</button>
        ${done ? `<button class="btn btn-primary" data-professional-download type="button">下载 PDF 报告</button>` : ""}
        ${failed ? `<button class="btn btn-primary" data-professional-retry type="button">重新生成</button>` : ""}
      </footer>
    </section>`;
  root.querySelector(".professional-report-close")?.addEventListener("click", closeProfessionalReportModal);
  root.querySelector("[data-professional-close]")?.addEventListener("click", closeProfessionalReportModal);
  root.querySelector("[data-professional-download]")?.addEventListener("click", downloadProfessionalSituationReport);
  root.querySelector("[data-professional-retry]")?.addEventListener("click", async () => {
    closeProfessionalReportModal();
    await startProfessionalSituationReport();
  });
}

function beginProfessionalReportPolling() {
  if (state.situations.professionalReportPoll) clearTimeout(state.situations.professionalReportPoll);
  const poll = async () => {
    if (!document.getElementById("professionalReportOverlay")) return;
    try {
      const job = await refreshProfessionalReportStatus(false);
      renderProfessionalReportModal();
      if (job && !["completed", "failed"].includes(job.status)) {
        state.situations.professionalReportPoll = setTimeout(poll, 1500);
      }
    } catch (err) {
      showToast(`报告状态读取失败：${err.message}`);
      state.situations.professionalReportPoll = setTimeout(poll, 3000);
    }
  };
  state.situations.professionalReportPoll = setTimeout(poll, 900);
}

async function downloadProfessionalSituationReport() {
  const job = state.situations.professionalReport;
  if (!job?.job_id || !state.situations.selectedId) return;
  const blob = await api(`/api/v2/situations/${encodeURIComponent(state.situations.selectedId)}/professional-report/download?job_id=${encodeURIComponent(job.job_id)}`, { responseType: "blob" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${state.situations.selectedId}_专业态势感知报告.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast("专业态势报告下载成功");
}

function renderSituationEvidence(actions) {
  const container = document.getElementById("situationEvidence");
  if (!container) return;
  container.innerHTML = actions
    .map((action, index) => {
      const catalogName = state.situations.graph?.nodes?.[index]?.name || action.action_type || "异常行为";
      const metadata = action.metadata || {};
      const ports = Array.isArray(metadata.ports) ? metadata.ports.slice(0, 12).join(", ") : "";
      return `
        <details class="situation-evidence-item" ${index === 0 ? "open" : ""}>
          <summary><b>${Number(action.sequence_no || index + 1)}</b><span><strong>${escapeHtml(catalogName)}</strong><small>${escapeHtml(action.source_ip ? `${action.source_ip} · ` : "")}${escapeHtml(action.sensor || "unknown")} · ${Number(action.action_count || action.count || 1)} 次</small></span><time>${escapeHtml(formatDateTime(action.occurred_at, false))}</time></summary>
          <div><p>目标接口：${escapeHtml(action.target_interface || "-")}</p><p>置信度：${Math.round(Number(action.confidence || 0) * 100)}%</p>${ports ? `<p>目标端口：${escapeHtml(ports)}</p>` : ""}<p>证据引用：${escapeHtml((action.evidence_refs || []).join("、") || "已留存于原始事件")}</p></div>
        </details>`;
    })
    .join("");
}

function aggregateSituationNodes(nodes, maxNodes = 10) {
  const byAction = new Map();
  nodes.forEach((node, index) => {
    const stage = node.stage || "unknown";
    const key = `${stage}|${node.action_type || node.name || "unknown"}`;
    const existing = byAction.get(key);
    if (existing) {
      existing.members.push(node);
      existing.count += Number(node.count || 1);
      existing.confidence = Math.max(existing.confidence, Number(node.confidence || 0));
      existing.last_seen_at = node.last_seen_at || node.occurred_at || existing.last_seen_at;
      return;
    }
    byAction.set(key, {
      ...node,
      stage,
      aggregateKey: key,
      firstIndex: index,
      members: [node],
      count: Number(node.count || 1),
      confidence: Number(node.confidence || 0),
      last_seen_at: node.last_seen_at || node.occurred_at,
    });
  });

  const groups = [...byAction.values()];
  // If there are still too many unique actions, only merge actions in the
  // same attack stage. Cross-stage merging destroys the swimlane semantics.
  while (groups.length > maxNodes) {
    let bestPair = null;
    for (let left = 0; left < groups.length; left += 1) {
      for (let right = left + 1; right < groups.length; right += 1) {
        if (groups[left].stage !== groups[right].stage) continue;
        const score = Number(groups[left].count || 0) + Number(groups[right].count || 0);
        if (!bestPair || score < bestPair.score) bestPair = { left, right, score };
      }
    }
    if (!bestPair) break;
    const first = groups[bestPair.left];
    const second = groups[bestPair.right];
    const names = [...new Set([first.name, second.name].filter(Boolean))];
    groups[bestPair.left] = {
      ...first,
      firstIndex: Math.min(first.firstIndex, second.firstIndex),
      name: names.length <= 2 ? names.join(" / ") : `${names.slice(0, 2).join(" / ")} 等`,
      count: Number(first.count || 0) + Number(second.count || 0),
      confidence: Math.max(Number(first.confidence || 0), Number(second.confidence || 0)),
      last_seen_at: second.last_seen_at || second.occurred_at || first.last_seen_at,
      members: [...(first.members || [first]), ...(second.members || [second])],
    };
    groups.splice(bestPair.right, 1);
  }
  return groups
    .sort((a, b) => a.firstIndex - b.firstIndex)
    .map((group, index) => ({ ...group, id: `aggregate-${index}` }));
}

function buildSituationGraphView(graph) {
  const sourceNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  if (state.situations.chainMode === "evidence") {
    return { nodes: sourceNodes, edges: Array.isArray(graph.edges) ? graph.edges : [], aggregated: false };
  }
  const nodes = aggregateSituationNodes(sourceNodes, 10);
  const edges = nodes.slice(1).map((node, index) => {
    const previous = nodes[index];
    const previousTime = new Date(previous.last_seen_at || previous.occurred_at || 0).getTime();
    const currentTime = new Date(node.occurred_at || 0).getTime();
    const gap = Number.isFinite(previousTime) && Number.isFinite(currentTime)
      ? Math.max(0, Math.round((currentTime - previousTime) / 1000))
      : 0;
    return { source: previous.id, target: node.id, gap_seconds: gap };
  });
  return { nodes, edges, aggregated: true };
}

function drawSituationChain(graph) {
  const empty = document.getElementById("situationChainEmpty");
  const chart = getEchartsInstance("situationChainChart");
  const graphView = buildSituationGraphView(graph);
  const nodes = graphView.nodes;
  if (!chart || !nodes.length) {
    if (empty) {
      empty.classList.remove("hidden");
      empty.innerHTML = `<b>暂无可绘制动作</b><span>等待关联引擎补充证据。</span>`;
    }
    return;
  }
  if (empty) empty.classList.add("hidden");
  const width = Math.max(640, chart.getWidth() || 900);
  const height = Math.max(340, chart.getHeight() || 420);
  const stageY = { recon: 72, credential: 144, exploit: 216, execution: 288, impact: 360, unknown: 28 };
  const left = 104;
  // Reserve enough room for long labels such as "WebShell 行为" at both ends.
  const right = 146;
  const usable = Math.max(340, width - left - right);
  const colors = { recon: "#58b8ff", credential: "#ffc45c", exploit: "#ff687f", execution: "#d986ff", impact: "#43e2aa", unknown: "#91a9be" };
  const crowded = nodes.length > 10;
  const graphNodes = nodes.map((node, index) => ({
    id: node.id,
    name: node.name,
    x: left + (nodes.length === 1 ? usable / 2 : (usable * index) / (nodes.length - 1)),
    y: Math.min(height - 42, stageY[node.stage] || 40),
    symbolSize: Math.max(42, Math.min(64, 42 + Math.log10(Number(node.count || 1) + 1) * 10)),
    itemStyle: { color: colors[node.stage] || colors.unknown, borderColor: "rgba(242,247,250,.72)", borderWidth: 1.5, shadowBlur: 12, shadowColor: `${colors[node.stage] || colors.unknown}55` },
    label: {
      show: !crowded || index % 2 === 0,
      position: index % 2 === 0 ? "bottom" : "top",
      distance: 8,
      formatter: `{name|${String(node.name || "异常动作").slice(0, 16)}}\n{count|${Number(node.count || 1)} 次}`,
      rich: { name: { color: "#edf3f6", fontSize: 12, fontWeight: 700, lineHeight: 18 }, count: { color: "#9caeb8", fontSize: 10 } },
    },
    raw: node,
  }));
  chart.setOption({
    animationDuration: 850,
    animationEasingUpdate: "cubicOut",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(5,15,27,.96)",
      borderColor: "rgba(116,188,246,.5)",
      textStyle: { color: "#eaf6ff" },
      formatter: (params) => {
        if (params.dataType === "edge") return `间隔 ${Number(params.data.gap_seconds || 0)} 秒`;
        const row = params.data.raw || {};
        const memberCount = Array.isArray(row.members) ? row.members.length : 1;
        return `<b>${escapeHtml(row.name || "")}</b><br/>阶段：${escapeHtml(row.stage_label || formatSituationStage(row.stage))}<br/>聚合动作：${memberCount} 条<br/>累计频次：${Number(row.count || 0)}<br/>最高置信度：${Math.round(Number(row.confidence || 0) * 100)}%<br/>首见：${escapeHtml(formatDateTime(row.occurred_at, false))}<br/>末见：${escapeHtml(formatDateTime(row.last_seen_at || row.occurred_at, false))}`;
      },
    },
    graphic: Object.entries(stageY)
      .filter(([stage]) => stage !== "unknown")
      .map(([stage, y]) => ({
        type: "group",
        left: 14,
        top: y - 14,
        children: [
          { type: "text", style: { text: formatSituationStage(stage), fill: "#7f9db8", font: "12px sans-serif" } },
          { type: "line", shape: { x1: 76, y1: 7, x2: width - 166, y2: 7 }, style: { stroke: "rgba(105,154,194,.12)", lineWidth: 1 } },
        ],
      })),
    series: [
      {
        type: "graph",
        layout: "none",
        roam: true,
        draggable: false,
        data: graphNodes,
        edges: graphView.edges.map((edge) => ({
          ...edge,
          lineStyle: { color: "rgba(134,166,184,.72)", width: 2, curveness: 0.08 },
          label: { show: nodes.length <= 7, formatter: `${Number(edge.gap_seconds || 0)}s`, color: "#8196a3", fontSize: 9 },
        })),
        edgeSymbol: ["none", "arrow"],
        edgeSymbolSize: [0, 10],
        emphasis: { focus: "adjacency", scale: 1.12, lineStyle: { width: 4, color: "#d7f2ff" } },
      },
    ],
  }, true);
}

function renderSituationEmptyState() {
  state.situations.detail = null;
  state.situations.graph = null;
  const chart = getEchartsInstance("situationChainChart");
  chart?.clear?.();
  const empty = document.getElementById("situationChainEmpty");
  if (empty) {
    empty.classList.remove("hidden");
    empty.innerHTML = `<div class="situation-empty-radar"><i></i><i></i><i></i></div><b>正在观察跨阶段行为</b><span>${state.situations.scopeMode === "cross_ip" ? "同一目标在所选时间窗内出现多个来源和至少三种动作后，将形成代理集群态势。" : "同一来源在 30 分钟内出现至少三种不同动作后，将形成攻击者态势。"}</span>`;
  }
  const title = document.getElementById("situationChainTitle");
  if (title) title.textContent = "攻击链路";
  const subtitle = document.getElementById("situationChainSubtitle");
  if (subtitle) subtitle.textContent = state.situations.scopeMode === "cross_ip" ? "选择一个代理集群查看跨来源动作推进" : "选择一个攻击者查看动作推进";
  const stagePills = document.getElementById("situationStagePills");
  if (stagePills) stagePills.innerHTML = "";
  const risk = document.getElementById("situationRiskSummary");
  if (risk) risk.innerHTML = `<div class="situation-risk-orbit"><strong>-</strong><span>等待态势</span></div><div class="situation-sensor-note"><b>数据来自真实传感器</b><span>HTTP / SSH / TCP SYN</span></div>`;
  const report = document.getElementById("situationAiReport");
  if (report) report.innerHTML = `<div class="situation-report-placeholder">暂无符合关联条件的攻击链，不生成虚构研判。</div>`;
  const reportMeta = document.getElementById("situationAiMeta");
  if (reportMeta) reportMeta.textContent = state.situations.scopeMode === "cross_ip" ? "跨 IP 融合研判" : "Ollama + RAG 可解释研判";
  const evidence = document.getElementById("situationEvidence");
  if (evidence) evidence.innerHTML = `<div class="situation-evidence-empty">证据将在动作发生后按时间顺序列出</div>`;
}

function renderSituationFailure(error) {
  const list = document.getElementById("situationList");
  if (list) list.innerHTML = `<div class="situation-list-empty error"><b>态势服务暂不可用</b><span>${escapeHtml(error?.message || String(error))}</span></div>`;
  renderSituationEmptyState();
}

async function reanalyzeSelectedSituation() {
  if (!state.situations.selectedId || state.profile?.role !== ROLE_ADMIN) return;
  const button = document.getElementById("btnSituationReanalyze");
  if (button) {
    button.disabled = true;
    button.textContent = "研判中...";
  }
  try {
    if (state.situations.scopeMode === "cross_ip") {
      const response = await api(`/api/v2/situation-clusters/${encodeURIComponent(state.situations.selectedId)}/reanalyze`, {
        method: "POST",
        body: { window_minutes: state.situations.clusterWindowMinutes, lookback_hours: state.situations.clusterLookbackHours },
      });
      if (state.situations.detail) {
        state.situations.detail.ai_report = response.report;
        state.situations.detail.ai_status = response.ai_status;
        renderSituationAiReport(state.situations.detail);
      }
    } else {
      await api(`/api/v2/situations/${encodeURIComponent(state.situations.selectedId)}/reanalyze`, { method: "POST", body: {} });
    }
    showToast("AI 态势报告已更新");
    if (state.situations.scopeMode !== "cross_ip") await loadSituationDetail(state.situations.selectedId);
  } catch (error) {
    showToast(`重新研判失败：${error.message}`);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "重新研判";
    }
  }
}

async function updateSelectedSituationStatus(status) {
  if (!state.situations.selectedId || state.profile?.role !== ROLE_ADMIN) return;
  try {
    await api(`/api/v2/situations/${encodeURIComponent(state.situations.selectedId)}/status`, { method: "POST", body: { status } });
    showToast(status === "handled" ? "已标记为处置完成" : "该态势已忽略");
    await refreshSituationData({ preserveSelection: true });
  } catch (error) {
    showToast(`状态更新失败：${error.message}`);
  }
}

function formatSituationStage(stage) {
  return { recon: "侦察探测", credential: "凭据攻击", exploit: "漏洞利用", execution: "执行控制", impact: "影响处置", unknown: "其他行为" }[stage] || "其他行为";
}

function formatAiStatus(status, report) {
  if (status === "complete") return `Ollama + RAG · 命中 ${Number(report?.rag_hits || 0)} 条知识`;
  if (status === "fallback") {
    const reason = String(report?.fallback_reason || "");
    if (/未经证据确认|事实|中文|ValueError/i.test(reason)) return "规则化应急报告 · AI 输出未通过事实校验";
    if (/urlopen|connect|timeout|timed out|ollama/i.test(reason)) return "规则化应急报告 · Ollama 暂不可用";
    return "规则化应急报告 · AI 结果不可用";
  }
  if (status === "failed") return "研判失败，等待重试";
  return "Ollama + RAG 可解释研判";
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
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          <select id="pro_attack_type"><option value="all">全部攻击类型</option></select>
          <select id="pro_target_port"><option value="all">全部攻击端口</option></select>
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
                <th>攻击端口</th>
                <th>IP封禁情况</th>
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
        <section class="auto-defense-card" id="autoDefenseCard">
          <div class="auto-defense-head">
            <div><span class="auto-defense-kicker">ACTIVE RESPONSE</span><h3>自动防御</h3><p>Windows 防火墙入站、出站双向联动</p></div>
            <label class="defense-switch ${canHandle ? "" : "disabled"}" title="${canHandle ? "开启后自动封禁达到风险阈值的来源 IP" : "仅管理员可更改自动防御策略"}">
              <input id="auto_defense_toggle" type="checkbox" ${canHandle ? "" : "disabled"} />
              <span></span>
            </label>
          </div>
          <div class="auto-defense-stats">
            <div><span id="auto_defense_state_dot" class="defense-state-dot"></span><small>策略状态</small><strong id="auto_defense_state">读取中</strong></div>
            <div><small>触发阈值</small><select id="auto_defense_risk" ${canHandle ? "" : "disabled"}><option value="critical">仅严重</option><option value="high">高危及以上</option></select></div>
            <div><small>已封禁</small><strong id="auto_defense_count">0</strong></div>
          </div>
          <div class="auto-defense-list-head"><span>最近封禁</span><button id="auto_defense_view_all" class="text-button" type="button">查看完整列表 ↓</button></div>
          <div id="auto_defense_recent" class="auto-defense-recent"><span>暂无封禁记录</span></div>
        </section>
        <div class="panel-head"><h3 class="panel-title">事件详情</h3><span class="panel-sub" id="pro_detail_hint">请选择左侧事件</span></div>
        <div id="pro_event_detail" class="detail-card">暂无详情</div>
        <div class="note-box">
          <textarea id="pro_note_text" rows="3" placeholder="处理备注" ${canHandle ? "" : "disabled"}></textarea>
          <button id="pro_save_note" class="btn btn-success" ${canHandle ? "" : "disabled"}>保存备注</button>
        </div>
        <div class="panel-head pro-node-head"><h3 class="panel-title">本机防护说明</h3></div>
        <div id="pro_node_detail" class="detail-card">本系统按单台服务器部署，事件中的攻击端口均为本机实际监听端口。</div>
      </article>
    </section>

    <section class="panel candidate-panel">
      <div class="panel-head">
        <h3 class="panel-title">候选事件复核队列</h3>
        <div class="ops-group">
          <input id="candidate_q" placeholder="按事件ID/IP/接口搜索候选" />
          <button id="candidate_refresh" class="btn btn-success">刷新候选</button>
        </div>
      </div>
      <div class="table-shell candidate-table-shell">
        <table>
          <thead>
            <tr>
              <th>候选ID</th>
              <th>评分</th>
              <th>风险</th>
              <th>类型</th>
              <th>来源IP</th>
              <th>目标接口</th>
              <th>时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="candidate_table_body"></tbody>
        </table>
      </div>
      <div class="table-pager">
        <span class="panel-sub" id="candidate_total">总计 0 条</span>
        <div class="ops-group">
          <button id="candidate_prev" class="btn btn-ghost">上一页</button>
          <button id="candidate_next" class="btn btn-ghost">下一页</button>
        </div>
      </div>
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
  document.getElementById("auto_defense_toggle")?.addEventListener("change", updateAutoDefenseConfig);
  document.getElementById("auto_defense_risk")?.addEventListener("change", updateAutoDefenseConfig);
  document.getElementById("auto_defense_view_all")?.addEventListener("click", () => {
    document.querySelector(".blocked-ip-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  document.getElementById("candidate_refresh")?.addEventListener("click", () => loadProCandidates(true));
  document.getElementById("candidate_q")?.addEventListener("keyup", (ev) => {
    if (ev.key === "Enter") loadProCandidates(true).catch((err) => showToast(err.message));
  });
  document.getElementById("candidate_prev")?.addEventListener("click", () => {
    state.pro.candidates.page = Math.max(1, state.pro.candidates.page - 1);
    loadProCandidates().catch((err) => showToast(err.message));
  });
  document.getElementById("candidate_next")?.addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(state.pro.candidates.total / state.pro.candidates.pageSize));
    state.pro.candidates.page = Math.min(maxPage, state.pro.candidates.page + 1);
    loadProCandidates().catch((err) => showToast(err.message));
  });
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
    "pro_target_port",
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
  loadProCandidates(true).catch((err) => showToast(`加载候选失败：${err.message}`));
  loadBlockedIpList(true).catch((err) => showToast(`加载封禁列表失败：${err.message}`));
  loadAutoDefenseStatus().catch((err) => showToast(`加载自动防御失败：${err.message}`));
}

async function refreshProWorkspace() {
  await loadProEvents();
  await loadProCandidates();
  await loadBlockedIpList();
  await loadAutoDefenseStatus();
}

async function loadAutoDefenseStatus() {
  const data = await api("/api/v2/defense/status");
  state.pro.defense.enabled = Boolean(data.enabled);
  state.pro.defense.minimumRisk = String(data.minimum_risk || "critical");
  state.pro.defense.blockedCount = Number(data.blocked_count || 0);
  state.pro.defense.enforcement = String(data.enforcement || "windows_firewall_bidirectional");
  renderAutoDefensePanel();
}

function renderAutoDefensePanel() {
  const data = state.pro.defense;
  const toggle = document.getElementById("auto_defense_toggle");
  const risk = document.getElementById("auto_defense_risk");
  const stateText = document.getElementById("auto_defense_state");
  const stateDot = document.getElementById("auto_defense_state_dot");
  const count = document.getElementById("auto_defense_count");
  if (toggle) toggle.checked = data.enabled;
  if (risk) risk.value = data.minimumRisk;
  if (stateText) stateText.textContent = data.enabled ? "持续防御中" : "已关闭";
  stateDot?.classList.toggle("active", data.enabled);
  if (count) count.textContent = String(data.blockedCount);
  renderAutoDefenseRecent();
}

async function updateAutoDefenseConfig() {
  if (state.profile?.role !== ROLE_ADMIN) return;
  const toggle = document.getElementById("auto_defense_toggle");
  const risk = document.getElementById("auto_defense_risk");
  if (toggle) toggle.disabled = true;
  if (risk) risk.disabled = true;
  try {
    await api("/api/v2/defense/config", {
      method: "PUT",
      body: { enabled: Boolean(toggle?.checked), minimum_risk: String(risk?.value || "critical"), allow_private: false },
    });
    await loadAutoDefenseStatus();
    showToast(state.pro.defense.enabled ? "自动防御已开启，将持续执行双向封禁" : "自动防御已关闭，现有封禁规则保持不变");
  } catch (error) {
    showToast(`自动防御配置失败：${error.message}`);
    await loadAutoDefenseStatus();
  } finally {
    if (toggle) toggle.disabled = false;
    if (risk) risk.disabled = false;
  }
}

async function initProOptions() {
  const [typeObj, eventObj] = await Promise.all([
    api("/api/v2/user/dashboard/top-attack-types"),
    api("/api/v2/pro/events?time_range=30d&page=1&page_size=200"),
  ]);
  const attackTypes = Array.from(new Set((typeObj.items || []).map((x) => x.attack_type))).filter(Boolean);
  const ports = Array.from(new Set((eventObj.items || []).map((x) => x.target_port))).filter(Boolean).sort((a, b) => Number(a) - Number(b));
  state.pro.options.attackTypes = attackTypes;
  state.pro.options.ports = ports;

  const typeSelect = document.getElementById("pro_attack_type");
  if (typeSelect) {
    typeSelect.innerHTML = `<option value="all">全部攻击类型</option>${attackTypes
      .map((x) => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`)
      .join("")}`;
  }
  const portSelect = document.getElementById("pro_target_port");
  if (portSelect) {
    portSelect.innerHTML = `<option value="all">全部攻击端口</option>${ports
      .map((x) => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`)
      .join("")}`;
  }
}

function collectProFilters() {
  state.pro.filters.time_range = String(document.getElementById("pro_time_range")?.value || "24h");
  state.pro.filters.risk_level = String(document.getElementById("pro_risk_level")?.value || "all");
  state.pro.filters.attack_type = String(document.getElementById("pro_attack_type")?.value || "all");
  state.pro.filters.target_port = String(document.getElementById("pro_target_port")?.value || "all");
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
  params.set("target_port", f.target_port);
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
            <td>${escapeHtml(row.target_port == null ? "-" : String(row.target_port))}</td>
            <td>${ipBlocked ? "已封禁" : "未封禁"}</td>
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
        <td>${escapeHtml(x.blocked_at || "-")}<span class="firewall-proof ${x.firewall_active ? "active" : "missing"}">${x.firewall_active ? "双向规则生效" : "规则待修复"}</span></td>
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
  state.pro.defense.blockedCount = state.pro.blocked.total;
  renderAutoDefenseRecent();
}

function renderAutoDefenseRecent() {
  const container = document.getElementById("auto_defense_recent");
  if (!container) return;
  const items = state.pro.blocked.items.slice(0, 3);
  if (!items.length) {
    container.innerHTML = `<span>暂无封禁记录</span>`;
    return;
  }
  container.innerHTML = items.map((item) => `
    <div><i class="${item.firewall_active ? "active" : "missing"}"></i><span><b>${escapeHtml(item.ip_address || "-")}</b><small>${escapeHtml(item.reason || "人工封禁")}</small></span><button type="button" data-defense-unblock="${escapeHtml(item.ip_address || "")}">解封</button></div>
  `).join("");
  container.querySelectorAll("[data-defense-unblock]").forEach((button) => {
    button.addEventListener("click", async () => {
      const ip = String(button.dataset.defenseUnblock || "");
      if (!ip) return;
      button.disabled = true;
      try {
        await api("/api/v2/pro/blocked-ips/unblock", { method: "POST", body: { ip_address: ip, reason: "manual_unblock_from_auto_defense" } });
        showToast(`已解除 ${ip} 的入站与出站封禁`);
        await Promise.all([loadBlockedIpList(true), loadAutoDefenseStatus(), loadProEvents()]);
      } catch (error) {
        showToast(`解封失败：${error.message}`);
      } finally {
        button.disabled = false;
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

async function loadProCandidates(forcePageOne = false) {
  if (forcePageOne) state.pro.candidates.page = 1;
  state.pro.candidates.q = String(document.getElementById("candidate_q")?.value || "").trim();
  const params = new URLSearchParams();
  params.set("page", String(state.pro.candidates.page));
  params.set("page_size", String(state.pro.candidates.pageSize));
  if (state.pro.candidates.q) params.set("q", state.pro.candidates.q);
  const data = await api(`/api/v2/pro/candidates?${params.toString()}`);
  state.pro.candidates.items = Array.isArray(data.items) ? data.items : [];
  state.pro.candidates.total = Number(data.total || 0);
  renderProCandidateTable();
}

function renderProCandidateTable() {
  const bodyEl = document.getElementById("candidate_table_body");
  const totalEl = document.getElementById("candidate_total");
  const canHandle = state.profile?.role === ROLE_ADMIN;
  if (totalEl) {
    const maxPage = Math.max(1, Math.ceil(state.pro.candidates.total / state.pro.candidates.pageSize));
    totalEl.textContent = `总计 ${state.pro.candidates.total} 条，当前第 ${state.pro.candidates.page}/${maxPage} 页`;
  }
  if (!bodyEl) return;
  if (!state.pro.candidates.items.length) {
    bodyEl.innerHTML = `<tr><td colspan="8" class="panel-sub">暂无候选事件</td></tr>`;
    return;
  }
  bodyEl.innerHTML = state.pro.candidates.items
    .map(
      (row) => `
        <tr>
          <td><span class="link-btn" data-candidate-detail="${escapeHtml(row.event_id || "")}">${escapeHtml(row.event_id || "-")}</span></td>
          <td>${escapeHtml(formatPercentScore(row.final_score))}</td>
          <td>${riskBadge(row.risk_level)}</td>
          <td>${escapeHtml(formatAttackType(row.attack_type || "-"))}</td>
          <td>${escapeHtml(row.source_ip || "-")}</td>
          <td>${escapeHtml(row.target_interface || "-")}</td>
          <td>${escapeHtml(row.created_at || "-")}</td>
          <td>
            <div class="candidate-actions">
              <button class="btn btn-primary" data-candidate-detail="${escapeHtml(row.event_id || "")}">查看</button>
              <button class="btn btn-danger" data-candidate-promote="${escapeHtml(row.event_id || "")}" ${canHandle ? "" : "disabled"}>提升</button>
              <button class="btn btn-ghost" data-candidate-ignore="${escapeHtml(row.event_id || "")}" ${canHandle ? "" : "disabled"}>忽略</button>
            </div>
          </td>
        </tr>
      `
    )
    .join("");
  bodyEl.querySelectorAll("[data-candidate-detail]").forEach((el) => {
    el.addEventListener("click", () => {
      const eventId = el.getAttribute("data-candidate-detail");
      if (!eventId) return;
      loadProCandidateDetail(eventId).catch((err) => showToast(`加载候选详情失败：${err.message}`));
    });
  });
  bodyEl.querySelectorAll("[data-candidate-promote]").forEach((el) => {
    el.addEventListener("click", () => {
      const eventId = el.getAttribute("data-candidate-promote");
      if (!eventId) return;
      promoteProCandidate(eventId).catch((err) => showToast(`提升失败：${err.message}`));
    });
  });
  bodyEl.querySelectorAll("[data-candidate-ignore]").forEach((el) => {
    el.addEventListener("click", () => {
      const eventId = el.getAttribute("data-candidate-ignore");
      if (!eventId) return;
      ignoreProCandidate(eventId).catch((err) => showToast(`忽略失败：${err.message}`));
    });
  });
}

async function loadProCandidateDetail(eventId) {
  state.pro.selectedEventId = "";
  state.pro.selectedEventDetail = await api(`/api/v2/pro/candidates/${encodeURIComponent(eventId)}`);
  renderProTable();
  renderProEventDetail();
}

async function promoteProCandidate(eventId) {
  await api(`/api/v2/pro/candidates/${encodeURIComponent(eventId)}/promote`, { method: "POST", body: {} });
  showToast("候选事件已提升为攻击事件");
  await loadProEvents(true);
  await loadProCandidates(true);
}

async function ignoreProCandidate(eventId) {
  await api(`/api/v2/pro/candidates/${encodeURIComponent(eventId)}/ignore`, { method: "POST", body: {} });
  showToast("候选事件已忽略");
  await loadProCandidates(true);
}

function formatPercentScore(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return `${(num * 100).toFixed(1)}%`;
}

function formatV2Decision(value) {
  const map = {
    raw_only: "原始日志",
    candidate: "候选事件",
    attack_event: "攻击事件",
  };
  return map[String(value || "")] || value || "-";
}

function renderEvidenceList(items) {
  const arr = Array.isArray(items) ? items : [];
  if (!arr.length) return `<div class="v2-empty">暂无证据</div>`;
  return `
    <ul class="v2-evidence-list">
      ${arr
        .map((item) => {
          const text = typeof item === "string" ? item : JSON.stringify(item, null, 2);
          return `<li>${escapeHtml(sanitizeEvidenceText(text))}</li>`;
        })
        .join("")}
    </ul>
  `;
}

function sanitizeEvidenceText(value) {
  const text = String(value ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim();
  if (!text) return "";
  const replacementCount = (text.match(/�/g) || []).length;
  const questionCount = (text.match(/\?{4,}/g) || []).reduce((total, row) => total + row.length, 0);
  if (!replacementCount && questionCount < 8) return text;
  const ips = [...new Set(text.match(/(?:\d{1,3}\.){3}\d{1,3}/g) || [])].slice(0, 5);
  return `Windows 登录失败事件（历史原始消息编码异常，乱码内容已隐藏）${ips.length ? `；关联IP：${ips.join("、")}` : ""}`;
}

function renderV2DetectionDetail(row) {
  const v2 = row?.v2_detection;
  if (!v2) {
    return `
      <section class="v2-section">
        <div class="v2-section-head">
          <span>新架构证据链</span>
          <em>当前事件尚未同步到 v2 分层表</em>
        </div>
        <div class="v2-empty">旧数据仍可正常查看；新产生的攻击事件会自动写入模型、规则、行为证据。</div>
      </section>
    `;
  }
  const predictions = Array.isArray(v2.model_predictions) ? v2.model_predictions : [];
  const pocs = Array.isArray(v2.poc_matches) ? v2.poc_matches : [];
  const windows = Array.isArray(v2.behavior_windows) ? v2.behavior_windows : [];
  const raw = v2.raw_http || {};
  const llm = v2.llm_review || {};
  const llmEvidence = Array.isArray(llm.evidence) ? llm.evidence : [];
  const impactItems = Array.isArray(llm.potential_impact) ? llm.potential_impact : [];
  const immediateItems = Array.isArray(llm.immediate_actions) ? llm.immediate_actions : [];
  const hardeningItems = Array.isArray(llm.hardening_actions) ? llm.hardening_actions : [];
  const knowledgeItems = Array.isArray(llm.knowledge_references) ? llm.knowledge_references : [];
  const llmStatusMap = { pending: "等待研判", processing: "正在研判", done: "研判完成", failed: "研判失败" };
  const llmVerdictMap = { attack: "确认攻击", benign: "正常流量", suspicious: "仍需复核", unknown: "无法确定" };
  return `
    <section class="v2-section">
      <div class="v2-section-head">
        <span>新架构证据链</span>
        <em>${escapeHtml(v2.case_id || "-")}</em>
      </div>
      <div class="v2-summary-grid">
        <div class="v2-summary-card">
          <span>融合判定</span>
          <strong>${escapeHtml(formatV2Decision(v2.decision))}</strong>
        </div>
        <div class="v2-summary-card">
          <span>融合评分</span>
          <strong>${escapeHtml(formatPercentScore(v2.final_score))}</strong>
        </div>
        <div class="v2-summary-card">
          <span>攻击类型</span>
          <strong>${escapeHtml(formatAttackType(v2.attack_type || "-"))}</strong>
        </div>
        <div class="v2-summary-card">
          <span>目标接口</span>
          <strong>${escapeHtml(v2.target_interface || "-")}</strong>
        </div>
      </div>

      <div class="v2-subtitle">Payload 模型预测</div>
      <div class="v2-chip-row">
        ${
          predictions.length
            ? predictions
                .map(
                  (p) => `
                    <span class="v2-chip">
                      ${escapeHtml(p.model_name || "payload_model_v2")}
                      <b>${escapeHtml(formatAttackType(p.label || "-"))}</b>
                      <i>${escapeHtml(formatPercentScore(p.score))}</i>
                    </span>
                  `
                )
                .join("")
            : `<span class="v2-empty">暂无模型预测记录</span>`
        }
      </div>

      <div class="v2-subtitle">POC 规则命中</div>
      <div class="v2-rule-list">
        ${
          pocs.length
            ? pocs
                .map(
                  (m) => `
                    <div class="v2-rule-card">
                      <div>
                        <strong>${escapeHtml(m.rule_name || m.rule_id || "-")}</strong>
                        <span>${escapeHtml(formatAttackType(m.attack_type || "-"))} / ${escapeHtml(formatRiskLevel(m.severity || "-"))}</span>
                      </div>
                      <b>${escapeHtml(formatPercentScore(m.score))}</b>
                      ${renderEvidenceList(m.evidence)}
                    </div>
                  `
                )
                .join("")
            : `<div class="v2-empty">未命中明确 POC 规则</div>`
        }
      </div>

      <div class="v2-subtitle">行为窗口证据</div>
      <div class="v2-chip-row">
        ${
          windows.length
            ? windows
                .map(
                  (w) => `
                    <span class="v2-chip v2-chip-wide">
                      ${escapeHtml(w.behavior_type || "-")}
                      <b>${escapeHtml(w.source_ip || "-")}</b>
                      <i>${escapeHtml(formatPercentScore(w.score))}</i>
                    </span>
                  `
                )
                .join("")
            : `<span class="v2-empty">暂无聚合行为命中</span>`
        }
      </div>

      <div class="v2-subtitle">融合证据摘要</div>
      ${renderEvidenceList(v2.evidence)}

      <div class="v2-subtitle">最终安全研判</div>
      <div class="llm-review-card ${escapeHtml(String(llm.verdict || llm.llm_status || "pending"))}">
        <div class="llm-review-head">
          <div>
            <span>LLM FINAL REVIEW</span>
            <strong>${escapeHtml(llmVerdictMap[String(llm.verdict || "").toLowerCase()] || llmStatusMap[String(llm.llm_status || "pending").toLowerCase()] || "等待研判")}</strong>
          </div>
          <em>${escapeHtml(llm.model_name || "模型队列")}</em>
        </div>
        <div class="llm-review-metrics">
          <div><span>风险等级</span><b>${escapeHtml(formatRiskLevel(llm.severity || "-"))}</b></div>
          <div><span>研判置信度</span><b>${escapeHtml(formatPercentScore(llm.confidence))}</b></div>
          <div><span>RAG 知识增强</span><b>${Number(llm.rag_enabled || 0) === 1 ? `已启用 · ${Number(llm.rag_hits || 0)} 条` : "未启用"}</b></div>
          <div><span>研判耗时</span><b>${llm.review_latency_ms == null ? "-" : `${escapeHtml(String(llm.review_latency_ms))} ms`}</b></div>
        </div>
        <div class="llm-review-summary">${escapeHtml(llm.summary || llm.llm_error || "候选事件已进入大模型研判队列，完成前不会发布为正式攻击事件。")}</div>
        <div class="llm-review-evidence">
          <span>最终判定依据</span>
          ${renderEvidenceList(llmEvidence)}
        </div>
        ${
          llm.analysis_reasoning
            ? `<div class="llm-review-block"><span>证据推理与结论</span><p>${escapeHtml(llm.analysis_reasoning)}</p></div>`
            : ""
        }
        ${
          impactItems.length
            ? `<div class="llm-review-block"><span>潜在影响</span>${renderEvidenceList(impactItems)}</div>`
            : ""
        }
        ${
          immediateItems.length
            ? `<div class="llm-review-block urgent"><span>立即处置</span>${renderEvidenceList(immediateItems)}</div>`
            : ""
        }
        ${
          hardeningItems.length
            ? `<div class="llm-review-block"><span>长期加固</span>${renderEvidenceList(hardeningItems)}</div>`
            : ""
        }
        ${
          llm.false_positive_notes
            ? `<div class="llm-review-block"><span>误报边界与待核验项</span><p>${escapeHtml(llm.false_positive_notes)}</p></div>`
            : ""
        }
        ${
          Number(llm.rag_enabled || 0) === 1 && knowledgeItems.length
            ? `<div class="llm-review-block knowledge"><span>RAG 知识引用</span>${renderEvidenceList(knowledgeItems)}</div>`
            : ""
        }
      </div>

      <details class="v2-raw-detail">
        <summary>查看原始请求/响应</summary>
        <div class="v2-raw-grid">
          <pre>${escapeHtml(raw.request_text || "")}</pre>
          <pre>${escapeHtml(raw.response_text || "")}</pre>
        </div>
      </details>
    </section>
  `;
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
      <div class="kv"><strong>攻击端口：</strong>${escapeHtml(row.target_port == null ? "-" : String(row.target_port))}</div>
      <div class="kv"><strong>目标接口：</strong>${escapeHtml(row.target_interface || "-")}</div>
      <div class="kv"><strong>IP封禁情况：</strong>${Number(row.ip_blocked || 0) === 1 ? "已封禁" : "未封禁"}</div>
      <div class="kv"><strong>处理状态：</strong>${escapeHtml(formatProcessStatus(row.process_status || "-"))}</div>
      <div class="kv"><strong>响应耗时：</strong>${escapeHtml(String(row.response_ms || 0))} ms</div>
    </div>
    ${renderV2DetectionDetail(row)}
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
    target_port: x.target_port,
    ip_blocked: Number(x.ip_blocked || 0) === 1 ? "已封禁" : "未封禁",
    process_status: x.process_status,
  }));
  downloadCsv("pro_events_export.csv", rows);
}

function renderRagSettingsView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const canRebuild = state.profile?.role === ROLE_ADMIN;
  const activePanel = state.llmSettings.activePanel || "prompt";

  root.innerHTML = `
    <section class="panel llm-settings-hero">
      <div>
        <h3 class="panel-title">大模型设置</h3>
        <div class="panel-sub">统一管理 LLM 系统提示词与 RAG 知识库。提示词保存后，后续新进入的大模型研判任务会自动使用最新版本。</div>
      </div>
      <div class="llm-settings-badges">
        <span>提示词可编辑</span>
        <span>RAG 可维护</span>
        <span>管理员专属</span>
      </div>
    </section>

    <section class="llm-settings-card-grid">
      <button class="llm-setting-card ${activePanel === "prompt" ? "is-active" : ""}" data-llm-setting-card="prompt">
        <span class="llm-card-kicker">Prompt</span>
        <strong>提示词设置</strong>
        <em>配置发给大模型的系统提示词，控制研判口径、输出字段和建议风格。</em>
        <small id="llm_card_prompt_meta">${state.llmSettings.prompt ? `${state.llmSettings.prompt.length} 字符` : "点击进入编辑"}</small>
      </button>
      <button class="llm-setting-card ${activePanel === "rag" ? "is-active" : ""}" data-llm-setting-card="rag">
        <span class="llm-card-kicker">RAG</span>
        <strong>RAG 知识库</strong>
        <em>维护攻击知识、判定依据和处置建议，增强大模型解释能力。</em>
        <small id="llm_card_rag_meta">${state.rag.total ? `${state.rag.total} 条知识` : "点击查看知识库"}</small>
      </button>
    </section>

    <section class="panel llm-prompt-panel llm-setting-panel ${activePanel === "prompt" ? "" : "hidden"}" data-llm-panel="prompt">
      <div class="panel-head">
        <div>
          <h3 class="panel-title">提示词设置</h3>
          <div class="panel-sub">这里编辑的是发给大模型的系统提示词，会影响攻击类型、证据链、风险等级和处置建议的输出风格。</div>
        </div>
        <div class="ops-group">
          <button id="llm_prompt_reload" class="btn btn-ghost">重新读取</button>
          <button id="llm_prompt_save" class="btn btn-primary">保存提示词</button>
        </div>
      </div>
      <div class="prompt-meta-grid">
        <div class="prompt-meta-card">
          <span>提示词文件</span>
          <strong id="llm_prompt_path">-</strong>
        </div>
        <div class="prompt-meta-card">
          <span>最后更新</span>
          <strong id="llm_prompt_updated">-</strong>
        </div>
        <div class="prompt-meta-card">
          <span>字符数</span>
          <strong id="llm_prompt_chars">0</strong>
        </div>
      </div>
      <textarea id="llm_prompt_editor" class="prompt-editor" rows="14" placeholder="正在读取提示词..."></textarea>
      <div class="panel-sub top-gap-xs">建议保留 JSON 输出要求、字段约束和安全研判口径；如果要改实验风格，可以优先调整判定依据、风险等级解释和处置建议部分。</div>
    </section>

    <div class="llm-setting-panel ${activePanel === "rag" ? "" : "hidden"}" data-llm-panel="rag">
    <section class="panel">
      <div class="panel-head">
        <div>
          <h3 class="panel-title">RAG 知识库设置</h3>
          <div class="panel-sub">维护可被大模型检索的攻防知识、证据模板和处置建议。</div>
        </div>
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

    <section class="panel rag-detail-panel">
      <div class="panel-head">
        <div>
          <h3 class="panel-title">知识详情与编辑</h3>
          <div class="panel-sub" id="rag_edit_hint">点击上方列表中的任意知识，即可查看完整内容并修改。</div>
        </div>
        <div class="ops-group">
          <button id="rag_edit_reload" class="btn btn-ghost" disabled>重新读取</button>
          <button id="rag_edit_save" class="btn btn-primary" disabled>保存修改</button>
        </div>
      </div>
      <div class="detail-grid top-gap-sm">
        <div><label class="panel-sub">文档ID</label><input id="rag_edit_doc_id" disabled /></div>
        <div><label class="panel-sub">标题</label><input id="rag_edit_title" disabled /></div>
        <div><label class="panel-sub">攻击类型</label><input id="rag_edit_attack_type" disabled /></div>
        <div><label class="panel-sub">标签</label><input id="rag_edit_tags" disabled /></div>
        <div>
          <label class="panel-sub">严重度</label>
          <select id="rag_edit_severity" disabled>
            <option value="low">低</option>
            <option value="medium">中</option>
            <option value="high">高</option>
            <option value="critical">严重</option>
          </select>
        </div>
        <div><label class="panel-sub">来源</label><input id="rag_edit_source" disabled /></div>
      </div>
      <div class="top-gap-sm">
        <label class="panel-sub">正文内容</label>
        <textarea id="rag_edit_content" rows="6" disabled placeholder="选择一条知识后显示完整正文"></textarea>
      </div>
      <div class="top-gap-sm">
        <label class="panel-sub">判定证据</label>
        <textarea id="rag_edit_evidence" rows="4" disabled></textarea>
      </div>
      <div class="top-gap-sm">
        <label class="panel-sub">处置建议</label>
        <textarea id="rag_edit_mitigation" rows="4" disabled></textarea>
      </div>
    </section>
    </div>
  `;

  document.querySelectorAll("[data-llm-setting-card]").forEach((card) => {
    card.addEventListener("click", () => switchLlmSettingPanel(String(card.getAttribute("data-llm-setting-card") || "prompt")));
  });
  document.getElementById("rag_refresh")?.addEventListener("click", () => loadRagDocs(true));
  document.getElementById("rag_rebuild")?.addEventListener("click", rebuildRagFromSeed);
  document.getElementById("llm_prompt_reload")?.addEventListener("click", () =>
    loadLlmPrompt().catch((err) => showToast(`读取提示词失败：${err.message}`))
  );
  document.getElementById("llm_prompt_save")?.addEventListener("click", () =>
    saveLlmPrompt().catch((err) => showToast(`保存提示词失败：${err.message}`))
  );
  document.getElementById("llm_prompt_editor")?.addEventListener("input", () => {
    const text = String(document.getElementById("llm_prompt_editor")?.value || "");
    const chars = document.getElementById("llm_prompt_chars");
    if (chars) chars.textContent = `${text.length}${state.llmSettings.promptMaxChars ? ` / ${state.llmSettings.promptMaxChars}` : ""}`;
  });
  document.getElementById("rag_add_doc")?.addEventListener("click", addRagDoc);
  document.getElementById("rag_edit_reload")?.addEventListener("click", () => {
    if (state.rag.selectedDocId) loadRagDocDetail(state.rag.selectedDocId).catch((err) => showToast(err.message));
  });
  document.getElementById("rag_edit_save")?.addEventListener("click", () => saveRagDoc().catch((err) => showToast(`保存失败：${err.message}`)));
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

  loadLlmPrompt().catch((err) => showToast(`读取提示词失败：${err.message}`));
  loadRagDocs(true).catch((err) => showToast(`加载RAG列表失败：${err.message}`));
}

function switchLlmSettingPanel(panel) {
  const nextPanel = panel === "rag" ? "rag" : "prompt";
  if (state.llmSettings.activePanel === nextPanel) return;
  state.llmSettings.activePanel = nextPanel;
  document.querySelectorAll("[data-llm-setting-card]").forEach((card) => {
    card.classList.toggle("is-active", card.getAttribute("data-llm-setting-card") === nextPanel);
  });
  document.querySelectorAll("[data-llm-panel]").forEach((pane) => {
    const isActive = pane.getAttribute("data-llm-panel") === nextPanel;
    pane.classList.toggle("hidden", !isActive);
    if (isActive) {
      pane.classList.remove("llm-panel-pop");
      void pane.offsetWidth;
      pane.classList.add("llm-panel-pop");
    }
  });
  if (nextPanel === "prompt") {
    loadLlmPrompt().catch((err) => showToast(`读取提示词失败：${err.message}`));
  } else {
    loadRagDocs().catch((err) => showToast(`加载RAG列表失败：${err.message}`));
  }
}

async function loadLlmPrompt() {
  const data = await api("/api/v2/llm/prompt");
  const prompt = String(data.prompt || "");
  state.llmSettings.prompt = prompt;
  state.llmSettings.promptPath = String(data.path || "-");
  state.llmSettings.promptUpdatedAt = String(data.updated_at || "-");
  state.llmSettings.promptMaxChars = Number(data.max_chars || 0);
  const editor = document.getElementById("llm_prompt_editor");
  if (editor) editor.value = prompt;
  const pathEl = document.getElementById("llm_prompt_path");
  const updatedEl = document.getElementById("llm_prompt_updated");
  const charsEl = document.getElementById("llm_prompt_chars");
  if (pathEl) pathEl.textContent = state.llmSettings.promptPath || "-";
  if (updatedEl) updatedEl.textContent = state.llmSettings.promptUpdatedAt || "-";
  if (charsEl) charsEl.textContent = `${prompt.length}${state.llmSettings.promptMaxChars ? ` / ${state.llmSettings.promptMaxChars}` : ""}`;
  const cardMeta = document.getElementById("llm_card_prompt_meta");
  if (cardMeta) cardMeta.textContent = `${prompt.length} 字符`;
}

async function saveLlmPrompt() {
  const editor = document.getElementById("llm_prompt_editor");
  const prompt = String(editor?.value || "");
  if (!prompt.trim()) {
    showToast("提示词不能为空");
    return;
  }
  const saveBtn = document.getElementById("llm_prompt_save");
  if (saveBtn) saveBtn.disabled = true;
  try {
    const data = await api("/api/v2/llm/prompt", { method: "PUT", body: { prompt } });
    state.llmSettings.prompt = String(data.prompt || prompt);
    state.llmSettings.promptPath = String(data.path || state.llmSettings.promptPath || "-");
    state.llmSettings.promptUpdatedAt = String(data.updated_at || "-");
    state.llmSettings.promptMaxChars = Number(data.max_chars || state.llmSettings.promptMaxChars || 0);
    const pathEl = document.getElementById("llm_prompt_path");
    const updatedEl = document.getElementById("llm_prompt_updated");
    const charsEl = document.getElementById("llm_prompt_chars");
    if (pathEl) pathEl.textContent = state.llmSettings.promptPath;
    if (updatedEl) updatedEl.textContent = state.llmSettings.promptUpdatedAt;
    if (charsEl) charsEl.textContent = `${state.llmSettings.prompt.length}${state.llmSettings.promptMaxChars ? ` / ${state.llmSettings.promptMaxChars}` : ""}`;
    const cardMeta = document.getElementById("llm_card_prompt_meta");
    if (cardMeta) cardMeta.textContent = `${state.llmSettings.prompt.length} 字符`;
    showToast("提示词已保存，后续新研判会使用最新版本");
  } finally {
    if (saveBtn) saveBtn.disabled = false;
  }
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
  const ragCardMeta = document.getElementById("llm_card_rag_meta");
  if (ragCardMeta) ragCardMeta.textContent = `${state.rag.total || 0} 条知识`;
  if (!body) return;
  if (!state.rag.items.length) {
    body.innerHTML = `<tr><td colspan="6" class="panel-sub">暂无RAG知识</td></tr>`;
    return;
  }
  body.innerHTML = state.rag.items
    .map(
      (x) => `
      <tr class="clickable-row ${state.rag.selectedDocId === x.doc_id ? "selected-row" : ""}" data-rag-open="${escapeHtml(x.doc_id || "")}">
        <td>${escapeHtml(x.doc_id || "-")}</td>
        <td title="${escapeHtml(x.title || "")}">${escapeHtml((x.title || "-").slice(0, 36))}</td>
        <td>${escapeHtml(x.attack_type || "-")}</td>
        <td>${escapeHtml(x.severity || "-")}</td>
        <td>${escapeHtml(x.source || "-")}</td>
        <td>
          <div class="row-actions compact-actions">
            <button class="btn btn-ghost" data-rag-view="${escapeHtml(x.doc_id || "")}">查看编辑</button>
            <button class="btn btn-danger" data-rag-del="${escapeHtml(x.doc_id || "")}">删除</button>
          </div>
        </td>
      </tr>
    `
    )
    .join("");
  body.querySelectorAll("[data-rag-open], [data-rag-view]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      const docId = String(el.getAttribute("data-rag-open") || el.getAttribute("data-rag-view") || "");
      if (!docId) return;
      ev.stopPropagation();
      loadRagDocDetail(docId).catch((err) => showToast(`加载详情失败：${err.message}`));
    });
  });
  body.querySelectorAll("[data-rag-del]").forEach((el) => {
    el.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const docId = String(el.getAttribute("data-rag-del") || "");
      if (!docId) return;
      try {
        await api(`/api/v2/rag/docs/${encodeURIComponent(docId)}/delete`, { method: "POST", body: {} });
        showToast(`已删除 ${docId}`);
        if (state.rag.selectedDocId === docId) {
          state.rag.selectedDocId = "";
          state.rag.selectedDoc = null;
          fillRagEditForm(null);
        }
        await loadRagDocs();
      } catch (err) {
        showToast(`删除失败：${err.message}`);
      }
    });
  });
}

function setRagEditDisabled(disabled) {
  [
    "rag_edit_title",
    "rag_edit_attack_type",
    "rag_edit_tags",
    "rag_edit_severity",
    "rag_edit_source",
    "rag_edit_content",
    "rag_edit_evidence",
    "rag_edit_mitigation",
    "rag_edit_reload",
    "rag_edit_save",
  ].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = disabled;
  });
}

function fillRagEditForm(doc) {
  const empty = !doc;
  const values = {
    rag_edit_doc_id: doc?.doc_id || "",
    rag_edit_title: doc?.title || "",
    rag_edit_attack_type: doc?.attack_type || "",
    rag_edit_tags: doc?.tags || "",
    rag_edit_severity: doc?.severity || "medium",
    rag_edit_source: doc?.source || "",
    rag_edit_content: doc?.content || "",
    rag_edit_evidence: doc?.evidence || "",
    rag_edit_mitigation: doc?.mitigation || "",
  };
  Object.entries(values).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) el.value = value;
  });
  setRagEditDisabled(empty);
  const docIdEl = document.getElementById("rag_edit_doc_id");
  if (docIdEl) docIdEl.disabled = true;
  const hint = document.getElementById("rag_edit_hint");
  if (hint) hint.textContent = empty ? "点击上方列表中的任意知识，即可查看完整内容并修改。" : `正在编辑：${doc.doc_id || ""}`;
}

async function loadRagDocDetail(docId) {
  const data = await api(`/api/v2/rag/docs/${encodeURIComponent(docId)}`);
  const doc = data.item || null;
  state.rag.selectedDocId = doc?.doc_id || docId;
  state.rag.selectedDoc = doc;
  fillRagEditForm(doc);
  renderRagTable();
}

async function saveRagDoc() {
  const docId = state.rag.selectedDocId;
  if (!docId) {
    showToast("请先选择一条RAG知识");
    return;
  }
  const payload = {
    title: String(document.getElementById("rag_edit_title")?.value || "").trim(),
    attack_type: String(document.getElementById("rag_edit_attack_type")?.value || "").trim(),
    tags: String(document.getElementById("rag_edit_tags")?.value || "").trim(),
    severity: String(document.getElementById("rag_edit_severity")?.value || "medium").trim().toLowerCase(),
    source: String(document.getElementById("rag_edit_source")?.value || "").trim(),
    content: String(document.getElementById("rag_edit_content")?.value || "").trim(),
    evidence: String(document.getElementById("rag_edit_evidence")?.value || "").trim(),
    mitigation: String(document.getElementById("rag_edit_mitigation")?.value || "").trim(),
  };
  if (!payload.title || !payload.content) {
    showToast("标题和正文内容必填");
    return;
  }
  const data = await api(`/api/v2/rag/docs/${encodeURIComponent(docId)}/update`, { method: "POST", body: payload });
  state.rag.selectedDoc = data.item || { ...payload, doc_id: docId };
  fillRagEditForm(state.rag.selectedDoc);
  showToast("RAG知识已保存");
  await loadRagDocs();
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
          <button id="adm_runtime_check" class="btn btn-warning">一键检查运行环境</button>
          <button id="adm_refresh_models" class="btn btn-primary">刷新模型列表</button>
          <button id="adm_refresh_ifaces" class="btn btn-primary">刷新网卡列表</button>
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
        <div>
          <label>LLM模型(已安装列表)</label>
          <select id="cfg_llm_model"></select>
        </div>
        <div>
          <label>抓包网卡</label>
          <select id="cfg_capture_interface"></select>
        </div>
        <div>
          <label>自定义模型(可选，优先)</label>
          <input id="cfg_llm_model_custom" placeholder="例如 qwen2.5:7b" />
        </div>
        <div>
          <label>形成态势所需动作种类</label>
          <input id="cfg_situation_minimum_actions" type="number" min="3" max="12" />
        </div>
        <div>
          <label>态势关联窗口(分钟)</label>
          <input id="cfg_situation_window_minutes" type="number" min="1" max="1440" />
        </div>
        <div>
          <label>静默切段时间(分钟)</label>
          <input id="cfg_situation_inactivity_minutes" type="number" min="1" max="1440" />
        </div>
        <div>
          <label>扫描判定端口数量</label>
          <input id="cfg_scan_port_threshold" type="number" min="3" max="65535" />
        </div>
        <div>
          <label>扫描聚合窗口(秒)</label>
          <input id="cfg_scan_window_seconds" type="number" min="10" max="3600" />
        </div>
      </div>
      <div class="background-config-card">
        <div id="cfg_home_bg_preview" class="background-preview"></div>
        <div class="background-uploader">
          <div>
            <h4 class="detail-title">主页背景图</h4>
            <p id="cfg_home_bg_current" class="panel-sub">当前背景：/assets/bg-main.jpg</p>
            <p class="panel-sub">支持 JPG、PNG、WebP，建议使用 1920×1080 或更高分辨率，上传后登录页和数据大屏背景会立即更新。</p>
          </div>
          <input id="cfg_home_background_file" class="file-input" type="file" accept="image/jpeg,image/png,image/webp" />
          <div class="ops-group">
            <button id="adm_bg_upload" class="btn btn-primary">上传并应用背景图</button>
            <button id="adm_bg_reset" class="btn btn-ghost">恢复默认背景</button>
          </div>
        </div>
      </div>
      <div class="background-config-card llm-judgement-config">
        <div class="config-switch-copy">
          <h4 class="detail-title">大模型实时研判</h4>
          <p class="panel-sub">开启后，所有候选事件都进入本地大模型完成最终研判；关闭后，系统使用多模型融合结果，并可复用 4000 靶场中完全一致请求的历史研判。</p>
        </div>
        <label class="config-toggle" for="cfg_llm_realtime_enabled">
          <input id="cfg_llm_realtime_enabled" type="checkbox" />
          <span class="config-toggle-track"><span></span></span>
          <b id="cfg_llm_realtime_label">已开启</b>
        </label>
      </div>
      <div class="row-actions">
        <button id="adm_cfg_save" class="btn btn-primary">保存全局配置</button>
      </div>
      <div id="adm_runtime_result" class="panel-sub" style="margin-top:10px;white-space:pre-wrap;"></div>
    </section>
  `;
  document.getElementById("adm_runtime_check")?.addEventListener("click", () => runAdminRuntimeCheck());
  document.getElementById("adm_refresh_models")?.addEventListener("click", () => refreshAdminModelOptions());
  document.getElementById("adm_refresh_ifaces")?.addEventListener("click", () => refreshAdminCaptureInterfaces());
  document.getElementById("adm_cfg_refresh")?.addEventListener("click", () => loadAdminConfig());
  document.getElementById("adm_cfg_save")?.addEventListener("click", () => saveAdminConfig());
  document.getElementById("adm_export_report")?.addEventListener("click", () => exportAdminReport());
  document.getElementById("adm_bg_upload")?.addEventListener("click", () => uploadAdminHomepageBackground());
  document.getElementById("adm_bg_reset")?.addEventListener("click", () => resetAdminHomepageBackground());
  document.getElementById("cfg_llm_realtime_enabled")?.addEventListener("change", updateRealtimeLlmLabel);
  loadAdminConfig()
    .then(async () => {
      await refreshAdminModelOptions(undefined, true);
      await refreshAdminCaptureInterfaces(undefined, true);
    })
    .catch((err) => showToast(`加载配置失败：${err.message}`));
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
  setInputValue("cfg_llm_model_custom", "");
  setInputValue("cfg_capture_interface", map.capture_interface || "auto");
  setInputValue("cfg_situation_minimum_actions", map.situation_minimum_actions || "3");
  setInputValue("cfg_situation_window_minutes", map.situation_window_minutes || "30");
  setInputValue("cfg_situation_inactivity_minutes", map.situation_inactivity_minutes || "15");
  setInputValue("cfg_scan_port_threshold", map.scan_port_threshold || "10");
  setInputValue("cfg_scan_window_seconds", map.scan_window_seconds || "60");
  const realtimeToggle = document.getElementById("cfg_llm_realtime_enabled");
  if (realtimeToggle) realtimeToggle.checked = String(map.llm_realtime_enabled || "1") === "1";
  updateRealtimeLlmLabel();
  applyHomepageBackground(map.homepage_background_url || "/assets/bg-main.jpg");
}

async function saveAdminConfig() {
  const selectedModel = String(document.getElementById("cfg_llm_model")?.value || "").trim();
  const customModel = String(document.getElementById("cfg_llm_model_custom")?.value || "").trim();
  const finalModel = customModel || selectedModel || state.admin.config?.llm_model || "qwen3:8b";
  const payload = {
    alert_threshold_high: String(document.getElementById("cfg_alert_threshold_high")?.value || "10"),
    auto_refresh_seconds: String(document.getElementById("cfg_auto_refresh_seconds")?.value || "5"),
    sound_alert_enabled: String(document.getElementById("cfg_sound_alert_enabled")?.value || "1"),
    capture_batch_size: String(document.getElementById("cfg_capture_batch_size")?.value || "4"),
    monitor_ports: String(document.getElementById("cfg_monitor_ports")?.value || "80,443,8080"),
    capture_interface: String(document.getElementById("cfg_capture_interface")?.value || "auto"),
    llm_model: finalModel,
    situation_minimum_actions: String(document.getElementById("cfg_situation_minimum_actions")?.value || "3"),
    situation_window_minutes: String(document.getElementById("cfg_situation_window_minutes")?.value || "30"),
    situation_inactivity_minutes: String(document.getElementById("cfg_situation_inactivity_minutes")?.value || "15"),
    scan_port_threshold: String(document.getElementById("cfg_scan_port_threshold")?.value || "10"),
    scan_window_seconds: String(document.getElementById("cfg_scan_window_seconds")?.value || "60"),
    llm_realtime_enabled: document.getElementById("cfg_llm_realtime_enabled")?.checked ? "1" : "0",
  };
  await api("/api/v2/admin/config", { method: "PUT", body: payload });
  showToast("配置保存成功");
  await loadAdminConfig();
  await refreshAdminModelOptions(finalModel, true);
  await refreshAdminCaptureInterfaces(payload.capture_interface, true);
}

function updateRealtimeLlmLabel() {
  const enabled = Boolean(document.getElementById("cfg_llm_realtime_enabled")?.checked);
  const label = document.getElementById("cfg_llm_realtime_label");
  if (label) label.textContent = enabled ? "已开启" : "已关闭";
}

async function uploadAdminHomepageBackground() {
  const input = document.getElementById("cfg_home_background_file");
  const file = input?.files?.[0];
  if (!file) {
    showToast("请先选择一张背景图片");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    showToast("图片过大，请选择 10MB 以内的文件");
    return;
  }
  const form = new FormData();
  form.append("file", file);
  const data = await apiForm("/api/v2/admin/home-background", form);
  applyHomepageBackground(data.url || "/assets/bg-main.jpg");
  if (input) input.value = "";
  showToast("主页背景图已更新");
  await loadAdminConfig();
}

async function resetAdminHomepageBackground() {
  await api("/api/v2/admin/config", { method: "PUT", body: { homepage_background_url: "/assets/bg-main.jpg" } });
  applyHomepageBackground("/assets/bg-main.jpg");
  showToast("已恢复默认背景");
  await loadAdminConfig();
}

async function refreshAdminModelOptions(preferModel, silent = false) {
  const selectEl = document.getElementById("cfg_llm_model");
  if (!selectEl) return;
  const data = await api("/api/v2/admin/ollama/models");
  const items = Array.isArray(data.items) ? data.items : [];
  state.admin.modelCandidates = items.map((x) => String(x.name || "").trim()).filter(Boolean);
  const currentModel = String(preferModel || state.admin.config?.llm_model || data.current_model || "qwen3:8b").trim();
  const merged = Array.from(new Set([...state.admin.modelCandidates, currentModel])).filter(Boolean);
  selectEl.innerHTML = merged.map((m) => `<option value="${escapeHtml(m)}">${escapeHtml(m)}</option>`).join("");
  selectEl.value = currentModel;
  const custom = document.getElementById("cfg_llm_model_custom");
  if (custom) custom.value = "";
  if (!data.ok && !silent) {
    showToast(`模型列表读取失败：${data.error || "Ollama服务不可用"}`);
  } else if (!silent) {
    showToast(`模型列表已刷新，共 ${items.length} 个`);
  }
}

async function refreshAdminCaptureInterfaces(preferIface, silent = false) {
  const selectEl = document.getElementById("cfg_capture_interface");
  if (!selectEl) return;
  const data = await api("/api/v2/admin/capture-interfaces");
  const items = Array.isArray(data.items) ? data.items : [];
  state.admin.captureInterfaces = items;

  const currentIface = String(preferIface || state.admin.config?.capture_interface || data.configured_interface || "auto").trim() || "auto";
  const options = [{ value: "auto", label: "自动选择（推荐）" }];
  items.forEach((x) => {
    const idx = String(x.index || "").trim();
    const name = String(x.name || "").trim();
    if (!idx) return;
    options.push({ value: idx, label: `${idx}. ${name || "未知网卡"}` });
  });
  if (!options.some((x) => x.value === currentIface)) {
    options.push({ value: currentIface, label: `${currentIface}（当前配置）` });
  }
  selectEl.innerHTML = options
    .map((x) => `<option value="${escapeHtml(x.value)}">${escapeHtml(x.label)}</option>`)
    .join("");
  selectEl.value = currentIface;

  if (!data.ok && !silent) {
    showToast(`网卡列表读取失败：${data.error || "tshark不可用"}`);
  } else if (!silent) {
    showToast(`网卡列表已刷新，共 ${items.length} 个`);
  }
}

async function runAdminRuntimeCheck() {
  const box = document.getElementById("adm_runtime_result");
  if (box) box.textContent = "正在检查运行环境，请稍候...";
  const data = await api("/api/v2/admin/runtime-check");
  state.admin.runtimeCheck = data;
  const lines = [];
  lines.push(`整体状态：${data.overall || "-"}（错误 ${data.errors || 0}，警告 ${data.warnings || 0}）`);
  lines.push(`当前模型：${data.selected_model || "-"}`);
  lines.push(`Ollama地址：${data.ollama_url || "-"}`);
  const checks = Array.isArray(data.checks) ? data.checks : [];
  checks.forEach((x) => {
    lines.push(`- [${x.status}] ${x.name}: ${x.message}${x.detail ? ` | ${x.detail}` : ""}`);
  });
  if (box) box.textContent = lines.join("\n");
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
    <section class="user-center-shell">
      <div class="panel user-profile-card account-identity-card">
        <div class="account-cover"></div>
        <div class="user-profile-hero">
          ${renderUserAvatar(state.profile, "avatar-xl account-avatar")}
          <div>
            <p class="panel-sub">当前账号</p>
            <h3>${escapeHtml(getProfileName(state.profile))}</h3>
            <span class="role-chip">${escapeHtml(ROLE_LABEL[state.profile?.role] || state.profile?.role || "-")}</span>
          </div>
        </div>
        <div class="profile-meta-grid">
          <div>
            <span>登录账号</span>
            <strong>${escapeHtml(state.profile?.username || "-")}</strong>
          </div>
          <div>
            <span>会话有效期</span>
            <strong>${escapeHtml(state.profile?.expires_at || "-")}</strong>
          </div>
        </div>
        <div class="account-mini-metrics">
          <article><b>JWT</b><span>Cookie 持久会话</span></article>
          <article><b>RBAC</b><span>普通用户 / 管理员</span></article>
          <article><b>Avatar</b><span>支持头像与昵称</span></article>
        </div>
      </div>

      <div class="panel user-profile-card account-edit-card">
        <div class="panel-head">
          <div>
            <p class="panel-sub">Profile</p>
            <h3 class="panel-title">个人资料</h3>
          </div>
          <span class="role-chip">实时保存</span>
        </div>
        <div class="detail-grid profile-form-grid">
          <div><label class="panel-sub">显示名称</label><input id="uc_display_name" value="${escapeHtml(state.profile?.display_name || "")}" maxlength="64" /></div>
          <div><label class="panel-sub">昵称</label><input id="uc_nickname" value="${escapeHtml(state.profile?.nickname || state.profile?.display_name || "")}" maxlength="64" /></div>
          <div class="grid-wide"><label class="panel-sub">头像链接</label><input id="uc_avatar_url" value="${escapeHtml(state.profile?.avatar_url || "")}" placeholder="/uploads/avatars/xxx.png 或 https://..." /></div>
          <div class="grid-wide avatar-upload-row">
            <input id="uc_avatar_file" type="file" accept="image/png,image/jpeg,image/webp" />
            <button id="uc_upload_avatar" class="btn btn-ghost">上传头像</button>
          </div>
        </div>
        <div class="row-actions">
          <button id="uc_save_profile" class="btn btn-primary">保存个人资料</button>
        </div>
      </div>

      <div class="panel user-security-card">
        <div class="panel-head">
          <div>
            <h3 class="panel-title">账号安全</h3>
            <p class="panel-sub">建议定期更新密码，避免测试账号长期暴露。</p>
          </div>
          <span class="security-chip">Protected</span>
        </div>
        <div class="detail-grid">
          <div class="grid-wide"><label class="panel-sub">旧密码</label><input id="uc_old_password" type="password" autocomplete="current-password" /></div>
          <div><label class="panel-sub">新密码</label><input id="uc_new_password" type="password" autocomplete="new-password" /></div>
          <div><label class="panel-sub">确认新密码</label><input id="uc_confirm_password" type="password" autocomplete="new-password" /></div>
        </div>
        <div class="row-actions">
          <button id="uc_save_password" class="btn btn-warning">修改密码</button>
        </div>
      </div>
    </section>
  `;
  document.getElementById("uc_save_profile")?.addEventListener("click", () => updateSelfProfile());
  document.getElementById("uc_upload_avatar")?.addEventListener("click", () => uploadSelfAvatar());
  document.getElementById("uc_save_password")?.addEventListener("click", () => updateSelfPassword());
}

async function updateSelfProfile() {
  const displayName = String(document.getElementById("uc_display_name")?.value || "").trim();
  const nickname = String(document.getElementById("uc_nickname")?.value || "").trim();
  const avatarUrl = String(document.getElementById("uc_avatar_url")?.value || "").trim();
  if (!displayName || !nickname) {
    showToast("显示名称和昵称不能为空");
    return;
  }
  await api("/api/v2/auth/profile", {
    method: "PUT",
    body: { display_name: displayName, nickname, avatar_url: avatarUrl },
  });
  state.profile = await api("/api/v2/auth/profile");
  refreshHeaderProfile();
  renderUserCenterView();
  showToast("个人资料已保存");
}

async function uploadSelfAvatar() {
  const input = document.getElementById("uc_avatar_file");
  const file = input?.files?.[0];
  if (!file) {
    showToast("请先选择头像图片");
    return;
  }
  if (file.size > 2 * 1024 * 1024) {
    showToast("头像图片不能超过 2MB");
    return;
  }
  const form = new FormData();
  form.append("avatar", file);
  const resp = await apiForm("/api/v2/auth/avatar", form);
  setInputValue("uc_avatar_url", resp.avatar_url || "");
  state.profile = await api("/api/v2/auth/profile");
  refreshHeaderProfile();
  renderUserCenterView();
  showToast("头像上传成功");
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
    <section class="panel admin-users-hero admin-users-console">
      <div>
        <p class="panel-sub">账号与权限</p>
        <h3 class="panel-title">用户管理</h3>
        <p class="panel-sub">集中维护用户资料、头像、角色和密码。管理员可以设置其他用户的角色。</p>
      </div>
      <div class="admin-users-actions">
        <span id="adm_users_summary" class="admin-users-summary">正在同步用户状态...</span>
        <button id="adm_users_refresh" class="btn btn-success">刷新用户</button>
      </div>
    </section>
    <section class="admin-user-list" id="adm_users_body"></section>
  `;
  document.getElementById("adm_users_refresh")?.addEventListener("click", () => loadAdminUsers());
  loadAdminUsers().catch((err) => showToast(`\u52a0\u8f7d\u7528\u6237\u5931\u8d25\uff1a${err.message}`));
}

function renderAdminUserCard(user) {
  const username = String(user.username || "");
  const isSelf = username === state.profile?.username;
  const roleLabel = ROLE_LABEL[user.role] || user.role || "-";
  return `
    <article class="panel admin-user-card admin-user-row" data-admin-user="${escapeHtml(username)}">
      <div class="admin-user-top">
        ${renderUserAvatar(user, "avatar-lg")}
        <div class="admin-user-title">
          <strong>${escapeHtml(user.nickname || user.display_name || username || "-")}</strong>
          <span>@${escapeHtml(username || "-")}</span>
          <em>${escapeHtml(roleLabel)}</em>
        </div>
        <div class="admin-user-role-cell">
          <label class="panel-sub">角色</label>
          <select data-field="role" ${isSelf ? "disabled" : ""}>
            <option value="${ROLE_NORMAL}" ${user.role === ROLE_NORMAL ? "selected" : ""}>普通用户</option>
            <option value="${ROLE_ADMIN}" ${user.role === ROLE_ADMIN ? "selected" : ""}>管理员</option>
          </select>
          ${isSelf ? `<span class="panel-sub">当前账号不可自降权</span>` : ""}
        </div>
      </div>
      <div class="profile-meta-grid compact">
        <div><span>用户ID</span><strong>${escapeHtml(String(user.id || "-"))}</strong></div>
        <div><span>更新时间</span><strong>${escapeHtml(user.updated_at || "-")}</strong></div>
      </div>
      <div class="detail-grid profile-form-grid">
        <div><label class="panel-sub">显示名称</label><input data-field="display_name" value="${escapeHtml(user.display_name || "")}" maxlength="64" /></div>
        <div><label class="panel-sub">昵称</label><input data-field="nickname" value="${escapeHtml(user.nickname || user.display_name || "")}" maxlength="64" /></div>
        <div class="grid-wide"><label class="panel-sub">头像链接</label><input data-field="avatar_url" value="${escapeHtml(user.avatar_url || "")}" placeholder="/uploads/avatars/xxx.png 或 https://..." /></div>
        <div class="grid-wide inline-pass-reset">
          <input type="password" data-field="new_password" placeholder="输入新密码后可重置" class="input-sm" />
          <button class="btn btn-danger" data-adm-user-pass-save>重置密码</button>
        </div>
      </div>
      <div class="row-actions">
        <button class="btn btn-primary" data-adm-user-profile-save>保存资料</button>
      </div>
    </article>
  `;
}

async function loadAdminUsers() {
  const data = await api("/api/v2/admin/users");
  state.admin.users = Array.isArray(data.items) ? data.items : [];
  const body = document.getElementById("adm_users_body");
  const summary = document.getElementById("adm_users_summary");
  if (summary) {
    const adminCount = state.admin.users.filter((x) => x.role === ROLE_ADMIN).length;
    const normalCount = state.admin.users.filter((x) => x.role !== ROLE_ADMIN).length;
    summary.textContent = `共 ${state.admin.users.length} 个账号 · 管理员 ${adminCount} · 普通用户 ${normalCount}`;
  }
  if (!body) return;
  if (!state.admin.users.length) {
    body.innerHTML = `<section class="panel empty-state">暂无用户</section>`;
    return;
  }
  body.innerHTML = state.admin.users.map((x) => renderAdminUserCard(x)).join("");
  body.querySelectorAll("[data-adm-user-profile-save]").forEach((el) => {
    el.addEventListener("click", async () => {
      await updateAdminUserProfile(el.closest(".admin-user-card"));
    });
  });
  body.querySelectorAll("[data-adm-user-pass-save]").forEach((el) => {
    el.addEventListener("click", async () => {
      const card = el.closest(".admin-user-card");
      const username = String(card?.getAttribute("data-admin-user") || "");
      const input = card?.querySelector('[data-field="new_password"]');
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

async function updateAdminUserProfile(card) {
  const username = String(card?.getAttribute("data-admin-user") || "");
  if (!username) return;
  const displayName = String(card?.querySelector('[data-field="display_name"]')?.value || "").trim();
  const nickname = String(card?.querySelector('[data-field="nickname"]')?.value || "").trim();
  const avatarUrl = String(card?.querySelector('[data-field="avatar_url"]')?.value || "").trim();
  const role = String(card?.querySelector('[data-field="role"]')?.value || "").trim();
  if (!displayName || !nickname) {
    showToast("显示名称和昵称不能为空");
    return;
  }
  await api(`/api/v2/admin/users/${encodeURIComponent(username)}/profile`, {
    method: "PUT",
    body: { display_name: displayName, nickname, avatar_url: avatarUrl, role },
  });
  if (username === state.profile?.username) {
    state.profile = await api("/api/v2/auth/profile");
    refreshHeaderProfile();
  }
  await loadAdminUsers();
  showToast(`已保存 ${username} 的资料`);
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
          lineStyle: { width: 2.4, color: "#2ca7ff" },
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
          lineStyle: { width: 2, color: "#16d88b" },
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
        splitLine: { lineStyle: { color: "rgba(130,180,225,.18)" } },
      },
      series: [
        {
          type: "bar",
          data: vals.map((v, idx) => ({
            value: v,
            itemStyle: {
              color:
                idx < 3
                  ? new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
                      { offset: 0, color: ["#ff4965", "#ff6a5c", "#ff8a47"][idx] || "#ff4965" },
                      { offset: 1, color: ["#ff8547", "#ff9b4a", "#ffad53"][idx] || "#ff8547" },
                    ])
                  : new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
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
  const data = (Array.isArray(rows) ? rows : [])
    .slice()
    .sort((a, b) => Number(b[valueKey] || 0) - Number(a[valueKey] || 0))
    .slice(0, 7)
    .map((x) => ({
      name: labelKey === "source_region" ? formatSourceRegionLabel(x[labelKey]) : String(x[labelKey] || "-"),
      value: Number(x[valueKey] || 0),
    }));
  chart.setOption(
    {
      backgroundColor: "transparent",
      animationDuration: 650,
      tooltip: { trigger: "item" },
      legend: { show: false },
      series: [
        {
          type: "pie",
          radius: ["38%", "66%"],
          center: ["50%", "52%"],
          data,
          avoidLabelOverlap: true,
          label: {
            show: true,
            position: "outside",
            color: "#f4fbff",
            fontSize: 12,
            fontWeight: 600,
            formatter: "{b}",
          },
          emphasis: {
            scale: true,
            scaleSize: 8,
            label: {
              show: true,
              color: "#eaf7ff",
              fontSize: 12,
              formatter: "{b}\n{d}%",
            },
          },
          labelLine: {
            show: true,
            length: 16,
            length2: 10,
            lineStyle: { color: "rgba(244,251,255,0.88)", width: 1.2 },
          },
          labelLayout: { hideOverlap: true, moveOverlap: "shiftY" },
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
  if (level === "critical" || level === "high") return `<span class="badge badge-high">${safe}</span>`;
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
    xxe: "XXE外部实体",
    ssti: "SSTI模板注入",
    deserialization: "反序列化",
    "dangerous file upload": "危险文件上传",
    dangerous_file_upload: "危险文件上传",
    "graphql introspection": "GraphQL探测",
    graphql: "GraphQL探测",
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

async function apiForm(path, formData) {
  const headers = {
    Accept: "application/json",
  };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const resp = await fetch(path, {
    method: "POST",
    headers,
    body: formData,
    credentials: "same-origin",
  });
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
    if (obj.message) return String(obj.message);
    if (obj.detail) return String(obj.detail);
    if (obj.error && obj.status) return `${obj.error} (${obj.status})`;
    return obj.error || `HTTP ${status}`;
  } catch {
    return `HTTP ${status}`;
  }
}

function formatDateTime(dt, withMs = true) {
  const d = dt instanceof Date ? dt : new Date(dt);
  if (Number.isNaN(d.getTime())) return "-";
  const base = d.toLocaleString("zh-CN", { hour12: false, timeZone: "Asia/Shanghai" });
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

/* Advanced RAG workspace. This intentionally overrides the legacy crowded
 * renderer while keeping its API and data untouched for rollback safety. */
function rag3State() {
  if (!state.rag.workspace) {
    state.rag.workspace = {
      status: null,
      kbs: [],
      query: "",
      selectedKb: null,
      detailTab: "documents",
      documents: [],
      chunks: [],
      recallItems: [],
      recallHistory: [],
      evalCases: [],
      evalRuns: [],
      evalResult: null,
      busy: false,
    };
  }
  return state.rag.workspace;
}

function rag3Date(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", { hour12: false });
}

function rag3StatusLabel(status) {
  const map = { ready: "已就绪", processing: "处理中", pending: "待索引", failed: "失败" };
  return map[String(status || "").toLowerCase()] || String(status || "未知");
}

function renderRagSettingsView() {
  const root = document.getElementById("viewRoot");
  if (!root) return;
  const workspace = rag3State();
  const activePanel = state.llmSettings.activePanel || "rag";
  root.innerHTML = `
    <section class="ai-config-shell">
      <header class="ai-config-header">
        <div>
          <span class="section-eyebrow">AI CONFIGURATION</span>
          <h2>大模型配置</h2>
          <p>管理研判提示词与检索增强知识。云端 API 仅承担向量化和重排，攻击报告仍由现有本地模型生成。</p>
        </div>
        <div class="ops-group">
          <label class="rag3-toggle" title="关闭后停止向量化、召回、重排和 RAG 上下文注入">
            <input id="rag3_master_enabled" type="checkbox" />
            <span>启用 RAG</span>
          </label>
          <div class="ai-config-health" id="rag3_health">
            <i></i><span>正在检查 RAG 服务</span>
          </div>
        </div>
      </header>
      <nav class="ai-config-tabs" aria-label="AI 配置分类">
        <button class="${activePanel === "rag" ? "active" : ""}" data-ai-panel="rag">知识库管理</button>
        <button class="${activePanel === "prompt" ? "active" : ""}" data-ai-panel="prompt">研判提示词</button>
        <button class="${activePanel === "report_prompt" ? "active" : ""}" data-ai-panel="report_prompt">专业报告提示词</button>
      </nav>
      <div id="ai_config_content"></div>
    </section>
    <div id="rag3_modal_root"></div>
  `;
  root.querySelectorAll("[data-ai-panel]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = String(button.dataset.aiPanel || "rag");
      state.llmSettings.activePanel = ["prompt", "report_prompt"].includes(target) ? target : "rag";
      renderRagSettingsView();
    });
  });
  document.getElementById("rag3_master_enabled")?.addEventListener("change", async (event) => {
    const input = event.currentTarget;
    input.disabled = true;
    try {
      const result = await api("/api/v3/rag/enabled", { method: "PUT", body: { enabled: input.checked } });
      showToast(result.enabled ? "RAG 已开启，研判进程将自动启用检索增强" : "RAG 已关闭，不再调用云端向量与重排 API");
      await rag3LoadStatus();
    } catch (err) {
      input.checked = !input.checked;
      showToast(`RAG 开关保存失败：${err.message}`);
    } finally {
      input.disabled = false;
    }
  });
  if (activePanel === "prompt") {
    rag3RenderPrompt();
  } else if (activePanel === "report_prompt") {
    rag3RenderProfessionalReportPrompt();
  } else {
    rag3RenderKbList();
  }
  rag3LoadStatus().catch((err) => rag3SetHealth(false, err.message));
}

function rag3SetHealth(ok, message) {
  const el = document.getElementById("rag3_health");
  if (!el) return;
  el.classList.toggle("error", !ok);
  const text = el.querySelector("span");
  if (text) text.textContent = message;
}

async function rag3LoadStatus() {
  const workspace = rag3State();
  workspace.status = await api("/api/v3/rag/status");
  const toggle = document.getElementById("rag3_master_enabled");
  if (toggle) toggle.checked = workspace.status.enabled !== false;
  rag3SetHealth(
    workspace.status.enabled === false || workspace.status.cloud_configured,
    workspace.status.enabled === false
      ? "RAG 已关闭 · 不产生云端检索费用"
      : workspace.status.cloud_configured
      ? `${workspace.status.embedding_model} · ${workspace.status.rerank_model}`
      : "云端向量 API 尚未配置"
  );
  rag3UpdateStats();
}

function rag3UpdateStats() {
  const status = rag3State().status;
  if (!status) return;
  const fields = {
    rag3_stat_kb: status.knowledge_base_count,
    rag3_stat_doc: status.document_count,
    rag3_stat_chunk: status.chunk_count,
  };
  Object.entries(fields).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value || 0);
  });
}

function rag3RenderPrompt() {
  const content = document.getElementById("ai_config_content");
  if (!content) return;
  content.innerHTML = `
    <section class="ai-prompt-workspace">
      <div class="ai-prompt-copy">
        <span class="section-eyebrow">SYSTEM PROMPT</span>
        <h3>态势研判提示词</h3>
        <p>控制攻击类型、判定依据、风险等级和处置建议的输出口径。修改只影响后续新任务，不会改写历史报告。</p>
        <dl>
          <div><dt>提示词文件</dt><dd id="llm_prompt_path">-</dd></div>
          <div><dt>最后更新</dt><dd id="llm_prompt_updated">-</dd></div>
          <div><dt>字符数量</dt><dd id="llm_prompt_chars">0</dd></div>
        </dl>
      </div>
      <div class="ai-prompt-editor-card">
        <textarea id="llm_prompt_editor" rows="22" spellcheck="false" placeholder="正在读取提示词..."></textarea>
        <footer>
          <button id="llm_prompt_reload" class="btn btn-ghost">重新读取</button>
          <button id="llm_prompt_save" class="btn btn-primary">保存提示词</button>
        </footer>
      </div>
    </section>
  `;
  document.getElementById("llm_prompt_reload")?.addEventListener("click", () => loadLlmPrompt().catch((err) => showToast(err.message)));
  document.getElementById("llm_prompt_save")?.addEventListener("click", () => saveLlmPrompt().catch((err) => showToast(err.message)));
  document.getElementById("llm_prompt_editor")?.addEventListener("input", (event) => {
    const el = document.getElementById("llm_prompt_chars");
    if (el) el.textContent = `${event.target.value.length} / ${state.llmSettings.promptMaxChars || 30000}`;
  });
  loadLlmPrompt().catch((err) => showToast(`读取提示词失败：${err.message}`));
}

function rag3RenderProfessionalReportPrompt() {
  const content = document.getElementById("ai_config_content");
  if (!content) return;
  content.innerHTML = `
    <section class="ai-prompt-workspace">
      <div class="ai-prompt-copy">
        <span class="section-eyebrow">REPORT PROMPT</span>
        <h3>专业态势报告提示词</h3>
        <p>控制专业 PDF 报告的章节、证据边界、分析深度和整改建议。保存后，下一次外部 API 生成任务会立即使用最新版本。</p>
        <dl>
          <div><dt>提示词文件</dt><dd id="report_prompt_path">-</dd></div>
          <div><dt>最后更新</dt><dd id="report_prompt_updated">-</dd></div>
          <div><dt>字符数量</dt><dd id="report_prompt_chars">0</dd></div>
        </dl>
      </div>
      <div class="ai-prompt-editor-card">
        <textarea id="report_prompt_editor" rows="22" spellcheck="false" placeholder="正在读取专业报告提示词..."></textarea>
        <footer>
          <button id="report_prompt_reload" class="btn btn-ghost">重新读取</button>
          <button id="report_prompt_save" class="btn btn-primary">保存提示词</button>
        </footer>
      </div>
    </section>`;
  document.getElementById("report_prompt_reload")?.addEventListener("click", () => loadProfessionalReportPrompt().catch((err) => showToast(err.message)));
  document.getElementById("report_prompt_save")?.addEventListener("click", () => saveProfessionalReportPrompt().catch((err) => showToast(err.message)));
  document.getElementById("report_prompt_editor")?.addEventListener("input", (event) => {
    const el = document.getElementById("report_prompt_chars");
    if (el) el.textContent = `${event.target.value.length} / ${state.llmSettings.reportPromptMaxChars || 60000}`;
  });
  loadProfessionalReportPrompt().catch((err) => showToast(`读取专业报告提示词失败：${err.message}`));
}

async function loadProfessionalReportPrompt() {
  const data = await api("/api/v2/llm/professional-report-prompt");
  state.llmSettings.reportPrompt = String(data.prompt || "");
  state.llmSettings.reportPromptPath = String(data.path || "-");
  state.llmSettings.reportPromptUpdatedAt = String(data.updated_at || "-");
  state.llmSettings.reportPromptMaxChars = Number(data.max_chars || 60000);
  const editor = document.getElementById("report_prompt_editor");
  if (editor) editor.value = state.llmSettings.reportPrompt;
  const path = document.getElementById("report_prompt_path");
  const updated = document.getElementById("report_prompt_updated");
  const chars = document.getElementById("report_prompt_chars");
  if (path) path.textContent = state.llmSettings.reportPromptPath;
  if (updated) updated.textContent = state.llmSettings.reportPromptUpdatedAt;
  if (chars) chars.textContent = `${state.llmSettings.reportPrompt.length} / ${state.llmSettings.reportPromptMaxChars}`;
}

async function saveProfessionalReportPrompt() {
  const prompt = String(document.getElementById("report_prompt_editor")?.value || "");
  if (!prompt.trim()) return showToast("专业报告提示词不能为空");
  const button = document.getElementById("report_prompt_save");
  if (button) button.disabled = true;
  try {
    await api("/api/v2/llm/professional-report-prompt", { method: "PUT", body: { prompt } });
    await loadProfessionalReportPrompt();
    showToast("专业报告提示词已保存，后续生成任务将使用新版本");
  } finally {
    if (button) button.disabled = false;
  }
}

function rag3RenderKbList() {
  const content = document.getElementById("ai_config_content");
  if (!content) return;
  content.innerHTML = `
    <section class="rag3-overview-strip">
      <div><span>知识库</span><strong id="rag3_stat_kb">0</strong><small>独立检索空间</small></div>
      <div><span>知识文档</span><strong id="rag3_stat_doc">0</strong><small>可追溯来源</small></div>
      <div><span>有效切片</span><strong id="rag3_stat_chunk">0</strong><small>向量与关键词双索引</small></div>
      <div class="rag3-pipeline"><span>检索链路</span><strong>Vector + BM25 → RRF → Rerank</strong><small>阿里云百炼向量与重排</small></div>
    </section>
    <section class="rag3-list-card">
      <header>
        <div>
          <h3>AI 知识库</h3>
          <p>知识库之间相互隔离，可分别配置切片与召回参数。</p>
        </div>
        <div class="rag3-toolbar">
          <label class="rag3-search"><span>⌕</span><input id="rag3_kb_search" placeholder="搜索知识库名称" /></label>
          <label class="rag3-toggle"><input id="rag3_show_disabled" type="checkbox" checked /><span>显示停用</span></label>
          <button id="rag3_refresh" class="btn btn-ghost">刷新</button>
          <button id="rag3_create" class="btn btn-primary">新建知识库</button>
        </div>
      </header>
      <div class="rag3-table-wrap">
        <table class="rag3-table">
          <thead><tr><th>名称</th><th>文档</th><th>切片</th><th>状态</th><th>向量模型</th><th>切片方式</th><th>创建人</th><th>最后修改</th><th>操作</th></tr></thead>
          <tbody id="rag3_kb_body"><tr><td colspan="9" class="rag3-empty">正在加载知识库...</td></tr></tbody>
        </table>
      </div>
      <footer class="rag3-list-footer"><span id="rag3_kb_total">共 0 个知识库</span><small>点击知识库名称进入文档、切片和召回工作台</small></footer>
    </section>
  `;
  document.getElementById("rag3_create")?.addEventListener("click", () => rag3OpenKbModal());
  document.getElementById("rag3_refresh")?.addEventListener("click", () => rag3LoadKbs().catch((err) => showToast(err.message)));
  document.getElementById("rag3_kb_search")?.addEventListener("input", (event) => {
    rag3State().query = event.target.value;
    clearTimeout(rag3State().searchTimer);
    rag3State().searchTimer = setTimeout(() => rag3LoadKbs().catch((err) => showToast(err.message)), 260);
  });
  document.getElementById("rag3_show_disabled")?.addEventListener("change", () => rag3LoadKbs().catch((err) => showToast(err.message)));
  rag3LoadKbs().catch((err) => showToast(`知识库加载失败：${err.message}`));
  rag3UpdateStats();
}

async function rag3LoadKbs() {
  const workspace = rag3State();
  const query = String(document.getElementById("rag3_kb_search")?.value ?? workspace.query ?? "").trim();
  const includeDisabled = document.getElementById("rag3_show_disabled")?.checked !== false;
  const params = new URLSearchParams({ q: query, include_disabled: includeDisabled ? "1" : "0" });
  const data = await api(`/api/v3/rag/knowledge-bases?${params}`);
  workspace.kbs = Array.isArray(data.items) ? data.items : [];
  rag3RenderKbRows();
  await rag3LoadStatus();
}

function rag3RenderKbRows() {
  const workspace = rag3State();
  const body = document.getElementById("rag3_kb_body");
  const total = document.getElementById("rag3_kb_total");
  if (total) total.textContent = `共 ${workspace.kbs.length} 个知识库`;
  if (!body) return;
  if (!workspace.kbs.length) {
    body.innerHTML = `<tr><td colspan="9"><div class="rag3-empty-state"><b>尚无匹配的知识库</b><span>新建知识库后即可上传安全文档并执行召回测试。</span></div></td></tr>`;
    return;
  }
  body.innerHTML = workspace.kbs.map((kb) => `
    <tr>
      <td><button class="rag3-kb-name" data-rag3-open="${kb.id}"><i>▰</i><span><strong>${escapeHtml(kb.name)}</strong><small>${escapeHtml(kb.description || "未填写描述")}</small></span></button></td>
      <td><b>${Number(kb.document_count || 0)}</b></td>
      <td><b>${Number(kb.chunk_count || 0)}</b></td>
      <td><span class="rag3-status ${kb.enabled ? "ready" : "disabled"}">${kb.enabled ? "启用" : "停用"}</span></td>
      <td>${escapeHtml(kb.embedding_model || "-")}</td>
      <td>${kb.chunk_method === "fixed" ? "固定长度" : "语义结构"}</td>
      <td>${escapeHtml(kb.created_by || "-")}</td>
      <td>${escapeHtml(rag3Date(kb.updated_at))}</td>
      <td><button class="rag3-more" data-rag3-more="${kb.id}" aria-label="知识库操作">•••</button></td>
    </tr>
  `).join("");
  body.querySelectorAll("[data-rag3-open]").forEach((button) => button.addEventListener("click", () => rag3OpenWorkspace(Number(button.dataset.rag3Open))));
  body.querySelectorAll("[data-rag3-more]").forEach((button) => button.addEventListener("click", (event) => rag3OpenActionMenu(event, Number(button.dataset.rag3More))));
}

function rag3OpenActionMenu(event, kbId) {
  event.stopPropagation();
  document.querySelectorAll(".rag3-action-menu").forEach((el) => el.remove());
  const kb = rag3State().kbs.find((item) => Number(item.id) === kbId);
  if (!kb) return;
  const menu = document.createElement("div");
  menu.className = "rag3-action-menu";
  menu.innerHTML = `
    <button data-action="open">进入工作台</button>
    <button data-action="edit">编辑配置</button>
    <button data-action="toggle">${kb.enabled ? "停用" : "启用"}</button>
    <button data-action="recall">召回测试</button>
    <button data-action="delete" class="danger">删除知识库</button>
  `;
  event.currentTarget.parentElement.appendChild(menu);
  menu.querySelectorAll("button").forEach((button) => button.addEventListener("click", async () => {
    menu.remove();
    if (button.dataset.action === "open") return rag3OpenWorkspace(kbId);
    if (button.dataset.action === "edit") return rag3OpenKbModal(kb);
    if (button.dataset.action === "recall") return rag3OpenWorkspace(kbId, "recall");
    if (button.dataset.action === "toggle") {
      await api(`/api/v3/rag/knowledge-bases/${kbId}/toggle`, { method: "POST", body: { enabled: !kb.enabled } });
      showToast(kb.enabled ? "知识库已停用" : "知识库已启用");
      return rag3LoadKbs();
    }
    if (button.dataset.action === "delete") {
      if (!confirm(`确定删除知识库“${kb.name}”及其全部文档和向量吗？`)) return;
      await api(`/api/v3/rag/knowledge-bases/${kbId}/delete`, { method: "POST", body: {} });
      showToast("知识库已删除");
      return rag3LoadKbs();
    }
  }));
  setTimeout(() => document.addEventListener("click", () => menu.remove(), { once: true }), 0);
}

function rag3OpenKbModal(kb = null) {
  const root = document.getElementById("rag3_modal_root");
  if (!root) return;
  root.innerHTML = `
    <div class="rag3-modal-backdrop">
      <form class="rag3-modal" id="rag3_kb_form">
        <header><div><span class="section-eyebrow">KNOWLEDGE BASE</span><h3>${kb ? "编辑知识库" : "新建知识库"}</h3></div><button type="button" data-close>×</button></header>
        <div class="rag3-modal-body">
          <label class="full"><span>知识库名称 *</span><input name="name" maxlength="160" value="${escapeHtml(kb?.name || "")}" placeholder="例如：Web 漏洞防护知识库" required /></label>
          <label class="full"><span>用途描述</span><textarea name="description" rows="3" maxlength="1000" placeholder="说明知识来源和适用范围">${escapeHtml(kb?.description || "")}</textarea></label>
          <label><span>向量模型 *</span><select name="embedding_model"><option value="text-embedding-v4">text-embedding-v4（1024维）</option></select></label>
          <label><span>重排模型 *</span><select name="rerank_model"><option value="qwen3-rerank">qwen3-rerank</option></select></label>
          <label><span>切片方式 *</span><select name="chunk_method"><option value="semantic" ${kb?.chunk_method !== "fixed" ? "selected" : ""}>语义结构切片</option><option value="fixed" ${kb?.chunk_method === "fixed" ? "selected" : ""}>固定长度切片</option></select></label>
          <label><span>切片长度</span><input name="chunk_size" type="number" min="200" max="4000" value="${Number(kb?.chunk_size || 900)}" /></label>
          <label><span>重叠字符</span><input name="chunk_overlap" type="number" min="0" max="1000" value="${Number(kb?.chunk_overlap || 120)}" /></label>
          <label><span>最终召回数</span><input name="final_top_k" type="number" min="1" max="20" value="${Number(kb?.final_top_k || 5)}" /></label>
          <label><span>向量候选数</span><input name="vector_top_k" type="number" min="1" max="100" value="${Number(kb?.vector_top_k || 20)}" /></label>
          <label><span>关键词候选数</span><input name="keyword_top_k" type="number" min="1" max="100" value="${Number(kb?.keyword_top_k || 20)}" /></label>
          <label><span>重排阈值</span><input name="score_threshold" type="number" min="0" max="1" step="0.01" value="${Number(kb?.score_threshold ?? 0.1)}" /></label>
          <label class="rag3-check"><input name="enabled" type="checkbox" ${kb?.enabled === 0 ? "" : "checked"} /><span>创建后立即启用</span></label>
        </div>
        <footer><button type="button" class="btn btn-ghost" data-close>取消</button><button type="submit" class="btn btn-primary">保存配置</button></footer>
      </form>
    </div>
  `;
  root.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => (root.innerHTML = "")));
  document.getElementById("rag3_kb_form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const payload = {
      name: form.get("name"), description: form.get("description"), embedding_model: form.get("embedding_model"),
      rerank_model: form.get("rerank_model"), chunk_method: form.get("chunk_method"), chunk_size: Number(form.get("chunk_size")),
      chunk_overlap: Number(form.get("chunk_overlap")), final_top_k: Number(form.get("final_top_k")),
      vector_top_k: Number(form.get("vector_top_k")), keyword_top_k: Number(form.get("keyword_top_k")),
      score_threshold: Number(form.get("score_threshold")), enabled: form.get("enabled") === "on",
    };
    try {
      await api(kb ? `/api/v3/rag/knowledge-bases/${kb.id}` : "/api/v3/rag/knowledge-bases", { method: kb ? "PUT" : "POST", body: payload });
      root.innerHTML = "";
      showToast(kb ? "知识库配置已保存" : "知识库创建成功");
      await rag3LoadKbs();
    } catch (err) { showToast(`保存失败：${err.message}`); }
  });
}

async function rag3OpenWorkspace(kbId, tab = "documents") {
  const workspace = rag3State();
  const data = await api(`/api/v3/rag/knowledge-bases/${kbId}`);
  workspace.selectedKb = data.item;
  workspace.detailTab = tab;
  await rag3LoadWorkspaceData();
  rag3RenderWorkspace();
}

async function rag3LoadWorkspaceData() {
  const workspace = rag3State();
  const kbId = workspace.selectedKb?.id;
  if (!kbId) return;
  const [documents, chunks, history, evalCases, evalRuns] = await Promise.all([
    api(`/api/v3/rag/knowledge-bases/${kbId}/documents`),
    api(`/api/v3/rag/knowledge-bases/${kbId}/chunks`),
    api(`/api/v3/rag/knowledge-bases/${kbId}/recall-history`),
    api(`/api/v3/rag/knowledge-bases/${kbId}/eval-cases`),
    api(`/api/v3/rag/knowledge-bases/${kbId}/eval-runs`),
  ]);
  workspace.documents = documents.items || [];
  workspace.chunks = chunks.items || [];
  workspace.recallHistory = history.items || [];
  workspace.evalCases = evalCases.items || [];
  workspace.evalRuns = evalRuns.items || [];
  if (!workspace.evalResult && workspace.evalRuns.length) {
    const latest = workspace.evalRuns[0];
    workspace.evalResult = {
      run_id: latest.id,
      total_cases: latest.total_cases,
      passed_cases: latest.passed_cases,
      pass_rate: latest.pass_rate,
      average_duration_ms: latest.average_duration_ms,
      items: latest.items || [],
    };
  }
}

function rag3RenderWorkspace() {
  const root = document.getElementById("viewRoot");
  const workspace = rag3State();
  const kb = workspace.selectedKb;
  if (!root || !kb) return;
  root.innerHTML = `
    <section class="rag3-workspace">
      <header class="rag3-workspace-head">
        <button id="rag3_back" class="rag3-back">←</button>
        <div class="rag3-workspace-title"><i>▰</i><span><strong>${escapeHtml(kb.name)}</strong><small>${escapeHtml(kb.description || "未填写描述")}</small></span></div>
        <nav>
          <button data-rag3-tab="documents" class="${workspace.detailTab === "documents" ? "active" : ""}">知识文档</button>
          <button data-rag3-tab="chunks" class="${workspace.detailTab === "chunks" ? "active" : ""}">分段管理</button>
          <button data-rag3-tab="recall" class="${workspace.detailTab === "recall" ? "active" : ""}">召回测试</button>
          <button data-rag3-tab="evaluation" class="${workspace.detailTab === "evaluation" ? "active" : ""}">回归评估</button>
        </nav>
        <button id="rag3_edit_current" class="btn btn-ghost">编辑配置</button>
      </header>
      <main id="rag3_workspace_body"></main>
    </section>
    <div id="rag3_modal_root"></div>
  `;
  document.getElementById("rag3_back")?.addEventListener("click", () => { workspace.selectedKb = null; renderRagSettingsView(); });
  document.getElementById("rag3_edit_current")?.addEventListener("click", () => rag3OpenKbModal(kb));
  root.querySelectorAll("[data-rag3-tab]").forEach((button) => button.addEventListener("click", () => {
    workspace.detailTab = button.dataset.rag3Tab;
    rag3RenderWorkspace();
  }));
  if (workspace.detailTab === "chunks") rag3RenderChunks();
  else if (workspace.detailTab === "recall") rag3RenderRecall();
  else if (workspace.detailTab === "evaluation") rag3RenderEvaluation();
  else rag3RenderDocuments();
}

function rag3RenderDocuments() {
  const body = document.getElementById("rag3_workspace_body");
  const workspace = rag3State();
  if (!body) return;
  body.innerHTML = `
    <section class="rag3-detail-toolbar"><div><h3>知识文档</h3><p>${workspace.documents.length} 个文档，${workspace.chunks.length} 个有效切片</p></div><div><button id="rag3_add_text" class="btn btn-ghost">添加文本</button><button id="rag3_upload_file" class="btn btn-primary">上传附件</button><input id="rag3_file_input" type="file" hidden accept=".txt,.md,.json,.jsonl,.csv,.pdf,.docx,.pptx,.xlsx" /></div></section>
    <div class="rag3-doc-grid">
      ${workspace.documents.length ? workspace.documents.map((doc) => `
        <article class="rag3-doc-card">
          <div class="rag3-doc-icon">${escapeHtml((doc.mime_type || "TXT").slice(0, 4).toUpperCase())}</div>
          <div class="rag3-doc-copy"><span class="rag3-status ${doc.status}">${rag3StatusLabel(doc.status)}</span><h4>${escapeHtml(doc.name)}</h4><p>${Number(doc.chunk_count || 0)} 个切片 · ${Number(doc.char_count || 0).toLocaleString()} 字符</p><small>${escapeHtml(rag3Date(doc.updated_at))}</small>${doc.error_message ? `<em>${escapeHtml(doc.error_message)}</em>` : ""}</div>
          <div class="rag3-doc-actions">${doc.status === "pending" ? `<button data-rag3-index="${doc.id}" class="btn btn-ghost">建立向量</button>` : ""}<button data-rag3-doc-chunks="${doc.id}" class="btn btn-ghost">查看切片</button><button data-rag3-doc-delete="${doc.id}" class="btn btn-danger">删除</button></div>
        </article>
      `).join("") : `<div class="rag3-empty-state wide"><b>还没有知识文档</b><span>支持 PDF、Word、PPT、Excel、Markdown、JSON、CSV 和纯文本，单文件最大 30MB。</span></div>`}
    </div>
  `;
  document.getElementById("rag3_upload_file")?.addEventListener("click", () => document.getElementById("rag3_file_input")?.click());
  document.getElementById("rag3_file_input")?.addEventListener("change", (event) => rag3UploadFile(event.target.files?.[0]));
  document.getElementById("rag3_add_text")?.addEventListener("click", rag3OpenTextModal);
  body.querySelectorAll("[data-rag3-doc-chunks]").forEach((button) => button.addEventListener("click", () => { workspace.chunkDocumentId = Number(button.dataset.rag3DocChunks); workspace.detailTab = "chunks"; rag3RenderWorkspace(); }));
  body.querySelectorAll("[data-rag3-index]").forEach((button) => button.addEventListener("click", async () => {
    button.disabled = true; showToast("正在建立向量索引，请稍候...");
    try { await api(`/api/v3/rag/documents/${button.dataset.rag3Index}/index`, { method: "POST", body: {} }); await rag3ReloadWorkspace("索引建立完成"); }
    catch (err) { showToast(`索引失败：${err.message}`); button.disabled = false; }
  }));
  body.querySelectorAll("[data-rag3-doc-delete]").forEach((button) => button.addEventListener("click", async () => {
    if (!confirm("确定删除该文档及其全部切片吗？")) return;
    await api(`/api/v3/rag/documents/${button.dataset.rag3DocDelete}/delete`, { method: "POST", body: {} });
    await rag3ReloadWorkspace("文档已删除");
  }));
}

async function rag3UploadFile(file) {
  if (!file) return;
  if (file.size > 30 * 1024 * 1024) return showToast("文件不能超过 30MB");
  const form = new FormData(); form.append("file", file);
  showToast("正在解析、切片并建立向量，请勿关闭页面...");
  try {
    const result = await apiForm(`/api/v3/rag/knowledge-bases/${rag3State().selectedKb.id}/documents/upload`, form);
    await rag3ReloadWorkspace(`已生成 ${result.item?.chunk_count || 0} 个切片`);
  } catch (err) { showToast(`上传失败：${err.message}`); }
}

function rag3OpenTextModal() {
  const root = document.getElementById("rag3_modal_root");
  if (!root) return;
  root.innerHTML = `<div class="rag3-modal-backdrop"><form class="rag3-modal compact" id="rag3_text_form"><header><div><span class="section-eyebrow">DIRECT INPUT</span><h3>添加文本知识</h3></div><button type="button" data-close>×</button></header><div class="rag3-modal-body"><label class="full"><span>文档标题 *</span><input name="title" placeholder="例如：SQL 注入应急处置指南" required /></label><label class="full"><span>知识正文 *</span><textarea name="content" rows="12" placeholder="粘贴经过核验的安全知识正文" required></textarea></label></div><footer><button type="button" class="btn btn-ghost" data-close>取消</button><button type="submit" class="btn btn-primary">解析并入库</button></footer></form></div>`;
  root.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => (root.innerHTML = "")));
  document.getElementById("rag3_text_form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    try { await api(`/api/v3/rag/knowledge-bases/${rag3State().selectedKb.id}/documents/text`, { method: "POST", body: { title: form.get("title"), content: form.get("content") } }); root.innerHTML = ""; await rag3ReloadWorkspace("文本知识已入库"); }
    catch (err) { showToast(`入库失败：${err.message}`); }
  });
}

function rag3RenderChunks() {
  const body = document.getElementById("rag3_workspace_body");
  const workspace = rag3State();
  if (!body) return;
  const docs = workspace.documents;
  const visible = workspace.chunkDocumentId ? workspace.chunks.filter((item) => Number(item.document_id) === Number(workspace.chunkDocumentId)) : workspace.chunks;
  body.innerHTML = `
    <section class="rag3-chunk-layout">
      <aside><label class="rag3-search"><span>⌕</span><input id="rag3_doc_filter" placeholder="筛选文档" /></label><button class="${workspace.chunkDocumentId ? "" : "active"}" data-doc-filter="0"><span>全部文档</span><b>${workspace.chunks.length}</b></button>${docs.map((doc) => `<button class="${Number(workspace.chunkDocumentId) === Number(doc.id) ? "active" : ""}" data-doc-filter="${doc.id}"><span>${escapeHtml(doc.name)}</span><b>${Number(doc.chunk_count || 0)}</b></button>`).join("")}</aside>
      <section><header><div><h3>分段列表</h3><p>共 ${visible.length} 段，点击切片可查看与修改完整正文。</p></div><button id="rag3_recall_from_chunks" class="btn btn-primary">召回测试</button></header><div class="rag3-chunk-list">${visible.length ? visible.map((chunk, index) => `<article data-rag3-chunk="${chunk.id}"><div><span>${index + 1}/${visible.length}</span><small>${Number(chunk.token_count || 0)} 估算 tokens · 召回 ${Number(chunk.retrieval_count || 0)} 次</small><i class="rag3-status ${chunk.enabled ? "ready" : "disabled"}">${chunk.enabled ? "启用" : "停用"}</i></div><h4>${escapeHtml(chunk.title_path || "正文")}</h4><p>${escapeHtml(String(chunk.content || "").slice(0, 420))}${String(chunk.content || "").length > 420 ? "…" : ""}</p><footer>${escapeHtml(chunk.document_name || "-")} · 更新于 ${escapeHtml(rag3Date(chunk.updated_at))}</footer></article>`).join("") : `<div class="rag3-empty-state"><b>暂无切片</b><span>请先上传并成功解析知识文档。</span></div>`}</div></section>
    </section>
  `;
  body.querySelectorAll("[data-doc-filter]").forEach((button) => button.addEventListener("click", () => { workspace.chunkDocumentId = Number(button.dataset.docFilter) || 0; rag3RenderChunks(); }));
  body.querySelectorAll("[data-rag3-chunk]").forEach((article) => article.addEventListener("click", () => rag3OpenChunkModal(workspace.chunks.find((item) => Number(item.id) === Number(article.dataset.rag3Chunk)))));
  document.getElementById("rag3_recall_from_chunks")?.addEventListener("click", () => { workspace.detailTab = "recall"; rag3RenderWorkspace(); });
  document.getElementById("rag3_doc_filter")?.addEventListener("input", (event) => { const q = event.target.value.toLowerCase(); body.querySelectorAll("aside [data-doc-filter]").forEach((button) => button.classList.toggle("hidden", !button.textContent.toLowerCase().includes(q))); });
}

function rag3OpenChunkModal(chunk) {
  if (!chunk) return;
  const root = document.getElementById("rag3_modal_root");
  root.innerHTML = `<div class="rag3-modal-backdrop"><form class="rag3-modal" id="rag3_chunk_form"><header><div><span class="section-eyebrow">CHUNK ${chunk.chunk_index + 1}</span><h3>${escapeHtml(chunk.title_path || "切片详情")}</h3></div><button type="button" data-close>×</button></header><div class="rag3-modal-body"><label class="full"><span>来源文档</span><input value="${escapeHtml(chunk.document_name || "-")}" disabled /></label><label class="full"><span>切片正文 *</span><textarea name="content" rows="17" required>${escapeHtml(chunk.content)}</textarea></label><label class="rag3-check"><input name="enabled" type="checkbox" ${chunk.enabled ? "checked" : ""}/><span>参与后续召回</span></label></div><footer><button type="button" class="btn btn-ghost" data-close>取消</button><button type="submit" class="btn btn-primary">保存并重建向量</button></footer></form></div>`;
  root.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => (root.innerHTML = "")));
  document.getElementById("rag3_chunk_form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget); try { await api(`/api/v3/rag/chunks/${chunk.id}`, { method: "PUT", body: { content: form.get("content"), enabled: form.get("enabled") === "on" } }); root.innerHTML = ""; await rag3ReloadWorkspace("切片与向量已更新"); } catch (err) { showToast(`保存失败：${err.message}`); } });
}

function rag3RenderRecall() {
  const body = document.getElementById("rag3_workspace_body");
  const workspace = rag3State();
  if (!body) return;
  body.innerHTML = `
    <section class="rag3-recall-layout">
      <main><header><div><h3>召回测试结果</h3><p>检查 Vector + BM25 + RRF + qwen3-rerank 的真实检索效果。</p></div>${workspace.recallItems.length ? `<span>${workspace.recallItems.length} 个切片</span>` : ""}</header><div class="rag3-recall-results">${workspace.recallItems.length ? workspace.recallItems.map((item, index) => `<article><div class="rag3-score"><strong>${Math.round(Number(item.score || 0) * 100)}</strong><span>相关度</span></div><div><span class="section-eyebrow">TOP ${index + 1} · ${escapeHtml(item.document_name || "未知文档")}</span><h4>${escapeHtml(item.title_path || "正文")}</h4><p>${escapeHtml(item.content)}</p><footer>切片 #${Number(item.chunk_index || 0) + 1} · RRF ${Number(item.rrf_score || 0).toFixed(4)}</footer></div></article>`).join("") : `<div class="rag3-recall-empty"><b>输入一段攻击证据开始召回</b><span>建议使用真实请求路径、Payload、响应特征与行为描述组合测试。</span></div>`}</div></main>
      <aside><div><span class="section-eyebrow">RETRIEVAL TEST</span><h3>召回测试</h3><p>${escapeHtml(workspace.selectedKb.name)}</p><textarea id="rag3_recall_query" rows="9" placeholder="例如：POST /login 的 password 参数出现单引号、OR 1=1 与注释符，应该如何判断和处置？"></textarea><button id="rag3_run_recall" class="btn btn-primary">运行混合召回</button></div><section><h4>最近测试</h4>${workspace.recallHistory.length ? workspace.recallHistory.map((item) => `<button data-history-query="${escapeHtml(item.query_text)}"><span>${escapeHtml(String(item.query_text).slice(0, 58))}</span><small>${item.duration_ms}ms · ${item.result_count} 条 · ${escapeHtml(rag3Date(item.created_at))}</small></button>`).join("") : `<p>暂无测试记录</p>`}</section></aside>
    </section>
  `;
  document.getElementById("rag3_run_recall")?.addEventListener("click", rag3RunRecall);
  body.querySelectorAll("[data-history-query]").forEach((button) => button.addEventListener("click", () => { document.getElementById("rag3_recall_query").value = button.dataset.historyQuery; }));
}

async function rag3RunRecall() {
  const workspace = rag3State();
  const query = String(document.getElementById("rag3_recall_query")?.value || "").trim();
  if (!query) return showToast("请输入召回测试文本");
  const button = document.getElementById("rag3_run_recall"); if (button) { button.disabled = true; button.textContent = "检索与重排中..."; }
  try {
    const data = await api(`/api/v3/rag/knowledge-bases/${workspace.selectedKb.id}/recall`, { method: "POST", body: { query } });
    workspace.recallItems = data.items || [];
    await rag3LoadWorkspaceData();
    rag3RenderRecall();
    showToast(`召回完成：${workspace.recallItems.length} 条，耗时 ${data.duration_ms || 0}ms`);
  } catch (err) { showToast(`召回失败：${err.message}`); if (button) { button.disabled = false; button.textContent = "运行混合召回"; } }
}

function rag3RenderEvaluation() {
  const body = document.getElementById("rag3_workspace_body");
  const workspace = rag3State();
  if (!body) return;
  const result = workspace.evalResult;
  body.innerHTML = `
    <section class="rag3-eval-layout">
      <main>
        <header><div><span class="section-eyebrow">REGRESSION EVALUATION</span><h3>知识库回归评估</h3><p>批量验证升级知识、切片参数或向量模型后，关键安全问题仍能召回正确证据。</p></div><button id="rag3_run_eval" class="btn btn-primary" ${workspace.evalCases.length ? "" : "disabled"}>运行全部用例</button></header>
        ${result ? `<div class="rag3-eval-summary"><article><span>通过率</span><strong>${Math.round(Number(result.pass_rate || 0) * 100)}%</strong></article><article><span>通过用例</span><strong>${result.passed_cases}/${result.total_cases}</strong></article><article><span>平均耗时</span><strong>${result.average_duration_ms}ms</strong></article><article><span>本次编号</span><strong>#${result.run_id}</strong></article></div>` : ""}
        <div class="rag3-eval-cases">
          ${workspace.evalCases.length ? workspace.evalCases.map((item, index) => {
            const row = result?.items?.find((candidate) => Number(candidate.case_id) === Number(item.id));
            return `<article class="${row ? (row.passed ? "passed" : "failed") : ""}"><div class="rag3-eval-index">${String(index + 1).padStart(2, "0")}</div><div><div class="rag3-eval-title"><h4>${escapeHtml(item.question)}</h4><span>${row ? (row.passed ? "通过" : "失败") : (item.enabled ? "待运行" : "已停用")}</span></div><p>期望关键词：${escapeHtml(item.expected_keywords || "任一有效结果")}</p><p>期望文档：${escapeHtml(item.expected_document || "不限")}</p>${row ? `<footer>${escapeHtml(row.reason)} · ${row.duration_ms}ms · TOP1 ${escapeHtml(row.top_document || "无")}</footer>` : ""}</div><div class="rag3-eval-actions"><button data-eval-edit="${item.id}" class="btn btn-ghost">编辑</button><button data-eval-delete="${item.id}" class="btn btn-danger">删除</button></div></article>`;
          }).join("") : `<div class="rag3-empty-state wide"><b>还没有回归用例</b><span>添加比赛演示中的典型 SQL 注入、XSS、扫描与爆破问题，建立可重复的质量基线。</span></div>`}
        </div>
      </main>
      <aside>
        <div><span class="section-eyebrow">TEST CASE</span><h3>新增回归用例</h3><p>关键词支持用逗号分隔，命中任意一个即满足关键词条件。</p></div>
        <form id="rag3_eval_form">
          <input type="hidden" name="case_id" />
          <label><span>测试问题 *</span><textarea name="question" rows="6" required placeholder="例如：登录参数出现单引号、恒真条件和注释符时，应判断为何种攻击？"></textarea></label>
          <label><span>期望关键词</span><input name="expected_keywords" placeholder="SQL注入, 参数化查询" /></label>
          <label><span>期望来源文档</span><input name="expected_document" placeholder="例如：OWASP（可留空）" /></label>
          <label class="rag3-check"><input name="enabled" type="checkbox" checked /><span>纳入批量回归</span></label>
          <div><button type="button" id="rag3_eval_cancel" class="btn btn-ghost hidden">取消编辑</button><button type="submit" class="btn btn-primary">保存用例</button></div>
        </form>
        <section><h4>最近运行</h4>${workspace.evalRuns.length ? workspace.evalRuns.map((run) => `<div class="rag3-eval-run"><span>#${run.id} · ${run.passed_cases}/${run.total_cases} 通过</span><small>${Math.round(Number(run.pass_rate || 0) * 100)}% · ${run.average_duration_ms}ms · ${escapeHtml(rag3Date(run.created_at))}</small></div>`).join("") : `<p>暂无批量运行记录</p>`}</section>
      </aside>
    </section>`;
  document.getElementById("rag3_run_eval")?.addEventListener("click", rag3RunEvaluation);
  document.getElementById("rag3_eval_form")?.addEventListener("submit", rag3SaveEvalCase);
  document.getElementById("rag3_eval_cancel")?.addEventListener("click", () => { document.getElementById("rag3_eval_form")?.reset(); document.querySelector('#rag3_eval_form [name="case_id"]').value = ""; document.getElementById("rag3_eval_cancel")?.classList.add("hidden"); });
  body.querySelectorAll("[data-eval-edit]").forEach((button) => button.addEventListener("click", () => rag3EditEvalCase(Number(button.dataset.evalEdit))));
  body.querySelectorAll("[data-eval-delete]").forEach((button) => button.addEventListener("click", () => rag3DeleteEvalCase(Number(button.dataset.evalDelete))));
}

function rag3EditEvalCase(caseId) {
  const item = rag3State().evalCases.find((row) => Number(row.id) === Number(caseId));
  const form = document.getElementById("rag3_eval_form");
  if (!item || !form) return;
  form.elements.case_id.value = item.id;
  form.elements.question.value = item.question || "";
  form.elements.expected_keywords.value = item.expected_keywords || "";
  form.elements.expected_document.value = item.expected_document || "";
  form.elements.enabled.checked = Boolean(Number(item.enabled));
  document.getElementById("rag3_eval_cancel")?.classList.remove("hidden");
  form.elements.question.focus();
}

async function rag3SaveEvalCase(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const caseId = Number(form.get("case_id") || 0);
  try {
    await api(`/api/v3/rag/knowledge-bases/${rag3State().selectedKb.id}/eval-cases${caseId ? `/${caseId}` : ""}`, { method: caseId ? "PUT" : "POST", body: { question: form.get("question"), expected_keywords: form.get("expected_keywords"), expected_document: form.get("expected_document"), enabled: form.get("enabled") === "on" } });
    rag3State().evalResult = null;
    await rag3ReloadWorkspace(caseId ? "回归用例已更新" : "回归用例已添加");
  } catch (err) { showToast(`保存失败：${err.message}`); }
}

async function rag3DeleteEvalCase(caseId) {
  if (!confirm("确定删除这条回归用例吗？")) return;
  try { await api(`/api/v3/rag/knowledge-bases/${rag3State().selectedKb.id}/eval-cases/${caseId}`, { method: "POST", body: { action: "delete" } }); rag3State().evalResult = null; await rag3ReloadWorkspace("回归用例已删除"); }
  catch (err) { showToast(`删除失败：${err.message}`); }
}

async function rag3RunEvaluation() {
  const button = document.getElementById("rag3_run_eval");
  if (button) { button.disabled = true; button.textContent = "批量检索中..."; }
  try {
    rag3State().evalResult = await api(`/api/v3/rag/knowledge-bases/${rag3State().selectedKb.id}/eval-runs`, { method: "POST", body: {} });
    await rag3LoadWorkspaceData();
    rag3RenderEvaluation();
    showToast(`回归完成：${rag3State().evalResult.passed_cases}/${rag3State().evalResult.total_cases} 通过`);
  } catch (err) { showToast(`回归评估失败：${err.message}`); if (button) { button.disabled = false; button.textContent = "运行全部用例"; } }
}

async function rag3ReloadWorkspace(message) {
  await rag3LoadWorkspaceData();
  rag3RenderWorkspace();
  if (message) showToast(message);
}
