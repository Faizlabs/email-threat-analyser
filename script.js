const themeBtn = document.getElementById("themeBtn");
const settingsThemeBtn = document.getElementById("settingsThemeBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const scanBtn = document.getElementById("scanBtn");
const inputText = document.getElementById("inputText");

const gauge = document.getElementById("gauge");
const gaugeScore = document.getElementById("gaugeScore");

const scoreStat = document.getElementById("scoreStat");
const flagsStat = document.getElementById("flagsStat");
const verdictStat = document.getElementById("verdictStat");
const scansStat = document.getElementById("scansStat");

const statusTitle = document.getElementById("statusTitle");
const statusText = document.getElementById("statusText");

const resultPill = document.getElementById("resultPill");

const tags = document.getElementById("tags");

const historyList = document.getElementById("historyList");
const logList = document.getElementById("logList");

const securityStatus = document.getElementById("securityStatus");

const navButtons = document.querySelectorAll(".nav button");

let scansToday = 12;
let history = [];

/* =========================
   THEME
========================= */

function setTheme(theme) {
  document.documentElement.setAttribute(
    "data-theme",
    theme
  );

  localStorage.setItem(
    "theme",
    theme
  );
}

setTheme(
  localStorage.getItem("theme") || "dark"
);

function toggleTheme() {

  const current =
    document.documentElement.getAttribute(
      "data-theme"
    );

  if (current === "dark") {
    setTheme("light");
  } else {
    setTheme("dark");
  }
}

themeBtn.addEventListener(
  "click",
  toggleTheme
);

settingsThemeBtn.addEventListener(
  "click",
  toggleTheme
);

/* =========================
   HISTORY
========================= */

function renderHistory() {

  historyList.innerHTML = "";

  history.forEach((item) => {

    const div =
      document.createElement("div");

    div.className =
      "history-item";

    let colorClass = "good";

    if (item.score >= 70) {
      colorClass = "bad";
    }

    else if (item.score >= 35) {
      colorClass = "warn";
    }

    div.innerHTML = `
      <div>
        <strong>${item.title}</strong>
        <small>${item.detail}</small>
      </div>

      <div class="${colorClass}">
        ${item.score}%
      </div>
    `;

    historyList.appendChild(div);

  });
}

/* =========================
   LOGS
========================= */

function pushLog(message) {

  const div =
    document.createElement("div");

  div.className =
    "log-item";

  div.innerHTML = `
    <div>${message}</div>
    <small>
      ${new Date().toLocaleTimeString()}
    </small>
  `;

  logList.prepend(div);
}

/* =========================
   ANALYZER
========================= */

function analyze(text) {

  const value =
    text.toLowerCase();

  let score = 0;

  const flags = [];

  const rules = [

    {
      regex: /urgent|verify now|suspended|immediately/,
      score: 18,
      flag: "Urgency Language"
    },

    {
      regex: /click here|confirm account|login/,
      score: 16,
      flag: "Credential Lure"
    },

    {
      regex: /http:\/\/|bit\.ly|tinyurl|\.xyz|\.ru/,
      score: 20,
      flag: "Unsafe URL"
    },

    {
      regex: /bank|invoice|crypto|payment/,
      score: 12,
      flag: "Finance Scam"
    },

    {
      regex: /attachment|download|pdf|docx/,
      score: 10,
      flag: "Suspicious Attachment"
    }

  ];

  rules.forEach((rule) => {

    if (rule.regex.test(value)) {

      score += rule.score;

      flags.push(rule.flag);

    }

  });

  if (score > 100) {
    score = 100;
  }

  return {
    score,
    flags
  };
}

/* =========================
   UPDATE UI
========================= */

function updateDashboard(
  result,
  original
) {

  gauge.style.setProperty(
    "--score",
    result.score
  );

  gaugeScore.textContent =
    result.score + "%";

  scoreStat.textContent =
    result.score + "%";

  flagsStat.textContent =
    result.flags.length;

  let verdict = "Low";

  if (result.score >= 70) {
    verdict = "High";
  }

  else if (result.score >= 35) {
    verdict = "Medium";
  }

  verdictStat.textContent =
    verdict;

  resultPill.textContent =
    verdict;

  statusTitle.textContent =
    verdict + " Risk Detected";

  if (result.flags.length > 0) {

    statusText.textContent =
      result.flags.join(", ");

  }

  else {

    statusText.textContent =
      "No major indicators found.";

  }

  securityStatus.textContent =
    verdict + " risk scan completed";

  tags.innerHTML = "";

  const activeTags =
    result.flags.length > 0
      ? result.flags
      : ["No Indicators"];

  activeTags.forEach((flag) => {

    const tag =
      document.createElement("div");

    tag.className = "tag";

    tag.textContent = flag;

    tags.appendChild(tag);

  });

  history.unshift({

    title:
      original.slice(0, 25),

    detail:
      verdict + " risk detected",

    score:
      result.score

  });

  history = history.slice(0, 6);

  renderHistory();

  scansToday++;

  scansStat.textContent =
    scansToday;

  pushLog(
    "Scan completed — " +
    result.score +
    "% threat detected"
  );
}

/* =========================
   SCAN BUTTON
========================= */

scanBtn.addEventListener(
  "click",
  function () {

    const text =
      inputText.value.trim();

    if (!text) {

      alert(
        "Please enter text or URL"
      );

      return;
    }

    const result =
      analyze(text);

    updateDashboard(
      result,
      text
    );
  }
);

/* =========================
   CLEAR HISTORY
========================= */

clearHistoryBtn.addEventListener(
  "click",
  function () {

    history = [];

    renderHistory();

    pushLog(
      "History cleared"
    );
  }
);

/* =========================
   NAVIGATION
========================= */

navButtons.forEach((button) => {

  button.addEventListener(
    "click",
    function () {

      navButtons.forEach((btn) => {

        btn.classList.remove(
          "active"
        );

      });

      button.classList.add(
        "active"
      );

      const target =
        document.getElementById(
          button.dataset.target
        );

      if (target) {

        target.scrollIntoView({
          behavior: "smooth"
        });

      }
    }
  );
});

/* =========================
   INITIAL LOGS
========================= */

pushLog("System Ready");

pushLog(
  "Monitoring suspicious activity"
);

pushLog(
  "Awaiting threat scan"
);