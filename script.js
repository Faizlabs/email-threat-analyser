<<<<<<< HEAD
const themeBtn = document.getElementById('themeBtn');
const scanBtn = document.getElementById('scanBtn');
const inputText = document.getElementById('inputText');

const gauge = document.getElementById('gauge');
const gaugeScore = document.getElementById('gaugeScore');

const scoreStat = document.getElementById('scoreStat');
const flagsStat = document.getElementById('flagsStat');
const verdictStat = document.getElementById('verdictStat');
const scansStat = document.getElementById('scansStat');

const statusTitle = document.getElementById('statusTitle');
const statusText = document.getElementById('statusText');

const resultPill = document.getElementById('resultPill');

const tags = document.getElementById('tags');

const historyList = document.getElementById('historyList');
const logList = document.getElementById('logList');

const securityStatus = document.getElementById('securityStatus');

let scansToday = 12;

let history = [
  {
    title: 'example-login.com',
    detail: 'High risk URL pattern',
    score: 82
  },
  {
    title: 'Invoice email',
    detail: 'Urgency + attachment lure',
    score: 54
  },
  {
    title: 'Bank alert',
    detail: 'Verified sender warning',
    score: 12
  }
];

// =========================
// THEME SYSTEM
// =========================

function setTheme(theme){

  document.documentElement.setAttribute('data-theme', theme);

  localStorage.setItem('theme', theme);

  themeBtn.textContent =
    theme === 'light'
      ? '☀️ Toggle Theme'
      : '🌙 Toggle Theme';

}

setTheme(localStorage.getItem('theme') || 'dark');

themeBtn.addEventListener('click', ()=>{

  const current =
    document.documentElement.getAttribute('data-theme');

  setTheme(current === 'dark' ? 'light' : 'dark');

});

// =========================
// RENDER HISTORY
// =========================

function renderHistory(){

  historyList.innerHTML = '';

  history.forEach(item=>{

    const div = document.createElement('div');

    div.className = 'history-item';

    div.innerHTML = `
      <div>
        <strong>${item.title}</strong>
        <small>${item.detail}</small>
      </div>

      <div class="${
        item.score >= 70
          ? 'bad'
          : item.score >= 35
            ? 'warn'
            : 'good'
      }">
        ${item.score}%
      </div>
    `;

    historyList.appendChild(div);

  });

}

// =========================
// TERMINAL LOGS
// =========================

function pushLog(message){

  const div = document.createElement('div');

  div.className = 'log-item';

  div.innerHTML = `
    <div>${message}</div>
    <small>${new Date().toLocaleTimeString()}</small>
  `;

  logList.prepend(div);

  while(logList.children.length > 6){

    logList.removeChild(logList.lastElementChild);

  }

}

// =========================
// THREAT ANALYZER
// =========================

function analyze(text){

  const value = text.toLowerCase();

  let score = 0;

  const flags = [];

  const rules = [

    {
      regex:/urgent|verify now|suspended|immediately/,
      score:18,
      flag:'Urgency language'
    },

    {
      regex:/click here|confirm account|login/,
      score:16,
      flag:'Credential lure'
    },

    {
      regex:/http:\/\/|bit\.ly|tinyurl|\.xyz|\.ru/,
      score:20,
      flag:'Unsafe URL pattern'
    },

    {
      regex:/bank|invoice|crypto|payment/,
      score:12,
      flag:'Finance themed attack'
    },

    {
      regex:/attachment|pdf|docx|download/,
      score:10,
      flag:'Attachment lure'
    }

  ];

  rules.forEach(rule=>{

    if(rule.regex.test(value)){

      score += rule.score;

      flags.push(rule.flag);

    }

  });

  score = Math.min(score,100);

  return {
    score,
    flags
  };

}

// =========================
// UPDATE DASHBOARD
// =========================

function updateDashboard(result, original){

  gauge.style.setProperty('--score', result.score);

  gaugeScore.textContent = `${result.score}%`;

  scoreStat.textContent = `${result.score}%`;

  flagsStat.textContent = result.flags.length;

  let verdict = 'Low';

  if(result.score >= 70){

    verdict = 'High';

  } else if(result.score >= 35){

    verdict = 'Medium';

  }

  verdictStat.textContent = verdict;

  statusTitle.textContent = `${verdict} Risk Detected`;

  statusText.textContent =
    result.flags.length
      ? result.flags.join(', ')
      : 'No major threat indicators found.';

  resultPill.textContent = verdict;

  securityStatus.textContent =
    `${verdict} risk scan completed.`;

  tags.innerHTML = '';

  (
    result.flags.length
      ? result.flags
      : ['No major indicators']
  ).forEach(flag=>{

    const tag = document.createElement('div');

    tag.className = 'tag';

    tag.textContent = flag;

    tags.appendChild(tag);

  });

  history.unshift({
    title: original.slice(0,25) || 'New Scan',
    detail: verdict + ' risk detected',
    score: result.score
  });

  history = history.slice(0,6);

  renderHistory();

  scansToday++;

  scansStat.textContent = scansToday;

  pushLog(
    `Scan completed — ${result.score}% threat detected`
  );

}

// =========================
// SCAN BUTTON
// =========================

scanBtn.addEventListener('click', ()=>{

  const text = inputText.value.trim();

  if(!text){

    alert('Please paste text or a URL first.');

    return;

  }

  const result = analyze(text);

  updateDashboard(result, text);

});

// =========================
// SIDEBAR NAVIGATION
// =========================

const navButtons =
  document.querySelectorAll('.nav button');

navButtons.forEach(button=>{

  button.addEventListener('click', ()=>{

    navButtons.forEach(btn=>{

      btn.classList.remove('active');

    });

    button.classList.add('active');

    const target =
      document.getElementById(
        button.dataset.target
      );

    if(target){

      target.scrollIntoView({
        behavior:'smooth'
      });

    }

  });

});

// =========================
// INITIALIZE
// =========================

renderHistory();

pushLog('System ready');

pushLog('Monitoring suspicious activity');

pushLog('Awaiting scan');
=======
document.addEventListener("DOMContentLoaded", function () {

    // Elements
    const themeToggle = document.getElementById("themeToggle");
    const scanButton = document.getElementById("scanButton");
    const userInput = document.getElementById("userInput");
    const resultText = document.getElementById("resultText");
    const progressBar = document.getElementById("progressBar");
    const progressContainer = document.querySelector(".progress-container");
    const copyButton = document.getElementById("copyButton");
    const riskMeter = document.querySelector(".risk-meter");
    const meterText = document.getElementById("meterText");
    const historyList = document.getElementById("historyList");

    // Report Storage
    let latestReport = "";

    // Load Existing History
    loadHistory();

    // Theme Toggle
    themeToggle.addEventListener("click", () => {

        document.body.classList.toggle("light-mode");

        if (document.body.classList.contains("light-mode")) {
            themeToggle.textContent = "Dark Theme";
        } else {
            themeToggle.textContent = "Toggle Theme";
        }

    });

    // Scan Button
    scanButton.addEventListener("click", () => {

        const input = userInput.value.trim().toLowerCase();

        // Empty Input
        if (input === "") {

            resultText.innerHTML = `
                <span style="color: orange;">
                    Please paste an email or URL first.
                </span>
            `;

            return;
        }

        // Reset Meter
        riskMeter.style.background = `
            conic-gradient(
                #22c55e 0deg,
                #1e293b 0deg
            )
        `;

        meterText.textContent = "0%";

        // Progress Bar
        progressContainer.style.display = "block";
        progressBar.style.width = "0%";

        // Loading
        resultText.innerHTML = `
            <div class="loading">
                Initializing Scan...
            </div>
        `;

        // Stage 1
        setTimeout(() => {

            progressBar.style.width = "25%";

            resultText.innerHTML = `
                <div class="loading">
                    Checking suspicious keywords...
                </div>
            `;

        }, 700);

        // Stage 2
        setTimeout(() => {

            progressBar.style.width = "50%";

            resultText.innerHTML = `
                <div class="loading">
                    Analyzing URLs...
                </div>
            `;

        }, 1400);

        // Stage 3
        setTimeout(() => {

            progressBar.style.width = "75%";

            resultText.innerHTML = `
                <div class="loading">
                    Calculating threat score...
                </div>
            `;

        }, 2100);

        // Final Analysis
        setTimeout(() => {

            progressBar.style.width = "100%";

            // Keywords
            const suspiciousWords = [
                "urgent",
                "verify",
                "password",
                "click here",
                "suspended",
                "login now",
                "account locked",
                "winner",
                "limited time",
                "act now",
                "bank",
                "security alert"
            ];

            let foundWords = [];
            let riskScore = 0;

            // Intelligence Flags
            let hasUnsafeProtocol = false;
            let hasShortenedUrl = false;
            let hasFakeDomain = false;

            // URL Extraction
            const urlRegex = /(https?:\/\/[^\s]+)/g;
            const detectedUrls = input.match(urlRegex) || [];

            // Keyword Scan
            suspiciousWords.forEach(word => {

                if (input.includes(word)) {
                    foundWords.push(word);
                    riskScore += 15;
                }

            });

            // URL Scan
            detectedUrls.forEach(url => {

                if (
                    url.startsWith("http://") &&
                    !url.includes("127.0.0.1") &&
                    !url.includes("localhost")
                ) {

                    riskScore += 20;
                    hasUnsafeProtocol = true;

                }

                if (
                    url.includes("bit.ly") ||
                    url.includes("tinyurl") ||
                    url.includes("goo.gl")
                ) {

                    riskScore += 25;
                    hasShortenedUrl = true;

                }

                if (
                    url.includes("paypa1") ||
                    url.includes("g00gle") ||
                    url.includes("micr0soft")
                ) {

                    riskScore += 40;
                    hasFakeDomain = true;

                }

            });

            // Limit Score
            if (riskScore > 100) {
                riskScore = 100;
            }

            // Risk Level
            let riskLevel = "";
            let badgeClass = "";
            let meterColor = "";

            if (riskScore >= 60) {

                riskLevel = "HIGH RISK";
                badgeClass = "high-risk";
                meterColor = "#ef4444";

            } else if (riskScore >= 30) {

                riskLevel = "MEDIUM RISK";
                badgeClass = "medium-risk";
                meterColor = "#f59e0b";

            } else {

                riskLevel = "LOW RISK";
                badgeClass = "low-risk";
                meterColor = "#22c55e";

            }

            // Meter
            const degrees = (riskScore / 100) * 360;

            riskMeter.style.background = `
                conic-gradient(
                    ${meterColor} ${degrees}deg,
                    #1e293b ${degrees}deg
                )
            `;

            meterText.textContent = `${riskScore}%`;

            // Save Report
            latestReport = `
Threat Analysis Report

Risk Level: ${riskLevel}
Risk Score: ${riskScore}/100

Warnings:
${foundWords.length > 0 ? foundWords.join(", ") : "None"}

URLs:
${detectedUrls.length > 0 ? detectedUrls.join("\n") : "None"}

Protocol Security:
${hasUnsafeProtocol ? "Unsafe HTTP" : "Secure HTTPS"}

Shortened URLs:
${hasShortenedUrl ? "Detected" : "Not Found"}

Fake Domain Risk:
${hasFakeDomain ? "Suspicious Domain" : "No Fake Domain"}

Scan Time:
${new Date().toLocaleTimeString()}
`;

            // Save to History
            saveToHistory({
                riskLevel,
                riskScore,
                time: new Date().toLocaleTimeString(),
                input: input.substring(0, 100)
            });

            // Final UI
            resultText.innerHTML = `

                <div class="risk-badge ${badgeClass}">
                    ${riskLevel}
                </div>

                <br>

                <strong>Risk Score:</strong> ${riskScore}/100

                <br><br>

                <strong>Detected Warnings:</strong>

                <ul class="warning-list">
                    ${
                        foundWords.length > 0
                        ? foundWords.map(word =>
                            `<li>${word}</li>`
                          ).join("")
                        : "<li>No suspicious keywords detected</li>"
                    }
                </ul>

                <br>

                <strong>Detected URLs:</strong>

                <div class="url-box">
                    ${
                        detectedUrls.length > 0
                        ? detectedUrls.map(url =>
                            `<div class="url-item">${url}</div>`
                          ).join("")
                        : "No URLs detected"
                    }
                </div>

                <br><br>

                <strong>Threat Intelligence:</strong>

                <div class="info-grid">

                    <div class="info-card">
                        <h4>Protocol Security</h4>
                        <p class="${hasUnsafeProtocol ? 'danger-text' : 'safe-text'}">
                            ${hasUnsafeProtocol ? 'Unsafe HTTP' : 'Secure HTTPS'}
                        </p>
                    </div>

                    <div class="info-card">
                        <h4>Shortened URLs</h4>
                        <p class="${hasShortenedUrl ? 'warning-text' : 'safe-text'}">
                            ${hasShortenedUrl ? 'Detected' : 'Not Found'}
                        </p>
                    </div>

                    <div class="info-card">
                        <h4>Fake Domain Risk</h4>
                        <p class="${hasFakeDomain ? 'danger-text' : 'safe-text'}">
                            ${hasFakeDomain ? 'Suspicious Domain' : 'No Fake Domain'}
                        </p>
                    </div>

                    <div class="info-card">
                        <h4>Scan Time</h4>
                        <p>
                            ${new Date().toLocaleTimeString()}
                        </p>
                    </div>

                </div>

            `;

        }, 3000);

    });

    // Copy Report
    copyButton.addEventListener("click", () => {

        if (latestReport === "") {
            alert("No report available to copy.");
            return;
        }

        navigator.clipboard.writeText(latestReport);

        copyButton.textContent = "Report Copied!";

        setTimeout(() => {
            copyButton.textContent = "Copy Report";
        }, 2000);

    });

    // Save History
    function saveToHistory(scan) {

        let history = JSON.parse(localStorage.getItem("scanHistory")) || [];

        history.unshift(scan);

        if (history.length > 5) {
            history.pop();
        }

        localStorage.setItem("scanHistory", JSON.stringify(history));

        loadHistory();

    }

    // Load History
    function loadHistory() {

        let history = JSON.parse(localStorage.getItem("scanHistory")) || [];

        if (history.length === 0) {

            historyList.innerHTML = "No previous scans yet.";
            return;

        }

        historyList.innerHTML = history.map(scan => `

            <div class="history-item">

                <p><strong>Risk:</strong> ${scan.riskLevel}</p>

                <p><strong>Score:</strong> ${scan.riskScore}/100</p>

                <p><strong>Time:</strong> ${scan.time}</p>

                <p><strong>Input:</strong> ${scan.input}</p>

            </div>

        `).join("");

    }

});
>>>>>>> 2d02e07be09bbfb4ad0e76134900398fdf3c758f
