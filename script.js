/* ============================================================
   EMAIL THREAT ANALYZER — ANALYSIS ENGINE v2.0
   25+ detection rules, URL extraction, header parsing,
   entropy analysis, localStorage persistence, animated UI
   ============================================================ */

(function () {
  "use strict";

  // Initialize Lucide icons
  if (window.lucide) lucide.createIcons();

  /* =========================
     DOM REFERENCES
  ========================= */

  const $ = (id) => document.getElementById(id);

  const DOM = {
    // Input
    inputText: $("inputText"),
    scanBtn: $("scanBtn"),
    scanBtnText: $("scanBtnText"),

    // Gauge
    gauge: $("gauge"),
    gaugeGlow: $("gaugeGlow"),
    gaugeScore: $("gaugeScore"),

    // Stats
    scoreStat: $("scoreStat"),
    flagsStat: $("flagsStat"),
    scansStat: $("scansStat"),
    verdictStat: $("verdictStat"),

    // Result
    resultPill: $("resultPill"),
    verdictTitle: $("verdictTitle"),
    verdictText: $("verdictText"),
    tags: $("tags"),

    // Breakdown
    breakdownList: $("breakdownList"),
    breakdownPill: $("breakdownPill"),
    noThreatsMsg: $("noThreatsMsg"),

    // URL
    urlList: $("urlList"),
    urlPill: $("urlPill"),

    // Bars
    barPhishing: $("barPhishing"),
    barCredential: $("barCredential"),
    barUnsafe: $("barUnsafe"),
    barFinance: $("barFinance"),
    barImpersonation: $("barImpersonation"),
    barSocial: $("barSocial"),
    barPhishingVal: $("barPhishingVal"),
    barCredentialVal: $("barCredentialVal"),
    barUnsafeVal: $("barUnsafeVal"),
    barFinanceVal: $("barFinanceVal"),
    barImpersonationVal: $("barImpersonationVal"),
    barSocialVal: $("barSocialVal"),

    // History
    historyList: $("historyList"),
    historyPill: $("historyPill"),
    historyEmpty: $("historyEmpty"),

    // Logs
    logList: $("logList"),

    // Settings
    themeToggle: $("themeToggle"),
    exportBtn: $("exportBtn"),
    clearHistoryBtn: $("clearHistoryBtn"),

    // Overlay
    scanOverlay: $("scanOverlay"),
    scanOverlayTitle: $("scanOverlayTitle"),
    scanOverlayText: $("scanOverlayText"),

    // Sidebar
    sidebar: $("sidebar"),
    hamburgerBtn: $("hamburgerBtn"),
    sidebarOverlay: $("sidebarOverlay"),
    sidebarStatus: $("sidebarStatus"),
  };

  /* =========================
     STATE
  ========================= */

  let state = {
    scansToday: 0,
    history: [],
    sensitivity: "medium",
    lastResult: null,
    categoryHits: {
      urgency: 0,
      credential: 0,
      unsafeUrl: 0,
      finance: 0,
      attachment: 0,
      socialEng: 0,
      impersonation: 0,
      technical: 0,
    },
    totalScans: 0,
  };

  let isScanning = false;

  // Load persisted state
  function loadState() {
    try {
      const saved = localStorage.getItem("threatAnalyzerState");
      if (saved) {
        const parsed = JSON.parse(saved);
        state = { ...state, ...parsed };
      }
    } catch (e) {
      console.warn("Could not load saved state:", e);
    }
  }

  function saveState() {
    try {
      localStorage.setItem("threatAnalyzerState", JSON.stringify(state));
    } catch (e) {
      console.warn("Could not save state:", e);
    }
  }

  loadState();

  /* =========================
     SENSITIVITY MULTIPLIERS
  ========================= */

  const SENSITIVITY = {
    low: 0.7,
    medium: 1.0,
    high: 1.4,
  };

  /* =========================
     DETECTION RULES (25+)
  ========================= */

  const RULES = [
    // ---- Urgency & Pressure (Category: urgency) ----
    {
      regex: /\b(urgent|urgently|immediately|right away)\b/i,
      baseScore: 15,
      flag: "Urgency Language",
      category: "urgency",
      severity: "medium",
      advice: "Legitimate organizations rarely pressure users with urgency.",
    },
    {
      regex: /\b(verify now|verify your|verification required)\b/i,
      baseScore: 18,
      flag: "Verification Pressure",
      category: "urgency",
      severity: "high",
      advice: "Do not verify credentials through email links.",
    },
    {
      regex: /\b(account.{0,10}suspend|account.{0,10}lock|account.{0,10}restrict)/i,
      baseScore: 20,
      flag: "Account Suspension Threat",
      category: "urgency",
      severity: "high",
      advice: "Log in directly at the official website to check your account status.",
    },
    {
      regex: /\b(last warning|final notice|expires today|act now|limited time)\b/i,
      baseScore: 14,
      flag: "Deadline Pressure",
      category: "urgency",
      severity: "medium",
      advice: "Scammers use artificial deadlines to prevent careful thinking.",
    },
    {
      regex: /\b(within \d+ hours?|within \d+ minutes?)\b/i,
      baseScore: 12,
      flag: "Time Constraint",
      category: "urgency",
      severity: "medium",
      advice: "Short time windows are a classic social engineering tactic.",
    },

    // ---- Credential Phishing (Category: credential) ----
    {
      regex: /\b(click here|click below|click the link)\b/i,
      baseScore: 14,
      flag: "Click Lure",
      category: "credential",
      severity: "medium",
      advice: "Hover over links to verify the destination before clicking.",
    },
    {
      regex: /\b(confirm your (account|identity|email|password))\b/i,
      baseScore: 20,
      flag: "Credential Harvest",
      category: "credential",
      severity: "high",
      advice: "Never confirm credentials via email. Go directly to the website.",
    },
    {
      regex: /\b(update.{0,8}(payment|billing|card)|reset.{0,8}password)\b/i,
      baseScore: 18,
      flag: "Payment/Password Reset Lure",
      category: "credential",
      severity: "high",
      advice: "Update payment info only through the official app or website.",
    },
    {
      regex: /\b(log\s*in|sign\s*in|enter.{0,6}password)\b/i,
      baseScore: 10,
      flag: "Login Request",
      category: "credential",
      severity: "low",
      advice: "Be cautious of emails asking you to sign in.",
    },

    // ---- Unsafe URLs (Category: unsafeUrl) ----
    {
      regex: /http:\/\/[^\s]+/i,
      baseScore: 16,
      flag: "HTTP (Unencrypted) Link",
      category: "unsafeUrl",
      severity: "medium",
      advice: "Secure sites use HTTPS. HTTP links may be intercepted.",
    },
    {
      regex: /\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|shorturl|rebrand\.ly)\b/i,
      baseScore: 18,
      flag: "URL Shortener Detected",
      category: "unsafeUrl",
      severity: "high",
      advice: "Shortened URLs hide the real destination. Expand before clicking.",
    },
    {
      regex: /\.(xyz|ru|tk|top|buzz|club|work|click|loan|racing|gq|cf|ga|ml)\b/i,
      baseScore: 15,
      flag: "Suspicious TLD",
      category: "unsafeUrl",
      severity: "medium",
      advice: "These TLDs are commonly abused by phishing campaigns.",
    },
    {
      regex: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      baseScore: 22,
      flag: "IP-Based URL",
      category: "unsafeUrl",
      severity: "high",
      advice: "Legitimate services use domain names, not raw IP addresses.",
    },
    {
      regex: /https?:\/\/[^\s]*@[^\s]+/i,
      baseScore: 20,
      flag: "URL with Embedded Credentials",
      category: "unsafeUrl",
      severity: "high",
      advice: "The @ symbol in URLs can disguise the real domain.",
    },

    // ---- Financial Scam (Category: finance) ----
    {
      regex: /\b(wire transfer|bank transfer|send money|western union)\b/i,
      baseScore: 18,
      flag: "Wire Transfer Request",
      category: "finance",
      severity: "high",
      advice: "Wire transfers are irreversible and commonly used in scams.",
    },
    {
      regex: /\b(crypto|bitcoin|ethereum|wallet address|btc)\b/i,
      baseScore: 14,
      flag: "Cryptocurrency Reference",
      category: "finance",
      severity: "medium",
      advice: "Crypto payments are untraceable. Legitimate orgs rarely request them.",
    },
    {
      regex: /\b(invoice attached|outstanding.{0,10}(payment|balance)|overdue.{0,10}payment)\b/i,
      baseScore: 16,
      flag: "Invoice/Payment Scam",
      category: "finance",
      severity: "high",
      advice: "Verify invoices directly with the vendor through known channels.",
    },
    {
      regex: /\b(lottery|congratulations.{0,15}(won|winner|selected)|prize claim)\b/i,
      baseScore: 22,
      flag: "Lottery/Prize Scam",
      category: "finance",
      severity: "high",
      advice: "You cannot win a lottery you never entered. This is a scam.",
    },

    // ---- Attachment Threats (Category: attachment) ----
    {
      regex: /\.(exe|scr|bat|cmd|msi|vbs|js|wsf|ps1)\b/i,
      baseScore: 22,
      flag: "Dangerous File Extension",
      category: "attachment",
      severity: "high",
      advice: "These file types can execute malicious code on your computer.",
    },
    {
      regex: /\b(enable (macros|content|editing)|macro-enabled)\b/i,
      baseScore: 20,
      flag: "Macro Enablement Request",
      category: "attachment",
      severity: "high",
      advice: "Macros can execute harmful scripts. Never enable them from unknown sources.",
    },
    {
      regex: /\b(download.{0,10}attachment|open.{0,10}attached|see attached)\b/i,
      baseScore: 10,
      flag: "Attachment Reference",
      category: "attachment",
      severity: "low",
      advice: "Verify the sender before opening any attachments.",
    },

    // ---- Social Engineering (Category: socialEng) ----
    {
      regex: /\b(dear (customer|user|client|member|valued))\b/i,
      baseScore: 12,
      flag: "Generic Greeting",
      category: "socialEng",
      severity: "low",
      advice: "Legitimate services usually address you by name.",
    },
    {
      regex: /\b(do not share|confidential|private.{0,6}(matter|information))\b/i,
      baseScore: 10,
      flag: "Secrecy Language",
      category: "socialEng",
      severity: "low",
      advice: "Scammers discourage victims from seeking advice from others.",
    },
    {
      regex: /\b(help me|i am.{0,10}(prince|minister|general)|stranded|inheritance)\b/i,
      baseScore: 20,
      flag: "Advance Fee / 419 Scam",
      category: "socialEng",
      severity: "high",
      advice: "Classic advance fee scam. Never send money to strangers.",
    },

    // ---- Impersonation (Category: impersonation) ----
    {
      regex: /\b(paypal|microsoft|apple|amazon|netflix|google|facebook|instagram|whatsapp)\b/i,
      baseScore: 8,
      flag: "Brand Name Mention",
      category: "impersonation",
      severity: "low",
      advice: "Verify emails claiming to be from major brands by checking the sender domain.",
    },
    {
      regex: /\b(official (notice|communication|letter)|from the desk of|IT department|helpdesk)\b/i,
      baseScore: 14,
      flag: "Authority Impersonation",
      category: "impersonation",
      severity: "medium",
      advice: "Verify the sender through official channels, not via the email itself.",
    },
    {
      regex: /\b(ceo|chief executive|managing director).{0,20}(request|asking|needs)\b/i,
      baseScore: 18,
      flag: "CEO Fraud / BEC",
      category: "impersonation",
      severity: "high",
      advice: "Business Email Compromise — always verify unusual requests by phone.",
    },

    // ---- Technical Indicators (Category: technical) ----
    {
      regex: /[A-Za-z0-9+/]{40,}={0,2}/,
      baseScore: 10,
      flag: "Possible Base64-Encoded Content",
      category: "technical",
      severity: "medium",
      advice: "Encoded content may hide malicious payloads or tracking data.",
    },
    {
      regex: /reply-to:\s*[^\n]+/i,
      baseScore: 6,
      flag: "Reply-To Header Detected",
      category: "technical",
      severity: "low",
      advice: "Check if the Reply-To address matches the From address.",
    },
    {
      regex: /from:\s*[^\n]+/i,
      baseScore: 4,
      flag: "From Header Detected",
      category: "technical",
      severity: "low",
      advice: "Email headers help verify authenticity. Check the domain carefully.",
    },
  ];

  /* =========================
     URL EXTRACTOR
  ========================= */

  function extractURLs(text) {
    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    const matches = text.match(urlRegex) || [];
    return [...new Set(matches)]; // deduplicate
  }

  function assessURL(url) {
    let score = 0;
    const issues = [];
    const lower = url.toLowerCase();

    if (lower.startsWith("http://")) {
      score += 20;
      issues.push("Uses unencrypted HTTP");
    }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 25;
      issues.push("IP-based URL");
    }
    if (/@/.test(url)) {
      score += 25;
      issues.push("Contains embedded @ symbol");
    }
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rebrand\.ly/i.test(url)) {
      score += 20;
      issues.push("URL shortener");
    }
    if (/\.(xyz|ru|tk|top|buzz|club|work|click|loan|gq|cf|ga|ml)\b/i.test(url)) {
      score += 15;
      issues.push("Suspicious TLD");
    }

    // Entropy check on path
    const pathMatch = url.match(/\/([^?#]+)/);
    if (pathMatch) {
      const entropy = calcEntropy(pathMatch[1]);
      if (entropy > 4.2) {
        score += 10;
        issues.push("High-entropy path (possibly obfuscated)");
      }
    }

    // Long URL
    if (url.length > 120) {
      score += 5;
      issues.push("Unusually long URL");
    }

    const verdict =
      score >= 40 ? "unsafe" : score >= 15 ? "suspect" : "safe";
    return { url, score: Math.min(score, 100), issues, verdict };
  }

  /* =========================
     ENTROPY CALCULATOR
  ========================= */

  function calcEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /* =========================
     MAIN ANALYZER
  ========================= */

  function analyze(text) {
    const value = text.toLowerCase();
    const multiplier = SENSITIVITY[state.sensitivity] || 1;

    let totalScore = 0;
    const matches = [];
    const categoryCounts = {};

    RULES.forEach((rule) => {
      // Test against lowercase but capture from original text for display
      const match = rule.regex.exec(value);
      if (match) {
        const adjustedScore = Math.round(rule.baseScore * multiplier);
        totalScore += adjustedScore;
        categoryCounts[rule.category] =
          (categoryCounts[rule.category] || 0) + 1;

        // Extract matched text from original (preserving case)
        const originalMatch = text.substring(match.index, match.index + match[0].length);

        matches.push({
          flag: rule.flag,
          category: rule.category,
          severity: rule.severity,
          score: adjustedScore,
          matched: originalMatch,
          advice: rule.advice,
        });
      }
    });

    // Bonus: mismatched From/Reply-To
    const fromMatch = text.match(/from:\s*([^\n<]+@[^\n>\s]+)/i);
    const replyToMatch = text.match(/reply-to:\s*([^\n<]+@[^\n>\s]+)/i);
    if (fromMatch && replyToMatch) {
      const fromDomain = fromMatch[1].split("@")[1];
      const replyDomain = replyToMatch[1].split("@")[1];
      if (fromDomain && replyDomain && fromDomain !== replyDomain) {
        totalScore += Math.round(18 * multiplier);
        matches.push({
          flag: "From/Reply-To Mismatch",
          category: "technical",
          severity: "high",
          score: Math.round(18 * multiplier),
          matched: `From: ${fromDomain} ≠ Reply-To: ${replyDomain}`,
          advice:
            "A mismatched Reply-To domain is a strong phishing indicator.",
        });
      }
    }

    // URL extraction
    const urls = extractURLs(text);
    const urlResults = urls.map(assessURL);

    // Add URL scores to total (weighted)
    urlResults.forEach((ur) => {
      if (ur.verdict === "unsafe") totalScore += Math.round(8 * multiplier);
      else if (ur.verdict === "suspect") totalScore += Math.round(4 * multiplier);
    });

    totalScore = Math.min(totalScore, 100);

    return {
      score: totalScore,
      matches,
      categoryCounts,
      urls: urlResults,
      flags: matches.map((m) => m.flag),
    };
  }

  /* =========================
     UI: GAUGE ANIMATION
  ========================= */

  function animateGauge(targetScore) {
    const gauge = DOM.gauge;
    let current = 0;
    const duration = 1200;
    const start = performance.now();

    // Set gauge color based on score
    let gaugeColor = "var(--success)";
    if (targetScore >= 70) gaugeColor = "var(--danger)";
    else if (targetScore >= 35) gaugeColor = "var(--warning)";
    else if (targetScore > 0) gaugeColor = "var(--accent)";

    gauge.style.setProperty("--gauge-color", gaugeColor);
    DOM.gaugeGlow.style.boxShadow = `0 0 30px ${gaugeColor}`;

    function step(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      current = Math.round(eased * targetScore);

      gauge.style.setProperty("--gauge-value", current);
      DOM.gaugeScore.textContent = current + "%";

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        // Activate glow if score > 0
        if (targetScore > 0) {
          DOM.gaugeGlow.classList.add("active");
        }
      }
    }

    DOM.gaugeGlow.classList.remove("active");
    requestAnimationFrame(step);
  }

  /* =========================
     UI: STAT CARDS
  ========================= */

  function updateStats(result) {
    // Score
    DOM.scoreStat.textContent = result.score + "%";
    DOM.scoreStat.className = "stat-value";
    if (result.score >= 70) DOM.scoreStat.classList.add("score-high");
    else if (result.score >= 35) DOM.scoreStat.classList.add("score-medium");
    else DOM.scoreStat.classList.add("score-low");

    // Flags
    DOM.flagsStat.textContent = result.matches.length;

    // Scans
    DOM.scansStat.textContent = state.scansToday;

    // Verdict
    let verdict = "Clean";
    let verdictClass = "score-low";
    if (result.score >= 70) {
      verdict = "High Risk";
      verdictClass = "score-high";
    } else if (result.score >= 35) {
      verdict = "Suspicious";
      verdictClass = "score-medium";
    } else if (result.score > 0) {
      verdict = "Low Risk";
      verdictClass = "score-low";
    }
    DOM.verdictStat.textContent = verdict;
    DOM.verdictStat.className = "stat-value " + verdictClass;

    return verdict;
  }

  /* =========================
     UI: RESULT PANEL
  ========================= */

  function updateResult(result, verdict) {
    // Pill
    DOM.resultPill.textContent = verdict;
    DOM.resultPill.className = "pill";
    if (result.score >= 70) DOM.resultPill.classList.add("danger");
    else if (result.score >= 35) DOM.resultPill.classList.add("warning");
    else DOM.resultPill.classList.add("success");

    // Verdict box
    let icon = "shield-check";
    if (result.score >= 70) icon = "shield-x";
    else if (result.score >= 35) icon = "shield-alert";

    DOM.verdictTitle.innerHTML = `<i data-lucide="${icon}"></i> ${verdict} Detected`;
    if (result.matches.length > 0) {
      DOM.verdictText.textContent = result.flags.join(", ");
    } else {
      DOM.verdictText.textContent = "No significant threat indicators found.";
    }

    // Tags
    DOM.tags.innerHTML = "";
    const tagItems =
      result.flags.length > 0 ? result.flags : ["No Indicators"];

    tagItems.forEach((flag, i) => {
      const tag = document.createElement("div");
      tag.className = "tag";
      if (result.score >= 70) tag.classList.add("danger");
      else if (result.score >= 35) tag.classList.add("warning");
      else tag.classList.add("success");
      tag.textContent = flag;
      tag.style.animationDelay = i * 0.06 + "s";
      DOM.tags.appendChild(tag);
    });

    // Re-init icons
    if (window.lucide) lucide.createIcons();
  }

  /* =========================
     UI: DETAILED BREAKDOWN
  ========================= */

  function updateBreakdown(result) {
    DOM.breakdownList.innerHTML = "";
    DOM.breakdownPill.textContent = result.matches.length + " rules matched";

    if (result.matches.length === 0) {
      const div = document.createElement("div");
      div.className = "no-threats-msg";
      div.innerHTML = `
        <i data-lucide="shield-check"></i>
        <p>No threat indicators detected in this content</p>
      `;
      DOM.breakdownList.appendChild(div);
      if (window.lucide) lucide.createIcons();
      return;
    }

    // Sort by score descending
    const sorted = [...result.matches].sort((a, b) => b.score - a.score);

    sorted.forEach((match, i) => {
      const item = document.createElement("div");
      item.className = "breakdown-item";
      item.style.animationDelay = i * 0.05 + "s";

      const categoryIcons = {
        urgency: "alert-triangle",
        credential: "key",
        unsafeUrl: "link",
        finance: "banknote",
        attachment: "paperclip",
        socialEng: "users",
        impersonation: "user-x",
        technical: "cpu",
      };

      const icon = categoryIcons[match.category] || "alert-circle";
      const sevClass =
        match.severity === "high"
          ? "severity-high"
          : match.severity === "medium"
          ? "severity-medium"
          : "severity-low";

      item.innerHTML = `
        <div class="breakdown-header">
          <div class="breakdown-category">
            <i data-lucide="${icon}"></i>
            ${match.flag}
          </div>
          <span class="breakdown-severity ${sevClass}">${match.severity}</span>
        </div>
        <div class="breakdown-match">Matched: <mark>${escapeHTML(match.matched)}</mark> (+${match.score} pts)</div>
        <div class="breakdown-advice">${match.advice}</div>
      `;

      DOM.breakdownList.appendChild(item);
    });

    if (window.lucide) lucide.createIcons();
  }

  /* =========================
     UI: URL ANALYSIS
  ========================= */

  function updateURLPanel(urlResults) {
    DOM.urlList.innerHTML = "";
    DOM.urlPill.textContent = urlResults.length + " URLs found";

    if (urlResults.length === 0) {
      DOM.urlList.innerHTML = `
        <div class="empty-state">
          <i data-lucide="globe"></i>
          <p>No URLs detected in the input text</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    urlResults.forEach((ur, i) => {
      const item = document.createElement("div");
      item.className = "url-item";
      item.style.animationDelay = i * 0.06 + "s";

      const iconClass = ur.verdict;
      const icon =
        ur.verdict === "safe"
          ? "check-circle"
          : ur.verdict === "unsafe"
          ? "x-circle"
          : "alert-circle";

      const assessment =
        ur.issues.length > 0 ? ur.issues.join(" · ") : "No issues detected";

      item.innerHTML = `
        <div class="url-icon ${iconClass}"><i data-lucide="${icon}"></i></div>
        <div class="url-details">
          <div class="url-text">${escapeHTML(ur.url)}</div>
          <div class="url-assessment">${assessment}</div>
        </div>
      `;

      DOM.urlList.appendChild(item);
    });

    if (window.lucide) lucide.createIcons();
  }

  /* =========================
     UI: THREAT BARS
  ========================= */

  function updateBars() {
    if (state.totalScans === 0) return;

    const cats = state.categoryHits;
    const total = state.totalScans;

    const data = {
      phishing: Math.min(Math.round((cats.urgency / total) * 100), 100),
      credential: Math.min(Math.round((cats.credential / total) * 100), 100),
      unsafe: Math.min(Math.round((cats.unsafeUrl / total) * 100), 100),
      finance: Math.min(Math.round((cats.finance / total) * 100), 100),
      impersonation: Math.min(Math.round((cats.impersonation / total) * 100), 100),
      social: Math.min(Math.round((cats.socialEng / total) * 100), 100),
    };

    DOM.barPhishing.style.width = data.phishing + "%";
    DOM.barPhishingVal.textContent = data.phishing + "%";

    DOM.barCredential.style.width = data.credential + "%";
    DOM.barCredentialVal.textContent = data.credential + "%";

    DOM.barUnsafe.style.width = data.unsafe + "%";
    DOM.barUnsafeVal.textContent = data.unsafe + "%";

    DOM.barFinance.style.width = data.finance + "%";
    DOM.barFinanceVal.textContent = data.finance + "%";

    DOM.barImpersonation.style.width = data.impersonation + "%";
    DOM.barImpersonationVal.textContent = data.impersonation + "%";

    DOM.barSocial.style.width = data.social + "%";
    DOM.barSocialVal.textContent = data.social + "%";
  }

  /* =========================
     UI: HISTORY
  ========================= */

  function renderHistory() {
    DOM.historyList.innerHTML = "";
    DOM.historyPill.textContent = state.history.length + " scans";

    if (state.history.length === 0) {
      DOM.historyList.innerHTML = `
        <div class="empty-state" id="historyEmpty">
          <i data-lucide="inbox"></i>
          <p>No scans yet. Start by analyzing an email or URL.</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    state.history.forEach((item, i) => {
      const div = document.createElement("div");
      div.className = "history-item";
      div.style.animationDelay = i * 0.04 + "s";

      let scoreClass = "low";
      if (item.score >= 70) scoreClass = "high";
      else if (item.score >= 35) scoreClass = "medium";

      div.innerHTML = `
        <div class="history-info">
          <strong>${escapeHTML(item.title)}</strong>
          <small>${item.verdict} · ${item.time}</small>
        </div>
        <div class="history-score ${scoreClass}">${item.score}%</div>
      `;

      DOM.historyList.appendChild(div);
    });
  }

  /* =========================
     UI: TERMINAL LOGS
  ========================= */

  function pushLog(message, level = "info") {
    const entry = document.createElement("div");
    entry.className = "log-entry";

    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    const prefix =
      level === "danger"
        ? "[ERR]"
        : level === "warning"
        ? "[WRN]"
        : level === "success"
        ? "[OK] "
        : "[LOG]";

    entry.innerHTML = `
      <span class="log-time">${time}</span>
      <span class="log-msg ${level}">${prefix} ${escapeHTML(message)}</span>
    `;

    DOM.logList.prepend(entry);

    // Keep max 50 log entries
    while (DOM.logList.children.length > 50) {
      DOM.logList.removeChild(DOM.logList.lastChild);
    }
  }

  /* =========================
     SCAN ORCHESTRATOR
  ========================= */

  function performScan() {
    if (isScanning) return; // Guard against double-scan

    const text = DOM.inputText.value.trim();
    if (!text) {
      pushLog("Scan aborted — no input provided", "warning");
      DOM.inputText.focus();
      return;
    }

    isScanning = true;

    // Show scanning state
    DOM.scanBtn.classList.add("scanning");
    DOM.scanBtnText.textContent = "Scanning...";
    DOM.scanOverlay.classList.add("active");

    pushLog("Initiating threat analysis...", "info");

    // Phase 1: Quick delay for scanning effect
    setTimeout(() => {
      pushLog("Extracting URLs and email headers...", "info");
      DOM.scanOverlayText.textContent = "Extracting URLs and headers...";
    }, 400);

    setTimeout(() => {
      pushLog("Running 28+ detection rules...", "info");
      DOM.scanOverlayText.textContent = "Pattern matching in progress...";
    }, 800);

    // Phase 2: Actual analysis
    setTimeout(() => {
      const result = analyze(text);

      DOM.scanOverlayTitle.textContent = "Analysis Complete";
      DOM.scanOverlayText.textContent = result.score + "% threat level detected";

      pushLog(`Analysis complete — ${result.score}% threat score`, result.score >= 70 ? "danger" : result.score >= 35 ? "warning" : "success");
      pushLog(`${result.matches.length} flags detected, ${result.urls.length} URLs analyzed`, "info");

      // Update state
      state.scansToday++;
      state.totalScans++;
      state.lastResult = result;

      // Track category hits (1 per scan if category was present)
      for (const cat in result.categoryCounts) {
        if (state.categoryHits[cat] !== undefined) {
          state.categoryHits[cat] += 1;
        }
      }

      // Add to history
      const verdict =
        result.score >= 70
          ? "High Risk"
          : result.score >= 35
          ? "Suspicious"
          : result.score > 0
          ? "Low Risk"
          : "Clean";

      state.history.unshift({
        title: text.slice(0, 40) + (text.length > 40 ? "…" : ""),
        verdict,
        score: result.score,
        time: new Date().toLocaleString(),
        flags: result.flags,
      });

      state.history = state.history.slice(0, 50);

      saveState();

      // Phase 3: Update UI
      setTimeout(() => {
        DOM.scanOverlay.classList.remove("active");
        DOM.scanBtn.classList.remove("scanning");
        DOM.scanBtnText.textContent = "Analyze Threat";

        animateGauge(result.score);
        const verdictText = updateStats(result);
        updateResult(result, verdictText);
        updateBreakdown(result);
        updateURLPanel(result.urls);
        updateBars();
        renderHistory();

        DOM.sidebarStatus.textContent =
          verdictText + " — scan completed";

        pushLog("Dashboard updated successfully", "success");
        isScanning = false;
      }, 500);
    }, 1400);
  }

  /* =========================
     THEME
  ========================= */

  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    DOM.themeToggle.checked = theme === "dark";
  }

  setTheme(localStorage.getItem("theme") || "dark");

  DOM.themeToggle.addEventListener("change", function () {
    setTheme(this.checked ? "dark" : "light");
    pushLog("Theme changed to " + (this.checked ? "dark" : "light"), "info");
  });

  /* =========================
     SENSITIVITY
  ========================= */

  const sensitivityBtns = document.querySelectorAll(".sensitivity-option");

  // Set initial state from persisted sensitivity
  sensitivityBtns.forEach((btn) => {
    if (btn.dataset.level === state.sensitivity) {
      btn.classList.add("active");
      btn.setAttribute("aria-checked", "true");
    } else {
      btn.classList.remove("active");
      btn.setAttribute("aria-checked", "false");
    }
  });

  sensitivityBtns.forEach((btn) => {
    btn.addEventListener("click", function () {
      sensitivityBtns.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-checked", "false");
      });
      this.classList.add("active");
      this.setAttribute("aria-checked", "true");
      state.sensitivity = this.dataset.level;
      saveState();
      pushLog("Sensitivity set to: " + state.sensitivity, "info");
    });
  });

  /* =========================
     EXPORT
  ========================= */

  DOM.exportBtn.addEventListener("click", function () {
    if (!state.lastResult) {
      pushLog("No scan results to export", "warning");
      return;
    }

    const report = {
      timestamp: new Date().toISOString(),
      sensitivity: state.sensitivity,
      score: state.lastResult.score,
      flags: state.lastResult.flags,
      matches: state.lastResult.matches,
      urls: state.lastResult.urls,
      verdict:
        state.lastResult.score >= 70
          ? "High Risk"
          : state.lastResult.score >= 35
          ? "Suspicious"
          : "Low Risk",
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);

    pushLog("Report exported as JSON", "success");
  });

  /* =========================
     CLEAR HISTORY
  ========================= */

  DOM.clearHistoryBtn.addEventListener("click", function () {
    state.history = [];
    state.categoryHits = {
      urgency: 0,
      credential: 0,
      unsafeUrl: 0,
      finance: 0,
      attachment: 0,
      socialEng: 0,
      impersonation: 0,
      technical: 0,
    };
    state.totalScans = 0;
    state.scansToday = 0;
    state.lastResult = null;

    saveState();
    renderHistory();
    updateBars();

    DOM.scansStat.textContent = "0";

    pushLog("History and statistics cleared", "warning");
  });

  /* =========================
     NAVIGATION
  ========================= */

  const navBtns = document.querySelectorAll(".nav-btn");

  navBtns.forEach((btn) => {
    btn.addEventListener("click", function () {
      navBtns.forEach((b) => {
        b.classList.remove("active");
        b.removeAttribute("aria-current");
      });
      this.classList.add("active");
      this.setAttribute("aria-current", "true");

      const target = document.getElementById(this.dataset.target);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }

      // Close mobile sidebar
      DOM.sidebar.classList.remove("open");
      DOM.sidebarOverlay.classList.remove("visible");
    });
  });

  /* =========================
     MOBILE SIDEBAR
  ========================= */

  DOM.hamburgerBtn.addEventListener("click", function () {
    DOM.sidebar.classList.toggle("open");
    DOM.sidebarOverlay.classList.toggle("visible");
  });

  DOM.sidebarOverlay.addEventListener("click", function () {
    DOM.sidebar.classList.remove("open");
    DOM.sidebarOverlay.classList.remove("visible");
  });

  /* =========================
     SCAN BUTTON
  ========================= */

  DOM.scanBtn.addEventListener("click", performScan);

  // Also scan on Ctrl+Enter
  DOM.inputText.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      performScan();
    }
  });

  /* =========================
     UTILITY
  ========================= */

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  /* =========================
     INITIALIZE
  ========================= */

  // Restore UI from persisted state
  DOM.scansStat.textContent = state.scansToday;
  renderHistory();
  updateBars();

  // Initial logs
  pushLog("Threat Analyzer v2.0 initialized", "success");
  pushLog("28 detection rules loaded across 8 categories", "info");
  pushLog("Monitoring active — awaiting scan input", "info");
  pushLog("Tip: Press Ctrl+Enter to scan quickly", "info");
})();