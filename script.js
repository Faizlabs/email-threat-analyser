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