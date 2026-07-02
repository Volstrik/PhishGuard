// static/js/scanner.js

// ==================== RECOMMENDATIONS BY RISK ====================
const RECOMMENDATIONS = {
    "Safe": "This URL appears to be safe. No threats were detected by our security engines. You can visit it with confidence.",
    "Suspicious": "This URL shows some suspicious characteristics. Proceed with caution and avoid entering personal information.",
    "High Risk": "This URL is high risk. We strongly recommend avoiding this website as it may attempt to steal your data.",
    "Malicious": "This URL is malicious and dangerous. Do NOT visit this website. It has been flagged by multiple security engines."
};

// ==================== RISK ICON MAP ====================
const RISK_ICONS = {
    "Safe":      "fa-shield-halved",
    "Suspicious":"fa-triangle-exclamation",
    "High Risk": "fa-circle-exclamation",
    "Malicious": "fa-skull-crossbones"
};

// ==================== RISK COLOR MAP ====================
const RISK_COLORS = {
    "Safe":      "#00ff88",
    "Suspicious":"#ffd93d",
    "High Risk": "#ff8c42",
    "Malicious": "#ff4757"
};


// ==================== LOADING STEP ANIMATOR ====================
let stepInterval = null;

function animateSteps() {
    const steps    = ["step1", "step2", "step3"];
    let   current  = 0;

    // Reset all steps
    steps.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("active");
    });

    stepInterval = setInterval(() => {
        // Remove active from all
        steps.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.remove("active");
        });

        // Activate current step
        const activeEl = document.getElementById(steps[current]);
        if (activeEl) activeEl.classList.add("active");

        current = (current + 1) % steps.length;
    }, 3000);
}

function stopStepAnimation() {
    if (stepInterval) {
        clearInterval(stepInterval);
        stepInterval = null;
    }

    // Mark all steps as done
    ["step1", "step2", "step3"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add("active");
    });
}


// ==================== SHOW / HIDE HELPERS ====================
function showElement(id)  {
    const el = document.getElementById(id);
    if (el) el.style.display = "block";
}

function hideElement(id)  {
    const el = document.getElementById(id);
    if (el) el.style.display = "none";
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setHTML(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}


// ==================== DISPLAY RESULT ====================
function displayResult(data) {
    const riskClass = data.risk_level.toLowerCase().replace(" ", "-");
    const color     = RISK_COLORS[data.risk_level] || "#00ff88";
    const icon      = RISK_ICONS[data.risk_level]  || "fa-shield-halved";

    // --- Result Header ---
    const resultIcon = document.getElementById("resultIcon");
    if (resultIcon) {
        resultIcon.className = `result-icon ${riskClass}`;
        resultIcon.innerHTML = `<i class="fas ${icon}"></i>`;
    }

    const resultTitle = document.getElementById("resultRiskLevel");
    if (resultTitle) {
        resultTitle.textContent = data.risk_level;
        resultTitle.style.color = color;
    }

    setText("resultUrl", data.url);

    // --- Score Circle ---
    setText("resultScore", data.score);

    const scoreCircle = document.getElementById("resultScoreCircle");
    if (scoreCircle) {
        scoreCircle.style.borderColor = color;
        scoreCircle.querySelector("span").style.color = color;
    }

    // --- Engine Counts ---
    setText("safeCount",       data.safe);
    setText("suspiciousCount", data.suspicious);
    setText("maliciousCount",  data.malicious);
    setText("undetectedCount", data.undetected);

    // --- Progress Bar ---
    setText("progressScore", `${data.score} / 100`);

    const fill = document.getElementById("progressFill");
    if (fill) {
        fill.style.width      = `${data.score}%`;
        fill.style.background = color;
    }

    // --- Recommendation ---
    const rec = document.getElementById("resultRecommendation");
    if (rec) {
        rec.style.borderColor     = color;
        rec.style.backgroundColor = `${color}11`;
        rec.querySelector("i").style.color = color;
    }

    setText(
        "recommendationText",
        RECOMMENDATIONS[data.risk_level] || "Analysis complete."
    );
// --- OSINT Intelligence ---
    if (data.domain && data.whois && data.ssl) {
        renderOsintSection(data);
    }

    // --- Show Result Card ---
    showElement("scanResult");
}


// ==================== OSINT RENDERING ====================
function renderOsintSection(data) {
    const section = document.getElementById("osintSection");
    if (!section) return;

    setText("osintDomain", data.domain);

    // WHOIS
    const whois = data.whois;
    setText("whoisRegistrar", whois.registrar || "Unknown");
    setText("whoisCreated",   whois.created_date || "Unknown");

    const ageEl = document.getElementById("whoisAge");
    if (ageEl) {
        const ageColor = whois.is_new_domain ? "#ff4757" : "#00ff88";
        ageEl.innerHTML = `<span style="color:${ageColor}">${whois.age_label}</span>`;
    }

    // SSL
    const ssl = data.ssl;
    const sslStatusEl = document.getElementById("sslStatus");
    if (sslStatusEl) {
        if (ssl.has_ssl && ssl.is_valid) {
            sslStatusEl.innerHTML = `<span class="osint-pill good"><i class="fas fa-check"></i> Valid</span>`;
        } else if (ssl.has_ssl && !ssl.is_valid) {
            sslStatusEl.innerHTML = `<span class="osint-pill bad"><i class="fas fa-xmark"></i> Expired</span>`;
        } else {
            sslStatusEl.innerHTML = `<span class="osint-pill bad"><i class="fas fa-xmark"></i> No SSL</span>`;
        }
    }

    setText("sslIssuer", ssl.issuer || "—");
    setText("sslExpiry", ssl.valid_until || "—");

    // Warnings banner
    const warningsEl = document.getElementById("osintWarnings");
    if (data.osint_warnings && data.osint_warnings.length > 0) {
        warningsEl.innerHTML = data.osint_warnings.map(w => `
            <div class="osint-warning-item">
                <i class="fas fa-triangle-exclamation"></i> ${w}
            </div>
        `).join("");
        warningsEl.style.display = "block";
    } else {
        warningsEl.style.display = "none";
    }

    section.style.display = "block";

    // --- Show Result Card ---
    showElement("scanResult");
}


// ==================== MAIN SCAN FUNCTION ====================
async function startScan() {
    // Get URL from either scanner page input or dashboard quick scan
    if (cooldownActive) return;
    const inputEl = document.getElementById("scanInput") ||
                    document.getElementById("quickScanInput");

    if (!inputEl) return;

    const url = inputEl.value.trim();

    if (!url) {
        inputEl.focus();
        inputEl.style.borderColor = "#ff4757";
        setTimeout(() => {
            inputEl.style.borderColor = "";
        }, 2000);
        return;
    }

    // --- UI: Show loading, hide result ---
    hideElement("scanResult");
    showElement("scanLoading");

    // Disable scan button
    const btn = document.getElementById("scanBtn");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>Scanning...</span>`;
    }

    // Start step animation
    animateSteps();

    try {
        // --- POST to Flask /scan route ---
        const response = await fetch("/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Stop loading animation
        stopStepAnimation();
        hideElement("scanLoading");

        if (!response.ok || data.error) {
            showError(data.error || "Something went wrong. Please try again.");
            return;
        }

        // If on dashboard, redirect to scanner page with result
        if (window.location.pathname === "/") {
            // Store result temporarily and redirect
            sessionStorage.setItem("lastScanResult", JSON.stringify(data));
            window.location.href = "/scanner";
            return;
        }

        // Display result on scanner page
        displayResult(data);

    } catch (err) {
        stopStepAnimation();
        hideElement("scanLoading");
        showError("Network error. Please check your connection and try again.");
        console.error("Scan error:", err);

    } finally {
        // Start cooldown instead of immediately re-enabling
        // (VirusTotal free tier = 4 requests/minute, scan uses ~9-10)
        startCooldown(65);
    }
    // ==================== COOLDOWN STATE ====================
let cooldownActive = false;

function startCooldown(seconds = 65) {
    cooldownActive = true;
    const btn = document.getElementById("scanBtn");
    let remaining = seconds;

    const tick = () => {
        if (remaining <= 0) {
            cooldownActive = false;
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="fas fa-magnifying-glass"></i> <span>Scan URL</span>`;
            }
            return;
        }
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fas fa-hourglass-half"></i> <span>Wait ${remaining}s</span>`;
        }
        remaining--;
        setTimeout(tick, 1000);
    };
    tick();
}
}


// ==================== QUICK SCAN (DASHBOARD) ====================
function quickScan() {
    const inputEl = document.getElementById("quickScanInput");
    if (!inputEl) return;

    const url = inputEl.value.trim();
    if (!url) {
        inputEl.focus();
        inputEl.style.borderColor = "#ff4757";
        setTimeout(() => inputEl.style.borderColor = "", 2000);
        return;
    }

    // Store URL and redirect to scanner page
    sessionStorage.setItem("pendingUrl", url);
    window.location.href = "/scanner";
}


// ==================== RESET SCANNER ====================
function resetScanner() {
    hideElement("scanResult");
    hideElement("scanLoading");
    hideElement("osintSection");
    const inputEl = document.getElementById("scanInput");
    if (inputEl) {
        inputEl.value = "";
        inputEl.focus();
    }

    // Reset step indicators
    ["step1", "step2", "step3"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("active");
    });
}


// ==================== SHOW ERROR ====================
function showError(message) {
    const resultEl = document.getElementById("scanResult");
    if (!resultEl) return;

    resultEl.style.display = "block";
    resultEl.innerHTML = `
        <div class="result-header">
            <div class="result-icon malicious">
                <i class="fas fa-circle-xmark"></i>
            </div>
            <div class="result-title-block">
                <h2 style="color:#ff4757">Scan Failed</h2>
                <p class="result-url">${message}</p>
            </div>
        </div>
        <div class="result-actions">
            <button onclick="resetScanner()">
                <i class="fas fa-rotate-left"></i> Try Again
            </button>
        </div>
    `;
}


// ==================== AUTO LOAD PENDING URL ====================
// If redirected from dashboard quick scan, auto-fill and run scan
document.addEventListener("DOMContentLoaded", () => {
    const pendingUrl = sessionStorage.getItem("pendingUrl");
    if (pendingUrl) {
        sessionStorage.removeItem("pendingUrl");
        const inputEl = document.getElementById("scanInput");
        if (inputEl) {
            inputEl.value = pendingUrl;
            // Small delay so page renders first
            setTimeout(() => startScan(), 300);
        }
    }

    // If redirected after a dashboard scan completed
    const lastResult = sessionStorage.getItem("lastScanResult");
    if (lastResult) {
        sessionStorage.removeItem("lastScanResult");
        try {
            const data = JSON.parse(lastResult);
            displayResult(data);
        } catch (e) {
            console.error("Failed to load last result:", e);
        }
    }
});