// static/js/dashboard.js

function startClock() {
    const el = document.getElementById("liveClock");
    if (!el) return;
    function tick() {
        const now  = new Date();
        const h    = String(now.getHours()).padStart(2,"0");
        const m    = String(now.getMinutes()).padStart(2,"0");
        el.textContent = `${h}:${m}`;
    }
    tick();
    setInterval(tick, 1000);
}

function animateCounters() {
    document.querySelectorAll(".stat-value").forEach(el => {
        const raw = el.textContent.trim();
        const num = parseInt(raw.replace(/[^0-9]/g, ""), 10);
        if (isNaN(num) || raw.includes("/")) return;
        let cur = 0;
        const step = Math.max(1, Math.floor(num / 40));
        const iv = setInterval(() => {
            cur += step;
            if (cur >= num) { cur = num; clearInterval(iv); }
            el.textContent = cur.toLocaleString();
        }, 28);
    });
}

function updateBadge() {
    const badge = document.querySelector(".badge");
    if (!badge) return;
    document.querySelectorAll(".stat-card").forEach(card => {
        const label = card.querySelector(".stat-label");
        const val   = card.querySelector(".stat-value");
        if (label && val && label.textContent.trim() === "Malicious") {
            const n = parseInt(val.textContent.replace(/[^0-9]/g,""), 10);
            badge.textContent = (!isNaN(n) && n > 0) ? (n > 99 ? "99+" : n) : "!";
        }
    });
}

function initCardGlow() {
    document.querySelectorAll(".stat-card, .chart-card, .feat-card").forEach(card => {
        card.addEventListener("mousemove", e => {
            const r = card.getBoundingClientRect();
            card.style.background = `radial-gradient(circle at ${e.clientX-r.left}px ${e.clientY-r.top}px, rgba(0,255,136,0.07), rgba(13,26,18,0.82) 65%)`;
        });
        card.addEventListener("mouseleave", () => { card.style.background = ""; });
    });
}

function initScrollTop() {
    const btn = document.createElement("button");
    btn.innerHTML = `<i class="fas fa-chevron-up"></i>`;
    btn.style.cssText = `
        position:fixed; bottom:24px; right:24px;
        width:38px; height:38px;
        background:rgba(0,255,136,0.12);
        color:#00ff88;
        border:1px solid rgba(0,255,136,0.4);
        border-radius:50%; font-size:13px;
        cursor:pointer; display:none;
        align-items:center; justify-content:center;
        z-index:999;
        box-shadow:0 0 16px rgba(0,255,136,0.3);
        transition:all 0.3s ease;
    `;
    document.body.appendChild(btn);
    window.addEventListener("scroll", () => {
        btn.style.display = window.scrollY > 200 ? "flex" : "none";
    });
    btn.addEventListener("click", () => window.scrollTo({ top:0, behavior:"smooth" }));
}

function autoRefresh() {
    const REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes

    setTimeout(function checkAndRefresh() {
        const activeEl = document.activeElement;
        const isTyping = activeEl && (
            activeEl.tagName === "INPUT" ||
            activeEl.tagName === "TEXTAREA"
        );

        const scanInProgress = document.getElementById("scanLoading") &&
            document.getElementById("scanLoading").style.display !== "none";

        if (isTyping || scanInProgress) {
            // User is busy — postpone refresh by another 30s, check again
            setTimeout(checkAndRefresh, 30000);
        } else {
            window.location.reload();
        }
    }, REFRESH_INTERVAL);
}

document.addEventListener("DOMContentLoaded", () => {
    startClock();
    animateCounters();
    updateBadge();
    initCardGlow();
    initScrollTop();
    autoRefresh();
});