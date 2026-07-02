// static/js/charts.js

// ==================== COLOR PALETTE ====================
const COLORS = {
    green:  "#00ff88",
    yellow: "#ffd93d",
    orange: "#ff8c42",
    red:    "#ff4757",
    teal:   "#00d4aa",
    muted:  "#4a6a55",
    bg:     "#0f1612",
    grid:   "rgba(0, 255, 136, 0.08)"
};

// ==================== CHART DEFAULTS ====================
Chart.defaults.color          = "#7a9e8a";
Chart.defaults.font.family    = "Rajdhani";
Chart.defaults.font.size      = 12;
Chart.defaults.borderColor    = "rgba(0, 255, 136, 0.08)";


// ==================== HELPER: GET DONUT DATA ====================
function getDonutData(data) {
    return {
        labels: ["Safe", "Suspicious", "High Risk", "Malicious"],
        datasets: [{
            data: [
                data.safe       || 0,
                data.suspicious || 0,
                data.high_risk  || 0,
                data.malicious  || 0
            ],
            backgroundColor: [
                "rgba(0,  255, 136, 0.75)",
                "rgba(255, 217,  61, 0.75)",
                "rgba(255, 140,  66, 0.75)",
                "rgba(255,  71,  87, 0.75)"
            ],
            borderColor: [
                COLORS.green,
                COLORS.yellow,
                COLORS.orange,
                COLORS.red
            ],
            borderWidth: 1.5,
            hoverOffset: 6
        }]
    };
}


// ==================== DONUT CHART OPTIONS ====================
const donutOptions = {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "68%",
    plugins: {
        legend: { display: false },
        tooltip: {
            callbacks: {
                label: ctx => ` ${ctx.label}: ${ctx.parsed} URLs`
            }
        }
    }
};


// ==================== TREND LINE CHART ====================
function buildTrendChart(canvasId, scores) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    // Generate labels like 1, 2, 3... based on number of scores
    const labels = scores.map((_, i) => i + 1);

    new Chart(canvas, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Threat Score",
                data: scores,
                borderColor:     COLORS.green,
                backgroundColor: "rgba(0, 255, 136, 0.08)",
                borderWidth:     2,
                pointBackgroundColor: COLORS.green,
                pointBorderColor:     COLORS.bg,
                pointBorderWidth:     2,
                pointRadius:          4,
                pointHoverRadius:     7,
                fill:            true,
                tension:         0.4   // smooth curve
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid:  { color: COLORS.grid },
                    ticks: { color: COLORS.muted }
                },
                y: {
                    min:  0,
                    max:  100,
                    grid: { color: COLORS.grid },
                    ticks: {
                        color: COLORS.muted,
                        stepSize: 25
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => ` Score: ${ctx.parsed.y} / 100`
                    }
                }
            }
        }
    });
}


// ==================== BAR CHART (REPORTS PAGE) ====================
function buildBarChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    new Chart(canvas, {
        type: "bar",
        data: {
            labels: ["Safe", "Suspicious", "High Risk", "Malicious"],
            datasets: [{
                label: "Number of URLs",
                data: [
                    data.safe       || 0,
                    data.suspicious || 0,
                    data.high_risk  || 0,
                    data.malicious  || 0
                ],
                backgroundColor: [
                    "rgba(0,  255, 136, 0.2)",
                    "rgba(255, 217,  61, 0.2)",
                    "rgba(255, 140,  66, 0.2)",
                    "rgba(255,  71,  87, 0.2)"
                ],
                borderColor: [
                    COLORS.green,
                    COLORS.yellow,
                    COLORS.orange,
                    COLORS.red
                ],
                borderWidth: 1.5,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid:  { color: COLORS.grid },
                    ticks: { color: COLORS.muted }
                },
                y: {
                    beginAtZero: true,
                    grid:  { color: COLORS.grid },
                    ticks: {
                        color:     COLORS.muted,
                        precision: 0   // whole numbers only
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => ` ${ctx.parsed.y} URLs`
                    }
                }
            }
        }
    });
}


// ==================== MINI SPARKLINE (STATUS CARD) ====================
function buildMiniChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    // Fake uptime sparkline data
    const sparkData = [60, 70, 55, 80, 75, 90, 85, 95, 88, 92];

    new Chart(canvas, {
        type: "line",
        data: {
            labels: sparkData.map((_, i) => i),
            datasets: [{
                data:            sparkData,
                borderColor:     COLORS.green,
                backgroundColor: "rgba(0, 255, 136, 0.08)",
                borderWidth:     1.5,
                pointRadius:     0,
                fill:            true,
                tension:         0.4
            }]
        },
        options: {
            responsive:          true,
            maintainAspectRatio: false,
            scales: {
                x: { display: false },
                y: { display: false }
            },
            plugins: {
                legend:  { display: false },
                tooltip: { enabled: false }
            }
        }
    });
}


// ==================== INIT ON PAGE LOAD ====================
document.addEventListener("DOMContentLoaded", () => {

    // --- DASHBOARD PAGE ---
    if (typeof donutData !== "undefined") {
        const donutCanvas = document.getElementById("threatDonut");
        if (donutCanvas) {
            new Chart(donutCanvas, {
                type: "doughnut",
                data: getDonutData(donutData),
                options: donutOptions
            });
        }
    }

    if (typeof trendScores !== "undefined") {
        buildTrendChart("trendChart", trendScores);
    }

    // Mini sparkline in system status card
    buildMiniChart("statusMiniChart");

    // --- REPORTS PAGE ---
    if (typeof reportDonutData !== "undefined") {
        const reportDonutCanvas = document.getElementById("reportDonut");
        if (reportDonutCanvas) {
            new Chart(reportDonutCanvas, {
                type: "doughnut",
                data: getDonutData(reportDonutData),
                options: donutOptions
            });
        }
        buildBarChart("reportBar", reportDonutData);
    }

});