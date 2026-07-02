const canvas = document.getElementById("bgCanvas");
const ctx    = canvas.getContext("2d");

function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
}
resize();
window.addEventListener("resize", resize);

const CONFIG = {
    gridSize: 38,
    dotCount: 80,
    lineCount: 22,
    speed: 0.45
};

function drawGrid() {
    ctx.strokeStyle = "rgba(0,255,136,0.10)";
    ctx.lineWidth   = 0.6;
    for (let x = 0; x < canvas.width;  x += CONFIG.gridSize) {
        ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,canvas.height); ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += CONFIG.gridSize) {
        ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(canvas.width,y); ctx.stroke();
    }
}

const particles = Array.from({ length: CONFIG.dotCount }, () => ({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    r: Math.random() * 1.8 + 0.6,
    alpha: Math.random() * 0.6 + 0.2,
    dx: (Math.random() - 0.5) * CONFIG.speed,
    dy: (Math.random() - 0.5) * CONFIG.speed,
    pulse: Math.random() * Math.PI * 2
}));

function drawParticles(t) {
    particles.forEach(p => {
        const a = p.alpha * (0.6 + 0.4 * Math.sin(t * 0.001 + p.pulse));
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle   = `rgba(0,255,136,${a})`;
        ctx.shadowBlur  = 8;
        ctx.shadowColor = "rgba(0,255,136,0.8)";
        ctx.fill();
        ctx.shadowBlur  = 0;
        p.x += p.dx; p.y += p.dy;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width)  p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;
    });
}

const circuits = Array.from({ length: CONFIG.lineCount }, () => generateCircuit());

function generateCircuit() {
    const startX = Math.random() * window.innerWidth;
    const startY = Math.random() * window.innerHeight;
    const steps  = Math.floor(Math.random() * 5) + 3;
    const points = [{ x: startX, y: startY }];
    for (let i = 0; i < steps; i++) {
        const last = points[points.length - 1];
        const horiz = Math.random() > 0.5;
        const dist  = Math.random() * 90 + 30;
        points.push({
            x: horiz ? last.x + (Math.random() > 0.5 ? dist : -dist) : last.x,
            y: horiz ? last.y : last.y + (Math.random() > 0.5 ? dist : -dist)
        });
    }
    return {
        points,
        alpha: Math.random() * 0.5 + 0.15,
        width: Math.random() > 0.7 ? 1.5 : 0.9,
        dot: { progress: Math.random(), speed: Math.random() * 0.004 + 0.002 }
    };
}

function totalLen(pts) {
    let l = 0;
    for (let i = 1; i < pts.length; i++) {
        const dx = pts[i].x - pts[i-1].x, dy = pts[i].y - pts[i-1].y;
        l += Math.sqrt(dx*dx + dy*dy);
    }
    return l;
}

function ptAtProg(pts, prog) {
    let target = totalLen(pts) * prog;
    for (let i = 1; i < pts.length; i++) {
        const dx = pts[i].x - pts[i-1].x, dy = pts[i].y - pts[i-1].y;
        const seg = Math.sqrt(dx*dx + dy*dy);
        if (target <= seg) {
            const t = target / seg;
            return { x: pts[i-1].x + dx*t, y: pts[i-1].y + dy*t };
        }
        target -= seg;
    }
    return pts[pts.length-1];
}

function drawCircuits() {
    circuits.forEach(c => {
        ctx.beginPath();
        ctx.moveTo(c.points[0].x, c.points[0].y);
        for (let i = 1; i < c.points.length; i++) ctx.lineTo(c.points[i].x, c.points[i].y);
        ctx.strokeStyle = `rgba(0,255,136,${c.alpha})`;
        ctx.lineWidth   = c.width;
        ctx.stroke();

        c.points.forEach(pt => {
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 2, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0,255,136,${c.alpha * 2.2})`;
            ctx.fill();
        });

        c.dot.progress += c.dot.speed;
        if (c.dot.progress > 1) c.dot.progress = 0;
        const pos = ptAtProg(c.points, c.dot.progress);
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 3, 0, Math.PI * 2);
        ctx.fillStyle   = "rgba(0,255,200,0.95)";
        ctx.shadowBlur  = 14;
        ctx.shadowColor = "rgba(0,255,136,1)";
        ctx.fill();
        ctx.shadowBlur  = 0;
    });
}

const orbs = [
    { x: 0.18, y: 0.25, r: 200, alpha: 0.05 },
    { x: 0.82, y: 0.72, r: 240, alpha: 0.04 },
    { x: 0.5,  y: 0.5,  r: 160, alpha: 0.03 }
];

function drawOrbs() {
    orbs.forEach(o => {
        const x = o.x * canvas.width, y = o.y * canvas.height;
        const g = ctx.createRadialGradient(x,y,0,x,y,o.r);
        g.addColorStop(0,   `rgba(0,255,136,${o.alpha})`);
        g.addColorStop(1,   "rgba(0,255,136,0)");
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(x,y,o.r,0,Math.PI*2);
        ctx.fill();
    });
}

function animate(t) {
    ctx.fillStyle = "#060d0a";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    drawOrbs();
    drawGrid();
    drawCircuits();
    drawParticles(t);
    requestAnimationFrame(animate);
}

requestAnimationFrame(animate);