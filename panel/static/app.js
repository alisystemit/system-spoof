/* app.js — منطق پنل injspoof (بدون هیچ وابستگی CDN؛ چارت با canvas دستی) */
window.PB = (function () {
  "use strict";

  /* ---------------------------------------------------------------- utils */
  const el = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  async function api(path, opts) {
    const o = Object.assign({ headers: { "Content-Type": "application/json" } }, opts || {});
    const res = await fetch(path, o);
    let body = null;
    try { body = await res.json(); } catch (e) { body = { error: "پاسخ JSON نبود" }; }
    if (!res.ok && res.status !== 422 && res.status !== 502) {
      throw new Error((body && body.error) || ("HTTP " + res.status));
    }
    return body;
  }

  const nf = new Intl.NumberFormat("en-US");
  const num = (v) => (v === undefined || v === null ? "—" : nf.format(Math.round(v)));

  function fmtBytes(n) {
    if (n === undefined || n === null || isNaN(n)) return "—";
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0, v = Number(n);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? Math.round(v) : v.toFixed(1)) + " " + units[i];
  }

  function fmtUptime(ms) {
    if (!ms && ms !== 0) return "—";
    let s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400); s -= d * 86400;
    const h = Math.floor(s / 3600); s -= h * 3600;
    const m = Math.floor(s / 60); s -= m * 60;
    if (d) return `${d} روز ${h} ساعت`;
    if (h) return `${h} ساعت ${m} دقیقه`;
    if (m) return `${m} دقیقه ${s} ثانیه`;
    return `${s} ثانیه`;
  }

  function rate(prev, cur, dt) {
    if (prev === undefined || cur === undefined || !dt || dt <= 0) return 0;
    const d = cur - prev;
    return d > 0 ? d / dt : 0;
  }

  function downloadText(name, text, mime) {
    const blob = new Blob([text], { type: mime || "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  /* ---------------------------------------------------------------- chart */
  function Chart(canvas, opts) {
    this.cv = canvas;
    this.opts = Object.assign({ minSpan: 3 }, opts || {});
    this.series = [];
    this.ctx = canvas.getContext("2d");
    window.addEventListener("resize", () => this.draw([]));
  }
  Chart.prototype.draw = function (series) {
    this.series = series || this.series;
    const cv = this.cv, ctx = this.ctx;
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth || 300, h = cv.clientHeight || 150;
    cv.width = w * dpr; cv.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const pad = { t: 8, r: 8, b: 18, l: 44 };
    const iw = Math.max(1, w - pad.l - pad.r), ih = Math.max(1, h - pad.t - pad.b);
    let max = 0;
    this.series.forEach((s) => s.data.forEach((v) => { if (v > max) max = v; }));
    if (max <= 0) max = this.opts.minSpan;
    max = niceCeil(max);

    // grid + y labels
    ctx.strokeStyle = "#e8edf5"; ctx.fillStyle = "#8b97a8";
    ctx.font = "10px ui-monospace, Consolas, monospace"; ctx.lineWidth = 1;
    ctx.textAlign = "right"; ctx.textBaseline = "middle";
    for (let g = 0; g <= 4; g++) {
      const y = pad.t + (ih * g) / 4;
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iw, y); ctx.stroke();
      ctx.fillText(tickLabel(max * (1 - g / 4), max), pad.l - 6, y);
    }

    this.series.forEach((s) => {
      const data = s.data;
      if (!data.length) return;
      const step = data.length > 1 ? iw / (data.length - 1) : 0;
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = pad.l + step * i;
        const y = pad.t + ih - (Math.min(v, max) / max) * ih;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.strokeStyle = s.color; ctx.lineWidth = 1.7; ctx.stroke();
      if (s.fill !== false) {
        ctx.lineTo(pad.l + step * (data.length - 1), pad.t + ih);
        ctx.lineTo(pad.l, pad.t + ih);
        ctx.closePath();
        ctx.fillStyle = s.fill || hexAlpha(s.color, 0.12);
        ctx.fill();
      }
    });

    // x label: زمان
    ctx.fillStyle = "#8b97a8"; ctx.textAlign = "left"; ctx.textBaseline = "bottom";
    ctx.font = "10px Tahoma, sans-serif";
    ctx.fillText("قدیمی‌تر", pad.l, h - 3);
    ctx.textAlign = "right";
    ctx.fillText("اکنون", pad.l + iw, h - 3);
  };

  function niceCeil(v) {
    if (v <= 0) return 1;
    const e = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / e;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * e;
  }
  function shortNum(v) {
    if (v >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (v >= 1e3) return (v / 1e3).toFixed(1) + "k";
    return Math.round(v).toString();
  }
  /* برچسب محور Y: روی مقیاس‌های کوچک، گرد کردن به عدد صحیح باعث تکرار
     همان مقدار روی چند خط شبکه می‌شود (1,1,1,0,0). */
  function tickLabel(v, max) {
    if (max >= 1000) return shortNum(v);
    if (max >= 10) return String(Math.round(v));
    return String(Math.round(v * 10) / 10);
  }
  function hexAlpha(hex, a) {
    const m = hex.replace("#", "");
    const n = m.length === 3 ? m.split("").map((c) => c + c).join("") : m;
    const r = parseInt(n.slice(0, 2), 16), g = parseInt(n.slice(2, 4), 16),
      b = parseInt(n.slice(4, 6), 16);
    return `rgba(${r},${g},${b},${a})`;
  }

  /* ------------------------------------------------------------- issues */
  function renderIssues(container, issues, summary) {
    container.innerHTML = "";
    if (summary) {
      const badge = document.createElement("div");
      badge.className = "chip " + (summary.error ? "chip-error" :
        (summary.warn ? "chip-dirty" : "chip-ok"));
      badge.textContent = `${summary.error} خطا · ${summary.warn} هشدار · ${summary.info} نکته`;
      container.appendChild(badge);
    }
    (issues || []).forEach((i) => {
      const div = document.createElement("div");
      div.className = "issue issue-" + i.level;
      const lvl = { error: "خطا", warn: "هشدار", info: "نکته" }[i.level] || i.level;
      div.innerHTML = `<b>${lvl}</b> <span class="path">${esc(i.path)}</span><br>${esc(i.message)}` +
        (i.hint ? `<span class="hint">${esc(i.hint)}</span>` : "");
      container.appendChild(div);
    });
    if (!(issues || []).length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "مشکلی پیدا نشد.";
      container.appendChild(p);
    }
  }
  function esc(s) {
    return String(s === undefined ? "" : s).replace(/[&<>"]/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  /* --------------------------------------------------------------- dash */
  const dash = {
    timer: null,
    infoTimer: null,
    charts: {},
    nodeId: null,

    init() {
      const root = el("dash");
      if (!root) return;
      this.nodeId = root.dataset.node || null;
      this.charts.pps = new Chart(el("chart-pps"), { minSpan: 100 });
      this.charts.bps = new Chart(el("chart-bps"), { minSpan: 1024 });
      this.charts.drops = new Chart(el("chart-drops"), { minSpan: 1 });

      const sel = el("node-select");
      if (sel) sel.addEventListener("change", () => {
        location.href = "/?node=" + sel.value;
      });
      const linkEditor = el("link-editor");
      const linkHistory = el("link-history");
      if (linkEditor) linkEditor.href = "/editor?node=" + this.nodeId;
      if (linkHistory) linkHistory.href = "/history/" + this.nodeId;
      el("btn-refresh").addEventListener("click", () => this.tick(true));
      el("btn-hot").addEventListener("click", () => this.reload("hot"));
      el("btn-hard").addEventListener("click", () => {
        if (confirm("هسته با execve جایگزین می‌شود؛ ترافیک لحظه‌ای قطع می‌شود. ادامه؟"))
          this.reload("hard");
      });
      this.tick();
      this.timer = setInterval(() => this.tick(), 2000);
      this.loadInfo();
      this.infoTimer = setInterval(() => this.loadInfo(), 15000);
    },

    async reload(mode) {
      const btn = el(mode === "hot" ? "btn-hot" : "btn-hard");
      btn.disabled = true;
      try {
        const r = await api(`/api/reload/${this.nodeId}`, {
          method: "POST", body: JSON.stringify({ mode })
        });
        btn.textContent = r.ok ? (mode === "hot" ? "Hot reload شد" : "Hard reload درخواست شد")
          : ("خطا: " + (r.error || ""));
        if (!r.ok) btn.disabled = false;
        setTimeout(() => {
          btn.disabled = false;
          btn.textContent = mode === "hot" ? "Hot reload" : "Hard reload (execve)";
        }, 4000);
      } catch (e) {
        btn.disabled = false;
        btn.textContent = "خطا: " + e.message;
      }
    },

    async loadInfo() {
      if (!this.nodeId) return;
      try {
        const r = await api(`/api/nodes/${this.nodeId}/info`);
        if (r.ok) {
          el("k-mode").textContent = r.info.mode || "—";
          el("k-version").textContent = "v" + (r.info.version || "?") +
            " · api " + (r.info.api_version || "?");
          el("k-pid").textContent = "pid " + (r.info.pid || "?") + " · " +
            (r.info.config || "");
        } else {
          el("k-mode").textContent = "قطع";
          el("k-version").textContent = r.error || "";
        }
      } catch (e) { /* ignore */ }
    },

    async tick(force) {
      if (!this.nodeId) return;
      let r;
      try {
        r = await api(`/api/nodes/${this.nodeId}/series?limit=180` + (force ? "&fresh=1" : ""));
      } catch (e) { return; }
      const samples = (r.samples || []).filter((s) => s.stats);
      const health = el("k-health"), sub = el("k-health-sub");
      if (!samples.length) {
        health.textContent = "در انتظار نمونه";
        sub.textContent = (r.status && r.status.error) || "نخستین نمونه‌برداری چند لحظه دیگر";
        return;
      }
      if (r.status && r.status.alive === false) {
        health.textContent = "غيرقابل‌دسترس";
        sub.textContent = r.status.error || "";
        health.parentElement.classList.add("is-bad");
      } else {
        health.textContent = "زنده";
        sub.textContent = "آخرین نمونه: " + new Date(samples[samples.length - 1].ts * 1000)
          .toLocaleTimeString("en-GB");
        health.parentElement.classList.remove("is-bad");
      }

      const ppsIn = [], ppsOut = [], bpsIn = [], bpsOut = [], drops = [], frags = [];
      let last = null, totIn = 0, totOut = 0, totBytes = 0, totDrops = 0, dropRate = 0;
      samples.forEach((s) => {
        const t = traffic(s.stats);
        if (last) {
          const dt = s.ts - last.ts;
          if (dt > 0.3) {
            const lt = traffic(last.stats);
            const pin = rate(lt.pkts_in, t.pkts_in, dt);
            const pout = rate(lt.pkts_out, t.pkts_out, dt);
            ppsIn.push(pin); ppsOut.push(pout);
            bpsIn.push(rate(lt.bytes_in, t.bytes_in, dt));
            bpsOut.push(rate(lt.bytes_out, t.bytes_out, dt));
            frags.push(rate(lt.frags_sent, t.frags_sent, dt));
            const dd = dropTotal(s.stats) - dropTotal(last.stats);
            drops.push(dd > 0 ? dd / dt : 0);
          }
        }
        last = s;
        totIn = t.pkts_in; totOut = t.pkts_out;
        totBytes = (t.bytes_in || 0) + (t.bytes_out || 0);
        totDrops = dropTotal(s.stats);
      });
      const curS = samples[samples.length - 1].stats;
      const prevS = samples.length > 1 ? samples[samples.length - 2].stats : null;
      const cur = traffic(curS), prev = prevS ? traffic(prevS) : null;
      const dt = prevS ? (samples[samples.length - 1].ts - samples[samples.length - 2].ts) : 0;
      const nowPps = prev ? rate(prev.pkts_in, cur.pkts_in, dt) + rate(prev.pkts_out, cur.pkts_out, dt) : 0;
      const nowBps = prev ? rate(prev.bytes_in, cur.bytes_in, dt) + rate(prev.bytes_out, cur.bytes_out, dt) : 0;
      dropRate = prevS ? (dropTotal(curS) - dropTotal(prevS)) / (dt || 1) : 0;
      el("k-pps").textContent = shortNum(nowPps);
      el("k-pps-total").textContent = `ورودی ${num(totIn)} · خروجی ${num(totOut)}`;
      el("k-bps").textContent = fmtBytes(nowBps) + "/s";
      el("k-bps-total").textContent = "تجمعی " + fmtBytes(totBytes);
      el("k-drops").textContent = num(totDrops);
      el("k-drops-rate").textContent = dropRate > 0.01 ? ("+" + dropRate.toFixed(1) + "/s") : "بدون drop";
      el("k-uptime").textContent = fmtUptime(curS.uptime_ms);

      this.charts.pps.draw([
        { name: "in", data: ppsIn, color: "#2b5ce6" },
        { name: "out", data: ppsOut, color: "#12a5a0" }]);
      this.charts.bps.draw([
        { name: "in", data: bpsIn, color: "#2b5ce6" },
        { name: "out", data: bpsOut, color: "#12a5a0" }]);
      this.charts.drops.draw([
        { name: "drops", data: drops, color: "#c0392b" },
        { name: "frags", data: frags, color: "#b07cd8", fill: false }]);

      this.renderDrops(curS, prevS, dt);
      this.renderPool(curS);
      this.renderOps(curS);
    },

    renderDrops(cur, prev, dt) {
      /* کلیدها همان فیلدهای آبجکت "drops" در /api/v1/stats هستند
         (src/api.c:285): filter/parse/pool/send/oversize. */
      const rows = [
        ["filter (فیلتر incoming)", "filter"],
        ["parse (هدر خراب)", "parse"],
        ["pool (استخر تمام)", "pool"],
        ["send (خطای ارسال)", "send"],
        ["oversize (بیش از حد بزرگ)", "oversize"],
      ];
      const errno = [
        ["ENOBUFS", "enobufs"], ["EAGAIN", "eagain"],
        ["EMSGSIZE", "emsgsize"], ["ENETDOWN", "enetdown"],
        ["EPERM", "eperm"], ["other", "other"],
      ];
      const tb = el("drops-table").querySelector("tbody");
      tb.innerHTML = "";
      const add = (label, key, indent) => {
        const v = (cur.drops || {})[key] !== undefined ? (cur.drops || {})[key]
          : cur[key];
        const p = prev ? (((prev.drops || {})[key] !== undefined ? (prev.drops || {})[key]
          : prev[key]) || 0) : 0;
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${indent ? "&nbsp;&nbsp;" : ""}${esc(label)}</td>` +
          `<td class="num">${num(v)}</td>` +
          `<td class="num ${v - p > 0 ? "warn-text" : ""}">${v - p > 0 ? "+" + ((v - p) / (dt || 1)).toFixed(1) + "/s" : "0"}</td>`;
        tb.appendChild(tr);
      };
      rows.forEach(([l, k]) => add(l, k));
      const head = document.createElement("tr");
      head.innerHTML = `<td colspan="3" class="muted small">breakdown خطای send</td>`;
      tb.appendChild(head);
      const byErr = (cur.drops || {}).send_by_errno || {};
      const prevErr = prev ? ((prev.drops || {}).send_by_errno || {}) : {};
      errno.forEach(([l, k]) => {
        const v = byErr[k] || 0, p = prevErr[k] || 0;
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>&nbsp;&nbsp;${esc(l)}</td><td class="num">${num(v)}</td>` +
          `<td class="num">${v - p > 0 ? "+" + ((v - p) / (dt || 1)).toFixed(1) + "/s" : "0"}</td>`;
        tb.appendChild(tr);
      });
    },

    renderPool(cur) {
      const pool = (cur && cur.pool) || {};
      const cap = pool.capacity || 0, avail = pool.avail || 0;
      const pct = cap ? Math.round((avail / cap) * 100) : 0;
      el("pool-bar").style.width = pct + "%";
      el("pool-avail").textContent = num(avail);
      el("pool-cap").textContent = num(cap);
      el("pool-hits").textContent = num(pool.hits);
      el("pool-misses").textContent = num(pool.misses);
      const sys = (cur && cur.syscalls) || {};
      const tb = el("sys-table").querySelector("tbody");
      tb.innerHTML = `
        <tr><td>recvmmsg</td><td class="num">${num(sys.recvmmsg)}</td></tr>
        <tr><td>sendmmsg</td><td class="num">${num(sys.sendmmsg)}</td></tr>
        <tr><td>sendto</td><td class="num">${num(sys.sendto)}</td></tr>
        <tr><td>frags_sent</td><td class="num">${num((cur.traffic || {}).frags_sent)}</td></tr>`;
    },

    renderOps(cur) {
      const log = (cur && cur.log) || {}, rel = (cur && cur.reloads) || {};
      const tb = el("ops-table").querySelector("tbody");
      tb.innerHTML = `
        <tr><td>لاگ emitted</td><td class="num">${num(log.emitted)}</td></tr>
        <tr><td>لاگ dropped (ring overrun)</td><td class="num">${num(log.dropped)}</td></tr>
        <tr><td>reload hot</td><td class="num">${num(rel.hot)}</td></tr>
        <tr><td>reload hard</td><td class="num">${num(rel.hard)}</td></tr>
        <tr><td>pkts_in_local / wire</td><td class="num">${num((cur.traffic || {}).pkts_in_local)} / ${num((cur.traffic || {}).pkts_in_wire)}</td></tr>
        <tr><td>pkts_out_wire / local</td><td class="num">${num((cur.traffic || {}).pkts_out_wire)} / ${num((cur.traffic || {}).pkts_out_local)}</td></tr>`;
    }
  };

  function dropTotal(s) {
    const d = (s && s.drops) || {};
    return (d.filter || 0) + (d.parse || 0) + (d.pool || 0) + (d.send || 0) + (d.oversize || 0);
  }

  /* پاسخ /api/v1/stats شمارنده‌های ترافیک را داخل "traffic" می‌گذارد
     (src/api.c:277). این accessor هم شکل تودرتو و هم شکل تخت را تحمل می‌کند. */
  function traffic(s) {
    return (s && (s.traffic || s)) || {};
  }

  /* ------------------------------------------------------------- nodes */
  const nodes = {
    init() {
      const rows = $$("tr[data-node]");
      if (!rows.length) return;
      const poll = async () => {
        for (const tr of rows) {
          const id = tr.dataset.node;
          try {
            const r = await api(`/api/nodes/${id}/series?limit=3`);
            const infoCell = tr.querySelector('[data-live="info"]');
            const ppsCell = tr.querySelector('[data-live="pps"]');
            const dot = tr.querySelector(".dot");
            if (r.status && r.status.alive === false) {
              if (dot) { dot.className = "dot dot-off"; }
              if (infoCell) infoCell.innerHTML = `<span class="muted small">${esc((r.status.error || "").slice(0, 60))}</span>`;
              if (ppsCell) ppsCell.textContent = "—";
              continue;
            }
            const samples = (r.samples || []).filter((s) => s.stats);
            if (!samples.length) {
              if (dot) dot.className = "dot dot-idle";
              continue;
            }
            if (dot) dot.className = "dot dot-on";
            const curS = samples[samples.length - 1].stats;
            const prevS = samples.length > 1 ? samples[samples.length - 2].stats : null;
            const cur = traffic(curS), prev = prevS ? traffic(prevS) : null;
            const dt = prevS ? samples[samples.length - 1].ts - samples[samples.length - 2].ts : 0;
            const pps = prev ? rate(prev.pkts_in, cur.pkts_in, dt) + rate(prev.pkts_out, cur.pkts_out, dt) : 0;
            if (ppsCell) ppsCell.textContent = shortNum(pps);
            if (infoCell) infoCell.textContent = fmtUptime(curS.uptime_ms);
          } catch (e) { /* ignore */ }
        }
      };
      $$("[data-act='test']").forEach((btn) => btn.addEventListener("click", async () => {
        const id = btn.closest("tr").dataset.node;
        btn.disabled = true; btn.textContent = "…";
        const r = await api(`/api/nodes/${id}/test`, { method: "POST" });
        btn.disabled = false; btn.textContent = "تست اتصال";
        btn.closest("tr").querySelector('[data-live="info"]').innerHTML =
          r.ok ? `<span class="ok-dot">✓</span> ${esc(r.mode)} v${esc(r.version)}`
               : `<span class="bad-dot">${esc(r.error)}</span>`;
      }));
      poll();
      setInterval(poll, 2500);
    }
  };

  /* -------------------------------------------------------------- core */
  /* صفحه‌ی «هسته»: همه‌ی کارها از راه /api/core/* و در نهایت helper
     injspoof-nodectl انجام می‌شود. متن خروجی همان چیزی است که helper
     نوشته؛ پنل چیزی را بازخوانی نمی‌کند. */
  const core = {
    nodeId: "",
    instance: "",
    disk: "",

    init() {
      const root = el("core");
      if (!root) return;
      this.nodeId = root.dataset.node || "";
      this.instance = "";
      const sel = el("core-node");
      if (sel) sel.addEventListener("change", () => {
        location.href = "/core?node=" + sel.value;
      });

      $$("[data-svc]").forEach((b) => b.addEventListener("click", () => {
        const act = b.dataset.svc;
        if (act !== "status" &&
            !confirm(`«${act}» روی injspoof@${this.instance || "…"} اجرا شود؟`)) return;
        this.post("/api/core/service", { action: act, node_id: Number(this.nodeId) }, b)
          .then((r) => { if (r && r.ok) this.refresh(); });
      }));

      const bind = (id, fn) => {
        const b = el(id);
        if (b) b.addEventListener("click", fn);
      };
      bind("btn-refresh", () => this.refresh());
      bind("btn-rescan", () => this.post("/api/core/rescan", { node_id: Number(this.nodeId) }));
      bind("btn-logs", () => this.post("/api/core/logs", {
        node_id: Number(this.nodeId), lines: Number(el("log-lines").value)
      }));
      bind("btn-write-disk", () => {
        if (!this.disk) { this.say("کانفیگ دیسک خوانده نشده است.", true); return; }
        if (!confirm("همین متن کانفیگ روی دیسک نوشته" +
            (el("write-restart").checked ? " و سرویس restart" : "") + " می‌شود. ادامه؟")) return;
        this.post("/api/core/config/write", {
          node_id: Number(this.nodeId), config: this.disk,
          restart: el("write-restart").checked, note: "بازنویسی کانفیگ دیسک از صفحه‌ی هسته"
        });
      });
      bind("btn-pull-live", () => this.pullLive());
      bind("btn-dl-disk", () => {
        if (this.disk) downloadText(`injspoof-${this.instance || "node"}.json`, this.disk);
      });
      bind("btn-fw-preview", () => this.fwScript(false));
      bind("btn-fw-download", () => this.fwScript(true));
      bind("btn-fw-apply", () => {
        if (!confirm("قواعد nft روی این ماشین اعمال شود؟")) return;
        this.post("/api/core/firewall/apply", { node_id: Number(this.nodeId) });
      });
      const up = el("btn-update");
      if (up) up.addEventListener("click", () => {
        if (!confirm("git pull و install.sh --update اجرا شود؟ چند لحظه طول می‌کشد.")) return;
        this.post("/api/core/update", {}, up, 240000).then(() => this.refresh());
      });

      this.refresh();
      this.pollLive();
      setInterval(() => this.pollLive(), 5000);
    },

    say(text, bad) {
      const box = el("core-out");
      if (box) showResult(box, typeof text === "string" ? text : JSON.stringify(text, null, 2), bad);
    },

    async post(path, body, btn, timeout) {
      if (btn) btn.disabled = true;
      const t = btn ? btn.textContent : "";
      if (btn) btn.textContent = "در حال اجرا…";
      try {
        const r = await api(path, { method: "POST", body: JSON.stringify(body),
                                    signal: timeout ? AbortSignal.timeout(timeout) : undefined });
        this.say(r.output || r.error || (r.ok ? "انجام شد" : "خطا"), !r.ok);
        if (r.issues && r.issues.length) {
          this.say((r.error || "") + "\n" + JSON.stringify(r.issues, null, 2), true);
        }
        return r;
      } catch (e) {
        this.say("خطا: " + e.message, true);
        return null;
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t; }
      }
    },

    async refresh() {
      if (!this.nodeId) return;
      try {
        const r = await api("/api/core/info?node=" + this.nodeId);
        this.instance = r.instance || "";
        this.disk = r.disk_config || "";
        const svc = el("k-service");
        if (svc) {
          svc.textContent = r.service;
          svc.closest(".stat").classList.toggle("is-ok", r.service === "active");
        }
        const api_ = el("k-api");
        if (api_ && r.api_alive !== null && r.api_alive !== undefined) {
          api_.textContent = r.api_alive ? "زنده" : "قطع";
          api_.closest(".stat").classList.toggle("is-bad", !r.api_alive);
          const sub = el("k-api-sub");
          if (sub) sub.textContent = r.api_error || (r.node ? r.node.api_url : "");
        }
        const issues = el("core-issues");
        if (issues) renderIssues(issues, r.issues, r.summary);
        if (r.config_error) this.say(r.config_error, true);
      } catch (e) { /* صفحه بدون helper هم معنا دارد؛ خطا را فریاد نمی‌زنیم */ }
    },

    async pullLive() {
      if (!this.nodeId) return;
      try {
        const r = await api(`/api/config/load/${this.nodeId}`);
        if (!r.ok) throw new Error(r.error || "نود در دسترس نیست");
        this.disk = r.config;
        renderIssues(el("core-issues"), r.issues, r.summary);
        const ok = await this.post("/api/core/config/write", {
          node_id: Number(this.nodeId), config: r.config,
          restart: el("write-restart").checked,
          note: "بازگردانی کانفیگ زنده‌ی نود روی دیسک"
        });
        if (ok && ok.ok) this.say("کانفیگ زنده روی دیسک نوشته شد.\n" + (ok.output || ""), false);
      } catch (e) {
        this.say("خواندن کانفیگ زنده شکست: " + e.message, true);
      }
    },

    async fwScript(download) {
      const engine = el("fw-engine").value;
      try {
        const r = await api(`/api/core/firewall/script?node=${this.nodeId}&engine=${engine}`);
        if (!r.ok || !r.script) throw new Error(r.error || "کانفیگی نیست");
        if (download) {
          downloadText(`injspoof-${this.instance || "node"}-${engine}.sh`, r.script, "text/x-sh");
          return;
        }
        const pre = el("fw-script");
        pre.textContent = r.script;
        pre.classList.remove("hidden");
      } catch (e) {
        this.say("تولید اسکریپت فایروال: " + e.message, true);
      }
    },

    async pollLive() {
      const cell = el("k-livepps");
      if (!cell || !this.nodeId) return;
      try {
        const r = await api(`/api/nodes/${this.nodeId}/series?limit=3`);
        const samples = (r.samples || []).filter((s) => s.stats);
        if (samples.length < 2) { cell.textContent = "—"; return; }
        const a = traffic(samples[samples.length - 2].stats);
        const b = traffic(samples[samples.length - 1].stats);
        const dt = samples[samples.length - 1].ts - samples[samples.length - 2].ts;
        cell.textContent = shortNum(rate(a.pkts_in, b.pkts_in, dt) +
                                    rate(a.pkts_out, b.pkts_out, dt)) + " pps";
      } catch (e) { /* ignore */ }
    }
  };

  /* ---------------------------------------------------------- nodeForm */
  const nodeForm = {
    init() {
      const box = el("is-local"), field = el("instance-field");
      if (!box || !field) return;
      const sync = () => field.classList.toggle("hidden", !box.checked);
      box.addEventListener("change", sync);
      sync();
    }
  };

  /* ------------------------------------------------------------ tree */
  function buildTree(container, model, onChange) {
    container.innerHTML = "";
    container.appendChild(node("root", null, model, onChange));
  }

  function node(keyName, keyOrIndex, value, onChange) {
    const wrap = document.createElement("div");
    wrap.className = "tnode" + (keyName === "root" ? " tnode-root" : "");
    const row = document.createElement("div");
    row.className = "trow";
    wrap.appendChild(row);

    const isObj = value !== null && typeof value === "object";
    const label = keyName === "root" ? "<root>"
      : (keyName === "index" ? `<span class="tidx">[${keyOrIndex}]</span>`
        : `<span class="tkey">${esc(keyOrIndex)}</span>`);
    row.innerHTML = label;

    if (!isObj) {
      const box = document.createElement("span");
      box.className = "tval";
      const input = document.createElement("input");
      input.value = value === null ? "null" : String(value);
      input.dataset.raw = input.value;
      const kind = value === null ? "tnull" : typeof value;
      input.className = "t" + (kind === "string" ? "str" : kind === "number" ? "num"
        : kind === "boolean" ? "bool" : "str");
      input.addEventListener("change", () => {
        const parsed = parseScalar(input.value, typeof value);
        onChange(keyOrIndex, parsed, input);
      });
      box.appendChild(input);
      if (keyName === "index") {
        const del = document.createElement("button");
        del.className = "tbtn"; del.textContent = "×";
        del.addEventListener("click", () => onChange("$$remove$$", keyOrIndex, row));
        box.appendChild(del);
      }
      row.appendChild(box);
      return wrap;
    }

    const isArr = Array.isArray(value);
    const toggle = document.createElement("span");
    toggle.className = "ttoggle"; toggle.textContent = "▾";
    const kids = document.createElement("div");
    kids.className = "children";
    toggle.addEventListener("click", () => {
      const hidden = kids.classList.toggle("hidden");
      toggle.textContent = hidden ? "▸" : "▾";
    });
    row.insertBefore(toggle, row.firstChild);

    const entries = isArr ? value.map((v, i) => ["index", i, v])
      : Object.entries(value).map(([k, v]) => ["key", k, v]);
    entries.forEach(([type, k, v]) => {
      kids.appendChild(node(type === "index" ? "index" : "key", k, v,
        makeChildHandler(value, k, onChange, isArr)));
    });
    wrap.appendChild(kids);

    const addRow = document.createElement("div");
    addRow.className = "trow";
    const add = document.createElement("span");
    add.className = "tadd";
    add.textContent = isArr ? "+ عنصر" : "+ کلید";
    add.addEventListener("click", () => {
      const fresh = { string: "", number: 0, boolean: false, object: {}, array: [] };
      if (isArr) {
        value.push(fresh.object);
        onChange("$$append$$", null, null);
      } else {
        let name = "key", n = 1;
        while (name in value) name = "key" + (++n);
        value[name] = fresh.string;
        onChange("$$touch$$", null, null);
      }
      kids.appendChild(node(isArr ? "index" : "key",
        isArr ? value.length - 1 : Object.keys(value).pop(),
        isArr ? value[value.length - 1] : value[Object.keys(value).pop()],
        makeChildHandler(value, isArr ? value.length - 1 : Object.keys(value).pop(),
          onChange, isArr)));
    });
    addRow.appendChild(add);
    wrap.appendChild(addRow);

    if (keyName !== "root") {
      const del = document.createElement("button");
      del.className = "tbtn"; del.textContent = "حذف";
      del.addEventListener("click", () => {
        if (isArr) value.splice(keyOrIndex, 1); else delete value[keyOrIndex];
        onChange("$$touch$$", null, null);
        wrap.remove();
      });
      row.appendChild(del);
    }
    return wrap;
  }

  function makeChildHandler(containerObj, key, parentChange, isArr) {
    return (childKey, childValue, src) => {
      if (childKey === "$$remove$$") {
        containerObj.splice(childValue, 1);
        parentChange("$$touch$$", null, null);
        if (src && src.closest(".tnode")) src.closest(".tnode").remove();
        return;
      }
      if (childKey === "$$touch$$" || childKey === "$$append$$") {
        parentChange("$$touch$$", null, null);
        return;
      }
      containerObj[childKey] = childValue;
      parentChange("$$touch$$", null, null);
    };
  }

  function parseScalar(raw, prevType) {
    const t = raw.trim();
    if (t === "true") return true;
    if (t === "false") return false;
    if (t === "null" || t === "") return t === "" ? "" : null;
    if (/^-?\d+$/.test(t) && (prevType === "number" || !isNaN(Number(t)))) {
      if (prevType === "number" || (prevType !== "string" && /^-?\d+$/.test(t))) {
        return Number(t);
      }
    }
    if (prevType === "number" && /^-?[\d.]+$/.test(t)) return Number(t);
    return raw;
  }

  /* ---------------------------------------------------------- editor */
  const editor = {
    model: null,
    nodeId: null,
    dirty: false,

    init() {
      const sel = el("node-select");
      if (!sel) return;
      this.nodeId = sel.value || (new URLSearchParams(location.search).get("node"));
      sel.addEventListener("change", () => {
        location.href = "/editor?node=" + sel.value;
      });
      el("btn-load").addEventListener("click", () => this.load());
      $$(".tab").forEach((t) => t.addEventListener("click", () => {
        $$(".tab").forEach((x) => x.classList.remove("active"));
        t.classList.add("active");
        const which = t.dataset.tab;
        el("pane-tree").classList.toggle("hidden", which !== "tree");
        el("pane-raw").classList.toggle("hidden", which !== "raw");
        if (which === "raw") el("raw-json").value = JSON.stringify(this.model, null, 2);
        if (which === "tree") this.renderTree();
      }));
      el("btn-validate").addEventListener("click", () => this.validate());
      el("btn-apply").addEventListener("click", () => this.apply());
      el("btn-download").addEventListener("click", (e) => {
        e.preventDefault();
        if (this.model) downloadText("injspoof-config.json", JSON.stringify(this.model, null, 2));
      });
      el("btn-pretty").addEventListener("click", () => {
        try { el("raw-json").value = JSON.stringify(JSON.parse(el("raw-json").value), null, 2); }
        catch (e) { alert("JSON قابل‌تحلیل نیست: " + e.message); }
      });
      el("btn-apply-raw").addEventListener("click", () => {
        try {
          this.model = JSON.parse(el("raw-json").value);
          this.renderTree(); this.markDirty(); el("pane-tree").classList.remove("hidden");
          el("pane-raw").classList.add("hidden");
          $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "tree"));
          this.validate();
        } catch (e) { alert("JSON قابل‌تحلیل نیست: " + e.message); }
      });
      el("btn-expand").addEventListener("click", () =>
        $$("#tree .children").forEach((c) => c.classList.remove("hidden")));
      el("btn-collapse").addEventListener("click", () =>
        $$("#tree .children").forEach((c) => c.classList.add("hidden")));
      if (this.nodeId) this.load();
    },

    async load() {
      if (!this.nodeId) return;
      el("btn-load").disabled = true;
      try {
        const r = await api(`/api/config/load/${this.nodeId}`);
        if (!r.ok) throw new Error(r.error || "خطا");
        this.model = JSON.parse(r.config);
        el("raw-json").value = r.config;
        this.renderTree();
        this.setDirty(false);
        renderIssues(el("issues"), r.issues, r.summary);
        el("issue-count").textContent =
          `${r.summary.error} خطا · ${r.summary.warn} هشدار`;
        this.renderCapacity(r.capacity);
      } catch (e) {
        showResult(el("apply-result"), "بارگذاری شکست: " + e.message, true);
      } finally {
        el("btn-load").disabled = false;
      }
    },

    renderTree() {
      if (!this.model) return;
      buildTree(el("tree"), this.model, () => { this.markDirty(); this.validate(); });
    },

    markDirty() { this.setDirty(true); },
    setDirty(v) {
      this.dirty = v;
      el("dirty-flag").classList.toggle("hidden", !v);
    },

    async validate() {
      if (!this.model) return null;
      const mode = (el("node-select").selectedOptions[0].textContent.includes("کلاینت"))
        ? "client" : "server";
      const r = await api("/api/config/validate", {
        method: "POST", body: JSON.stringify({ config: this.model, mode })
      });
      renderIssues(el("issues"), r.issues, r.summary);
      el("issue-count").textContent =
        `${r.summary.error} خطا · ${r.summary.warn} هشدار · ${r.summary.info} نکته`;
      this.renderCapacity(r.capacity);
      el("btn-apply").disabled = !r.ok;
      return r;
    },

    renderCapacity(rows) {
      const tb = el("capacity") ? el("capacity").querySelector("tbody") : null;
      if (!tb) return;
      tb.innerHTML = "";
      (rows || []).forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${esc(r.tag)}</td>` +
          `<td class="num">${r.hosts_unknown ? "؟" : num(r.hosts)}</td>` +
          `<td class="num">${r.explicit_ports ? num(r.ports) : "تصادفی"}</td>` +
          `<td class="num">${r.hosts_unknown ? "؟" : num(r.flows)}</td>`;
        tb.appendChild(tr);
      });
      if (!(rows || []).length)
        tb.innerHTML = `<tr><td colspan="4" class="muted">rule‌ای نیست</td></tr>`;
    },

    async apply() {
      if (!this.model) return;
      if (!confirm("این کانفیگ با PUT روی نود نوشته و hot reload می‌شود. ادامه؟")) return;
      const btn = el("btn-apply");
      btn.disabled = true;
      try {
        const r = await api(`/api/config/apply/${this.nodeId}`, {
          method: "POST",
          body: JSON.stringify({
            config: JSON.stringify(this.model, null, 2),
            note: el("apply-note").value || "ویرایش از پنل",
            reload: el("reload-mode").value
          })
        });
        showResult(el("apply-result"),
          r.ok ? ("اعمال شد.\n" + JSON.stringify(r.reloaded || {}, null, 2))
               : (r.stage + ": " + r.error + "\n" +
                  JSON.stringify(r.issues || r.rollback_hint || "", null, 2)),
          !r.ok);
        if (r.ok) this.setDirty(false);
      } catch (e) {
        showResult(el("apply-result"), "خطا: " + e.message, true);
      } finally {
        btn.disabled = false;
      }
    }
  };

  function showResult(node, text, bad) {
    node.classList.remove("hidden");
    node.classList.toggle("is-bad", !!bad);
    node.classList.toggle("is-ok", !bad);
    node.textContent = text;
  }

  /* -------------------------------------------------------------- pair */
  const pair = {
    last: null,
    savedId: null,

    init() {
      const form = el("wizard");
      if (!form) return;
      const inject = el("pair-data");
      if (inject) {
        try { this.fill(JSON.parse(inject.textContent)); } catch (e) { /* ignore */ }
      }
      this.bindProtocolToggle();
      this.bindFwd();
      this.bindTokenGen();
      $$("[data-side] select, [data-side] input").forEach(() => { });
      if (el("f-fill-example").checked && !el("f-client.pool").value) this.fillExample();
      el("btn-preview").addEventListener("click", () => this.preview());
      el("btn-save").addEventListener("click", () => this.save());
      el("btn-push").addEventListener("click", () => this.push());
      el("btn-check-live").addEventListener("click", () => this.checkLive());
      $$("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
        const map = {
          client: "out-client", server: "out-server",
          client_nft: "out-client-nft", server_nft: "out-server-nft"
        };
        const txt = el(map[b.dataset.copy]).textContent;
        await navigator.clipboard.writeText(txt);
        b.textContent = "کپی شد";
        setTimeout(() => (b.textContent = "کپی"), 1500);
      }));
      $$("[data-dl]").forEach((a) => a.addEventListener("click", (e) => {
        if (!this.last) return;
        e.preventDefault();
        downloadText(a.dataset.dl, a.dataset.dl.startsWith("client")
          ? this.last.client_json : this.last.server_json);
      }));
      el("pair-select").addEventListener("change", (e) => {
        location.href = e.target.value ? "/pair?pair=" + e.target.value : "/pair";
      });
    },

    readSpec() {
      const v = (id) => (el("f-" + id) ? el("f-" + id).value.trim() : "");
      const list = (id) => v(id).split(/[,\s]+/).filter(Boolean).map(Number);
      const cidrs = (id) => v(id).split(/\n+/).map((s) => s.trim()).filter(Boolean);
      const side = (name) => ({
        label: name,
        public_ip: v(name + ".public_ip"),
        iface: v(name + ".iface"),
        gw_mac: v(name + ".gw_mac"),
        api_bind: v(name + ".api_bind"),
        api_token: v(name + ".api_token"),
        pool: cidrs(name + ".pool"),
        src_ports: list(name + ".src_ports"),
      });
      const forwards = $$("#fwd-table tbody tr").map((tr) => ({
        bind: tr.querySelector(".f-bind").value.trim(),
        redirect: tr.querySelector(".f-redirect").value.trim(),
      })).filter((f) => f.bind && f.redirect);
      return {
        name: v("name"),
        hid: v("hid") || null,
        protocol: v("protocol"),
        tcp_flags: v("tcp_flags"),
        tcp_seq: v("tcp_seq"),
        seq_base: v("seq_base"),
        ack_base: v("ack_base"),
        icmp_type: Number(v("icmp_type") || 8),
        icmp_code: Number(v("icmp_code") || 0),
        wire_dst_port: Number(v("wire_dst_port") || 443),
        fragment_size: Number(v("fragment_size") || 1400),
        iface_tag: v("iface_tag"),
        fastpath_mode: v("fastpath_mode"),
        log_level: v("log_level"),
        client: side("client"),
        server: side("server"),
        forwards: forwards,
      };
    },

    fill(spec) {
      const set = (id, val) => { if (el("f-" + id) && val !== undefined && val !== null) el("f-" + id).value = val; };
      Object.keys(spec).forEach((k) => {
        if (k === "client" || k === "server") {
          Object.keys(spec[k]).forEach((sk) => set(k + "." + sk,
            Array.isArray(spec[k][sk]) ? spec[k][sk].join(k.endsWith("pool") ? "\n" : ", ") : spec[k][sk]));
        } else if (k === "forwards") {
          spec[k].forEach((f) => this.addFwdRow(f.bind, f.redirect));
        } else if (["protocol", "tcp_seq", "fastpath_mode", "log_level"].includes(k)) {
          if (el("f-" + k)) el("f-" + k).value = spec[k];
        } else {
          set(k, spec[k]);
        }
      });
      this.bindProtocolToggle();
    },

    fillExample() {
      el("f-client.pool").value = "198.51.100.0/24";
      el("f-server.pool").value = "203.0.113.0/24";
      this.addFwdRow("127.0.0.1:51820", "127.0.0.1:51820");
    },

    addFwdRow(bind, redirect) {
      const tb = el("fwd-table").querySelector("tbody");
      if (tb.querySelector("td.muted")) tb.innerHTML = "";
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><input class="input f-bind" placeholder="127.0.0.1:51820"></td>
        <td><input class="input f-redirect" placeholder="203.0.113.10:51820"></td>
        <td><button type="button" class="btn btn-sm btn-danger">×</button></td>`;
      tr.querySelector(".f-bind").value = bind || "";
      tr.querySelector(".f-redirect").value = redirect || "";
      tr.querySelector("button").addEventListener("click", () => tr.remove());
      tb.appendChild(tr);
    },

    bindFwd() {
      el("btn-add-fwd").addEventListener("click", () => this.addFwdRow("", ""));
      if (!el("fwd-table").querySelector("tbody").children.length) this.addFwdRow("", "");
    },

    bindProtocolToggle() {
      const p = el("f-protocol").value;
      $$('[data-only="tcp"]').forEach((e) => e.classList.toggle("hidden", p !== "tcp"));
      $$('[data-only="icmp"]').forEach((e) => e.classList.toggle("hidden", p !== "icmp"));
    },

    bindTokenGen() {
      $$("[data-gen-token]").forEach((b) => b.addEventListener("click", () => {
        const rnd = () => Math.random().toString(16).slice(2, 10);
        el("f-" + b.dataset.genToken + ".api_token").value =
          (rnd() + rnd() + rnd() + rnd());
      }));
    },

    async preview() {
      this.bindProtocolToggle();
      const spec = this.readSpec();
      const r = await api("/api/pair/preview", {
        method: "POST", body: JSON.stringify({ spec })
      });
      this.last = r;
      /* هر preview یک hid تصادفی تازه می‌سازد اگر hid خالی باشد. آن را در
         فیلد می‌نویسیم تا چیزی که ذخیره/اعمال می‌شود دقیقاً همان چیزی باشد
         که کاربر پیش‌نمایش دیده است. */
      if (r.hid && el("f-hid")) el("f-hid").value = r.hid;
      el("preview").classList.remove("hidden");
      el("out-client").textContent = r.client_json || "";
      el("out-server").textContent = r.server_json || "";
      el("out-client-nft").textContent = r.client_nft || "";
      el("out-server-nft").textContent = r.server_nft || "";
      el("preview-badge").className = "chip " + (r.ok ? "chip-ok" : "chip-error");
      el("preview-badge").textContent = r.ok ? "کانفیگ هم‌راستاست" : "ایراد دارد";
      renderIssues(el("preview-issues"), (r.issues || []).concat(r.extra || []), r.summary);
      el("preview").scrollIntoView({ behavior: "smooth", block: "start" });
    },

    async save() {
      if (!this.last) await this.preview();
      if (this.last && !this.last.ok) {
        if (!confirm("کانفیگ ایراد دارد. با این حال ذخیره شود؟")) return;
      }
      const r = await api("/api/pair/save", {
        method: "POST",
        body: JSON.stringify({
          name: el("f-name").value.trim(),
          spec: this.readSpec(),
          pair_id: el("pair-id").value ? Number(el("pair-id").value) : null,
          client_node_id: el("push-client").value ? Number(el("push-client").value) : null,
          server_node_id: el("push-server").value ? Number(el("push-server").value) : null
        })
      });
      if (r.ok) {
        this.savedId = r.pair_id;
        el("pair-id").value = r.pair_id;
        if (el("f-hid")) el("f-hid").value = r.hid;
        const dl = el("btn-download");
        dl.href = "/pair/" + r.pair_id + "/download";
        showResult(el("push-result"), `pair ذخیره شد (id=${r.pair_id}, hid=${r.hid}). ZIP از دکمه‌ی دانلود.`);
        el("push-result").classList.remove("hidden");
      } else {
        showResult(el("push-result"), "خطا: " + (r.error || "") + "\n" +
          JSON.stringify(r.issues || [], null, 2), true);
        el("push-result").classList.remove("hidden");
      }
    },

    async push() {
      if (!this.savedId) { await this.save(); if (!this.savedId) return; }
      if (!confirm("کانفیگ روی نود(های) انتخابی نوشته و hot reload می‌شود. ادامه؟")) return;
      const r = await api(`/api/pair/${this.savedId}/push`, {
        method: "POST",
        body: JSON.stringify({
          client_node_id: el("push-client").value ? Number(el("push-client").value) : null,
          server_node_id: el("push-server").value ? Number(el("push-server").value) : null
        })
      });
      showResult(el("push-result"), JSON.stringify(r, null, 2), !r.ok);
      el("push-result").classList.remove("hidden");
    },

    async checkLive() {
      if (!this.savedId) { alert("اول pair را ذخیره کنید."); return; }
      const r = await api(`/api/pair/${this.savedId}/check`);
      renderIssues(el("preview-issues"), r.issues || [{ level: "error", path: "live",
        message: r.error || "خطا", hint: "" }], r.summary);
    }
  };

  /* ---------------------------------------------------------- history */
  const history = {
    init() {
      $$("[data-view]").forEach((b) => b.addEventListener("click", async () => {
        const pre = el("version-view");
        pre.classList.remove("hidden");
        pre.textContent = "…";
        const r = await api("/versions/" + b.dataset.view + ".json");
        pre.textContent = `# version ${r.id} · ${r.created_at} · sha ${r.sha256.slice(0, 16)}\n\n` + r.config;
      }));
    }
  };

  return { dash, nodes, core, nodeForm, editor, pair, history, api,
           utils: { fmtBytes, num, esc } };
})();
