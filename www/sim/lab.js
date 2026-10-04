/*
 * The simulation lab: draws every scenario's results from the JSON the
 * scenario scripts export (`wayfinder_sim.showcase`, schema 1).
 *
 * The data arrives as `window.WF_SIM`, an array the site build assembles from
 * www/sim/data/*.json into /sim/data.js — a script rather than a fetch,
 * because the site's CSP is `connect-src 'none'` and a results page is no
 * reason to loosen it.
 *
 * No dependencies, like the rest of the site. Charts are SVG drawn at the
 * container's real width (re-drawn on resize) so axis text stays legible on a
 * phone instead of being scaled down with a viewBox. Mark specs follow the
 * dataviz rules the simulator's own plots use: 2px lines, r=4 dots with a 2px
 * surface ring, bars capped at 24px with a rounded data end, hairline solid
 * gridlines, a legend for two or more series, text in ink tokens only, and a
 * data table under every chart.
 */

(() => {
  "use strict";

  const root = document.getElementById("lab-scenarios");
  const tip = document.getElementById("lab-tip");
  const data = Array.isArray(window.WF_SIM) ? window.WF_SIM : [];
  if (!root) return;

  const NS = "http://www.w3.org/2000/svg";
  const ORDER = [
    "failover",
    "captured-device",
    "jammer-map",
    "coverage-per-relay",
    "battery-life",
    "crowded-lora",
    "scale",
  ];
  const CATEGORY = {
    resilience: "Resilience",
    security: "Security",
    planning: "Planning",
    capacity: "Capacity",
  };
  const SERIES = ["#2a78d6", "#1baf7a", "#eda100", "#4a3aa7"];
  const SURFACE = "#f3f1ed";
  // Marks drawn over a heatmap: the blue series hue vanishes on the blue
  // sequential ramp, so overlays use ink and the site's accent red instead.
  const OVERLAY = ["#16171a", "#d43735"];
  const colorsFor = (chart) => (chart.heatmap ? OVERLAY : SERIES);
  const SEQ = [
    "#cde2fb",
    "#b7d3f6",
    "#9ec5f4",
    "#86b6ef",
    "#6da7ec",
    "#5598e7",
    "#3987e5",
    "#2a78d6",
    "#256abf",
    "#1c5cab",
    "#184f95",
    "#104281",
    "#0d366b",
  ];
  const REPO = "https://github.com/benj2468/wayfinder/blob/main/";

  /* ------------------------------------------------------------- helpers */

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "text") node.textContent = v;
      else if (k === "style") setStyle(node, v);
      else node.setAttribute(k, v);
    }
    for (const child of children || []) if (child) node.append(child);
    return node;
  }

  // The site's CSP has no 'unsafe-inline' for styles, so a `style="…"`
  // attribute is dropped on the deployed site (and only there — a local
  // preview serves no headers). Properties set through the CSSOM are not
  // subject to it, so per-element colours go in that way.
  function setStyle(node, css) {
    for (const decl of css.split(";")) {
      const at = decl.indexOf(":");
      if (at > 0)
        node.style.setProperty(
          decl.slice(0, at).trim(),
          decl.slice(at + 1).trim(),
        );
    }
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined) continue;
      if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    return node;
  }

  const isNum = (v) => typeof v === "number" && Number.isFinite(v);

  function fmt(v, asPct) {
    if (v === null || v === undefined) return "–";
    if (typeof v !== "number") return String(v);
    if (asPct)
      return `${(v * 100).toFixed(v !== 0 && Math.abs(v) < 0.1 ? 1 : 0)}%`;
    const a = Math.abs(v);
    if (a >= 1000) return Math.round(v).toLocaleString("en-US");
    if (a >= 100) return v.toFixed(0);
    if (a >= 10) return v.toFixed(1).replace(/\.0$/, "");
    if (a >= 1) return v.toFixed(2).replace(/\.?0+$/, "");
    if (a === 0) return "0";
    return a >= 0.01 ? String(Number(v.toFixed(2))) : v.toPrecision(2);
  }

  function niceStep(span, count) {
    const raw = span / Math.max(1, count);
    const mag = 10 ** Math.floor(Math.log10(raw));
    const norm = raw / mag;
    return (norm < 1.5 ? 1 : norm < 3 ? 2 : norm < 7 ? 5 : 10) * mag;
  }

  function linearTicks(lo, hi, count) {
    if (hi <= lo) return [lo];
    const step = niceStep(hi - lo, count);
    const out = [];
    for (
      let v = Math.ceil(lo / step) * step;
      v <= hi + step * 1e-9;
      v += step
    ) {
      out.push(Math.abs(v) < step * 1e-9 ? 0 : v);
    }
    return out;
  }

  function logTicks(lo, hi) {
    const out = [];
    for (
      let e = Math.floor(Math.log10(lo));
      e <= Math.ceil(Math.log10(hi));
      e++
    ) {
      for (const m of [1, 2, 5]) {
        const v = m * 10 ** e;
        if (v >= lo * 0.999 && v <= hi * 1.001) out.push(v);
      }
    }
    return out;
  }

  function seqColor(t) {
    const x = Math.max(0, Math.min(1, t)) * (SEQ.length - 1);
    return SEQ[Math.round(x)];
  }

  /* ------------------------------------------------------------- tooltip */

  function showTip(evt, rows) {
    tip.replaceChildren(...rows);
    tip.hidden = false;
    const pad = 14;
    const { innerWidth: w, innerHeight: h } = window;
    const r = tip.getBoundingClientRect();
    let x = evt.clientX + pad;
    let y = evt.clientY + pad;
    if (x + r.width > w - 8) x = evt.clientX - r.width - pad;
    if (y + r.height > h - 8) y = evt.clientY - r.height - pad;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  }

  function hideTip() {
    tip.hidden = true;
  }

  function tipRow(color, label, value) {
    const row = el("div", { class: "lab-tip__row" });
    if (color)
      row.append(
        el("span", {
          class: "lab-key lab-key--dot",
          style: `background:${color}`,
        }),
      );
    row.append(el("span", { text: label }));
    if (value !== undefined) row.append(el("b", { text: value }));
    return row;
  }

  /* --------------------------------------------------------------- chart */

  function drawChart(host, chart) {
    const width = Math.max(280, Math.floor(host.clientWidth));
    const heat = chart.heatmap;
    const series = chart.series || [];
    const categorical = series.some(
      (s) => s.kind === "bar" || s.x.some((x) => typeof x === "string"),
    );
    const pct =
      Array.isArray(chart.y_range) &&
      chart.y_range[0] === 0 &&
      chart.y_range[1] === 1;
    // Categorical labels may wrap onto a second line; leave room for it above
    // the axis title.
    const m = { l: 46, r: 14, t: 26, b: categorical ? 54 : 40 };
    const innerW = width - m.l - m.r;

    // Domains.
    let xs = [];
    let ys = [];
    for (const s of series) {
      // Every x counts toward the domain, valued or not: a gap (no route, no
      // data) at the start of a series is often the point of the chart.
      s.x.forEach((x, i) => {
        xs.push(x);
        if (s.y[i] !== null) ys.push(s.y[i]);
      });
    }
    if (heat) {
      xs = xs.concat(heat.xs);
      ys = ys.concat(heat.ys);
    }
    const cats = categorical
      ? [...new Set(series.flatMap((s) => s.x.map(String)))]
      : [];
    const numXs = xs.filter(isNum);
    let x0 = Math.min(...numXs);
    let x1 = Math.max(...numXs);
    if (heat) {
      const dx = heat.xs.length > 1 ? (heat.xs[1] - heat.xs[0]) / 2 : 1;
      x0 = Math.min(x0, heat.xs[0] - dx);
      x1 = Math.max(x1, heat.xs[heat.xs.length - 1] + dx);
    }
    if (x0 === x1) {
      x0 -= 1;
      x1 += 1;
    }
    const numYs = ys.filter(isNum);
    let y0;
    let y1;
    if (chart.y_range) [y0, y1] = chart.y_range;
    else if (heat) {
      const dy = heat.ys.length > 1 ? (heat.ys[1] - heat.ys[0]) / 2 : 1;
      y0 = Math.min(...numYs, heat.ys[0] - dy);
      y1 = Math.max(...numYs, heat.ys[heat.ys.length - 1] + dy);
    } else {
      y0 = Math.min(0, ...numYs);
      y1 = Math.max(...numYs);
      if (y1 === y0) y1 = y0 + 1;
      y1 += (y1 - y0) * 0.06;
    }
    const innerH = heat
      ? Math.max(180, Math.min(420, (innerW * (y1 - y0)) / (x1 - x0)))
      : Math.round(Math.max(170, Math.min(260, innerW * 0.5)));
    const height = innerH + m.t + m.b;

    const logX = !!chart.x_log && x0 > 0;
    const sx = categorical
      ? (x) => m.l + ((cats.indexOf(String(x)) + 0.5) / cats.length) * innerW
      : logX
        ? (x) =>
            m.l +
            ((Math.log(x) - Math.log(x0)) / (Math.log(x1) - Math.log(x0))) *
              innerW
        : (x) => m.l + ((x - x0) / (x1 - x0)) * innerW;
    const sy = (y) => m.t + innerH - ((y - y0) / (y1 - y0)) * innerH;

    const root = svg("svg", {
      class: "lab-svg",
      width,
      height,
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": chart.title,
    });

    // Heatmap cells first, beneath everything.
    if (heat) {
      const [v0, v1] = heat.value_range || [
        Math.min(...heat.values.flat().filter(isNum)),
        Math.max(...heat.values.flat().filter(isNum)),
      ];
      const cw =
        heat.xs.length > 1 ? Math.abs(sx(heat.xs[1]) - sx(heat.xs[0])) : innerW;
      const ch =
        heat.ys.length > 1 ? Math.abs(sy(heat.ys[1]) - sy(heat.ys[0])) : innerH;
      heat.values.forEach((row, j) => {
        row.forEach((v, i) => {
          if (!isNum(v)) return;
          const cell = svg("rect", {
            x: sx(heat.xs[i]) - cw / 2,
            y: sy(heat.ys[j]) - ch / 2,
            width: cw + 0.5,
            height: ch + 0.5,
            fill: seqColor((v - v0) / (v1 - v0 || 1)),
          });
          cell.addEventListener("pointermove", (e) =>
            showTip(e, [
              el("div", { text: `${fmt(heat.xs[i])}, ${fmt(heat.ys[j])} m` }),
              tipRow(null, `${heat.label}:`, fmt(v, v1 <= 1)),
            ]),
          );
          cell.addEventListener("pointerleave", hideTip);
          root.append(cell);
        });
      });
    }

    // Grid and axes.
    const yTicks =
      heat && !chart.y_range ? linearTicks(y0, y1, 5) : linearTicks(y0, y1, 4);
    for (const t of yTicks) {
      const y = sy(t);
      if (!heat)
        root.append(
          svg("line", {
            x1: m.l,
            x2: m.l + innerW,
            y1: y,
            y2: y,
            stroke: "var(--grid)",
            "stroke-width": 1,
          }),
        );
      root.append(
        svg("text", {
          x: m.l - 7,
          y: y + 3.5,
          "text-anchor": "end",
          text: fmt(t, pct),
        }),
      );
    }
    if (!heat)
      root.append(
        svg("line", {
          x1: m.l,
          x2: m.l + innerW,
          y1: sy(Math.max(y0, 0)),
          y2: sy(Math.max(y0, 0)),
          stroke: "var(--axis)",
          "stroke-width": 1,
        }),
      );

    if (categorical) {
      // A label wider than its band breaks onto two lines at the space
      // nearest its middle, rather than running into its neighbour.
      const bandW = innerW / Math.max(1, cats.length);
      cats.forEach((c) => {
        const label = svg("text", {
          x: sx(c),
          y: m.t + innerH + 16,
          "text-anchor": "middle",
        });
        const words = c.split(" ");
        if (c.length * 6 > bandW - 6 && words.length > 1) {
          let cut = 1;
          let best = Infinity;
          for (let i = 1; i < words.length; i++) {
            const d = Math.abs(
              words.slice(0, i).join(" ").length - c.length / 2,
            );
            if (d < best) {
              best = d;
              cut = i;
            }
          }
          label.append(
            svg("tspan", {
              x: sx(c),
              dy: 0,
              text: words.slice(0, cut).join(" "),
            }),
          );
          label.append(
            svg("tspan", {
              x: sx(c),
              dy: 13,
              text: words.slice(cut).join(" "),
            }),
          );
        } else {
          label.textContent = c;
        }
        root.append(label);
      });
    } else {
      const xTicks = logX
        ? logTicks(x0, x1)
        : linearTicks(x0, x1, Math.max(3, Math.floor(innerW / 90)));
      for (const t of xTicks) {
        root.append(
          svg("text", {
            x: sx(t),
            y: m.t + innerH + 16,
            "text-anchor": "middle",
            text: fmt(t),
          }),
        );
      }
    }
    root.append(
      svg("text", {
        class: "lab-axis-label",
        x: m.l + innerW / 2,
        y: height - 6,
        "text-anchor": "middle",
        text: chart.x_label,
      }),
    );
    // The y label sits above the axis, horizontal: a rotated label is hard to
    // read, and a long one runs off the card.
    root.append(
      svg("text", {
        class: "lab-axis-label",
        x: 0,
        y: 11,
        text: chart.y_label,
      }),
    );

    // Event markers.
    for (const mk of chart.markers || []) {
      if (!isNum(mk.x) || mk.x < x0 || mk.x > x1) continue;
      const x = sx(mk.x);
      root.append(
        svg("line", {
          x1: x,
          x2: x,
          y1: m.t,
          y2: m.t + innerH,
          stroke: "var(--muted)",
          "stroke-width": 1,
          opacity: 0.6,
        }),
      );
      root.append(
        svg("text", {
          class: "lab-marker-label",
          x: x + 4,
          y: m.t + 9,
          text: mk.label,
        }),
      );
    }

    // Series.
    const bars = series.filter((s) => s.kind === "bar");
    const band = categorical ? innerW / Math.max(1, cats.length) : 0;
    const barW = bars.length ? Math.min(24, (band * 0.7) / bars.length) : 0;
    const base = sy(Math.max(y0, 0));
    series.forEach((s, si) => {
      const palette = colorsFor(chart);
      const color = palette[si % palette.length];
      if (s.kind === "bar") {
        const bi = bars.indexOf(s);
        s.x.forEach((x, i) => {
          const v = s.y[i];
          if (!isNum(v)) return;
          const cx = sx(x) + (bi - (bars.length - 1) / 2) * (barW + 2);
          const top = sy(v);
          const h = Math.max(0, base - top);
          const r = Math.min(4, h, barW / 2);
          const left = cx - barW / 2;
          const d = `M${left},${base}V${top + r}Q${left},${top} ${left + r},${top}H${left + barW - r}Q${left + barW},${top} ${left + barW},${top + r}V${base}Z`;
          const bar = svg("path", { d, fill: color });
          bar.addEventListener("pointermove", (e) =>
            showTip(e, [
              el("div", { text: String(x) }),
              tipRow(color, `${s.name}:`, fmt(v, pct)),
            ]),
          );
          bar.addEventListener("pointerleave", hideTip);
          root.append(bar);
        });
        return;
      }
      if (s.kind === "scatter") {
        s.x.forEach((x, i) => {
          const v = s.y[i];
          if (!isNum(v) || !isNum(x)) return;
          const dot = svg("circle", {
            cx: sx(x),
            cy: sy(v),
            r: heat ? 5 : 4,
            fill: color,
            stroke: SURFACE,
            "stroke-width": 2,
          });
          dot.addEventListener("pointermove", (e) =>
            showTip(e, [
              el("div", { text: `${chart.x_label}: ${fmt(x)}` }),
              tipRow(color, `${s.name}:`, fmt(v, pct)),
            ]),
          );
          dot.addEventListener("pointerleave", hideTip);
          root.append(dot);
        });
        return;
      }
      // line / step / area: a path broken at nulls.
      let d = "";
      let pen = false;
      s.x.forEach((x, i) => {
        const v = s.y[i];
        if (!isNum(v) || !isNum(x)) {
          pen = false;
          return;
        }
        const px = sx(x);
        const py = sy(v);
        if (!pen) d += `M${px},${py}`;
        else if (s.kind === "step") d += `H${px}V${py}`;
        else d += `L${px},${py}`;
        pen = true;
      });
      root.append(
        svg("path", {
          d,
          fill: "none",
          stroke: color,
          "stroke-width": 2,
          "stroke-linejoin": "round",
          "stroke-linecap": "round",
        }),
      );
      // Few points: mark them, so a sparse sweep reads as samples.
      const pts = s.x.filter((x, i) => isNum(x) && isNum(s.y[i])).length;
      if (pts <= 12 && s.kind !== "step") {
        s.x.forEach((x, i) => {
          if (!isNum(x) || !isNum(s.y[i])) return;
          root.append(
            svg("circle", {
              cx: sx(x),
              cy: sy(s.y[i]),
              r: 4,
              fill: color,
              stroke: SURFACE,
              "stroke-width": 2,
            }),
          );
        });
      }
    });

    // Crosshair hover for line/step charts.
    const lines = series.filter(
      (s) => s.kind === "line" || s.kind === "step" || s.kind === "area",
    );
    if (lines.length && !categorical) {
      const cross = svg("line", {
        y1: m.t,
        y2: m.t + innerH,
        stroke: "var(--muted)",
        "stroke-width": 1,
        visibility: "hidden",
      });
      root.append(cross);
      const hit = svg("rect", {
        x: m.l,
        y: m.t,
        width: innerW,
        height: innerH,
        fill: "transparent",
      });
      hit.addEventListener("pointermove", (e) => {
        const box = root.getBoundingClientRect();
        const px = e.clientX - box.left;
        const rows = [];
        let snapX = null;
        lines.forEach((s) => {
          let best = -1;
          let bestD = Infinity;
          s.x.forEach((x, i) => {
            if (!isNum(x) || !isNum(s.y[i])) return;
            const dd = Math.abs(sx(x) - px);
            if (dd < bestD) {
              bestD = dd;
              best = i;
            }
          });
          if (best < 0) return;
          if (snapX === null) {
            snapX = s.x[best];
            rows.push(el("div", { text: `${chart.x_label}: ${fmt(snapX)}` }));
          }
          rows.push(
            tipRow(
              SERIES[series.indexOf(s) % SERIES.length],
              `${s.name}:`,
              fmt(s.y[best], pct),
            ),
          );
        });
        if (snapX === null) return;
        cross.setAttribute("x1", sx(snapX));
        cross.setAttribute("x2", sx(snapX));
        cross.setAttribute("visibility", "visible");
        showTip(e, rows);
      });
      hit.addEventListener("pointerleave", () => {
        cross.setAttribute("visibility", "hidden");
        hideTip();
      });
      root.append(hit);
    }

    host.replaceChildren(root);
  }

  function legendFor(chart) {
    const series = chart.series || [];
    if (series.length < 2) return null;
    const list = el("ul", { class: "lab-legend" });
    series.forEach((s, i) => {
      const kind =
        s.kind === "scatter"
          ? "lab-key--dot"
          : s.kind === "bar"
            ? "lab-key--bar"
            : "";
      const palette = colorsFor(chart);
      list.append(
        el("li", {}, [
          el("span", {
            class: `lab-key ${kind}`,
            style: `background:${palette[i % palette.length]}`,
          }),
          document.createTextNode(s.name),
        ]),
      );
    });
    return list;
  }

  function scaleFor(chart) {
    const heat = chart.heatmap;
    if (!heat) return null;
    const [v0, v1] = heat.value_range || [0, 1];
    const pct = v1 <= 1;
    return el("div", { class: "lab-scale" }, [
      el("span", { text: fmt(v0, pct) }),
      el("span", {
        class: "lab-scale__bar",
        style: `background:linear-gradient(90deg, ${SEQ[0]}, ${SEQ[6]}, ${SEQ[12]})`,
      }),
      el("span", { text: fmt(v1, pct) }),
      el("span", { text: heat.label }),
    ]);
  }

  function chartTable(chart) {
    const MAX = 150;
    const series = chart.series || [];
    const pct =
      Array.isArray(chart.y_range) &&
      chart.y_range[0] === 0 &&
      chart.y_range[1] === 1;
    const table = el("table", { class: "lab-table" });
    if (chart.heatmap) {
      const h = chart.heatmap;
      table.append(
        el("tr", {}, [
          el("th", { text: `${chart.y_label} \\ ${chart.x_label}` }),
          ...h.xs.map((x) => el("th", { text: fmt(x) })),
        ]),
      );
      h.values.forEach((row, j) =>
        table.append(
          el("tr", {}, [
            el("td", { text: fmt(h.ys[j]) }),
            ...row.map((v) =>
              el("td", {
                text: fmt(v, h.value_range && h.value_range[1] <= 1),
              }),
            ),
          ]),
        ),
      );
      return table;
    }
    const sameX =
      series.length > 0 &&
      series.every((s) => JSON.stringify(s.x) === JSON.stringify(series[0].x));
    if (sameX) {
      table.append(
        el("tr", {}, [
          el("th", { text: chart.x_label }),
          ...series.map((s) => el("th", { text: s.name })),
        ]),
      );
      series[0].x.slice(0, MAX).forEach((x, i) => {
        table.append(
          el("tr", {}, [
            el("td", { text: fmt(x) }),
            ...series.map((s) => el("td", { text: fmt(s.y[i], pct) })),
          ]),
        );
      });
    } else {
      table.append(
        el("tr", {}, [
          el("th", { text: "series" }),
          el("th", { text: chart.x_label }),
          el("th", { text: chart.y_label }),
        ]),
      );
      let n = 0;
      for (const s of series) {
        for (let i = 0; i < s.x.length && n < MAX; i++, n++) {
          table.append(
            el("tr", {}, [
              el("td", { text: s.name }),
              el("td", { text: fmt(s.x[i]) }),
              el("td", { text: fmt(s.y[i], pct) }),
            ]),
          );
        }
      }
    }
    return table;
  }

  function figure(chart, wide) {
    const host = el("div", {});
    const fig = el(
      "figure",
      { class: `lab-chart${wide ? " lab-chart--wide" : ""}` },
      [
        el("h3", { class: "lab-chart__title", text: chart.title }),
        legendFor(chart),
        scaleFor(chart),
        host,
        chart.caption
          ? el("p", { class: "lab-chart__cap", text: chart.caption })
          : null,
        el("details", { class: "lab-details" }, [
          el("summary", { text: "Data" }),
          el("div", { class: "lab-details__body" }, [chartTable(chart)]),
        ]),
      ],
    );
    let last = 0;
    const redraw = () => {
      const w = Math.floor(host.clientWidth);
      if (w && w !== last) {
        last = w;
        drawChart(host, chart);
      }
    };
    if ("ResizeObserver" in window) new ResizeObserver(redraw).observe(host);
    requestAnimationFrame(redraw);
    return fig;
  }

  /* ------------------------------------------------------------ scenario */

  function scenario(s, anchorCategory) {
    const stats = el(
      "div",
      { class: "lab-stats" },
      s.headlines.map((h) =>
        el("div", { class: "lab-stat" }, [
          el("span", { class: "lab-stat__v", text: h.value }),
          el("span", { class: "lab-stat__l", text: h.label }),
          h.detail
            ? el("span", { class: "lab-stat__d", text: h.detail })
            : null,
        ]),
      ),
    );
    const charts = el(
      "div",
      { class: "lab-charts" },
      s.charts.map((c) => figure(c, !!c.heatmap)),
    );
    const more = el("div", { class: "lab-more" }, [
      el("details", { class: "lab-details" }, [
        el("summary", { text: "How this was measured" }),
        el("div", { class: "lab-details__body" }, [
          el("p", { text: s.method || "" }),
          el("pre", {
            class: "lab-params",
            text: JSON.stringify(s.params || {}, null, 1),
          }),
          s.scenario
            ? el("p", { class: "lab-src" }, [
                document.createTextNode("Source: "),
                el("a", { href: REPO + s.scenario, text: s.scenario }),
                document.createTextNode(" · "),
                el("a", {
                  href: `/sim/data/${s.slug}.json`,
                  text: "raw results (JSON)",
                }),
              ])
            : null,
        ]),
      ]),
      s.table && s.table.length > 1
        ? el("details", { class: "lab-details" }, [
            el("summary", { text: "Results table" }),
            el("div", { class: "lab-details__body" }, [
              el("table", { class: "lab-table" }, [
                el(
                  "tr",
                  {},
                  s.table[0].map((h) => el("th", { text: String(h) })),
                ),
                ...s.table.slice(1).map((row) =>
                  el(
                    "tr",
                    {},
                    row.map((v) => el("td", { text: fmt(v) })),
                  ),
                ),
              ]),
            ]),
          ])
        : null,
    ]);
    return el("section", { class: "lab-scn", id: anchorCategory }, [
      el("div", { class: "wrap" }, [
        el("p", { class: "eyebrow", text: CATEGORY[s.category] || s.category }),
        el("h2", {
          class: "section__title",
          id: `scn-${s.slug}`,
          text: s.title,
        }),
        el("p", { class: "lab-scn__q", text: s.question }),
        stats,
        el("p", { class: "lab-scn__summary", text: s.summary }),
        charts,
        more,
      ]),
    ]);
  }

  const bySlug = new Map(
    data.filter((d) => d && d.schema === 1).map((d) => [d.slug, d]),
  );
  const ordered = [
    ...ORDER.filter((slug) => bySlug.has(slug)).map((slug) => bySlug.get(slug)),
    ...[...bySlug.values()].filter((d) => !ORDER.includes(d.slug)),
  ];
  const seen = new Set();
  const sections = ordered.map((s) => {
    const anchor = seen.has(s.category) ? null : s.category;
    seen.add(s.category);
    return scenario(s, anchor);
  });
  if (sections.length) root.replaceChildren(...sections);
  else
    root.append(
      el("div", {
        class: "wrap lab-noscript",
        text: "No results have been exported yet — run `just sim-export`.",
      }),
    );

  window.addEventListener("scroll", hideTip, { passive: true });
})();
