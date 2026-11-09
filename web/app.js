/* Static answer-checking page. No server, no framework.
   Answers are compared as salted SHA-256 hashes (same scheme as questions.py). */
(function () {
  "use strict";
  var SALT = "hunting-labs-v1";
  var LABS = window.LABDATA || [];
  var state = load();

  /* ---------- SHA-256 (pure JS so it also works from file://) ---------- */
  function sha256(str) {
    var utf8 = unescape(encodeURIComponent(str)), i, j;
    var K = [], H = [], isP = {}, cnt = 0;
    for (var c = 2; cnt < 64; c++) {
      if (!isP[c]) {
        for (i = c * c; i < 313; i += c) isP[i] = 1;
        H[cnt] = (Math.pow(c, .5) * 4294967296) | 0;
        K[cnt++] = (Math.pow(c, 1 / 3) * 4294967296) | 0;
      }
    }
    H = H.slice(0, 8);
    var words = [], bitLen = utf8.length * 8;
    for (i = 0; i < utf8.length; i++) words[i >> 2] |= utf8.charCodeAt(i) << ((3 - i) % 4) * 8;
    words[bitLen >> 5] |= 0x80 << (24 - bitLen % 32);
    words[(((bitLen + 64) >> 9) << 4) + 15] = bitLen;
    for (i = 0; i < (((bitLen + 64) >> 9) << 4) + 16; i++) words[i] = words[i] | 0; // no holes
    for (j = 0; j < words.length; j += 16) {
      var w = words.slice(j, j + 16), h = H.slice(0);
      for (i = 0; i < 64; i++) {
        if (i >= 16) {
          var w15 = w[i - 15], w2 = w[i - 2];
          var s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
          var s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        var a = h[0], e = h[4];
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & h[5]) ^ (~e & h[6]);
        var t1 = (h[7] + S1 + ch + K[i] + w[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & h[1]) ^ (a & h[2]) ^ (h[1] & h[2]);
        var t2 = (S0 + maj) | 0;
        h = [(t1 + t2) | 0, a, h[1], h[2], (h[3] + t1) | 0, e, h[5], h[6]];
      }
      for (i = 0; i < 8; i++) H[i] = (H[i] + h[i]) | 0;
    }
    var out = "";
    for (i = 0; i < 8; i++) for (j = 3; j >= 0; j--) out += ((H[i] >> (j * 8)) & 255).toString(16).replace(/^(.)$/, "0$1");
    return out;
  }
  window.__sha256 = sha256; // exposed for the test script

  function norm(s) {
    return String(s).trim().toLowerCase().replace(/\s+/g, " ").replace(/^["'`]+|["'`]+$/g, "").replace(/\.+$/, "");
  }
  function numberOf(s) {
    var m = String(s).replace(/,/g, "").match(/-?\d+(?:\.\d+)?/);
    return m ? String(Math.round(parseFloat(m[0]))) : "";
  }
  function hashFor(q, raw) {
    var v = q.type === "number" ? numberOf(raw) : norm(raw);
    return sha256(SALT + "|" + q.id + "|" + v);
  }
  window.__check = function (q, raw) { return q.hashes.indexOf(hashFor(q, raw)) >= 0; };

  /* ---------- progress (per-browser convenience only) ---------- */
  function load() {
    try { return JSON.parse(localStorage.getItem("hl-progress") || "{}"); } catch (e) { return {}; }
  }
  function save() { try { localStorage.setItem("hl-progress", JSON.stringify(state)); } catch (e) { /* ignore */ } }
  function qs(q) { return state[q.id] || (state[q.id] = { ok: false, hints: 0, tries: 0 }); }

  /* ---------- helpers ---------- */
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else if (k === "class") n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { n.appendChild(c); });
    return n;
  }
  function stats(lab) {
    var ok = 0, hints = 0;
    lab.questions.forEach(function (q) { var s = qs(q); if (s.ok) ok++; hints += s.hints; });
    return { ok: ok, total: lab.questions.length, hints: hints };
  }

  /* ---------- views ---------- */
  function nav(cur) {
    var n = document.getElementById("nav");
    n.innerHTML = "";
    [["home", "Start"]].concat(LABS.map(function (l) { return [l.id, l.nav || l.title.split(":")[0]]; })).forEach(function (p) {
      n.appendChild(el("a", { href: "#" + p[0], class: p[0] === cur ? "on" : "", text: p[1] }));
    });
  }

  function home(v) {
    v.appendChild(el("h2", { text: "How this works" }));
    v.appendChild(el("p", { text: "Each lab gives you a packet capture (PCAP) from a small office network. You investigate it in Wireshark and answer questions. Attackers in these captures hide inside encrypted or normally trusted traffic, so you will rely on timing, size, volume, and structure instead of readable content." }));
    var ul = el("ul");
    ["New here? Start with the Tutorial: a short worked example that teaches the method step by step.",
     "Read the 'Before you start' notes at the top of each lab.",
     "Download the PCAP for a lab and open it in Wireshark (free, wireshark.org).",
     "Answer the questions. Hints are optional (two per question) and are counted in your summary.",
     "When you finish, the walkthrough explains the detection logic and a defense for each attack.",
     "Do the final quiz to connect each attack to its TCP/IP layer and mitigation."].forEach(function (t) { ul.appendChild(el("li", { text: t })); });
    v.appendChild(ul);
    v.appendChild(el("p", { text: "Prerequisites: you know the TCP/IP layers and have used Wireshark filters and Follow Stream. No scripting is required, although one question is easier with a few lines of Python." }));
    v.appendChild(el("h2", { text: "Your progress" }));
    LABS.forEach(function (l) {
      var s = stats(l);
      v.appendChild(el("p", {}, [el("a", { href: "#" + l.id, text: l.title }),
        el("span", { text: " - " + s.ok + "/" + s.total + " correct, " + s.hints + " hints used" })]));
    });
    v.appendChild(el("p", { class: "fb", text: "Note: answers are checked in your browser and progress is saved only in this browser. Anyone who views the page source can find the answers; this is a learning tool, not a secure exam." }));
  }

  function question(lab, q, i, summary) {
    var s = qs(q);
    var box = el("div", { class: "q" + (s.ok ? " ok" : "") });
    box.appendChild(el("p", {}, [el("strong", { text: (i + 1) + ". " }), document.createTextNode(q.prompt)]));
    var input, radios = [];
    var row = el("p");
    if (q.type === "choice") {
      q.options.forEach(function (o, k) {
        var r = el("input", { type: "radio", name: q.id, value: o });
        radios.push(r);
        box.appendChild(el("label", { class: "opt" }, [r, document.createTextNode(" " + o)]));
      });
    } else {
      input = el("input", { type: "text", "aria-label": "answer", autocomplete: "off", placeholder: q.type === "number" ? "number" : "answer" });
      row.appendChild(input);
    }
    var fb = el("p", { class: "fb" });
    var hintBox = el("div");
    var check = el("button", { type: "button", text: "Check" });
    row.appendChild(check);
    var hintBtn = el("button", { type: "button", text: "Hint" });
    row.appendChild(hintBtn);
    box.appendChild(row); box.appendChild(fb); box.appendChild(hintBox);

    function showHints() {
      hintBox.innerHTML = "";
      for (var k = 0; k < s.hints; k++) hintBox.appendChild(el("div", { class: "hint", text: "Hint " + (k + 1) + ": " + q.hints[k] }));
      hintBtn.textContent = s.hints >= q.hints.length ? "No more hints" : "Hint (" + s.hints + "/" + q.hints.length + ")";
      hintBtn.disabled = s.hints >= q.hints.length;
    }
    function solved() {
      box.className = "q ok";
      fb.className = "fb good";
      fb.textContent = "Correct. " + q.explain;
      check.disabled = true;
      if (input) input.disabled = true;
      radios.forEach(function (r) { r.disabled = true; });
    }
    hintBtn.addEventListener("click", function () { if (s.hints < q.hints.length) { s.hints++; save(); showHints(); summary(); } });
    check.addEventListener("click", function () {
      var raw = input ? input.value : (radios.filter(function (r) { return r.checked; })[0] || {}).value;
      if (!raw) { fb.className = "fb bad"; fb.textContent = "Enter an answer first."; return; }
      s.tries++;
      if (window.__check(q, raw)) { s.ok = true; save(); solved(); summary(); }
      else { save(); fb.className = "fb bad"; fb.textContent = "Not quite. Check the question again, or use a hint."; }
    });
    if (input) input.addEventListener("keydown", function (e) { if (e.key === "Enter") check.click(); });
    showHints();
    if (s.ok) { if (input) input.value = "(answered)"; solved(); }
    return box;
  }

  function labView(v, lab) {
    v.appendChild(el("h2", { text: lab.title }));
    if (lab.layer !== "All") v.appendChild(el("p", {}, [el("span", { class: "badge", text: "Layer: " + lab.layer })]));
    lab.intro.forEach(function (t) { v.appendChild(el("p", { text: t })); });
    if (lab.pcap) {
      v.appendChild(el("p", {}, [el("a", { href: lab.pcap, download: "", text: "Download " + lab.pcap.split("/").pop() })]));
    }
    if (lab.prelab && lab.prelab.length) {
      var det = el("details", { open: "" }, [el("summary", { text: "Before you start" })]);
      lab.prelab.forEach(function (b) {
        det.appendChild(el("p", {}, [el("strong", { text: b.h + ". " }), document.createTextNode(b.p)]));
      });
      v.appendChild(det);
    }
    if (lab.steps && lab.steps.length) {
      v.appendChild(el("h3", { text: "Worked example: follow these steps in Wireshark" }));
      var ol = el("ol", { class: "steps" });
      lab.steps.forEach(function (st) {
        ol.appendChild(el("li", {}, [
          el("strong", { text: st.title }),
          el("div", {}, [el("em", { text: "Do: " }), document.createTextNode(st.do)]),
          el("div", { class: "expect" }, [el("em", { text: "You should see: " }), document.createTextNode(st.expect)])]));
      });
      v.appendChild(ol);
      v.appendChild(el("h3", { text: "Checkpoint" }));
    }
    var summary = el("p", { class: "score" });
    var wbox = el("div");
    function update() {
      var s = stats(lab);
      summary.textContent = "Score: " + s.ok + " / " + s.total + " correct, " + s.hints + " hints used";
      renderWalk();
    }
    var confirmGiveUp = false;
    function renderWalk() {
      wbox.innerHTML = "";
      if (!lab.walkthrough.length) return;
      var s = stats(lab), done = s.ok === s.total;
      var btn = el("button", { type: "button", text: done ? "Show walkthrough" : "Give up and show walkthrough" });
      var out = el("div");
      btn.addEventListener("click", function () {
        if (!done && !confirmGiveUp) { confirmGiveUp = true; btn.textContent = "Click again to confirm (spoilers!)"; return; }
        btn.remove();
        out.appendChild(el("h3", { text: "Walkthrough" }));
        var ul = el("ul");
        lab.walkthrough.forEach(function (t) { ul.appendChild(el("li", { text: t })); });
        out.appendChild(ul);
      });
      wbox.appendChild(btn); wbox.appendChild(out);
    }
    v.appendChild(summary);
    lab.questions.forEach(function (q, i) { v.appendChild(question(lab, q, i, update)); });
    v.appendChild(wbox);
    update();
  }

  function route() {
    var id = (location.hash || "#home").slice(1);
    var v = document.getElementById("view");
    v.innerHTML = "";
    var lab = LABS.filter(function (l) { return l.id === id; })[0];
    nav(lab ? id : "home");
    if (lab) labView(v, lab); else home(v);
    window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", route);
  route();
})();
