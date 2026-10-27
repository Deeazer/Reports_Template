// Мини-помощники для построения DOM
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "html") el.innerHTML = v;
    else if (k === "value") el.value = v;
    else if (k in el && k !== "list") { try { el[k] = v; } catch { el.setAttribute(k, v); } }
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

export function toast(msg, isErr) {
  const t = h("div", { class: "toast" + (isErr ? " err" : "") }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), isErr ? 5000 : 3000);
}

export function field(label, control) {
  return h("label", { class: "field" }, h("span", {}, label), control);
}

export function select(options, value, onChange, opts = {}) {
  const sel = h("select", { onchange: (e) => onChange(e.target.value) });
  if (opts.placeholder) sel.append(h("option", { value: "" }, opts.placeholder));
  for (const o of options) {
    const val = o.value !== undefined ? o.value : o;
    const lab = o.label !== undefined ? o.label : o;
    sel.append(h("option", { value: val, selected: String(val) === String(value) }, lab));
  }
  return sel;
}

// Подтверждение необратимого удаления: кнопка активна, только когда
// введено точное значение expected (например, название проекта).
export function confirmTyped(message, expected, onYes) {
  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  const btn = h("button", { class: "btn danger", disabled: true, onclick: () => { close(); onYes(); } }, "Удалить навсегда");
  const inp = h("input", { placeholder: expected, oninput: e => { btn.disabled = e.target.value.trim() !== expected.trim(); } });
  bg.append(h("div", { class: "modal" },
    h("p", {}, message),
    h("p", { class: "muted", style: { fontSize: "13px" } }, "Действие необратимо. Для подтверждения введите: ", h("b", {}, expected)),
    inp,
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "16px" } },
      h("button", { class: "btn sec", onclick: close }, "Отмена"), btn)));
  bg.addEventListener("click", (e) => { if (e.target === bg) close(); });
  document.body.append(bg);
  inp.focus();
}

export function confirmModal(message, onYes) {
  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  bg.append(h("div", { class: "modal" },
    h("p", {}, message),
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "16px" } },
      h("button", { class: "btn sec", onclick: close }, "Отмена"),
      h("button", { class: "btn danger", onclick: () => { close(); onYes(); } }, "Удалить"),
    )));
  bg.addEventListener("click", (e) => { if (e.target === bg) close(); });
  document.body.append(bg);
}

export function badge(level) {
  if (!level) return h("span", { class: "muted" }, "—");
  return h("span", { class: "badge b-" + level }, level);
}

export const debounce = (fn, ms = 600) => {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};

// Как debounce, но для частичных обновлений: патчи, пришедшие за время
// ожидания, объединяются, чтобы правка одного поля не терялась при быстрой
// правке другого.
export const debouncePatch = (fn, ms = 600) => {
  let t, acc = {};
  return (patch) => {
    Object.assign(acc, patch); clearTimeout(t);
    t = setTimeout(() => { const p = acc; acc = {}; fn(p); }, ms);
  };
};

// Дата и время из ISO-строки сервера (время на сервере — UTC без зоны)
export function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + "Z");
  if (isNaN(d)) return iso;
  return d.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

// Строка «Добавил: … · Изменил: …» для проекта или уязвимости
export function whoLine(o) {
  const parts = [];
  if (o.created_by_name || o.created_at) parts.push(["Добавил", o.created_by_name, o.created_at]);
  if (o.updated_by_name && (o.updated_at !== o.created_at || o.updated_by_name !== o.created_by_name))
    parts.push(["Изменил", o.updated_by_name, o.updated_at]);
  const el = h("div", { class: "meta" });
  parts.forEach(([label, who, at], i) => {
    if (i) el.append(" · ");
    el.append(label + ": ", h("b", {}, who || "—"), at ? ", " + fmtDate(at) : "");
  });
  return el;
}
