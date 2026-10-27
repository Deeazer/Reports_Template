import { api } from "../api.js";
import { state } from "../main.js";
import { h, field, select, toast, badge, confirmModal, debouncePatch, whoLine } from "../ui.js";
import { richEditor } from "../richtext.js";

// Мультивыбор кодов (угрозы/интерфейсы) из каталога проекта
function multiPick(options, selected, onChange) {
  const chosen = new Set(selected || []);
  const box = h("div", { style: { maxHeight: "180px", overflow: "auto", border: "1px solid var(--line2)", borderRadius: "8px", padding: "6px 10px" } });
  let query = "";
  const draw = () => {
    box.replaceChildren();
    if (!options.length) { box.append(h("div", { class: "muted", style: { fontSize: "12px" } }, "Каталог пуст")); return; }
    // отмеченные — сверху, затем найденные по поиску
    const list = options.filter(o => chosen.has(o.code))
      .concat(options.filter(o => !chosen.has(o.code) && (!query || (o.code + " " + o.label).toLowerCase().includes(query))));
    list.forEach(o => {
      const cb = h("input", { type: "checkbox", checked: chosen.has(o.code), style: { width: "auto", marginRight: "6px" },
        onchange: e => { e.target.checked ? chosen.add(o.code) : chosen.delete(o.code); onChange([...chosen]); } });
      box.append(h("label", { class: "row", style: { padding: "2px 0", alignItems: "flex-start", cursor: "pointer" } },
        cb, h("span", { style: { fontSize: "12px" } }, h("b", {}, o.code + " "), o.label)));
    });
  };
  draw();
  if (options.length <= 12) return box;
  const search = h("input", { placeholder: `Поиск (${options.length})…`, style: { marginBottom: "4px" },
    oninput: e => { query = e.target.value.trim().toLowerCase(); draw(); } });
  return h("div", {}, search, box);
}

// Карточка уязвимости с живым пересчётом и загрузкой изображений
export function vulnCard(v, onChange, onDelete, index, project) {
  const ref = state.ref;
  project = project || { threats: [], interfaces: [] };
  let open = v._open || false;
  const container = h("div", { class: "vuln" });

  const save = debouncePatch(async (patch) => {
    try { const updated = await api.updateVuln(v.id, patch); Object.assign(v, updated); onChange(); refreshHead(); refreshMeta(); refreshComputed(); refreshAutoHint(); }
    catch (e) { toast(e.message, true); }
  }, 500);
  const field_ = (key) => (val) => { v[key] = val; save({ [key]: val }); };

  const head = h("div", { class: "head", onclick: (e) => { if (e.target.closest("button")) return; open = !open; v._open = open; body.classList.toggle("hidden", !open); } });
  const body = h("div", { class: "body" + (open ? "" : " hidden") });
  // номер раздела уязвимости в отчёте (4.1, 5.2, …) — префикс нумерации рисунков
  const secRef = ((project.summary || {}).rows || []).find(r => r.id === v.id)?.ref;
  body.style.setProperty("--fig-prefix", JSON.stringify(secRef ? `Рисунок ${secRef}.` : "Рисунок "));

  function refreshHead() {
    head.replaceChildren(
      h("span", { class: "num" }, (index + 1) + "."),
      h("span", { class: "t" }, v.title || "Без названия"),
      badge(v.severity), badge(v.final_risk),
      h("button", { class: "btn danger sm", onclick: () => confirmModal("Удалить уязвимость?", async () => { try { await api.deleteVuln(v.id); onDelete(); } catch (e) { toast(e.message, true); } }) }, "Удалить"),
    );
  }

  const meta = h("div", { style: { marginBottom: "10px" } });
  const refreshMeta = () => meta.replaceChildren(whoLine(v));

  // ---- computed display ----
  const computed = h("div", { class: "card pad", style: { background: "#eef2fb", marginBottom: "14px" } });
  function refreshComputed() {
    const score = v.cvss_score;
    const kids = [
      h("div", {}, h("span", { class: "muted" }, "CVSS: "), h("b", {}, score != null ? score : "—")),
      h("div", {}, h("span", { class: "muted" }, "Критичность: "), badge(v.severity)),
      h("div", {}, h("span", { class: "muted" }, "Вероятность: "), badge(v.probability)),
      h("div", {}, h("span", { class: "muted" }, "Итоговый риск: "), badge(v.final_risk)),
    ];
    cvssErr.textContent = v.cvss_error || "";
    if (v.cvss_vector_full && document.activeElement !== cvssOut) cvssOut.value = v.cvss_vector_full;
    if (v.fstec) kids.push(h("div", {}, h("span", { class: "muted" }, "ФСТЭК V: "), h("b", {}, v.fstec.value + " "), badge(v.fstec.level)));
    computed.replaceChildren(h("div", { class: "row", style: { gap: "20px" } }, ...kids));
  }

  // ---- CVSS builder ----
  const metricsDefs = ref.cvss_metrics;
  const cvssVals = parseVector(v.cvss_vector);
  const cvssOut = h("input", { class: "cvss-out", value: v.cvss_vector_full || v.cvss_vector || "",
    placeholder: "Вставьте вектор: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    onchange: (e) => {
      const vec = e.target.value.trim(); v.cvss_vector = vec; save({ cvss_vector: vec });
      const parsed = parseVector(vec);
      [...cvssGrid.querySelectorAll("select")].forEach((sel, i) => { const m = Object.keys(metricsDefs)[i]; sel.value = parsed[m] || ""; cvssVals[m] = parsed[m] || ""; });
    } });
  const cvssErr = h("div", { style: { color: "var(--crit)", fontSize: "12px", marginTop: "4px" } });
  const buildVector = () => Object.keys(metricsDefs).map(m => `${m}:${cvssVals[m] || ""}`).join("/");
  const cvssGrid = h("div", { class: "cvss" });
  for (const [m, opts] of Object.entries(metricsDefs)) {
    const sel = select(Object.entries(opts).map(([val, lab]) => ({ value: val, label: `${lab} (${val})` })), cvssVals[m], (val) => {
      cvssVals[m] = val; const vec = "CVSS:3.1/" + buildVector(); cvssOut.value = vec;
      v.cvss_vector = vec; save({ cvss_vector: vec });
    }, { placeholder: "—" });
    cvssGrid.append(h("div", { class: "m" }, h("span", {}, m), sel));
  }

  // подсказка: какие угрозы подберутся сами, если вручную ничего не отмечено
  const autoHint = h("div", { class: "muted", style: { fontSize: "12px", marginTop: "-6px", marginBottom: "10px" } });
  function refreshAutoHint() {
    if ((v.threat_codes || []).length) { autoHint.textContent = "Угрозы выбраны вручную — автоподбор отключён."; return; }
    const codes = v.auto_threat_codes || [];
    autoHint.textContent = codes.length
      ? "Не отмечено вручную — подобраны автоматически по последствиям (H): " + codes.join(", ")
      : "Не отмечено вручную — угрозы подберутся автоматически, когда будут указаны последствия (H) или вектор CVSS.";
  }

  const fstecSel = (table, key, label) => field(label, select(ref.fstec[table].map(o => ({ value: o.key, label: o.name })), v[key], field_(key), { placeholder: "— не выбрано —" }));

  const inp = (key, ph) => h("input", { value: v[key] || "", placeholder: ph || "", oninput: e => field_(key)(e.target.value) });
  const txt = (key, ph) => h("textarea", { placeholder: ph || "", oninput: e => field_(key)(e.target.value) }, v[key] || "");
  // форматированный текст со скриншотами внутри (block — к какому блоку относятся загружаемые файлы)
  const rich = (key, block, ph) => richEditor({
    value: v[key],
    legacyImages: (v.images || []).filter(im => im.block === block).sort((a, b) => a.order_index - b.order_index),
    upload: async (file) => { const im = await api.uploadImage(v.id, file, block, ""); (v.images = v.images || []).push(im); return im; },
    onChange: field_(key),
    placeholder: ph,
  });

  body.append(...[
    meta,
    computed,
    field("Название уязвимости", inp("title", "Напр.: Обход авторизации панели администратора")),
    v.work_type === "web" && field("Категория OWASP Top 10 (2021)",
      select((ref.owasp_top10 || []).map(o => ({ value: o.key, label: o.name })), v.owasp, field_("owasp"), { placeholder: "— не выбрано —" })),
    h("div", { class: "cols2" },
      field("Границы", inp("scope", "домен / IP / endpoint")),
      field("Инструменты", inp("tools", "BurpSuite, nmap…")),
    ),
    field("Описание", txt("description")),
    h("div", { class: "cols2" },
      field("Время обнаружения", inp("detected_at", "05.09.2026 12:30")),
      field("Модели нарушителя", inp("intruder_models", "Н1, Н2")),
    ),
    h("div", { class: "cols2" },
      h("div", {},
        field("Реализуемые угрозы БДУ (таблица 1.8.3)",
          multiPick((project.threats || []).map(t => ({ code: t.code, label: `${t.name}${t.bdu ? " (" + t.bdu + ")" : ""}` })),
            v.threat_codes, (codes) => { field_("threat_codes")(codes); refreshAutoHint(); })),
        autoHint),
      field("Интерфейсы воздействия",
        // только интерфейсы, относящиеся к виду работ этой уязвимости
        multiPick((project.interfaces || []).filter(i => !(i.work_types || []).length || i.work_types.includes(v.work_type))
          .map(i => ({ code: i.code, label: i.name })),
          v.interface_codes, field_("interface_codes"))),
    ),
    h("div", { class: "sec-title", style: { fontSize: "13px" } }, "Оценка CVSS v3.1 (базовые метрики)"),
    cvssGrid,
    h("div", { style: { marginTop: "6px" } }, cvssOut, cvssErr,
      h("div", { class: "muted", style: { fontSize: "12px", marginTop: "4px" } },
        "Базовые метрики CVSS v3.1 (FIRST). Сверить вектор: ",
        h("a", { href: "https://www.first.org/cvss/calculator/3.1", target: "_blank", rel: "noopener" }, "first.org/cvss/calculator/3.1"))),
    h("div", { class: "cols2", style: { marginTop: "12px" } },
      field("Доступность уязвимой функциональности", select(ref.levels3, v.availability, field_("availability"), { placeholder: "—" })),
      field("Простота эксплуатации", select(ref.levels3, v.ease, field_("ease"), { placeholder: "—" })),
    ),
    h("div", { class: "sec-title", style: { fontSize: "13px" } }, "Показатели методики ФСТЭК (30.06.2025)"),
    h("p", { class: "muted", style: { marginTop: "-6px" } }, "Уровень критичности V рассчитывается автоматически"),
    fstecSel("K", "fstec_k", "Тип компонента (K)"),
    h("div", { class: "cols2" },
      fstecSel("L", "fstec_l", "Количество уязвимых компонентов (L)"),
      fstecSel("P", "fstec_p", "Доступность из сети «Интернет» (P)"),
    ),
    h("div", { class: "cols2" },
      fstecSel("E", "fstec_e", "Эксплуатация уязвимости (E)"),
      fstecSel("H", "fstec_h", "Последствия эксплуатации (H)"),
    ),
    h("div", { class: "sec-title", style: { fontSize: "13px" } }, "Proof of Concept"),
    h("p", { class: "muted", style: { marginTop: "-6px", fontSize: "12px" } },
      "Скриншоты вставляются в текст кнопкой на панели, через Ctrl+V или перетаскиванием; подпись — щелчком под рисунком. Код выделяется кнопками «<>» (в строке) и «блок кода»."),
    rich("poc", "poc", "Шаги воспроизведения, запросы, ответы сервера…"),
    h("div", { class: "sec-title", style: { fontSize: "13px" } }, "Результаты эксплуатации"),
    rich("exploitation_result", "result"),
    h("div", { class: "sec-title", style: { fontSize: "13px" } }, "Рекомендации"),
    rich("recommendations", "rec"),
  ].filter(Boolean));

  refreshHead(); refreshComputed(); refreshAutoHint(); refreshMeta();
  container.append(head, body);
  return container;
}

function parseVector(vec) {
  const o = {};
  (vec || "").split(/[\/\s]+/).forEach(p => { const [k, val] = p.split(":"); if (k && val) o[k.toUpperCase()] = val.toUpperCase(); });
  return o;
}
