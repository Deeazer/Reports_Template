import { api } from "../api.js";
import { h, field, toast, debouncePatch } from "../ui.js";

// Вкладка «Социотехническое тестирование»: сценарии, целевая группа, подготовка,
// рекомендации. Статистика (переходы/вводы) считается на сервере и показывается здесь.
const ACTIONS = [
  ["opened", "Открыл"],
  ["clicked", "Перешёл"],
  ["submitted", "Ввёл данные"],
  ["reported", "Сообщил в ИБ"],
];

function uid() { return "s" + Math.random().toString(36).slice(2, 8); }

export function socialTab(p, afterSave) {
  p.social = p.social || {};
  const S = p.social;
  S.scenarios = S.scenarios || [];
  S.targets = S.targets || [];

  const wrap = h("div", {});
  const stats = h("div");
  // статистика пересчитывается на сервере и приходит в ответе на сохранение
  const onSave = debouncePatch(async () => {
    try {
      const r = await api.updateProject(p.id, { social: S });
      for (const k of ["social_stats", "summary", "auto_threats", "updated_by_name", "updated_at"]) p[k] = r[k];
      renderStats(); afterSave && afterSave(); toast("Сохранено");
    } catch (e) { toast(e.message, true); }
  }, 600);
  const saveAndStat = onSave;

  function renderStats() {
    const st = p.social_stats || {};
    stats.replaceChildren();
    if (!st.total) { stats.append(h("div", { class: "muted" }, "Добавьте сотрудников в целевую группу, чтобы увидеть статистику.")); return; }
    const row = (d, bold) => h("tr", {}, h("td", {}, bold ? h("b", {}, d.name || "Всего") : (d.name || "Всего")),
      h("td", {}, String(d.total)),
      ...["opened", "clicked", "submitted", "reported"].map(k => h("td", {}, `${d[k] || 0} (${d[k + "_pct"] || 0}%)`)));
    const tbl = h("table");
    tbl.append(h("tr", {}, ...["Сценарий", "Группа", "Открыли", "Перешли", "Ввели данные", "Сообщили в ИБ"].map(x => h("th", {}, x))));
    (st.by_scenario || []).filter(d => d.total).forEach(d => tbl.append(row(d)));
    tbl.append(row(st, true));
    stats.append(tbl);
  }
  renderStats();

  // ---- сценарии ----
  const scenBox = h("div");
  const renderScen = () => {
    scenBox.replaceChildren();
    if (!S.scenarios.length) scenBox.append(h("div", { class: "muted", style: { marginBottom: "8px" } }, "Сценарии не добавлены."));
    S.scenarios.forEach((sc, i) => {
      sc.id = sc.id || uid();
      scenBox.append(h("div", { class: "card pad", style: { marginBottom: "10px", background: "var(--bg)" } },
        h("div", { class: "between" }, h("b", {}, `Сценарий ${i + 1}`),
          h("button", { class: "btn danger sm", onclick: () => { S.scenarios.splice(i, 1); onSave(); renderScen(); } }, "Удалить")),
        h("div", { class: "cols2" },
          field("Название", h("input", { value: sc.name || "", placeholder: "Фишинговая ссылка", oninput: e => { sc.name = e.target.value; saveAndStat(); } })),
          field("Целевая группа", h("input", { value: sc.target_group || "", placeholder: "Сотрудники Заказчика", oninput: e => { sc.target_group = e.target.value; onSave(); } }))),
        field("Повод / триггер", h("input", { value: sc.trigger || "", placeholder: "Инцидент ИБ (смена паролей)", oninput: e => { sc.trigger = e.target.value; onSave(); } })),
        field("Описание сценария", h("textarea", { oninput: e => { sc.description = e.target.value; onSave(); } }, sc.description || "")),
        scenarioImages(p, sc)));
    });
  };
  renderScen();

  // ---- целевая группа ----
  const targBox = h("div");
  const renderTargets = () => {
    targBox.replaceChildren();
    const tbl = h("table");
    tbl.append(h("tr", {}, h("th", {}, "Сотрудник / контакт"), h("th", {}, "Сценарий"),
      ...ACTIONS.map(([, l]) => h("th", { style: { width: "70px" } }, l)), h("th", { style: { width: "40px" } }, "")));
    S.targets.forEach((t, i) => {
      const cells = [
        h("td", {}, h("input", { value: t.contact || "", placeholder: "i.ivanov@org.ru", style: { border: "none", padding: "2px" }, oninput: e => { t.contact = e.target.value; saveAndStat(); } })),
        h("td", {}, scenSelect(t)),
      ];
      ACTIONS.forEach(([k]) => cells.push(h("td", { style: { textAlign: "center" } },
        h("input", { type: "checkbox", checked: !!t[k], style: { width: "auto" }, onchange: e => { t[k] = e.target.checked; saveAndStat(); } }))));
      cells.push(h("td", {}, h("button", { class: "btn danger sm", onclick: () => { S.targets.splice(i, 1); saveAndStat(); renderTargets(); } }, "×")));
      tbl.append(h("tr", {}, ...cells));
    });
    if (!S.targets.length) tbl.append(h("tr", {}, h("td", { colspan: 7, class: "muted" }, "Целевая группа пуста")));
    targBox.append(tbl);
  };
  const scenSelect = (t) => {
    const sel = h("select", { onchange: e => { t.scenario = e.target.value; saveAndStat(); } });
    sel.append(h("option", { value: "" }, "—"));
    S.scenarios.forEach((sc, i) => sel.append(h("option", { value: sc.id, selected: t.scenario === sc.id }, sc.name || `Сценарий ${i + 1}`)));
    return sel;
  };
  renderTargets();

  wrap.append(
    h("p", { class: "muted" }, "Раздел попадает в отчёт отдельной главой; целевая группа также выводится в Приложение 1, а итоги — в таблицу 3.3. «Перешёл» подразумевает «Открыл», «Ввёл данные» — «Перешёл»."),
    h("div", { class: "between", style: { margin: "6px 0" } }, h("b", {}, "Сценарии социальной инженерии"),
      h("button", { class: "btn sec sm", onclick: () => { S.scenarios.push({ id: uid(), name: "", target_group: "Сотрудники Заказчика", trigger: "", description: "" }); onSave(); renderScen(); renderTargets(); } }, "+ Сценарий")),
    scenBox,
    h("div", { class: "between", style: { margin: "14px 0 6px" } }, h("b", {}, "Целевая группа"),
      h("button", { class: "btn sec sm", onclick: () => { S.targets.push({ contact: "", scenario: S.scenarios[0] && S.scenarios[0].id || "", opened: false, clicked: false, submitted: false, reported: false }); saveAndStat(); renderTargets(); } }, "+ Сотрудник")),
    h("div", { class: "card pad" }, targBox),
    h("div", { style: { marginTop: "16px" } }, h("b", {}, "Итоги (таблица 3.3 и 1.4)"), h("div", { style: { marginTop: "8px" } }, stats)),
    h("div", { class: "card pad", style: { marginTop: "16px" } },
      field("Процесс подготовки (необязательно)", h("textarea", { placeholder: "Средства рассылки, обход спам-фильтров и т. п.", oninput: e => { S.preparation = e.target.value; onSave(); } }, S.preparation || "")),
      field("Дополнительные рекомендации (по одной в строке)", h("textarea", { oninput: e => { S.recommendations = e.target.value; onSave(); } }, S.recommendations || ""))),
  );
  return wrap;
}

// Изображения сценария (фишинговое письмо, поддельная страница и т. п.)
function scenarioImages(p, sc) {
  const section = "social:" + sc.id;
  const list = h("div", { class: "imgs" });
  const render = () => {
    list.replaceChildren();
    (p.images || []).filter(im => im.section === section).sort((a, b) => a.order_index - b.order_index).forEach(im => {
      const cap = h("input", { value: im.caption, placeholder: "Рисунок — подпись", onchange: e => api.updateProjectImage(im.id, e.target.value).catch(x => toast(x.message, true)) });
      list.append(h("div", { class: "ic" }, h("img", { src: im.url }),
        h("div", { class: "cap" }, cap,
          h("button", { class: "btn danger sm", style: { marginTop: "4px", width: "100%" }, onclick: async () => { try { await api.deleteProjectImage(im.id); p.images = p.images.filter(x => x.id !== im.id); render(); } catch (e) { toast(e.message, true); } } }, "Удалить"))));
    });
  };
  render();
  const fileInput = h("input", { type: "file", accept: "image/*", style: { display: "none" }, onchange: async e => {
    const f = e.target.files[0]; if (!f) return;
    try { const im = await api.uploadProjectImage(p.id, f, section, ""); (p.images = p.images || []).push(im); render(); } catch (x) { toast(x.message, true); }
    e.target.value = "";
  } });
  return h("div", { style: { marginTop: "6px" } },
    h("div", { class: "between" }, h("span", { class: "muted", style: { fontWeight: 600 } }, "Изображения сценария"),
      h("button", { class: "btn sec sm", onclick: () => fileInput.click() }, "+ Изображение")),
    fileInput, list);
}
