import { api } from "../api.js";
import { h, field, select, toast, debouncePatch } from "../ui.js";
import { richEditor } from "../richtext.js";

// Вкладка «Анализ защищённости беспроводных сетей»: цели, перечень выявленных
// сетей, описание процесса анализа и результаты по группам сетей (с итогом
// эксплуатации). Всё попадает в отчёт отдельной главой и в сводку (1.4, 3).
const OUTCOMES = [
  { value: "fail", label: "Не успешно (сеть устойчива)" },
  { value: "success", label: "Успешно (проникновение удалось)" },
];

function uid() { return "w" + Math.random().toString(36).slice(2, 8); }

export function wirelessTab(p, afterSave) {
  p.wireless = p.wireless || {};
  const W = p.wireless;
  W.networks = W.networks || [];
  W.results = W.results || [];
  const sec = (p.summary || {}).section_no ? p.summary.section_no.wireless : null;

  const onSave = debouncePatch(async () => {
    try {
      const r = await api.updateProject(p.id, { wireless: W });
      for (const k of ["summary", "updated_by_name", "updated_at"]) p[k] = r[k];
      afterSave && afterSave(); toast("Сохранено");
    } catch (e) { toast(e.message, true); }
  }, 600);

  const richField = (obj, key, section, prefix, ph) => {
    const ed = richEditor({
      value: obj[key], legacyImages: [],
      upload: async (file) => { const im = await api.uploadProjectImage(p.id, file, section, ""); (p.images = p.images || []).push(im); return im; },
      onChange: (json) => { obj[key] = json; onSave(); },
      placeholder: ph || "",
    });
    const scope = h("div", { class: "fig-scope" }, ed);
    scope.style.setProperty("--fig-prefix", JSON.stringify(prefix));
    return scope;
  };

  // ---- перечень выявленных сетей ----
  const netBox = h("div");
  const renderNets = () => {
    netBox.replaceChildren();
    const tbl = h("table");
    tbl.append(h("tr", {}, h("th", { style: { width: "40px" } }, "№"), h("th", {}, "Беспроводная сеть (SSID)"),
      h("th", {}, "Протокол"), h("th", {}, "Примечание"), h("th", { style: { width: "40px" } }, "")));
    W.networks.forEach((nw, i) => {
      nw.id = nw.id || uid();
      tbl.append(h("tr", {},
        h("td", {}, String(i + 1)),
        h("td", {}, h("input", { value: nw.ssid || "", placeholder: "Ekoprom_Guest", style: { border: "none", padding: "2px" }, oninput: e => { nw.ssid = e.target.value; onSave(); } })),
        h("td", {}, h("input", { value: nw.protocol || "", placeholder: "WPA3-SAE / WPA2-Enterprise", style: { border: "none", padding: "2px" }, oninput: e => { nw.protocol = e.target.value; onSave(); } })),
        h("td", {}, h("input", { value: nw.note || "", placeholder: "необязательно", style: { border: "none", padding: "2px" }, oninput: e => { nw.note = e.target.value; onSave(); } })),
        h("td", {}, h("button", { class: "btn danger sm", onclick: () => { W.networks.splice(i, 1); onSave(); renderNets(); } }, "×"))));
    });
    if (!W.networks.length) tbl.append(h("tr", {}, h("td", { colspan: 5, class: "muted" }, "Сети не добавлены")));
    netBox.append(tbl);
  };
  renderNets();

  // ---- результаты по группам сетей ----
  const resBox = h("div");
  const renderResults = () => {
    resBox.replaceChildren();
    if (!W.results.length) resBox.append(h("div", { class: "muted", style: { marginBottom: "8px" } }, "Группы результатов не добавлены."));
    W.results.forEach((r, i) => {
      r.id = r.id || uid();
      const prefix = sec ? `Рисунок ${sec}.4.${i + 1}.` : "Рисунок ";
      resBox.append(h("div", { class: "card pad", style: { marginBottom: "12px", background: "var(--bg)" } },
        h("div", { class: "between" }, h("b", {}, `Группа ${i + 1}`),
          h("button", { class: "btn danger sm", onclick: () => { W.results.splice(i, 1); onSave(); renderResults(); } }, "Удалить")),
        h("div", { class: "cols2" },
          field("Группа сетей / алгоритм", h("input", { value: r.title || "", placeholder: "сетей WPA3-SAE", oninput: e => { r.title = e.target.value; onSave(); } })),
          field("Результат эксплуатации", select(OUTCOMES, r.outcome, v => { r.outcome = v; onSave(); }, { placeholder: "— не выбрано —" }))),
        field("Описание (техники, ход анализа, скриншоты)",
          richField(r, "description", "wireless:" + r.id, prefix, "Какие техники применялись (перехват handshake, Rogue-AP…), что получилось…"))));
    });
  };
  renderResults();

  const wrap = h("div", {});
  wrap.append(
    h("p", { class: "muted" }, "Раздел попадает в отчёт отдельной главой. Итоговый уровень защищённости в таблицах 1.4 и 3 определяется по полю «Результат эксплуатации»: если хотя бы по одной группе сетей атака успешна — уровень «Низкий»."),
    h("div", { class: "card pad", style: { marginTop: "6px" } },
      field("Цели обследования (необязательно — иначе типовой текст)",
        richField(W, "intro", "wireless:intro", sec ? `Рисунок ${sec}.1.` : "Рисунок ",
          "Цели анализа и перечень проведённых работ…"))),
    h("div", { class: "between", style: { margin: "16px 0 6px" } }, h("b", {}, "Выявленные беспроводные сети (таблица 7.3.1)"),
      h("button", { class: "btn sec sm", onclick: () => { W.networks.push({ id: uid(), ssid: "", protocol: "", note: "" }); onSave(); renderNets(); } }, "+ Сеть")),
    h("div", { class: "card pad" }, netBox),
    h("div", { class: "card pad", style: { marginTop: "16px" } },
      field("Анализ защищённости (описание процесса, скриншоты выявленных сетей)",
        richField(W, "survey", "wireless:survey", sec ? `Рисунок ${sec}.3.` : "Рисунок ",
          "Опишите процесс анализа, приложите скриншоты выявленных сетей на площадках…"))),
    h("div", { class: "between", style: { margin: "16px 0 6px" } }, h("b", {}, "Результаты по группам сетей"),
      h("button", { class: "btn sec sm", onclick: () => { W.results.push({ id: uid(), title: "", outcome: "", description: "" }); onSave(); renderResults(); } }, "+ Группа")),
    resBox,
    h("div", { class: "card pad", style: { marginTop: "16px" } },
      field("Дополнительные рекомендации (по одной в строке)",
        h("textarea", { placeholder: "Например: перейти на WPA3, отключить WPS, вынести гостевой Wi-Fi в отдельный VLAN…", oninput: e => { W.recommendations = e.target.value; onSave(); } }, W.recommendations || ""))),
  );
  return wrap;
}
