import { api } from "../api.js";
import { h, field, toast } from "../ui.js";

export async function renderSettings() {
  const s = await api.settings();
  const wrap = h("div", {});
  wrap.append(h("h2", {}, "Настройки"));

  // Исполнитель (реквизиты)
  const ex = s.executor || { name: "", requisites: "" };
  const exName = h("input", { value: ex.name || "" });
  const exReq = h("textarea", { style: { minHeight: "140px" } }, ex.requisites || "");
  wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
    h("h3", { style: { marginTop: 0 } }, "Реквизиты Исполнителя"),
    h("p", { class: "muted" }, "Подставляются в раздел 1.6 «Реквизиты сторон» всех новых отчётов."),
    field("Наименование организации", exName),
    field("Реквизиты (каждый пункт с новой строки)", exReq),
    h("button", { class: "btn", onclick: async () => { try { await api.saveSetting("executor", { name: exName.value, requisites: exReq.value }); toast("Сохранено"); } catch (e) { toast(e.message, true); } } }, "Сохранить")));

  // Параметры отчёта
  const rep = s.report || {};
  const cb = (key, label, def) => {
    const input = h("input", { type: "checkbox", checked: rep[key] ?? def, style: { width: "auto" } });
    return { input, el: h("label", { class: "row", style: { padding: "4px 0" } }, input, " " + label), key };
  };
  const c1 = cb("include_fstec_v", "Добавлять в карточку уязвимости уровень критичности по методике ФСТЭК (V)", true);
  const c2 = cb("include_risk_stats", "Добавлять таблицу 3.2 «Количество уязвимостей по уровням опасности»", true);
  const confLabel = h("input", { value: rep.confidential_label || "Конфиденциально" });
  wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
    h("h3", { style: { marginTop: 0 } }, "Параметры отчёта"),
    c1.el, c2.el,
    field("Текст грифа в колонтитуле", confLabel),
    h("button", { class: "btn", onclick: async () => { try { await api.saveSetting("report", { include_fstec_v: c1.input.checked, include_risk_stats: c2.input.checked, confidential_label: confLabel.value }); toast("Сохранено"); } catch (e) { toast(e.message, true); } } }, "Сохранить")));

  // Перечень угроз БДУ ФСТЭК России (импорт thrlist.xlsx)
  const bduInfo = h("span", { class: "muted" });
  api.bdu().then(b => { bduInfo.textContent = `Сейчас: ${Object.keys(b.threats).length} угроз, выгрузка от ${b.retrieved || "—"}.`; }).catch(() => {});
  const bduFile = h("input", { type: "file", accept: ".xlsx", style: { display: "none" }, onchange: async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const r = await api.importBdu(f);
      toast(`Загружено угроз: ${r.threats}; обновлено проектов: ${r.projects_updated}`);
      bduInfo.textContent = `Сейчас: ${r.threats} угроз, выгрузка от ${r.retrieved}.`;
    } catch (x) { toast(x.message, true); }
    e.target.value = "";
  } });
  wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
    h("h3", { style: { marginTop: 0 } }, "Перечень угроз БДУ ФСТЭК России"),
    h("p", { class: "muted" }, "Загрузите файл thrlist.xlsx с bdu.fstec.ru (раздел «Угрозы» → выгрузка в Excel). Каталог угроз по умолчанию и каталоги проектов дополнятся новыми угрозами; у угроз заполнятся пустые поля — нарушители (по источнику угрозы), нарушаемые свойства, последствия и интерфейсы (по объекту воздействия). Заполненные вручную значения не меняются."),
    h("div", { class: "row" }, h("button", { class: "btn", onclick: () => bduFile.click() }, "Загрузить thrlist.xlsx"), bduInfo, bduFile)));

  // Справочники по умолчанию (JSON редактор)
  const sections = [
    ["tools", "Инструментарий по умолчанию"],
    ["intruders", "Нарушители по умолчанию"],
    ["interfaces", "Интерфейсы по умолчанию"],
    ["threats", "Угрозы по умолчанию"],
    ["fstec", "Коэффициенты методики ФСТЭК (K, L, P, E, H, веса)"],
  ];
  const jsonCard = h("div", { class: "card pad" },
    h("h3", { style: { marginTop: 0 } }, "Справочники по умолчанию"),
    h("p", { class: "muted" }, "Копируются в каждый новый проект. Редактирование в формате JSON — для опытных пользователей."));
  sections.forEach(([key, label]) => {
    const ta = h("textarea", { style: { minHeight: "120px", fontFamily: "monospace", fontSize: "12px" } }, JSON.stringify(s[key], null, 1));
    jsonCard.append(h("details", { style: { marginBottom: "10px" } },
      h("summary", { style: { cursor: "pointer", fontWeight: 600 } }, label),
      ta,
      h("button", { class: "btn sm", style: { marginTop: "6px" }, onclick: async () => {
        let val; try { val = JSON.parse(ta.value); } catch { toast("Некорректный JSON", true); return; }
        try { await api.saveSetting(key, val); toast("Сохранено"); } catch (e) { toast(e.message, true); }
      } }, "Сохранить")));
  });
  wrap.append(jsonCard);
  return wrap;
}
