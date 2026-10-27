import { api } from "../api.js";
import { h, field, select, toast, debouncePatch } from "../ui.js";
import { richEditor } from "../richtext.js";

// Вкладка «Тестирование отказа в обслуживании»: исходные данные, этапы атак
// (параметры + описание и результаты с таблицами/кодом/скриншотами) и рекомендации.
// Всё попадает в отчёт отдельной главой и в сводку (таблицы 1.4 и 3).
const OUTCOMES = [
  { value: "withstood", label: "Устойчив (сервис доступен)" },
  { value: "failed", label: "Достигнут отказ в обслуживании" },
];
const STAGE_FIELDS = [
  ["host", "Хост", "bitrix.example.org"],
  ["method", "Тип тестирования", "HTTP Flood / Slowloris"],
  ["start", "Время начала атаки", "26.07.2026 17:23"],
  ["end", "Время окончания атаки", "26.07.2026 17:55"],
  ["duration", "Длительность", "32 минуты"],
  ["power", "Мощность", "8000 RPS / 4000 соединений"],
];

function uid() { return "d" + Math.random().toString(36).slice(2, 8); }

export function dosTab(p, afterSave) {
  p.dos = p.dos || {};
  const D = p.dos;
  D.stages = D.stages || [];
  // номер главы отчёта для нумерации рисунков (4, 5, …); до пересчёта — обычная подпись
  const sec = (p.summary || {}).section_no ? p.summary.section_no.dos : null;

  const onSave = debouncePatch(async () => {
    try {
      const r = await api.updateProject(p.id, { dos: D });
      for (const k of ["summary", "updated_by_name", "updated_at"]) p[k] = r[k];
      afterSave && afterSave(); toast("Сохранено");
    } catch (e) { toast(e.message, true); }
  }, 600);

  // форматируемый редактор с нужным префиксом нумерации рисунков
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

  // ---- этапы ----
  const stageBox = h("div");
  const renderStages = () => {
    stageBox.replaceChildren();
    if (!D.stages.length) stageBox.append(h("div", { class: "muted", style: { marginBottom: "8px" } }, "Этапы тестирования не добавлены."));
    D.stages.forEach((st, i) => {
      st.id = st.id || uid();
      const prefix = sec ? `Рисунок ${sec}.${i + 2}.` : "Рисунок ";
      const section = "dos:" + st.id;
      const grid = h("div", { class: "cols2" },
        ...STAGE_FIELDS.map(([k, label, ph]) =>
          field(label, h("input", { value: st[k] || "", placeholder: ph, oninput: e => { st[k] = e.target.value; onSave(); } }))));
      stageBox.append(h("div", { class: "card pad", style: { marginBottom: "12px", background: "var(--bg)" } },
        h("div", { class: "between" }, h("b", {}, `Этап ${i + 1}`),
          h("button", { class: "btn danger sm", onclick: () => { D.stages.splice(i, 1); onSave(); renderStages(); } }, "Удалить этап")),
        grid,
        field("Результат этапа (для сводки)", select(OUTCOMES, st.outcome, v => { st.outcome = v; onSave(); }, { placeholder: "— не выбрано —" })),
        field("Описание этапа (нагрузка, метод, параметры)",
          richField(st, "description", section, prefix, "Как генерировалась нагрузка, число соединений, трафик…")),
        field("Результаты тестирования (поведение сервиса, ошибки, скриншоты)",
          richField(st, "result", section, prefix, "Отвечал ли сервис, фиксировались ли ошибки, итоговая доступность…"))));
    });
  };
  renderStages();

  const wrap = h("div", {});
  wrap.append(
    h("p", { class: "muted" }, "Раздел попадает в отчёт отдельной главой. Итоговый уровень устойчивости в таблицах 1.4 и 3 определяется по полю «Результат этапа»: если хотя бы на одном этапе достигнут отказ в обслуживании — уровень «Низкий»."),
    h("div", { class: "card pad", style: { marginTop: "6px" } },
      field("Исходные данные и описание процесса тестирования",
        richField(D, "intro", "dos:intro", sec ? `Рисунок ${sec}.1.` : "Рисунок ",
          "Какие ресурсы и какими методами тестировались, как развёрнута инфраструктура атаки…"))),
    h("div", { class: "between", style: { margin: "16px 0 6px" } }, h("b", {}, "Этапы тестирования"),
      h("button", { class: "btn sec sm", onclick: () => { D.stages.push({ id: uid(), host: "", method: "", start: "", end: "", duration: "", power: "", outcome: "" }); onSave(); renderStages(); } }, "+ Этап")),
    stageBox,
    h("div", { class: "card pad", style: { marginTop: "16px" } },
      field("Дополнительные рекомендации (по одной в строке)",
        h("textarea", { placeholder: "Оставьте пустым — будут типовые рекомендации по защите от DDoS", oninput: e => { D.recommendations = e.target.value; onSave(); } }, D.recommendations || ""))),
  );
  return wrap;
}
