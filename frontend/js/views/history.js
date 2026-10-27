import { api } from "../api.js";
import { h, toast, fmtDate } from "../ui.js";

// Подписи полей для журнала изменений
const FIELD_LABELS = {
  name: "название", client_name: "Заказчик", client_requisites: "реквизиты Заказчика",
  object_description: "описание объекта (1.1)", test_methods: "методы тестирования", work_types: "виды работ",
  period_from: "начало периода", period_to: "окончание периода", tech_sites: "технологические участки (1.3)",
  status: "статус", intruders: "нарушители (1.8.1)", interfaces: "интерфейсы (1.8.2)", threats: "каталог угроз",
  tools: "инструментарий (2.2)", executors: "исполнители (1.7)", scope: "границы (Прил. 1)",
  approvals: "лист согласования", security_notes: "преимущества (1.4)", member_ids: "доступ к проекту",
  social: "социотехническое тестирование", social_images: "изображения сценариев",
  title: "название", description: "описание", detected_at: "время обнаружения",
  cvss_vector: "CVSS", intruder_models: "модели нарушителя", threat_codes: "угрозы БДУ",
  interface_codes: "интерфейсы", availability: "доступность", ease: "простота эксплуатации",
  fstec_k: "K", fstec_l: "L", fstec_p: "P", fstec_e: "E", fstec_h: "H", poc: "Proof of Concept",
  exploitation_result: "результаты эксплуатации", recommendations: "рекомендации", owasp: "категория OWASP Top 10", wstg: "категория OWASP WSTG",
  order_index: "порядок", work_type: "вид работ", images_poc: "изображения PoC", images_result: "изображения результатов",
};
const ACTIONS = { create: "добавил", update: "изменил", delete: "удалил" };
const ENTITY = { project: "проект", vuln: "уязвимость" };

function describe(e) {
  const labels = (e.fields || []).map(f => (e.entity === "vuln" && f === "tools") ? "инструменты"
    : (e.entity === "vuln" && f === "scope") ? "границы" : FIELD_LABELS[f] || f);
  return labels.join(", ");
}

export async function historyTab(p) {
  let rows = [];
  try { rows = await api.history(p.id); } catch (e) { toast(e.message, true); }
  const card = h("div", { class: "card pad" },
    h("p", { class: "muted", style: { marginTop: 0 } },
      "Кто и когда добавлял, изменял или удалял данные проекта. Правки одного объекта одним пользователем подряд (в пределах 10 минут) объединяются в одну запись."));
  if (!rows.length) { card.append(h("div", { class: "empty" }, "Записей пока нет")); return card; }
  const tbl = h("table", { class: "hist" });
  tbl.append(h("tr", {}, ...["Когда", "Кто", "Действие", "Объект", "Что изменено"].map(x => h("th", {}, x))));
  rows.forEach(e => tbl.append(h("tr", {},
    h("td", { style: { whiteSpace: "nowrap" } }, fmtDate(e.at)),
    h("td", {}, e.user_name || "—"),
    h("td", {}, ACTIONS[e.action] || e.action),
    h("td", {}, (ENTITY[e.entity] || e.entity) + (e.entity_title ? ` «${e.entity_title}»` : "")),
    h("td", {}, describe(e)))));
  card.append(tbl);
  return card;
}
