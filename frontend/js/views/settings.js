import { api, auth } from "../api.js";
import { h, field, toast } from "../ui.js";

export async function renderSettings() {
  const s = await api.settings();
  const wrap = h("div", {});
  wrap.append(h("h2", {}, "Настройки"));

  // Исполнитель (реквизиты)
  const ex = s.executor || { name: "", requisites: "" };
  const exName = h("input", { value: ex.name || "" });
  const exReq = h("textarea", { style: { minHeight: "140px" } }, ex.requisites || "");
  if (auth.isAdmin) wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
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
  if (auth.isAdmin) wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
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
  if (auth.isAdmin) wrap.append(h("div", { class: "card pad", style: { marginBottom: "16px" } },
    h("h3", { style: { marginTop: 0 } }, "Перечень угроз БДУ ФСТЭК России"),
    h("p", { class: "muted" }, "Загрузите файл thrlist.xlsx с bdu.fstec.ru (раздел «Угрозы» → выгрузка в Excel). Каталог угроз по умолчанию и каталоги проектов дополнятся новыми угрозами; у угроз заполнятся пустые поля — нарушители (по источнику угрозы), нарушаемые свойства, последствия и интерфейсы (по объекту воздействия). Заполненные вручную значения не меняются."),
    h("div", { class: "row" }, h("button", { class: "btn", onclick: () => bduFile.click() }, "Загрузить thrlist.xlsx"), bduInfo, bduFile)));

  // Интеграция с Yonote (yonote.ru)
  wrap.append(await yonoteCard());

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
  if (auth.isAdmin) wrap.append(jsonCard);
  return wrap;
}

// ---- Интеграция с Yonote ----
async function yonoteCard() {
  let cfg = { base_url: "", collection_id: "", has_token: false, is_admin: auth.isAdmin };
  try { cfg = await api.yonoteConfig(); } catch { /* недоступно */ }
  const isAdmin = cfg.is_admin ?? auth.isAdmin;

  // Адрес пространства — общий для всех, меняет только администратор.
  const baseInput = h("input", { value: cfg.base_url || "", placeholder: "https://cyberbits.yonote.ru",
    disabled: !isAdmin });
  // API-токен — персональный: каждый пользователь указывает свой.
  const tokenInput = h("input", { type: "password",
    placeholder: cfg.has_token ? "токен сохранён — оставьте пустым, чтобы не менять" : "вставьте свой API-токен" });
  const status = h("span", { class: "muted", style: { marginLeft: "8px" } });

  // Коллекция по умолчанию — только для администратора.
  const colSel = h("select", {});
  const setCollections = (cols, selected) => {
    colSel.replaceChildren(h("option", { value: "" }, "— выберите коллекцию —"),
      ...cols.map(c => h("option", { value: c.id, selected: c.id === selected }, c.name)));
  };
  setCollections(cfg.collection_id ? [{ id: cfg.collection_id, name: "Сохранённая коллекция (" + cfg.collection_id + ")" }] : [], cfg.collection_id);

  const saveConfig = async (extra = {}) => {
    const body = { ...extra };
    if (tokenInput.value.trim()) body.token = tokenInput.value.trim();
    if (isAdmin) { body.base_url = baseInput.value.trim(); body.collection_id = colSel.value; }
    const r = await api.yonoteSaveConfig(body);
    cfg = r; tokenInput.value = "";
    tokenInput.placeholder = r.has_token ? "токен сохранён — оставьте пустым, чтобы не менять" : "вставьте свой API-токен";
    return r;
  };

  const loadCollections = async () => {
    try {
      await saveConfig();
      const { collections } = await api.yonoteCollections();
      setCollections(collections, cfg.collection_id);
      status.textContent = `Коллекций: ${collections.length}`;
      status.style.color = "";
    } catch (e) { status.textContent = e.message; status.style.color = "var(--crit)"; }
  };

  const hint = isAdmin
    ? "Импорт из базы знаний Yonote (yonote.ru). Адрес пространства и коллекция по умолчанию — общие для всех. API-токен у каждого пользователя свой: создайте его в Yonote (Настройки → API-токены) и вставьте здесь. Картинки из блоков Proof of Concept и «Результаты эксплуатации» переносятся в карточку уязвимости."
    : "Укажите свой персональный API-токен Yonote (в Yonote: Настройки → API-токены). Адрес пространства задаёт администратор. Импорт идёт под вашим токеном — вы видите те коллекции и документы, к которым у вас есть доступ в Yonote.";

  const children = [
    h("h3", { style: { marginTop: 0 } }, "Интеграция с Yonote"),
    h("p", { class: "muted" }, hint),
    field("Адрес Yonote" + (isAdmin ? "" : " (задаёт администратор)"), baseInput),
    field("Ваш API-токен", tokenInput),
  ];
  if (isAdmin) {
    children.push(field("Коллекция с проектами (по умолчанию)",
      h("div", { class: "row", style: { gap: "8px" } }, colSel,
        h("button", { class: "btn sec sm", onclick: loadCollections }, "Загрузить коллекции"))));
  }
  children.push(h("div", { class: "row", style: { gap: "8px", marginTop: "8px", alignItems: "center" } },
    h("button", { class: "btn", onclick: async () => {
      try { await saveConfig(); toast("Сохранено"); } catch (e) { toast(e.message, true); }
    } }, "Сохранить"),
    h("button", { class: "btn sec", onclick: async () => {
      try {
        await saveConfig();
        const r = await api.yonoteTest();
        status.textContent = `Подключено: ${r.user || ""}${r.team ? " · " + r.team : ""}`;
        status.style.color = "var(--ok, green)";
        toast("Подключение работает");
      } catch (e) { status.textContent = e.message; status.style.color = "var(--crit)"; toast(e.message, true); }
    } }, "Проверить подключение"),
    status));

  return h("div", { class: "card pad", style: { marginBottom: "16px" } }, ...children);
}
