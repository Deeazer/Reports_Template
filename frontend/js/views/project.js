import { api, auth } from "../api.js";
import { state, navigate } from "../main.js";
import { h, field, select, toast, confirmModal, badge, debouncePatch } from "../ui.js";
import { vulnCard } from "./vuln.js";

export async function renderProject(pid) {
  const p = await api.project(pid);
  const ref = state.ref;
  let users = [];
  try { if (auth.isAdmin) users = await api.users(); } catch {}

  const wrap = h("div", {});
  const save = debouncePatch(async (patch) => {
    try { Object.assign(p, await api.updateProject(pid, patch)); toast("Сохранено"); }
    catch (e) { toast(e.message, true); }
  }, 700);
  const upd = (key) => (val) => { p[key] = val; save({ [key]: val }); };

  // header
  wrap.append(h("div", { class: "between", style: { marginBottom: "10px" } },
    h("div", {},
      h("a", { onclick: () => navigate({ name: "projects" }), style: { cursor: "pointer" } }, "← Проекты"),
      h("h2", { style: { margin: "6px 0 0" } }, p.name),
      h("div", { class: "muted" }, p.client_name || "")),
    h("div", { class: "row" },
      h("button", { class: "btn sec", onclick: () => doDownload(p) }, "⭳ Скачать отчёт (.docx)"),
      (auth.isAdmin || p.created_by === auth.user.id) &&
        h("button", { class: "btn danger", onclick: () => confirmModal("Удалить проект целиком?", async () => { try { await api.deleteProject(pid); navigate({ name: "projects" }); } catch (e) { toast(e.message, true); } }) }, "Удалить проект"),
    )));

  // tabs
  const tabs = [
    { key: "general", label: "Общие данные" },
    { key: "model", label: "Модель угроз" },
    ...p.work_types.map(wt => ({ key: "wt_" + wt, label: ref.work_types[wt].title })),
    { key: "tools", label: "Инструментарий" },
  ];
  // список пользователей доступен только администратору, поэтому и вкладка — только ему
  if (auth.isAdmin) tabs.push({ key: "access", label: "Доступ" });

  let active = p.work_types.length ? "wt_" + p.work_types[0] : "general";
  const tabBar = h("div", { class: "tabs" });
  const content = h("div", {});
  const setTab = (key) => {
    active = key;
    [...tabBar.children].forEach(b => b.classList.toggle("active", b.dataset.key === key));
    renderTab(key);
  };
  tabs.forEach(t => tabBar.append(h("button", { "data-key": t.key, onclick: () => setTab(t.key) }, t.label)));
  wrap.append(tabBar, content);

  async function renderTab(key) {
    content.replaceChildren();
    if (key === "general") content.append(generalTab(p, ref, upd));
    else if (key === "model") {
      // обновляем проект, чтобы предпросмотр актуальных угроз (1.8.3) был свежим
      try { Object.assign(p, await api.project(p.id)); } catch {}
      content.replaceChildren(modelTab(p, ref, save));
    }
    else if (key === "tools") content.append(toolsTab(p, save));
    else if (key === "access") content.append(accessTab(p, users, save));
    else if (key.startsWith("wt_")) content.append(vulnsTab(p, key.slice(3)));
  }
  setTab(active);
  return wrap;
}

async function doDownload(p) {
  toast("Формирование отчёта…");
  try { await api.downloadReport(p.id, `Отчет_${(p.client_name || p.name).replace(/\s+/g, "_")}.docx`); }
  catch (e) { toast(e.message, true); }
}

// ---------- Общие данные ----------
function generalTab(p, ref, upd) {
  const methodsBox = h("div", { class: "row" });
  const methods = new Set(p.test_methods || []);
  for (const [key, label] of Object.entries(ref.test_methods))
    methodsBox.append(h("label", { class: "chip", style: { cursor: "pointer" } },
      h("input", { type: "checkbox", style: { width: "auto" }, checked: methods.has(key), onchange: e => { e.target.checked ? methods.add(key) : methods.delete(key); upd("test_methods")([...methods]); } }), " метод " + label));

  return h("div", { class: "card pad" },
    field("Название проекта", h("input", { value: p.name, oninput: e => upd("name")(e.target.value) })),
    h("div", { class: "cols2" },
      field("Наименование Заказчика", h("input", { value: p.client_name, oninput: e => upd("client_name")(e.target.value) })),
      field("Методы тестирования", methodsBox)),
    field("Описание объекта оценки (п. 1.1)", h("textarea", { placeholder: "Оставьте пустым — будет сформировано автоматически", oninput: e => upd("object_description")(e.target.value) }, p.object_description || "")),
    field("Технологические участки (п. 1.3)", h("textarea", { oninput: e => upd("tech_sites")(e.target.value) }, p.tech_sites || "")),
    h("div", { class: "cols2" },
      field("Период работ — с", h("input", { value: p.period_from, placeholder: "03.09.2026", oninput: e => upd("period_from")(e.target.value) })),
      field("Период работ — по", h("input", { value: p.period_to, placeholder: "21.10.2026", oninput: e => upd("period_to")(e.target.value) }))),
    field("Реквизиты Заказчика (п. 1.6)", h("textarea", { oninput: e => upd("client_requisites")(e.target.value) }, p.client_requisites || "")),
    executorsEditor(p, upd),
  );
}

function executorsEditor(p, upd) {
  const box = h("div", {});
  const render = () => {
    box.replaceChildren();
    (p.executors || []).forEach((ex, i) => {
      box.append(h("div", { class: "row", style: { marginBottom: "6px" } },
        h("input", { value: ex.org || "", placeholder: "Организация", oninput: e => { ex.org = e.target.value; upd("executors")(p.executors); } }),
        h("input", { value: ex.position || "", placeholder: "Должность", oninput: e => { ex.position = e.target.value; upd("executors")(p.executors); } }),
        h("input", { value: ex.name || "", placeholder: "Ф.И.О.", oninput: e => { ex.name = e.target.value; upd("executors")(p.executors); } }),
        h("button", { class: "btn danger sm", onclick: () => { p.executors.splice(i, 1); upd("executors")(p.executors); render(); } }, "×")));
    });
  };
  render();
  return h("div", {}, h("div", { class: "between", style: { margin: "10px 0 6px" } },
    h("span", { style: { fontWeight: 600, fontSize: "12px", color: "var(--muted)" } }, "ИСПОЛНИТЕЛИ (п. 1.7)"),
    h("button", { class: "btn sec sm", onclick: () => { (p.executors = p.executors || []).push({ org: "", position: "Специалист по информационной безопасности", name: "" }); upd("executors")(p.executors); render(); } }, "+ Добавить")),
    box);
}

// ---------- Модель угроз ----------
let BDU = null;
function modelTab(p, ref, save) {
  if (!BDU) api.bdu().then(r => { BDU = r.threats; }).catch(() => {});
  return h("div", {},
    jsonTable("Нарушители (таблица 1.8.1) — в отчёт попадают отмеченные «В отчёт»", p.intruders,
      [["include", "В отчёт"], ["code", "Код"], ["name", "Описание"], ["category", "Категория"], ["potential", "Возможности"], ["probability", "Вероятность"]],
      { code: "Н5", name: "", category: "Внешний", potential: "", types: "", goals: "", interfaces: "", restrictions: "", tools: "", skills: "", probability: "Высокая", include: true }, () => save({ intruders: p.intruders }), true),
    jsonTable("Интерфейсы воздействия (таблица 1.8.2) — в отчёт попадают интерфейсы видов работ проекта",
      p.interfaces, [["work_types", "Виды работ"], ["code", "№"], ["name", "Интерфейс"], ["intruders", "Нарушители"], ["description", "Описание"], ["note", "Примечание"]],
      { work_types: [...p.work_types], code: "", name: "", intruders: "", description: "", note: "" }, () => save({ interfaces: p.interfaces }), false, p.work_types),
    autoThreatsPreview(p),
    jsonTable("Каталог угроз (из него уязвимости выбирают реализуемые угрозы)",
      p.threats, [["code", "№"], ["name", "Угроза"], ["bdu", "БДУ"], ["interfaces", "Интерфейс (по умолч.)"], ["intruders", "Наруш."], ["consequences", "Последствия"]],
      { code: "", name: "", bdu: "", interfaces: "", intruders: "", properties: "", consequences: "" }, () => save({ threats: p.threats })),
  );
}

// Предпросмотр таблицы 1.8.3 — что попадёт в отчёт (считается на бэкенде)
function autoThreatsPreview(p) {
  const rows = p.auto_threats || [];
  const card = h("div", { class: "card pad", style: { marginBottom: "16px" } },
    h("div", { style: { fontWeight: 700, marginBottom: "4px" } }, "Актуальные угрозы (таблица 1.8.3) — формируются автоматически"),
    h("p", { class: "muted", style: { marginTop: 0 } }, "Строки собираются из уязвимостей: берутся угрозы, отмеченные в карточке, а если не отмечено ничего — подбираются автоматически по последствиям эксплуатации (H). Интерфейсы и нарушители агрегируются; «авто» — строка подобрана автоматически."));
  if (!rows.length) { card.append(h("div", { class: "empty", style: { padding: "20px" } }, "Пока ни одной угрозы не выбрано в уязвимостях")); return card; }
  const tbl = h("table");
  tbl.append(h("tr", {}, ...["№", "Угроза", "БДУ", "Интерфейс", "Наруш.", "Последствия"].map(t => h("th", {}, t))));
  rows.forEach(r => tbl.append(h("tr", {},
    h("td", {}, r.code, r.auto ? h("div", { class: "muted", style: { fontSize: "11px" } }, "авто") : ""), h("td", {}, r.name), h("td", {}, r.bdu),
    h("td", {}, r.interfaces), h("td", {}, r.intruders), h("td", {}, r.consequences))));
  card.append(tbl);
  return card;
}

function jsonTable(title, rows, cols, template, onSave, expandable, projectWorkTypes) {
  const card = h("div", { class: "card pad", style: { marginBottom: "16px" } });
  const tbl = h("table");
  const render = () => {
    tbl.replaceChildren();
    const head = h("tr", {}, ...cols.map(([k, l]) => h("th", {}, l)), h("th", { style: { width: "40px" } }, ""));
    tbl.append(head);
    rows.forEach((row, i) => {
      const tr = h("tr", {});
      const inputs = {};
      cols.forEach(([k]) => {
        // колонка-флаг (например «В отчёт») рисуется чекбоксом
        // колонка «Виды работ»: флажки по видам работ проекта; строка без
        // отмеченных видов работ в отчёт не попадёт
        if (k === "work_types") {
          const td = h("td", { style: { whiteSpace: "nowrap" } });
          (projectWorkTypes || []).forEach(wt => {
            const cb = h("input", { type: "checkbox", style: { width: "auto" }, checked: (row.work_types || []).includes(wt),
              onchange: e => {
                const set = new Set(row.work_types || []);
                e.target.checked ? set.add(wt) : set.delete(wt);
                row.work_types = [...set]; onSave();
              } });
            td.append(h("label", { style: { display: "block", fontSize: "12px" } }, cb, " " + state.ref.work_types[wt].title));
          });
          tr.append(td);
          return;
        }
        if (k === "include") {
          const cb = h("input", { type: "checkbox", checked: row.include !== false, style: { width: "auto" },
            onchange: e => { row.include = e.target.checked; onSave(); } });
          inputs[k] = cb;
          tr.append(h("td", { style: { textAlign: "center" } }, cb));
          return;
        }
        const inp = h("input", { value: row[k] || "", style: { border: "none", padding: "2px" }, oninput: e => {
          row[k] = e.target.value;
          // наименование угрозы подставляется из перечня БДУ по номеру УБИ
          if (k === "bdu" && BDU && "name" in row) {
            const id = e.target.value.trim().toUpperCase().replace(/^УБИ\.?\s*/, "УБИ.").replace(/^(УБИ\.)(\d{1,2})$/, (m, a, n) => a + n.padStart(3, "0"));
            if (BDU[id]) { row.bdu = id; row.name = BDU[id]; if (inputs.name) inputs.name.value = BDU[id]; e.target.style.color = ""; }
            else e.target.style.color = "var(--crit)";
          }
          onSave();
        } });
        inputs[k] = inp;
        tr.append(h("td", {}, inp));
      });
      tr.append(h("td", {}, h("button", { class: "btn danger sm", onclick: () => { rows.splice(i, 1); onSave(); render(); } }, "×")));
      tbl.append(tr);
      if (expandable) {
        const extra = ["types", "goals", "interfaces", "restrictions", "tools", "skills"].filter(f => f in row);
        if (extra.length) {
          const td = h("td", { colspan: cols.length + 1 });
          extra.forEach(f => td.append(field(f, h("textarea", { style: { minHeight: "40px" }, oninput: e => { row[f] = e.target.value; onSave(); } }, row[f] || ""))));
          tbl.append(h("tr", {}, td));
        }
      }
    });
  };
  render();
  card.append(h("div", { class: "between", style: { marginBottom: "8px" } },
    h("span", { style: { fontWeight: 700 } }, title),
    h("button", { class: "btn sec sm", onclick: () => { rows.push(JSON.parse(JSON.stringify(template))); onSave(); render(); } }, "+ Строка")),
    tbl);
  return card;
}

// ---------- Инструментарий ----------
function toolsTab(p, save) {
  return jsonTable("Используемые инструменты (таблица 2.2.1)", p.tools, [["purpose", "Цель применения"], ["tools", "Инструменты"]],
    { purpose: "", tools: "" }, () => save({ tools: p.tools }));
}

// ---------- Уязвимости по виду работ ----------
function vulnsTab(p, wt) {
  const box = h("div", {});
  const list = h("div", {});
  const vulns = () => p.vulns.filter(v => v.work_type === wt).sort((a, b) => a.order_index - b.order_index);

  const reload = async () => {
    try { Object.assign(p, await api.project(p.id)); draw(); } catch (e) { toast(e.message, true); }
  };
  const draw = () => {
    list.replaceChildren();
    const vs = vulns();
    if (!vs.length) list.append(h("div", { class: "empty" }, "Уязвимости не добавлены"));
    vs.forEach((v, i) => list.append(vulnCard(v, () => {}, reload, i, p)));
  };
  draw();

  box.append(h("div", { class: "between", style: { marginBottom: "12px" } },
    h("div", {}, h("b", {}, state.ref.work_types[wt].title),
      h("span", { class: "muted" }, "  —  каждая уязвимость попадает в сводные таблицы автоматически")),
    h("button", { class: "btn", onclick: async () => {
      try { const v = await api.addVuln(p.id, { work_type: wt, title: "Новая уязвимость" }); v._open = true; p.vulns.push(v); draw(); }
      catch (e) { toast(e.message, true); }
    } }, "+ Добавить уязвимость")),
    list);
  return box;
}

// ---------- Доступ ----------
function accessTab(p, users, save) {
  const selected = new Set(p.member_ids || []);
  const box = h("div", { class: "card pad" },
    h("p", { class: "muted" }, "Исполнители, у которых будет доступ к этому проекту (администраторы видят все проекты):"));
  users.filter(u => u.role === "executor" && u.is_active).forEach(u => {
    box.append(h("label", { class: "row", style: { padding: "6px 0" } },
      h("input", { type: "checkbox", checked: selected.has(u.id), style: { width: "auto" },
        onchange: e => { e.target.checked ? selected.add(u.id) : selected.delete(u.id); save({ member_ids: [...selected] }); } }),
      h("span", {}, u.full_name || u.login), h("span", { class: "muted" }, u.position || "")));
  });
  if (!users.filter(u => u.role === "executor").length) box.append(h("div", { class: "muted" }, "Нет исполнителей. Создайте их в разделе «Пользователи»."));
  return box;
}
