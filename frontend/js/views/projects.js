import { api, auth } from "../api.js";
import { state, navigate } from "../main.js";
import { h, field, toast, confirmModal, badge, fmtDate } from "../ui.js";
import { deleteProject } from "./project.js";

export async function renderProjects() {
  const projects = await api.projects();
  const wt = state.ref.work_types;

  const wrap = h("div", {});
  wrap.append(h("div", { class: "between", style: { marginBottom: "18px" } },
    h("h2", { style: { margin: 0 } }, "Проекты"),
    h("div", { class: "row", style: { gap: "8px" } },
      auth.isAdmin && h("button", { class: "btn sec", onclick: openImport }, "Импорт из Yonote"),
      h("button", { class: "btn", onclick: () => openCreate(wrap) }, "+ Новый проект"),
    ),
  ));

  if (!projects.length) {
    wrap.append(h("div", { class: "card pad empty" }, "Пока нет проектов. Создайте первый проект."));
    return wrap;
  }

  const grid = h("div", { class: "grid", style: { gridTemplateColumns: "repeat(auto-fill,minmax(320px,1fr))" } });
  for (const p of projects) {
    const counts = p.counts || {};
    const stats = h("div", { class: "stat-row", style: { marginTop: "10px" } });
    const map = [["Высокий", "var(--red)"], ["Средний", "var(--yellow)"], ["Низкий", "var(--green)"], ["Информативный", "var(--blue)"]];
    for (const [lvl, col] of map) {
      if (counts[lvl]) stats.append(h("span", { class: "stat", style: { background: col, color: lvl === "Средний" || lvl === "Низкий" ? "#333" : "#fff" } }, `${counts[lvl]} · ${lvl.toLowerCase()}`));
    }
    const card = h("div", { class: "card pad", style: { cursor: "pointer" }, onclick: () => navigate({ name: "project", id: p.id }) },
      h("div", { class: "between" },
        h("div", { style: { fontWeight: 700, fontSize: "15px" } }, p.name),
        (auth.isAdmin || p.created_by === auth.user.id) &&
          h("button", { class: "btn danger sm", title: "Удалить проект",
            onclick: (e) => { e.stopPropagation(); deleteProject(p, () => card.remove()); } }, "Удалить"),
      ),
      h("div", { class: "muted", style: { marginTop: "4px" } }, p.client_name || "—"),
      h("div", { class: "row", style: { marginTop: "8px" } },
        ...(p.work_types || []).map(w => h("span", { class: "chip" }, wt[w] ? wt[w].title : w))),
      stats,
      h("div", { class: "muted", style: { marginTop: "10px", fontSize: "12px" } },
        `Уязвимостей: ${p.vuln_count} · изменён ${fmtDate(p.updated_at)}` + (p.updated_by_name ? ` (${p.updated_by_name})` : "")),
      p.created_by_name && h("div", { class: "muted", style: { fontSize: "12px" } }, `Создал: ${p.created_by_name}`),
    );
    grid.append(card);
  }
  wrap.append(grid);
  return wrap;
}

async function openImport() {
  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  const body = h("div", {}, h("div", { class: "muted" }, "Загрузка…"));
  const colSel = h("select", {});
  const docBox = h("div", { style: { maxHeight: "340px", overflow: "auto", marginTop: "8px" } });
  const result = h("div", { style: { marginTop: "8px" } });
  const importBtn = h("button", { class: "btn", onclick: doImport }, "Импортировать выбранные");

  let cfg = null;
  try { cfg = await api.yonoteConfig(); } catch { /* нет прав */ }
  if (!cfg || !cfg.has_token || !cfg.base_url) {
    body.replaceChildren(h("p", {}, "Интеграция с Yonote не настроена. Откройте «Настройки» → «Интеграция с Yonote», укажите адрес и API-токен."));
    importBtn.style.display = "none";
  } else {
    body.replaceChildren(
      field("Коллекция", h("div", { class: "row", style: { gap: "8px" } }, colSel,
        h("button", { class: "btn sec sm", onclick: loadDocs }, "Обновить список"))),
      docBox, result);
    try {
      const { collections } = await api.yonoteCollections();
      colSel.replaceChildren(...collections.map(c => h("option", { value: c.id, selected: c.id === cfg.collection_id }, c.name)));
      colSel.addEventListener("change", loadDocs);
      await loadDocs();
    } catch (e) { docBox.replaceChildren(h("div", { style: { color: "var(--crit)" } }, e.message)); }
  }

  async function loadDocs() {
    docBox.replaceChildren(h("div", { class: "muted" }, "Загрузка документов…"));
    result.replaceChildren();
    try {
      const { documents } = await api.yonoteDocuments(colSel.value);
      if (!documents.length) { docBox.replaceChildren(h("div", { class: "muted" }, "В коллекции нет документов верхнего уровня.")); return; }
      docBox.replaceChildren(...documents.map(d =>
        h("label", { class: "row", style: { padding: "4px 0", cursor: "pointer" } },
          h("input", { type: "checkbox", value: d.id, style: { width: "auto", marginRight: "8px" } }),
          h("span", {}, d.title || "(без названия)"))));
    } catch (e) { docBox.replaceChildren(h("div", { style: { color: "var(--crit)" } }, e.message)); }
  }

  async function doImport() {
    const ids = [...docBox.querySelectorAll("input:checked")].map(c => c.value);
    if (!ids.length) { toast("Выберите хотя бы один документ", true); return; }
    importBtn.disabled = true; importBtn.textContent = "Импорт…";
    try {
      const r = await api.yonoteImport(ids);
      const ok = r.results.filter(x => x.ok), bad = r.results.filter(x => !x.ok);
      result.replaceChildren(
        h("div", {}, `Импортировано проектов: ${r.imported}`),
        ...ok.map(x => h("div", { class: "muted", style: { fontSize: "12px" } }, `✓ ${x.name} (уязвимостей: ${x.vulns})`)),
        ...bad.map(x => h("div", { style: { color: "var(--crit)", fontSize: "12px" } }, `✗ ${x.document_id}: ${x.error}`)));
      if (r.imported) { toast(`Импортировано: ${r.imported}`); setTimeout(() => { close(); navigate({ name: "projects" }); }, 1200); }
    } catch (e) { toast(e.message, true); }
    importBtn.disabled = false; importBtn.textContent = "Импортировать выбранные";
  }

  bg.append(h("div", { class: "modal" },
    h("h3", { style: { marginTop: 0 } }, "Импорт проектов из Yonote"),
    body,
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "10px", gap: "8px" } },
      h("button", { class: "btn sec", onclick: close }, "Закрыть"), importBtn)));
  bg.addEventListener("click", e => { if (e.target === bg) close(); });
  document.body.append(bg);
}

function openCreate(wrap) {
  const name = h("input", { placeholder: "Например: Пентест АО «Ромашка»" });
  const client = h("input", { placeholder: "АО «Ромашка»" });
  const chosen = new Set(["external", "internal"]);
  const wtBox = h("div", { class: "row" });
  for (const [key, info] of Object.entries(state.ref.work_types)) {
    // нереализованные виды работ показываются, но выбрать их нельзя
    const cb = h("input", { type: "checkbox", style: { width: "auto" }, checked: chosen.has(key), disabled: !info.enabled, onchange: e => e.target.checked ? chosen.add(key) : chosen.delete(key) });
    wtBox.append(h("label", { class: "chip", style: { cursor: info.enabled ? "pointer" : "default", opacity: info.enabled ? 1 : 0.55 } },
      cb, " " + info.title + (info.enabled ? "" : " (в разработке)")));
  }
  const methods = new Set(["black", "grey"]);
  const mBox = h("div", { class: "row" });
  for (const [key, label] of Object.entries(state.ref.test_methods)) {
    const cb = h("input", { type: "checkbox", style: { width: "auto" }, checked: methods.has(key), onchange: e => e.target.checked ? methods.add(key) : methods.delete(key) });
    mBox.append(h("label", { class: "chip", style: { cursor: "pointer" } }, cb, " метод " + label));
  }
  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  const create = async () => {
    if (!name.value.trim()) { toast("Укажите название проекта", true); return; }
    if (!chosen.size) { toast("Выберите хотя бы один вид работ", true); return; }
    try {
      const p = await api.createProject({ name: name.value.trim(), client_name: client.value.trim(),
        work_types: [...chosen], test_methods: [...methods] });
      close(); navigate({ name: "project", id: p.id });
    } catch (e) { toast(e.message, true); }
  };
  bg.append(h("div", { class: "modal" },
    h("h3", { style: { marginTop: 0 } }, "Новый проект"),
    field("Название проекта", name),
    field("Наименование Заказчика", client),
    field("Виды работ", wtBox),
    field("Методы тестирования", mBox),
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "10px" } },
      h("button", { class: "btn sec", onclick: close }, "Отмена"),
      h("button", { class: "btn", onclick: create }, "Создать")),
  ));
  bg.addEventListener("click", e => { if (e.target === bg) close(); });
  document.body.append(bg);
}
