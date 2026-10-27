import { api, auth } from "../api.js";
import { state, navigate } from "../main.js";
import { h, field, toast, confirmModal, badge } from "../ui.js";
import { deleteProject } from "./project.js";

export async function renderProjects() {
  const projects = await api.projects();
  const wt = state.ref.work_types;

  const wrap = h("div", {});
  wrap.append(h("div", { class: "between", style: { marginBottom: "18px" } },
    h("h2", { style: { margin: 0 } }, "Проекты"),
    h("button", { class: "btn", onclick: () => openCreate(wrap) }, "+ Новый проект"),
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
        `Уязвимостей: ${p.vuln_count} · обновлён ${new Date(p.updated_at).toLocaleDateString("ru")}`),
    );
    grid.append(card);
  }
  wrap.append(grid);
  return wrap;
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
