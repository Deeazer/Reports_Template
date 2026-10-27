import { api, auth } from "../api.js";
import { h, field, select, toast, confirmModal } from "../ui.js";

export async function renderUsers() {
  const users = await api.users();
  const wrap = h("div", {});
  wrap.append(h("div", { class: "between", style: { marginBottom: "16px" } },
    h("h2", { style: { margin: 0 } }, "Пользователи"),
    h("button", { class: "btn", onclick: () => openForm() }, "+ Новый пользователь")));

  const tbl = h("table");
  tbl.append(h("tr", {}, h("th", {}, "Логин"), h("th", {}, "Ф.И.О."), h("th", {}, "Должность"),
    h("th", {}, "Роль"), h("th", {}, "Статус"), h("th", {}, "")));
  users.forEach(u => {
    tbl.append(h("tr", {},
      h("td", {}, u.login),
      h("td", {}, u.full_name || "—"),
      h("td", {}, u.position || "—"),
      h("td", {}, h("span", { class: "pill-role " + (u.role === "admin" ? "admin" : "") }, u.role === "admin" ? "администратор" : "исполнитель")),
      h("td", {}, u.is_active ? "активен" : h("span", { class: "muted" }, "отключён")),
      h("td", {}, h("div", { class: "row" },
        h("button", { class: "btn sec sm", onclick: () => openForm(u) }, "Изменить"),
        u.login !== auth.user.login && h("button", { class: "btn danger sm", onclick: () => confirmModal(`Удалить пользователя ${u.login}?`, async () => { try { await api.deleteUser(u.id); location.reload(); } catch (e) { toast(e.message, true); } }) }, "×"))),
    ));
  });
  wrap.append(h("div", { class: "card pad" }, tbl));
  return wrap;
}

function openForm(user) {
  const isEdit = !!user;
  const login = h("input", { value: user?.login || "", disabled: isEdit });
  const full = h("input", { value: user?.full_name || "" });
  const pos = h("input", { value: user?.position || "" });
  const pass = h("input", { type: "password", placeholder: isEdit ? "Оставьте пустым, чтобы не менять" : "" });
  let role = user?.role || "executor";
  const roleSel = select([{ value: "executor", label: "Исполнитель" }, { value: "admin", label: "Администратор" }], role, v => role = v);
  let active = user?.is_active ?? true;
  const activeCb = h("label", { class: "row" }, h("input", { type: "checkbox", checked: active, style: { width: "auto" }, onchange: e => active = e.target.checked }), " Активен");

  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  const submit = async () => {
    try {
      if (isEdit) {
        const patch = { full_name: full.value, position: pos.value, role, is_active: active };
        if (pass.value) patch.password = pass.value;
        await api.updateUser(user.id, patch);
      } else {
        if (!login.value.trim() || !pass.value) { toast("Логин и пароль обязательны", true); return; }
        await api.createUser({ login: login.value.trim(), password: pass.value, full_name: full.value, position: pos.value, role });
      }
      close(); location.reload();
    } catch (e) { toast(e.message, true); }
  };
  bg.append(h("div", { class: "modal" },
    h("h3", { style: { marginTop: 0 } }, isEdit ? "Редактирование пользователя" : "Новый пользователь"),
    field("Логин", login),
    field("Ф.И.О.", full),
    field("Должность", pos),
    field(isEdit ? "Новый пароль" : "Пароль", pass),
    field("Роль", roleSel),
    isEdit && activeCb,
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "12px" } },
      h("button", { class: "btn sec", onclick: close }, "Отмена"),
      h("button", { class: "btn", onclick: submit }, "Сохранить"))));
  bg.addEventListener("click", e => { if (e.target === bg) close(); });
  document.body.append(bg);
}
