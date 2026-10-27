import { api, auth } from "./api.js";
import { h, clear, toast } from "./ui.js";
import { renderLogin } from "./views/login.js";
import { renderProjects } from "./views/projects.js";
import { renderProject } from "./views/project.js";
import { renderUsers } from "./views/users.js";
import { renderSettings } from "./views/settings.js";

export const state = { ref: null, route: { name: "projects" } };

const root = () => document.getElementById("app");

export function navigate(route) {
  state.route = route;
  location.hash = routeToHash(route);
  render();
}
function routeToHash(r) {
  if (r.name === "project") return `#/project/${r.id}`;
  return "#/" + r.name;
}
function hashToRoute() {
  const hsh = location.hash.replace(/^#\//, "");
  const [name, id] = hsh.split("/");
  if (name === "project" && id) return { name: "project", id: +id };
  if (["projects", "users", "settings"].includes(name)) return { name };
  return { name: "projects" };
}

function shell(content) {
  const u = auth.user;
  const navBtn = (key, label) => h("button", {
    class: state.route.name === key ? "active" : "",
    onclick: () => navigate({ name: key }),
  }, label);
  const nav = h("nav", {}, navBtn("projects", "Проекты"));
  if (auth.isAdmin) { nav.append(navBtn("users", "Пользователи"), navBtn("settings", "Настройки")); }
  return h("div", {},
    h("div", { class: "topbar" },
      h("img", { src: "/img/logo.png", alt: "Business IT", class: "logo", onclick: () => navigate({ name: "projects" }) }),
      h("div", { class: "brand" }, "Генератор отчётов"),
      nav,
      h("div", { class: "spacer" }),
      h("div", { class: "user" }, `${u.full_name} · ${u.role === "admin" ? "администратор" : "исполнитель"}`),
      h("button", { class: "btn sec sm", onclick: () => { auth.clear(); location.reload(); } }, "Выход"),
    ),
    h("div", { class: "container" }, content),
  );
}

export async function render() {
  const el = root();
  clear(el);
  if (!auth.token) { el.append(renderLogin(onLogin)); return; }
  if (!state.ref) { try { state.ref = await api.refdata(); } catch (e) { toast(e.message, true); } }
  const r = state.route;
  const slot = h("div", {}, h("div", { class: "empty" }, "Загрузка…"));
  el.append(shell(slot));
  try {
    let view;
    if (r.name === "project") view = await renderProject(r.id);
    else if (r.name === "users") view = await renderUsers();
    else if (r.name === "settings") view = await renderSettings();
    else view = await renderProjects();
    clear(slot); slot.append(view);
  } catch (e) { clear(slot); slot.append(h("div", { class: "empty" }, "Ошибка: " + e.message)); }
}

async function onLogin(login, password) {
  const res = await api.login(login, password);
  auth.set(res.access_token, { full_name: res.full_name, role: res.role, login: res.login });
  state.route = hashToRoute();
  render();
}

window.addEventListener("hashchange", () => { const r = hashToRoute(); if (routeToHash(r) !== location.hash) {} state.route = r; render(); });
state.route = hashToRoute();
render();
