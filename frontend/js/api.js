// Клиент REST API + хранение токена
const TOKEN_KEY = "pentest_token";
const USER_KEY = "pentest_user";

export const auth = {
  get token() { return localStorage.getItem(TOKEN_KEY); },
  get user() { try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch { return null; } },
  set(token, user) { localStorage.setItem(TOKEN_KEY, token); localStorage.setItem(USER_KEY, JSON.stringify(user)); },
  clear() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); },
  get isAdmin() { return this.user && this.user.role === "admin"; },
};

async function req(method, path, body, isForm) {
  const headers = {};
  if (auth.token) headers["Authorization"] = "Bearer " + auth.token;
  let payload;
  if (isForm) { payload = body; }
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch("/api" + path, { method, headers, body: payload });
  if (res.status === 401) { auth.clear(); location.reload(); throw new Error("Сессия истекла"); }
  if (!res.ok) {
    let msg = "Ошибка " + res.status;
    try { const j = await res.json(); if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res;
}

export const api = {
  login: async (login, password) => {
    const form = new URLSearchParams(); form.set("username", login); form.set("password", password);
    const res = await fetch("/api/auth/login", { method: "POST", body: form });
    if (!res.ok) { let m = "Неверный логин или пароль"; try { m = (await res.json()).detail || m; } catch {} throw new Error(m); }
    return res.json();
  },
  me: () => req("GET", "/auth/me"),
  refdata: () => req("GET", "/refdata"),
  bdu: () => req("GET", "/bdu"),
  settings: () => req("GET", "/settings"),
  saveSetting: (key, value) => req("PUT", "/settings/" + key, value),

  users: () => req("GET", "/users"),
  createUser: (d) => req("POST", "/users", d),
  updateUser: (id, d) => req("PATCH", "/users/" + id, d),
  deleteUser: (id) => req("DELETE", "/users/" + id),

  projects: () => req("GET", "/projects"),
  project: (id) => req("GET", "/projects/" + id),
  createProject: (d) => req("POST", "/projects", d),
  updateProject: (id, d) => req("PATCH", "/projects/" + id, d),
  deleteProject: (id) => req("DELETE", "/projects/" + id),

  addVuln: (pid, d) => req("POST", `/projects/${pid}/vulns`, d),
  updateVuln: (id, d) => req("PATCH", "/vulns/" + id, d),
  deleteVuln: (id) => req("DELETE", "/vulns/" + id),

  uploadImage: (vid, file, block, caption) => {
    const fd = new FormData(); fd.append("file", file); fd.append("block", block); fd.append("caption", caption || "");
    return req("POST", `/vulns/${vid}/images`, fd, true);
  },
  updateImage: (id, caption) => { const fd = new FormData(); fd.append("caption", caption); return req("PATCH", "/images/" + id, fd, true); },
  deleteImage: (id) => req("DELETE", "/images/" + id),

  reportUrl: (pid) => `/api/projects/${pid}/report`,
  downloadReport: async (pid, name) => {
    const res = await fetch(api.reportUrl(pid), { headers: { Authorization: "Bearer " + auth.token } });
    if (!res.ok) throw new Error("Не удалось сформировать отчёт");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = name || "Отчет.docx";
    document.body.append(a); a.click(); a.remove();
    // освобождаем ссылку позже: при немедленном revoke часть браузеров не успевает начать загрузку
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  },
};
