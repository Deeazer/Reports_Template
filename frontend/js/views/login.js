import { h, field, toast } from "../ui.js";

export function renderLogin(onLogin) {
  const login = h("input", { placeholder: "Логин", value: "admin" });
  const pass = h("input", { type: "password", placeholder: "Пароль" });
  const btn = h("button", { class: "btn", style: { width: "100%" } }, "Войти");
  const submit = async () => {
    btn.disabled = true; btn.textContent = "Вход…";
    try { await onLogin(login.value.trim(), pass.value); }
    catch (e) { toast(e.message, true); btn.disabled = false; btn.textContent = "Войти"; }
  };
  btn.addEventListener("click", submit);
  const onEnter = (e) => { if (e.key === "Enter") submit(); };
  login.addEventListener("keydown", onEnter); pass.addEventListener("keydown", onEnter);
  return h("div", { class: "login-wrap" },
    h("div", { class: "login-card" },
      h("div", { class: "flag-bar", style: { marginBottom: "22px" } }),
      h("h1", {}, "Вход в систему"),
      h("p", {}, "Генератор отчётов по тестированию на проникновение"),
      field("Логин", login),
      field("Пароль", pass),
      btn,
      h("p", { style: { marginTop: "16px", fontSize: "12px" } }, "По умолчанию: admin / admin"),
    ));
}
