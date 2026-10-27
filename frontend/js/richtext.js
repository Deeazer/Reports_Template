// Редактор форматированного текста для PoC, результатов и рекомендаций (Quill 2).
// Как в pwndoc: скриншоты вставляются прямо в текст, подпись редактируется под
// рисунком, номер «Рисунок 4.1.N» проставляется автоматически по порядку в карточке.
// Код выделяется моноширинным шрифтом — в строке или отдельным блоком.
// Значение хранится как Delta Quill в JSON: {"ops": [...]}.
import { h, toast } from "./ui.js";

const Quill = window.Quill;
const IMAGE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"];

if (Quill && !Quill.imports["formats/figure"]) {
  const BlockEmbed = Quill.import("blots/block/embed");
  class Figure extends BlockEmbed {
    static create(v) {
      const node = super.create();
      node.setAttribute("contenteditable", "false");
      node.dataset.id = v.id;
      node.dataset.caption = v.caption || "";
      const img = document.createElement("img");
      img.src = v.url || `/api/images/${v.id}`;
      const cap = document.createElement("figcaption");
      cap.textContent = v.caption || "";
      cap.title = "Нажмите, чтобы изменить подпись";
      node.append(img, cap);
      return node;
    }
    static value(node) {
      return { id: +node.dataset.id, url: node.querySelector("img")?.getAttribute("src"), caption: node.dataset.caption || "" };
    }
  }
  Figure.blotName = "figure";
  Figure.tagName = "FIGURE";
  Figure.className = "ql-fig";
  Quill.register(Figure);
}

export function isDelta(value) {
  return typeof value === "string" && value.startsWith('{"ops"');
}

// Текст без форматирования (для поиска, предпросмотра и т. п.)
export function plainText(value) {
  if (!isDelta(value)) return value || "";
  try { return JSON.parse(value).ops.map(o => typeof o.insert === "string" ? o.insert : "").join(""); }
  catch { return ""; }
}

/**
 * value      — сохранённое значение (Delta JSON или обычный текст старых карточек);
 * legacyImages — скриншоты старого формата (отдельным блоком), добавляются в конец текста;
 * upload(file) → {id, url} — загрузка изображения на сервер;
 * onChange(json) — вызывается при каждом изменении.
 */
export function richEditor({ value, legacyImages = [], upload, onChange, placeholder }) {
  const holder = h("div", { class: "rich" });
  const editorEl = h("div");
  holder.append(editorEl);
  const fileInput = h("input", { type: "file", accept: IMAGE_TYPES.join(","), multiple: true, style: { display: "none" } });
  holder.append(fileInput);

  const insertFiles = async (files, index) => {
    for (const f of files) {
      if (!IMAGE_TYPES.includes(f.type)) { toast("Поддерживаются PNG, JPEG, GIF, WEBP, BMP", true); continue; }
      try {
        const im = await upload(f);
        const at = index ?? (quill.getSelection(true) || { index: quill.getLength() }).index;
        quill.insertEmbed(at, "figure", { id: im.id, url: im.url, caption: "" }, "user");
        quill.setSelection(at + 1, 0, "silent");
        index = at + 1;
      } catch (e) { toast(e.message, true); }
    }
  };

  const quill = new Quill(editorEl, {
    theme: "snow",
    placeholder: placeholder || "",
    modules: {
      table: true,   // таблицы (вставка, добавление и удаление строк/столбцов)
      toolbar: {
        container: [["bold", "italic", "underline"], ["code", "code-block"],
                    [{ list: "ordered" }, { list: "bullet" }], ["image"], ["clean"]],
        handlers: { image: () => fileInput.click() },
      },
      // вставка из буфера обмена и перетаскивание файлов
      uploader: { mimetypes: IMAGE_TYPES, handler: (range, files) => insertFiles(files, range.index) },
    },
  });
  fileInput.addEventListener("change", async (e) => { await insertFiles([...e.target.files]); e.target.value = ""; });

  // панель управления таблицами (встроенный модуль Quill)
  const table = quill.getModule("table");
  const emit = () => onChange(JSON.stringify(quill.getContents()));
  const tbtn = (label, title, fn, needCell = true) => h("button", {
    type: "button", class: "rich-tbl-btn", title,
    onclick: (e) => {
      e.preventDefault();
      if (needCell && !quill.getModule("table").getTable()[0]) { toast("Поставьте курсор в ячейку таблицы", true); return; }
      try { fn(quill.getModule("table")); quill.focus(); emit(); }
      catch (err) { toast("Не удалось выполнить действие с таблицей", true); }
    },
  }, label);
  const tableBar = h("div", { class: "rich-tablebar" },
    h("span", { class: "rich-tbl-lbl" }, "Таблица:"),
    tbtn("вставить", "Вставить таблицу 2×2", (m) => m.insertTable(2, 2), false),
    tbtn("+ строка", "Добавить строку ниже", (m) => m.insertRowBelow()),
    tbtn("+ столбец", "Добавить столбец справа", (m) => m.insertColumnRight()),
    tbtn("− строка", "Удалить текущую строку", (m) => m.deleteRow()),
    tbtn("− столбец", "Удалить текущий столбец", (m) => m.deleteColumn()),
    tbtn("удалить", "Удалить таблицу целиком", (m) => m.deleteTable()),
  );
  const toolbarEl = holder.querySelector(".ql-toolbar");
  if (toolbarEl) toolbarEl.after(tableBar); else holder.insertBefore(tableBar, editorEl);

  // подсказки на кнопках
  const tips = { "ql-bold": "Жирный", "ql-italic": "Курсив", "ql-underline": "Подчёркнутый", "ql-code": "Код в строке (моноширинный шрифт)",
    "ql-code-block": "Блок кода", "ql-list": "Список", "ql-image": "Вставить скриншот (также Ctrl+V или перетаскивание)", "ql-clean": "Убрать форматирование" };
  holder.querySelectorAll(".ql-toolbar button").forEach(b => { const c = [...b.classList].find(x => tips[x]); if (c) b.title = tips[c]; });

  // начальное содержимое
  if (isDelta(value)) {
    try { quill.setContents(JSON.parse(value), "silent"); } catch { quill.setText(value, "silent"); }
  } else {
    quill.setText(value || "", "silent");
    const used = new Set(quill.getContents().ops.filter(o => o.insert && o.insert.figure).map(o => o.insert.figure.id));
    legacyImages.filter(im => !used.has(im.id)).forEach(im =>
      // номер в старых подписях вводился вручную — теперь он проставляется сам
      quill.insertEmbed(quill.getLength() - 1, "figure", { id: im.id, url: im.url,
        caption: (im.caption || "").replace(/^\s*Рисунок\s*[\d.]*\s*[–—-]?\s*/i, "") }, "silent"));
  }

  quill.on("text-change", (delta, old, source) => { if (source !== "silent") onChange(JSON.stringify(quill.getContents())); });

  // редактирование подписи по щелчку
  quill.root.addEventListener("click", (e) => {
    const cap = e.target.closest("figure.ql-fig figcaption");
    if (!cap) return;
    const node = cap.parentElement;
    const blot = Quill.find(node);
    if (!blot) return;
    editCaption(node.dataset.caption || "", (caption) => {
      const idx = quill.getIndex(blot);
      const v = { ...Quill.imports["formats/figure"].value(node), caption };
      quill.deleteText(idx, 1, "user");
      quill.insertEmbed(idx, "figure", v, "user");
    });
  });
  return holder;
}

function editCaption(current, onSave) {
  const bg = h("div", { class: "modal-bg" });
  const close = () => bg.remove();
  const inp = h("input", { value: current, placeholder: "Например: Ответ сервера с содержимым файла" });
  const save = () => { close(); onSave(inp.value.trim()); };
  inp.addEventListener("keydown", e => { if (e.key === "Enter") save(); if (e.key === "Escape") close(); });
  bg.append(h("div", { class: "modal" },
    h("h3", { style: { marginTop: 0 } }, "Подпись к рисунку"),
    h("p", { class: "muted", style: { fontSize: "13px" } }, "Номер «Рисунок N.N.N –» добавляется автоматически."),
    inp,
    h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "12px" } },
      h("button", { class: "btn sec", onclick: close }, "Отмена"),
      h("button", { class: "btn", onclick: save }, "Сохранить"))));
  bg.addEventListener("click", e => { if (e.target === bg) close(); });
  document.body.append(bg);
  inp.focus(); inp.select();
}
