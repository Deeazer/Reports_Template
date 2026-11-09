"""Разбор проекта, который ведётся в Yonote (Markdown), в структуру приложения.

Формат документа-проекта в Yonote (см. README интеграции):

    # <Название проекта>            ← заголовок документа = название проекта

    ## Карточка
    - Заказчик: АО «Экопром»
    - Реквизиты: ИНН ...
    - Период: 01.10.2026 — 20.10.2026
    - Виды работ: external, internal, web
    - Описание объекта: ...
    - Технологические участки: ...

    ## Уязвимости
    ### Обход авторизации
    - Вид работ: external
    - CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    - Границы: admin.example.com
    - Инструменты: BurpSuite
    - Обнаружена: 05.09.2026 12:30
    - Модели нарушителя: Н1, Н2

    **Описание:** ...
    **PoC:** ...
    **Результаты эксплуатации:** ...
    **Рекомендации:** ...

Разбор устойчив к мелким отличиям: регистр меток не важен, разделитель
«:» или «—», лишние пробелы и отсутствующие поля/разделы допускаются.
"""
from __future__ import annotations

import re

from .. import refdata as R

# --- сопоставление названий полей проекта ---
_PROJECT_FIELDS = {
    "заказчик": "client_name",
    "клиент": "client_name",
    "реквизиты": "client_requisites",
    "реквизиты заказчика": "client_requisites",
    "описание объекта": "object_description",
    "объект": "object_description",
    "технологические участки": "tech_sites",
    "участки": "tech_sites",
}

# --- сопоставление названий полей уязвимости ---
_VULN_FIELDS = {
    "вид работ": "work_type",
    "тип работ": "work_type",
    "cvss": "cvss_vector",
    "вектор cvss": "cvss_vector",
    "границы": "scope",
    "инструменты": "tools",
    "инструментарий": "tools",
    "обнаружена": "detected_at",
    "время обнаружения": "detected_at",
    "обнаружено": "detected_at",
    "модели нарушителя": "intruder_models",
    "нарушители": "intruder_models",
    "owasp": "owasp",
    "owasp top 10": "owasp",
    "wstg": "wstg",
    "owasp wstg": "wstg",
}

# «жирные» блоки текста уязвимости
_VULN_BLOCKS = {
    "описание": "description",
    "proof of concept": "poc",
    "poc": "poc",
    "результаты эксплуатации": "exploitation_result",
    "результат эксплуатации": "exploitation_result",
    "результаты": "exploitation_result",
    "рекомендации": "recommendations",
}

# виды работ: ключ и название → ключ
_WT_ALIASES = {}
for _k, _v in R.WORK_TYPES.items():
    _WT_ALIASES[_k.lower()] = _k
    _WT_ALIASES[_v["title"].lower()] = _k
# частые сокращения
_WT_ALIASES.update({
    "внешний": "external", "внешний пентест": "external",
    "внутренний": "internal", "внутренний пентест": "internal",
    "веб": "web", "веб-приложение": "web", "web-приложение": "web",
    "социотехническое": "social", "социалка": "social",
    "отказ в обслуживании": "dos", "ddos": "dos", "dos": "dos",
    "беспроводные сети": "wireless", "wi-fi": "wireless", "wifi": "wireless",
})


def _norm_wt(token: str) -> str | None:
    return _WT_ALIASES.get((token or "").strip().lower())


def _split_kv(line: str):
    """Разбирает строку «- Ключ: значение» → (ключ, значение) или None."""
    s = line.strip().lstrip("-*•").strip()
    m = re.match(r"^(.{1,60}?)\s*[:：—–-]\s+(.*)$", s)
    if not m:
        return None
    return m.group(1).strip().lower().strip("*_ "), m.group(2).strip()


def _normalize_period(value: str):
    """«01.10.2026 — 20.10.2026» → ('01.10.2026', '20.10.2026')."""
    parts = re.split(r"\s*(?:—|–|-|по|до)\s*", value.strip(), maxsplit=1)
    frm = parts[0].strip()
    to = parts[1].strip() if len(parts) > 1 else ""
    return frm, to


def _sections(text: str) -> list[tuple[str, str]]:
    """Делит markdown по заголовкам 2-го уровня: [(заголовок, тело), ...].
    Текст до первого ## попадает в секцию с пустым заголовком."""
    out, title, buf = [], "", []
    for line in text.splitlines():
        m = re.match(r"^##\s+(?!#)(.*)$", line)
        if m:
            out.append((title, "\n".join(buf)))
            title, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    out.append((title, "\n".join(buf)))
    return out


def _parse_vuln_block(title: str, body: str) -> dict:
    v = {"title": title.strip(), "work_type": ""}
    # bullet-поля идут до первого «жирного» блока
    lines = body.splitlines()
    i = 0
    for i, line in enumerate(lines):
        if re.match(r"^\s*\*\*", line):
            break
        kv = _split_kv(line)
        if not kv:
            continue
        key, val = kv
        field = _VULN_FIELDS.get(key)
        if field == "work_type":
            v["work_type"] = _norm_wt(val) or ""
        elif field:
            v[field] = val
    else:
        i = len(lines)
    # «жирные» блоки: **Метка:** текст ... до следующей метки
    rest = "\n".join(lines[i:])
    blocks = re.split(r"(?m)^\s*\*\*(.+?)\*\*\s*[:：]?\s*", rest)
    # blocks = [pre, label1, text1, label2, text2, ...]
    for j in range(1, len(blocks) - 1, 2):
        label = blocks[j].strip().lower().rstrip(":：")
        field = _VULN_BLOCKS.get(label)
        if field:
            v[field] = blocks[j + 1].strip()
    return v


def parse_project(title: str, text: str) -> dict:
    """title — заголовок документа, text — markdown-тело.
    Возвращает {"project": {...поля...}, "vulns": [ {...}, ... ]}."""
    project = {"name": (title or "").strip() or "Импортированный проект"}
    vulns = []
    for sec_title, body in _sections(text):
        st = sec_title.lower()
        if "уязвимост" in st or "недостатк" in st:
            # уязвимости: каждый ### — отдельная
            parts = re.split(r"(?m)^###\s+(?!#)(.*)$", body)
            for k in range(1, len(parts) - 1, 2):
                vt = parts[k].strip()
                vb = parts[k + 1]
                if vt:
                    vulns.append(_parse_vuln_block(vt, vb))
        else:
            # поля проекта (из «Карточки» или из шапки до первого ##)
            for line in body.splitlines():
                kv = _split_kv(line)
                if not kv:
                    continue
                key, val = kv
                if key in ("период", "период работ", "сроки"):
                    project["period_from"], project["period_to"] = _normalize_period(val)
                elif key in ("виды работ", "вид работ", "работы"):
                    wts = [_norm_wt(t) for t in re.split(r"[,;/]", val)]
                    project["work_types"] = [w for w in wts if w]
                elif key in _PROJECT_FIELDS:
                    project[_PROJECT_FIELDS[key]] = val
    return {"project": project, "vulns": vulns}


# ==========================================================================
# Отдельный документ-уязвимость (один документ Yonote = одна уязвимость)
# ==========================================================================
# Шаблон: заголовок документа = название уязвимости, в начале — таблица полей
# (две колонки «поле | значение»), ниже — текстовые блоки PoC/результатов/
# рекомендаций (заголовками ## или метками **…**). См. docs/yonote-integration.md.

# регулярка вектора CVSS v3.1 (префикс «CVSS:3.1/» необязателен)
_CVSS_RE = re.compile(
    r"(?:CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]",
    re.IGNORECASE)

# поля таблицы уязвимости: метка → поле модели
_VULN_TABLE_FIELDS = {
    "вид работ": "work_type", "тип работ": "work_type", "вид": "work_type",
    "описание": "description",
    "границы": "scope", "scope": "scope", "объект": "scope",
    "инструменты": "tools", "инструментарий": "tools",
    "обнаружена": "detected_at", "обнаружено": "detected_at",
    "время обнаружения": "detected_at", "дата обнаружения": "detected_at", "дата": "detected_at",
    "модели нарушителя": "intruder_models", "нарушители": "intruder_models", "нарушитель": "intruder_models",
    "owasp": "owasp", "owasp top 10": "owasp", "wstg": "wstg", "owasp wstg": "wstg",
    "рекомендации": "recommendations",
    "результаты эксплуатации": "exploitation_result", "результат эксплуатации": "exploitation_result",
    "poc": "poc", "proof of concept": "poc",
}

# строки, которые игнорируем как справочные (приложение считает само)
_VULN_SKIP_KEYS = {"cvssv3.1", "cvss v3.1", "cvss", "вектор cvss", "вектор", "опасность",
                   "критичность", "уровень", "оценка"}


# картинки в markdown: ![подпись](url "title") и html <img src="url" alt="подпись">
_IMG_MD_RE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_IMG_HTML_RE = re.compile(r"<img\b[^>]*?\bsrc=[\"']([^\"']+)[\"'][^>]*?>", re.IGNORECASE)
_IMG_ALT_RE = re.compile(r"\balt=[\"']([^\"']*)[\"']", re.IGNORECASE)


def extract_images(md: str) -> tuple[str, list[dict]]:
    """Вынимает картинки из markdown-блока.

    Возвращает (текст без картинок, [{"url":…, "caption":…}, …]) в порядке
    появления. Нужна для импорта скриншотов PoC/результатов: сами картинки
    скачиваются и привязываются к уязвимости, а из текста ссылки убираются,
    чтобы не осталось «сырого» markdown."""
    images: list[dict] = []

    def _md(m):
        images.append({"caption": (m.group(1) or "").strip(), "url": m.group(2).strip()})
        return ""

    def _html(m):
        alt = _IMG_ALT_RE.search(m.group(0))
        images.append({"caption": (alt.group(1).strip() if alt else ""), "url": m.group(1).strip()})
        return ""

    text = _IMG_MD_RE.sub(_md, md or "")
    text = _IMG_HTML_RE.sub(_html, text)
    # убираем пустые строки, оставшиеся от вырезанных картинок
    text = re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", text).strip()
    return text, images


def _strip_emoji(s: str) -> str:
    """Убирает ведущие значки/эмодзи и пробелы из заголовка."""
    return re.sub(r"^[\s\W_]*?(?=[\wА-Яа-яЁё])", "", s or "").strip() or (s or "").strip()


def _is_sep_row(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{2,}:?", c.strip() or "-") or not c.strip() for c in cells) and \
        any(set(c.strip()) <= set(":-") and c.strip() for c in cells)


def _first_table(lines: list[str]):
    """Возвращает (строки_таблицы, индекс_после_таблицы). Таблица — первый
    непрерывный блок строк, начинающихся с «|»."""
    rows, start = [], None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("|"):
            if start is None:
                start = i
            rows.append(line)
        elif start is not None:
            return rows, i
    return rows, (len(lines) if start is not None else 0)


def _row_cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _apply_field(v: dict, key: str, val: str):
    """Присваивает поле уязвимости по метке и значению (из таблицы или строки)."""
    mvec = _CVSS_RE.search(val)
    if mvec:                         # значение-вектор — это CVSS, какой бы ни была метка
        v["cvss_vector"] = mvec.group(0)
        return
    key = (key or "").lower().strip(" *_:")
    if key in _VULN_SKIP_KEYS:       # напр. «CVSSv3.1 | 8.6» — число игнорируем
        return
    field = _VULN_TABLE_FIELDS.get(key)
    if field == "work_type":
        v["work_type"] = _norm_wt(val) or ""
    elif field and not v.get(field):
        v[field] = val


def _normalize_md(text: str) -> str:
    """Приводит markdown Yonote к предсказуемому виду:
    - снимает хвостовые «\\» (жёсткие переносы Outline);
    - разэкранирует ведущие решётки заголовков (``\\#\\# X`` → ``## X``);
    - убирает ведущие пробелы перед заголовком (``  ## X`` → ``## X``).
    Так заголовки распознаются одинаково и при разбивке тела, и при поиске
    его начала."""
    out = []
    for line in (text or "").splitlines():
        s = re.sub(r"\\+\s*$", "", line)  # хвостовой hard-break «\»
        m = re.match(r"^[ \t]*((?:\\?#){1,6})([ \t]+.*)$", s)
        if m:
            s = m.group(1).replace("\\", "") + m.group(2)
        out.append(s)
    return "\n".join(out)


_HEADING_RE = re.compile(r"^[ \t]*#{1,6}[ \t]+(.+?)[ \t]*$")
# «жирная» метка в отдельной строке: **Метка:**
_BOLD_LABEL_RE = re.compile(r"^[ \t]*\*\*(.+?)\*\*[ \t]*[:：]?[ \t]*$")
# «жирная» метка с текстом на той же строке: **Метка:** текст
_BOLD_INLINE_RE = re.compile(r"^[ \t]*\*\*(.+?)\*\*[ \t]*[:：]?[ \t]*(\S.*)$")


def _block_label(line: str):
    """Если строка целиком — это метка блока тела, возвращает поле модели.

    Yonote отдаёт через API заголовки блоков (PoC, результаты, рекомендации)
    по-разному: как ``## Метка``, как ``**Метка**`` или просто ``Метка`` на
    отдельной строке (без оформления). Распознаём все три варианта."""
    s = (line or "").strip()
    if not s:
        return None
    s = re.sub(r"^#{1,6}\s+", "", s)                  # снять «## » заголовка
    s = re.sub(r"^\*\*(.+?)\*\*$", r"\1", s.strip())  # снять «**…**» жирное
    s = s.strip().rstrip(":：").strip().lower()
    return _VULN_BLOCKS.get(s)


def _body_start(lines: list[str]) -> int:
    """Индекс первой строки тела — заголовка, жирной метки или строки-метки блока."""
    for i, line in enumerate(lines):
        if _HEADING_RE.match(line) or re.match(r"^[ \t]*\*\*.+?\*\*", line) \
                or _block_label(line):
            return i
    return len(lines)


def parse_vuln(title: str, text: str) -> dict:
    """Разбирает документ-уязвимость Yonote в поля модели Vulnerability.

    Поля читаются как из markdown-таблицы «поле | значение», так и из простых
    строк «Поле: значение» (списком или просто текстом) в начале документа —
    оформление роли не играет. work_type может оказаться пустым — тогда
    подставляется при импорте.
    """
    v = {"title": _strip_emoji(title) or "Уязвимость", "work_type": ""}
    lines = _normalize_md(text).splitlines()
    head_end = _body_start(lines)
    head, body_lines = lines[:head_end], lines[head_end:]

    # 1) поля из таблицы в шапке
    table, _ = _first_table(head)
    for row in table:
        cells = _row_cells(row)
        if len(cells) < 2 or _is_sep_row(cells):
            if cells and _CVSS_RE.search(" ".join(cells)):
                v["cvss_vector"] = _CVSS_RE.search(" ".join(cells)).group(0)
            continue
        _apply_field(v, cells[0], cells[1].strip())

    # 2) поля из простых строк «Поле: значение» в шапке (не табличных)
    for line in head:
        if line.lstrip().startswith("|"):
            continue
        kv = _split_kv(line)
        if kv:
            _apply_field(v, kv[0], kv[1])

    # тело: блоки PoC/результатов/рекомендаций.
    # Сегмент начинается со строки-метки блока: ``## Метка``, ``**Метка**`` или
    # просто ``Метка`` на отдельной строке (Yonote отдаёт их по-разному), а также
    # с ``**Метка:** текст`` (метка и текст на одной строке).
    rest = "\n".join(body_lines).strip()
    if rest:
        sections: list[tuple[str, list[str]]] = []
        cur_field: str | None = None
        cur_buf: list[str] = []

        def _flush():
            if cur_field is not None:
                sections.append((cur_field, cur_buf))

        for line in body_lines:
            bi = _BOLD_INLINE_RE.match(line)
            inline_field = (_VULN_BLOCKS.get(bi.group(1).strip().rstrip(":：").lower())
                            if bi else None)
            field = _block_label(line)
            if field is not None:
                _flush()
                cur_field, cur_buf = field, []
            elif inline_field:
                _flush()
                cur_field, cur_buf = inline_field, [bi.group(2)]
            elif cur_field is not None:
                cur_buf.append(line)
        _flush()

        matched = False
        for field, buf in sections:
            if field and not v.get(field):
                v[field] = "\n".join(buf).strip()
                matched = True
        # если ни меток, ни заголовков не распознали — весь текст считаем PoC
        if not matched and not v.get("poc"):
            v["poc"] = rest
    return v
