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


def parse_vuln(title: str, text: str) -> dict:
    """Разбирает документ-уязвимость Yonote в поля модели Vulnerability.
    work_type может оказаться пустым — тогда подставляется при импорте."""
    v = {"title": _strip_emoji(title) or "Уязвимость", "work_type": ""}
    lines = (text or "").splitlines()
    table, after = _first_table(lines)

    for row in table:
        cells = _row_cells(row)
        if len(cells) < 2 or _is_sep_row(cells):
            # строка без метки, но со значением-вектором — это вектор CVSS
            if cells and _CVSS_RE.search(" ".join(cells)):
                v["cvss_vector"] = _CVSS_RE.search(" ".join(cells)).group(0)
            continue
        key = cells[0].lower().strip(" *_:")
        val = cells[1].strip()
        # значение-вектор перекрывает любую метку (в т.ч. пустую или «CVSSv3.1»)
        mvec = _CVSS_RE.search(val)
        if mvec:
            v["cvss_vector"] = mvec.group(0)
            continue
        if key in _VULN_SKIP_KEYS:
            continue
        field = _VULN_TABLE_FIELDS.get(key)
        if field == "work_type":
            v["work_type"] = _norm_wt(val) or ""
        elif field:
            v[field] = val

    # тело после таблицы: блоки PoC/результатов/рекомендаций
    rest = "\n".join(lines[after:]).strip()
    if rest:
        # по «жирным» меткам **Метка:** …
        blocks = re.split(r"(?m)^\s*\*\*(.+?)\*\*\s*[:：]?\s*", rest)
        matched = False
        for j in range(1, len(blocks) - 1, 2):
            label = blocks[j].strip().lower().rstrip(":：")
            field = _VULN_BLOCKS.get(label)
            if field and not v.get(field):
                v[field] = blocks[j + 1].strip(); matched = True
        # по заголовкам ## Метка (секция — до следующего заголовка или **метки**)
        for m in re.finditer(r"(?m)^#{1,3}\s+(.+?)\s*$", rest):
            label = m.group(1).strip().lower()
            field = _VULN_BLOCKS.get(label)
            if field and not v.get(field):
                nxt = re.search(r"(?m)^(?:#{1,3}\s+|\s*\*\*.+?\*\*)", rest[m.end():])
                v[field] = rest[m.end(): m.end() + (nxt.start() if nxt else len(rest))].strip()
                matched = True
        # если ни меток, ни заголовков — весь текст считаем PoC
        if not matched and not v.get("poc"):
            v["poc"] = rest
    return v
