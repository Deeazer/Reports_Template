"""Импорт перечня угроз БДУ ФСТЭК России (файл thrlist.xlsx с bdu.fstec.ru).

Из выгрузки берутся официальные поля: наименование, источник угрозы
(характеристика и потенциал нарушителя), объект воздействия и нарушаемые
свойства (К/Ц/Д). По ним заполняются поля каталога угроз проекта:
нарушители (Н1–Н4), нарушаемые свойства, последствия и интерфейсы воздействия.
"""
import io
import re
from datetime import date

import openpyxl

COLUMNS = {
    "id": "Идентификатор УБИ",
    "name": "Наименование УБИ",
    "source": "Источник угрозы (характеристика и потенциал нарушителя)",
    "object": "Объект воздействия",
    "c": "Нарушение конфиденциальности",
    "i": "Нарушение целостности",
    "a": "Нарушение доступности",
    "status": "Статус угрозы",
}


def parse_thrlist(data: bytes) -> dict:
    ws = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True).active
    rows = ws.iter_rows(values_only=True)
    header, idx = None, None
    for row in rows:
        cells = [str(c).strip() if c is not None else "" for c in row]
        if COLUMNS["id"] in cells:
            header = cells
            break
    if not header:
        raise ValueError("Не найдена строка заголовков «Идентификатор УБИ» — это не выгрузка thrlist.xlsx")
    try:
        idx = {k: header.index(v) for k, v in COLUMNS.items()}
    except ValueError as e:
        raise ValueError(f"В файле нет столбца: {e}")
    threats, details = {}, {}
    for row in rows:
        num = str(row[idx["id"]] or "").strip()
        if not num.isdigit():
            continue
        bdu_id = f"УБИ.{int(num):03d}"
        name = " ".join(str(row[idx["name"]] or "").split())
        threats[bdu_id] = name
        details[bdu_id] = {
            "source": " ".join(str(row[idx["source"]] or "").split()),
            "object": " ".join(str(row[idx["object"]] or "").split()),
            "c": str(row[idx["c"]] or "").strip() == "1",
            "i": str(row[idx["i"]] or "").strip() == "1",
            "a": str(row[idx["a"]] or "").strip() == "1",
            "archived": str(row[idx["status"]] or "").strip().lower().startswith("архив"),
        }
    if not threats:
        raise ValueError("В файле не найдено ни одной угрозы")
    return {"source": "bdu.fstec.ru/threat (thrlist.xlsx)", "retrieved": date.today().isoformat(),
            "threats": threats, "details": details}


# Внешний нарушитель с низким/средним потенциалом — Н1, с высоким — Н4;
# внутренний с низким — Н2, со средним/высоким — Н3 (каталог нарушителей 1.8.1).
def intruders_from_source(source: str) -> str:
    codes = set()
    for part in source.split(";"):
        p = part.strip().lower()
        if p.startswith("внешн"):
            codes.add("Н4" if "высок" in p else "Н1")
        elif p.startswith("внутрен"):
            codes.add("Н2" if "низк" in p else "Н3")
    return ", ".join(sorted(codes))


def properties_text(d: dict) -> str:
    names = [n for n, f in (("Конфиденциальность", d.get("c")), ("целостность", d.get("i")),
                            ("доступность", d.get("a"))) if f]
    if not names:
        return ""
    names[0] = names[0][0].upper() + names[0][1:]
    return ", ".join(names)


def consequences_text(d: dict) -> str:
    props = [n for n, f in (("конфиденциальности", d.get("c")), ("целостности", d.get("i")),
                            ("доступности", d.get("a"))) if f]
    obj = d.get("object", "")
    obj = obj[0].lower() + obj[1:] if obj else ""
    if not props:
        return f"Воздействие на объект: {obj}" if obj else ""
    head = "Нарушение " + (", ".join(props[:-1]) + " и " + props[-1] if len(props) > 1 else props[0])
    return f"{head}: {obj}" if obj else head


# Интерфейсы воздействия каталога (И-01…И-12) по составу объекта воздействия
_OBJECT_TO_INTERFACES = [
    (r"трафик|канал", ["И-05"]),
    (r"сетев(ой узел|ое программное|ое оборудование)|телекоммуникац", ["И-08"]),
    (r"прикладное программное", ["И-01", "И-02"]),
    (r"баз[аы] данных|хранилищ|метаданн", ["И-06"]),
    (r"уч[её]тные данные|аутентификационн", ["И-03"]),
    (r"беспроводн", ["И-12"]),
    (r"микропрограмм|BIOS|аппаратн|носител|техническ(ое|ие) средств|устройств", ["И-11"]),
    (r"контейнер", ["И-07", "И-10"]),
    (r"гипервизор|виртуальн|облач|консол|средств[оа] защиты|системное программное|реестр|"
     r"файлов|информационн(ая|ые) систем|суперкомпьютер|грид", ["И-10"]),
]
# если ничего не подошло: программы (в том числе машинного обучения) — И-02, иное — И-10
_FALLBACK = (r"машинного обучения|искусственного интеллекта|программ", ["И-02"])


def interfaces_from_object(obj: str) -> str:
    found = []
    for pattern, codes in _OBJECT_TO_INTERFACES:
        if re.search(pattern, obj, re.IGNORECASE):
            found += [c for c in codes if c not in found]
    if not found:
        found = _FALLBACK[1] if re.search(_FALLBACK[0], obj, re.IGNORECASE) else ["И-10"]
    return ", ".join(sorted(found))


def threat_fields(d: dict) -> dict:
    """Поля каталога угроз по официальным данным БДУ."""
    return {
        "interfaces": interfaces_from_object(d.get("object", "")),
        "intruders": intruders_from_source(d.get("source", "")),
        "properties": properties_text(d),
        "consequences": consequences_text(d),
    }
