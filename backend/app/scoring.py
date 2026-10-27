"""Автоматические расчёты по уязвимости и сводные таблицы.

Карточка уязвимости заполняется исполнителем, а производные поля
(критичность, вероятность эксплуатации, итоговый риск, уровень по методике
ФСТЭК) вычисляются здесь, чтобы исключить ручные ошибки и расхождения
между карточками и общими таблицами отчёта.
"""
from __future__ import annotations
import re
from . import refdata as R

# --------------------------------------------------------------------------
# CVSS v3.1 base score (реализация по спецификации FIRST)
# --------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

CVSS_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def parse_cvss_vector(vector: str) -> dict | None:
    """Разбирает вектор CVSS v3.1: «CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H».

    Префикс «CVSS:3.1/» необязателен. Вектор другой версии (3.0, 4.0) не принимается.
    """
    return _parse(vector)[0]


_ALLOWED = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}


def _parse(vector):
    if not vector or not vector.strip():
        return None, ""
    m = {}
    version = None
    for part in re.split(r"[/\s]+", vector.strip()):
        if not part:
            continue
        if ":" not in part:
            return None, f"Некорректный фрагмент вектора: «{part}»"
        k, v = part.split(":", 1)
        k, v = k.upper(), v.upper()
        if k == "CVSS":
            version = v
            continue
        m[k] = v
    if version and version != "3.1":
        return None, f"Используется CVSS {version}; требуется вектор CVSS 3.1"
    missing = [k for k in CVSS_METRICS if k not in m]
    if missing:
        return None, "Не заданы базовые метрики: " + ", ".join(missing)
    for k in CVSS_METRICS:
        if m[k] not in _ALLOWED[k]:
            return None, f"Недопустимое значение {k}:{m[k]}"
    return m, ""


def cvss_validate(vector: str) -> str:
    """Пустая строка, если вектор корректен (или не задан), иначе текст ошибки."""
    return _parse(vector)[1]


def cvss_normalize(vector: str) -> str:
    """Каноническая запись: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H."""
    m = parse_cvss_vector(vector)
    if not m:
        return (vector or "").strip()
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in CVSS_METRICS)


def _roundup(x: float) -> float:
    # round up to one decimal, как в спецификации CVSS 3.1
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (int(i / 10000) + 1) / 10.0


def cvss_base_score(vector: str) -> float | None:
    m = parse_cvss_vector(vector)
    if not m:
        return None
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10)
        else:
            score = min(impact + exploitability, 10)
        return _roundup(score)
    except (KeyError, ValueError):
        return None


def severity_from_score(score: float | None) -> str:
    """Критичность (опасность) по шкале из Приложения 2 действующего отчёта."""
    if score is None:
        return ""
    if score == 0:
        return "Информативная"
    if score <= 3.9:
        return "Низкая"
    if score <= 6.9:
        return "Средняя"
    if score <= 8.9:
        return "Высокая"
    return "Критическая"


# --------------------------------------------------------------------------
# Вероятность эксплуатации и итоговый риск (матрицы Приложения 2)
# --------------------------------------------------------------------------
def probability(availability: str, ease: str) -> str:
    return R.PROBABILITY_MATRIX.get(availability, {}).get(ease, "")


def final_risk(severity: str, prob: str) -> str:
    return R.RISK_MATRIX.get(severity, {}).get(prob, "")


# --------------------------------------------------------------------------
# Методика ФСТЭК России от 30.06.2025
# V = Icvss × Iinfr × (Iat + Iimp); Iinfr = kK + lL + pP; Iat = eE; Iimp = hH
# --------------------------------------------------------------------------
def _lookup(table, key):
    for row in table:
        if row["key"] == key:
            return row
    return None


def fstec_criticality(cvss_score, k_key, l_key, p_key, e_key, h_key, settings_fstec=None):
    f = settings_fstec or R.DEFAULT_SETTINGS["fstec"]
    w = f["weights"]
    K = _lookup(f["K"], k_key)
    L = _lookup(f["L"], l_key)
    P = _lookup(f["P"], p_key)
    E = _lookup(f["E"], e_key)
    H = _lookup(f["H"], h_key)
    if not all([K, L, P, E, H]) or cvss_score is None:
        return None
    i_infr = w["k"] * K["value"] + w["l"] * L["value"] + w["p"] * P["value"]
    i_at = w["e"] * E["value"]
    i_imp = w["h"] * H["value"]
    v = cvss_score * i_infr * (i_at + i_imp)
    v = round(v, 2)
    level = next(name for lo, name in R.FSTEC_LEVELS if v >= lo)
    return {
        "value": v,
        "level": level,
        "i_infr": round(i_infr, 3),
        "i_at": round(i_at, 3),
        "i_imp": round(i_imp, 3),
        "components": {
            "K": {"name": K["name"], "kv": round(w["k"] * K["value"], 3)},
            "L": {"name": L["name"], "lv": round(w["l"] * L["value"], 3)},
            "P": {"name": P["name"], "pv": round(w["p"] * P["value"], 3)},
            "E": {"name": E["name"], "ev": round(w["e"] * E["value"], 3)},
            "H": {"name": H["name"], "hv": round(w["h"] * H["value"], 3)},
        },
    }


def h_key_from_cvss(vector: str) -> str:
    """Подсказка показателя H методики ФСТЭК по вектору CVSS."""
    m = parse_cvss_vector(vector) or {}
    if m.get("C") == "H" and m.get("I") == "H" and m.get("A") == "H":
        return "ace"
    if m.get("I") == "H":
        return "integrity"
    if m.get("A") == "H":
        return "dos"
    if m.get("C") == "H":
        return "info"
    if m.get("C") in ("L", "H"):
        return "read_local"
    return "info"


# --------------------------------------------------------------------------
# Полный пересчёт карточки уязвимости
# --------------------------------------------------------------------------
RISK_ORDER = {"Высокий": 0, "Средний": 1, "Низкий": 2, "Информативный": 3, "": 4}
SEV_ORDER = {"Критическая": 0, "Высокая": 1, "Средняя": 2, "Низкая": 3, "Информативная": 4, "": 5}


def recompute_vuln(v: dict, settings_fstec=None) -> dict:
    """Возвращает производные поля уязвимости. v — dict с полями ввода."""
    score = cvss_base_score(v.get("cvss_vector", ""))
    sev = severity_from_score(score)
    prob = probability(v.get("availability", ""), v.get("ease", ""))
    risk = final_risk(sev, prob)
    out = {
        "cvss_score": score,
        "cvss_vector_full": cvss_normalize(v.get("cvss_vector", "")),
        "cvss_error": cvss_validate(v.get("cvss_vector", "")),
        "severity": sev,
        "probability": prob,
        "final_risk": risk,
        "fstec": None,
    }
    if all(v.get(x) for x in ("fstec_k", "fstec_l", "fstec_p", "fstec_e", "fstec_h")):
        out["fstec"] = fstec_criticality(
            score, v["fstec_k"], v["fstec_l"], v["fstec_p"], v["fstec_e"], v["fstec_h"], settings_fstec
        )
    return out


# --------------------------------------------------------------------------
# Сводные таблицы отчёта (считаются автоматически из набора уязвимостей)
# --------------------------------------------------------------------------
def _auto_advantages(ws_vulns: list[dict]) -> list[str]:
    """Преимущества для таблиц 1.4.x, которые следуют из набора уязвимостей."""
    risks = {v.get("final_risk") for v in ws_vulns}
    sevs = {v.get("severity") for v in ws_vulns}
    out = []
    if not ws_vulns:
        out.append("Уязвимостей не выявлено")
        return out
    if "Высокий" not in risks:
        out.append("Не выявлено уязвимостей с высоким уровнем риска")
    if "Критическая" not in sevs:
        out.append("Не выявлено уязвимостей критического уровня опасности")
    return out


# --------------------------------------------------------------------------
# Социотехническое тестирование: сводная статистика по целевой группе
# --------------------------------------------------------------------------
SOCIAL_ACTIONS = [
    ("opened", "открыл сообщение"),
    ("clicked", "перешёл по ссылке"),
    ("submitted", "ввёл учётные данные"),
    ("reported", "сообщил в службу ИБ"),
]


def _pct(n, total):
    return round(100 * n / total) if total else 0


def social_stats(social: dict | None) -> dict:
    """Считает итоги по целевой группе: всего, открыли, перешли, ввели данные, сообщили.

    Переход по ссылке подразумевает открытие сообщения, ввод данных — переход,
    поэтому старшее действие засчитывается и в младших.
    """
    social = social or {}
    scenarios = social.get("scenarios") or []
    names = {sc.get("id"): (sc.get("name") or f"Сценарий {i}") for i, sc in enumerate(scenarios, 1)}

    def norm(t):
        sub = bool(t.get("submitted"))
        clk = sub or bool(t.get("clicked"))
        return {"opened": clk or bool(t.get("opened")), "clicked": clk, "submitted": sub,
                "reported": bool(t.get("reported"))}

    targets = [t for t in (social.get("targets") or []) if str(t.get("contact", "")).strip()]

    def agg(items):
        total = len(items)
        out = {"total": total}
        for key, _ in SOCIAL_ACTIONS:
            n = sum(1 for t in items if norm(t)[key])
            out[key] = n
            out[key + "_pct"] = _pct(n, total)
        return out

    by_scenario = []
    for sc in scenarios:
        items = [t for t in targets if t.get("scenario") == sc.get("id")]
        by_scenario.append({"id": sc.get("id"), "name": names[sc.get("id")], **agg(items)})
    unassigned = [t for t in targets if t.get("scenario") not in names]
    if unassigned:
        by_scenario.append({"id": None, "name": "Сценарий не указан", **agg(unassigned)})

    affected = []
    for t in targets:
        n = norm(t)
        acts = [label for key, label in SOCIAL_ACTIONS if n[key] and key != "opened"]
        if n["clicked"] or n["submitted"]:
            affected.append({"contact": t.get("contact", "").strip(),
                             "scenario": names.get(t.get("scenario"), ""),
                             "actions": ", ".join(acts)})
    return {**agg(targets), "by_scenario": by_scenario, "affected": affected}


def social_security(stats: dict) -> tuple[str, list[str], list[str]]:
    """Уровень защищенности, недостатки и автоматические преимущества для таблицы 1.4.x."""
    total = stats.get("total", 0)
    if not total:
        return "Не определён", [], []
    clicked, submitted = stats["clicked_pct"], stats["submitted_pct"]
    if submitted >= 10 or clicked >= 30:
        level = "Низкий"
    elif stats["submitted"] or stats["clicked"]:
        level = "Средний"
    else:
        level = "Высокий"
    dis, adv = [], []
    if stats["clicked"]:
        dis.append(f"Из исследуемой группы {clicked}% перешли по ссылке"
                   + (f", {submitted}% ввели учётные данные" if stats["submitted"] else ""))
    else:
        adv.append("Сотрудники не переходили по ссылкам из сообщений")
    if not stats["submitted"]:
        adv.append("Сотрудники не вводили учётные данные на поддельных ресурсах")
    if stats["reported"]:
        adv.append(f"О подозрительном сообщении в службу ИБ сообщили {stats['reported']} из {total}")
    return level, dis, adv


def dos_security(dos: dict | None) -> tuple[str, list[str], list[str]]:
    """Уровень устойчивости, недостатки и преимущества для таблицы 1.4.x (отказ в обслуживании)."""
    stages = (dos or {}).get("stages") or []
    if not stages:
        return "Не определён", [], []
    failed = [s for s in stages if s.get("outcome") == "failed"]
    dis, adv = [], []
    if failed:
        level = "Низкий"
        for s in failed:
            host = (s.get("host") or "ресурс").strip()
            method = (s.get("method") or "").strip()
            dis.append(f"Ресурс {host} оказался недоступен при атаке"
                       + (f" методом «{method}»" if method else ""))
    else:
        level = "Высокий"
        adv.append("Исследуемые ресурсы сохранили доступность при всех проведённых атаках")
    return level, dis, adv


def wireless_security(wireless: dict | None) -> tuple[str, list[str], list[str]]:
    """Уровень защищённости, недостатки и преимущества для таблицы 1.4.x (беспроводные сети)."""
    results = (wireless or {}).get("results") or []
    if not results:
        return "Не определён", [], []
    breached = [r for r in results if r.get("outcome") == "success"]
    dis, adv = [], []
    if breached:
        level = "Низкий"
        for r in breached:
            title = (r.get("title") or "беспроводная сеть").strip()
            dis.append(f"Успешная атака на {title}")
    else:
        level = "Высокий"
        adv.append("Проникновение в инфраструктуру через беспроводные сети не удалось")
    return level, dis, adv


def summary_tables(vulns: list[dict], work_types: list[str], security_notes: dict | None = None,
                   social: dict | None = None, dos: dict | None = None,
                   wireless: dict | None = None) -> dict:
    """vulns — список уязвимостей с уже вычисленными производными полями.

    Возвращает данные для:
      - таблицы 3.1 (список уязвимостей по уровню риска);
      - таблицы 3.2 (количество по уровням риска);
      - таблиц 1.4.* (общий уровень защищенности) по видам работ.
    security_notes — введённые в проекте преимущества по видам работ
    ({work_type: {"advantages": [str]}}); дополняются автоматическими.
    """
    security_notes = security_notes or {}
    ordered = sorted(
        vulns,
        key=lambda x: (RISK_ORDER.get(x.get("final_risk"), 4), SEV_ORDER.get(x.get("severity"), 5)),
    )
    # нумерация ссылок в отчёте: раздел на вид работ, порядковый номер внутри
    section_no = {}
    base = 4
    for wt in work_types:
        section_no[wt] = base
        base += 1
    counters = {wt: 0 for wt in work_types}
    rows = []
    for v in ordered:
        wt = v.get("work_type")
        if wt not in counters:
            continue
        counters[wt] += 1
        ref = f"{section_no[wt]}.{counters[wt]}"
        rows.append({"id": v.get("id"), "title": v.get("title"), "final_risk": v.get("final_risk"),
                     "ref": ref, "work_type": wt})

    counts = {lvl: 0 for lvl in R.RISK_LEVELS}
    # распределение по уровням риска в разрезе видов работ (таблица 3.2)
    counts_by_wt = {wt: {lvl: 0 for lvl in R.RISK_LEVELS} for wt in work_types}
    not_rated = 0
    for v in vulns:
        r = v.get("final_risk")
        if r in counts:
            counts[r] += 1
            if v.get("work_type") in counts_by_wt:
                counts_by_wt[v["work_type"]][r] += 1
        else:
            not_rated += 1

    # таблица 3.2: количество по уровню опасности (критичности CVSS), включая критические
    sev_levels = list(reversed(R.SEVERITY_LEVELS))   # Критическая … Информативная
    sev_counts = {lvl: 0 for lvl in sev_levels}
    sev_by_wt = {wt: {lvl: 0 for lvl in sev_levels} for wt in work_types}
    sev_not_rated = 0
    for v in vulns:
        sv = v.get("severity")
        if sv in sev_counts:
            sev_counts[sv] += 1
            if v.get("work_type") in sev_by_wt:
                sev_by_wt[v["work_type"]][sv] += 1
        else:
            sev_not_rated += 1

    # общий уровень защищенности: Низкий, если есть Высокий риск; Средний — если Средний; иначе Высокий
    def security_level(ws_vulns):
        risks = {v.get("final_risk") for v in ws_vulns}
        if "Высокий" in risks:
            return "Низкий"
        if "Средний" in risks:
            return "Средний"
        return "Высокий"

    security = {}
    for wt in work_types:
        manual = [a.strip() for a in (security_notes.get(wt, {}).get("advantages") or []) if str(a).strip()]
        if R.WORK_TYPES[wt].get("kind") == "social":
            level, dis, auto_adv = social_security(social or {})
            security[wt] = {"title": R.WORK_TYPES[wt]["summary_title"], "level": level,
                            "disadvantages": dis, "advantages": manual + auto_adv,
                            "manual_advantages": manual, "count": (social or {}).get("total", 0)}
            continue
        if R.WORK_TYPES[wt].get("kind") == "dos":
            level, dis, auto_adv = dos_security(dos or {})
            security[wt] = {"title": R.WORK_TYPES[wt]["summary_title"], "level": level,
                            "disadvantages": dis, "advantages": manual + auto_adv,
                            "manual_advantages": manual, "count": len((dos or {}).get("stages") or [])}
            continue
        if R.WORK_TYPES[wt].get("kind") == "wireless":
            level, dis, auto_adv = wireless_security(wireless or {})
            security[wt] = {"title": R.WORK_TYPES[wt]["summary_title"], "level": level,
                            "disadvantages": dis, "advantages": manual + auto_adv,
                            "manual_advantages": manual, "count": len((wireless or {}).get("networks") or [])}
            continue
        ws_vulns = [v for v in vulns if v.get("work_type") == wt]
        # недостатки — все уязвимости, кроме информативных, по убыванию риска
        disadvantages = [(v.get("title") or "Без названия")
                         + (f" (риск: {v['final_risk'].lower()})" if v.get("final_risk") else "")
                         for v in sorted(ws_vulns, key=lambda x: (RISK_ORDER.get(x.get("final_risk"), 4),
                                                                  SEV_ORDER.get(x.get("severity"), 5)))
                         if v.get("final_risk") != "Информативный"]
        security[wt] = {
            "title": R.WORK_TYPES[wt]["summary_title"],
            "level": security_level(ws_vulns),
            "disadvantages": disadvantages,
            "advantages": manual + _auto_advantages(ws_vulns),
            "manual_advantages": manual,
            "count": len(ws_vulns),
        }

    return {
        "rows": rows,
        "counts": counts,
        "counts_by_wt": counts_by_wt,
        "not_rated": not_rated,
        "sev_counts": sev_counts,
        "sev_counts_by_wt": sev_by_wt,
        "sev_not_rated": sev_not_rated,
        "total": len(vulns),
        "security": security,
        "section_no": section_no,
    }


# --------------------------------------------------------------------------
# Актуальные угрозы (таблица 1.8.3) формируются из уязвимостей.
# Для каждой угрозы БДУ, выбранной хотя бы в одной уязвимости, собираются:
# интерфейсы воздействия и модели нарушителя из этих уязвимостей, а также
# нарушаемые свойства и последствия из каталога угроз проекта.
# --------------------------------------------------------------------------
def _split_codes(value):
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [p.strip() for p in str(value or "").replace(";", ",").split(",") if p.strip()]


def _sort_codes(codes):
    def key(c):
        m = re.search(r"(\d+)", c)
        return (c[:2], int(m.group(1)) if m else 0, c)
    return sorted(set(codes), key=key)


def _interfaces_for(work_type, interfaces):
    """Коды интерфейсов, относящихся к виду работ (интерфейс без work_types — общий)."""
    return {i.get("code") for i in (interfaces or [])
            if not i.get("work_types") or work_type in i.get("work_types")}


def auto_threat_codes(v: dict, threat_catalog: list[dict]) -> list[str]:
    """Угрозы каталога, подобранные по последствиям эксплуатации (H) уязвимости.

    Если H не выбран, он подсказывается по вектору CVSS.
    """
    h = v.get("fstec_h") or (h_key_from_cvss(v.get("cvss_vector", "")) if v.get("cvss_vector") else "")
    wanted = R.H_TO_BDU.get(h, [])
    by_bdu = {t.get("bdu"): t.get("code") for t in (threat_catalog or []) if t.get("bdu")}
    return [by_bdu[b] for b in wanted if b in by_bdu]


SOCIAL_BDU = "УБИ.175"   # Угроза «фишинга»


def actual_threats(vulns: list[dict], threat_catalog: list[dict], interfaces: list[dict] | None = None,
                   social_stats: dict | None = None) -> list[dict]:
    """Строит строки таблицы 1.8.3 из уязвимостей.

    Угрозы уязвимости — отмеченные в карточке вручную, а если не отмечено ничего,
    подобранные автоматически (auto_threat_codes). Интерфейсы — из карточки,
    иначе интерфейсы угрозы по каталогу, относящиеся к виду работ уязвимости.
    Нарушители — из карточки, иначе нарушители по умолчанию для вида работ.
    """
    catalog = {t.get("code"): t for t in (threat_catalog or [])}
    agg = {}   # code -> {interfaces:set, intruders:set, vulns:[titles], auto:bool}
    order = []
    for v in vulns:
        manual = _split_codes(v.get("threat_codes"))
        codes = manual or auto_threat_codes(v, threat_catalog)
        wt = v.get("work_type")
        intruders = _split_codes(v.get("intruder_models")) or R.WORK_TYPES.get(wt, {}).get("default_intruders", [])
        vuln_intf = _split_codes(v.get("interface_codes"))
        allowed = _interfaces_for(wt, interfaces) if interfaces is not None else None
        for code in codes:
            if code not in agg:
                agg[code] = {"interfaces": set(), "intruders": set(), "vulns": [], "auto": False}
                order.append(code)
            a = agg[code]
            if vuln_intf:
                a["interfaces"].update(vuln_intf)
            else:
                cat_intf = _split_codes(catalog.get(code, {}).get("interfaces"))
                a["interfaces"].update(c for c in cat_intf if allowed is None or c in allowed)
            a["intruders"].update(intruders)
            a["auto"] = a["auto"] or not manual
            if v.get("title"):
                a["vulns"].append(v["title"])
    # социотехническое тестирование: если сотрудники переходили по ссылкам или
    # вводили данные, актуальна угроза фишинга (по каталогу проекта)
    if social_stats and (social_stats.get("clicked") or social_stats.get("submitted")):
        code = next((t.get("code") for t in (threat_catalog or [])
                     if (t.get("bdu") or "").strip().upper() == SOCIAL_BDU), None)
        if code:
            if code not in agg:
                agg[code] = {"interfaces": set(), "intruders": set(), "vulns": [], "auto": True}
                order.append(code)
            a = agg[code]
            allowed = _interfaces_for("social", interfaces) if interfaces is not None else None
            cat_intf = _split_codes(catalog.get(code, {}).get("interfaces"))
            a["interfaces"].update(c for c in cat_intf if allowed is None or c in allowed)
            a["intruders"].update(R.WORK_TYPES["social"]["default_intruders"])
            a["vulns"].append("Социотехническое тестирование")
    rows = []
    # сохраняем порядок каталога, затем угрозы, которых нет в каталоге
    seq = [c for c in (t.get("code") for t in (threat_catalog or [])) if c in agg]
    seq += [c for c in order if c not in seq]
    for code in seq:
        a = agg[code]
        cat = catalog.get(code, {})
        rows.append({
            "code": code,
            "name": cat.get("name", ""),
            "bdu": cat.get("bdu", ""),
            "interfaces": ", ".join(_sort_codes(a["interfaces"])) or cat.get("interfaces", ""),
            "intruders": ", ".join(_sort_codes(a["intruders"])) or cat.get("intruders", ""),
            "properties": cat.get("properties", ""),
            "consequences": cat.get("consequences", ""),
            "source_vulns": a["vulns"],
            "auto": a["auto"],
        })
    return rows


# --------------------------------------------------------------------------
# Интерфейсы воздействия (таблица 1.8.2) определяются видами работ проекта:
# в отчёт попадают интерфейсы каталога, у которых в work_types есть хотя бы
# один вид работ проекта. Интерфейс без work_types считается общим.
# --------------------------------------------------------------------------
def active_interfaces(interfaces: list[dict], work_types: list[str]) -> list[dict]:
    wts = set(work_types or [])
    return [i for i in (interfaces or [])
            if not i.get("work_types") or wts & set(i.get("work_types"))]
