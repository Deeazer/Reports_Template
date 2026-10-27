"""Превращает ORM-объекты в dict и добавляет вычисляемые поля."""
from . import models, scoring


def _name(u):
    return u.short_name if u else None


def _ts(dt):
    return dt.isoformat() if dt else None


def vuln_dict(v: "models.Vulnerability", settings_fstec=None) -> dict:
    data = {
        "id": v.id,
        "project_id": v.project_id,
        "work_type": v.work_type,
        "order_index": v.order_index,
        "title": v.title,
        "description": v.description,
        "scope": v.scope,
        "tools": v.tools,
        "detected_at": v.detected_at,
        "cvss_vector": v.cvss_vector,
        "intruder_models": v.intruder_models,
        "threat_codes": v.threat_codes or [],
        "interface_codes": v.interface_codes or [],
        "availability": v.availability,
        "ease": v.ease,
        "fstec_k": v.fstec_k,
        "fstec_l": v.fstec_l,
        "fstec_p": v.fstec_p,
        "fstec_e": v.fstec_e,
        "fstec_h": v.fstec_h,
        "poc": v.poc,
        "exploitation_result": v.exploitation_result,
        "recommendations": v.recommendations,
        "owasp": v.owasp or "",
        "wstg": v.wstg or "",
        "created_by": v.created_by,
        "created_by_name": _name(v.creator),
        "updated_by": v.updated_by,
        "updated_by_name": _name(v.updater),
        "created_at": _ts(v.created_at),
        "updated_at": _ts(v.updated_at),
        "images": [
            {"id": im.id, "caption": im.caption, "block": im.block,
             "order_index": im.order_index, "url": f"/api/images/{im.id}"}
            for im in v.images
        ],
    }
    data.update(scoring.recompute_vuln(data, settings_fstec))
    return data


def project_dict(p: "models.Project", with_vulns=True, settings_fstec=None) -> dict:
    d = {
        "id": p.id,
        "name": p.name,
        "client_name": p.client_name,
        "client_requisites": p.client_requisites,
        "object_description": p.object_description,
        "test_methods": p.test_methods or [],
        "work_types": p.work_types or [],
        "period_from": p.period_from,
        "period_to": p.period_to,
        "tech_sites": p.tech_sites,
        "status": p.status,
        "intruders": p.intruders or [],
        "interfaces": p.interfaces or [],
        "active_interfaces": scoring.active_interfaces(p.interfaces or [], p.work_types or []),
        "threats": p.threats or [],
        "tools": p.tools or [],
        "executors": p.executors or [],
        "scope": p.scope or {},
        "approvals": p.approvals or [],
        "security_notes": p.security_notes or {},
        "social": p.social or {},
        "dos": p.dos or {},
        "wireless": p.wireless or {},
        "images": [{"id": im.id, "section": im.section, "caption": im.caption,
                    "order_index": im.order_index, "url": f"/api/project-images/{im.id}"}
                   for im in p.images],
        "member_ids": [m.user_id for m in p.members],
        "created_by": p.created_by,
        "created_by_name": _name(p.creator),
        "updated_by": p.updated_by,
        "updated_by_name": _name(p.updater),
        "created_at": _ts(p.created_at),
        "updated_at": _ts(p.updated_at),
    }
    d["social_stats"] = scoring.social_stats(d["social"])
    if with_vulns:
        vulns = [vuln_dict(v, settings_fstec) for v in p.vulns]
        d["vulns"] = vulns
        d["summary"] = scoring.summary_tables(vulns, p.work_types or [], p.security_notes or {},
                                              d["social_stats"], d["dos"], d["wireless"])
        for v in vulns:
            # угрозы, которые будут подобраны, если в карточке ничего не отмечено
            v["auto_threat_codes"] = scoring.auto_threat_codes(v, p.threats or [])
        d["auto_threats"] = scoring.actual_threats(vulns, p.threats or [], p.interfaces or [],
                                                   social_stats=d["social_stats"] if "social" in (p.work_types or []) else None)
    return d
