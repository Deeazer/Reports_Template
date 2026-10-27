"""Превращает ORM-объекты в dict и добавляет вычисляемые поля."""
from . import models, scoring


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
        "member_ids": [m.user_id for m in p.members],
        "created_by": p.created_by,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
    if with_vulns:
        vulns = [vuln_dict(v, settings_fstec) for v in p.vulns]
        d["vulns"] = vulns
        d["summary"] = scoring.summary_tables(vulns, p.work_types or [])
        for v in vulns:
            # угрозы, которые будут подобраны, если в карточке ничего не отмечено
            v["auto_threat_codes"] = scoring.auto_threat_codes(v, p.threats or [])
        d["auto_threats"] = scoring.actual_threats(vulns, p.threats or [], p.interfaces or [])
    return d
