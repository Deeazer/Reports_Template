from typing import Optional, Any
from pydantic import BaseModel, Field


# ---------- auth / users ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    id: int
    role: str
    full_name: str
    login: str


class UserOut(BaseModel):
    id: int
    login: str
    full_name: str
    position: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    login: str
    password: str
    full_name: str = ""
    position: str = ""
    role: str = "executor"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    position: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


# ---------- projects ----------
class ProjectBase(BaseModel):
    name: str
    client_name: str = ""
    client_requisites: str = ""
    object_description: str = ""
    test_methods: list[str] = []
    work_types: list[str] = []
    period_from: str = ""
    period_to: str = ""
    tech_sites: str = ""
    intruders: list[dict] = []
    interfaces: list[dict] = []
    threats: list[dict] = []
    tools: list[dict] = []
    executors: list[dict] = []
    member_ids: list[int] = []


class ProjectCreate(BaseModel):
    name: str
    client_name: str = ""
    work_types: list[str] = ["external", "internal"]
    test_methods: list[str] = ["black", "grey"]


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    client_name: Optional[str] = None
    client_requisites: Optional[str] = None
    object_description: Optional[str] = None
    test_methods: Optional[list[str]] = None
    work_types: Optional[list[str]] = None
    period_from: Optional[str] = None
    period_to: Optional[str] = None
    tech_sites: Optional[str] = None
    status: Optional[str] = None
    intruders: Optional[list[dict]] = None
    interfaces: Optional[list[dict]] = None
    threats: Optional[list[dict]] = None
    tools: Optional[list[dict]] = None
    executors: Optional[list[dict]] = None
    scope: Optional[dict] = None
    approvals: Optional[list[dict]] = None
    security_notes: Optional[dict] = None
    member_ids: Optional[list[int]] = None


# ---------- vulnerabilities ----------
class VulnBase(BaseModel):
    work_type: str
    title: str = ""
    description: str = ""
    scope: str = ""
    tools: str = ""
    detected_at: str = ""
    cvss_vector: str = ""
    intruder_models: str = ""
    threat_codes: list[str] = []
    interface_codes: list[str] = []
    availability: str = ""
    ease: str = ""
    fstec_k: str = ""
    fstec_l: str = ""
    fstec_p: str = ""
    fstec_e: str = ""
    fstec_h: str = ""
    poc: str = ""
    exploitation_result: str = ""
    recommendations: str = ""


class VulnCreate(VulnBase):
    pass


class VulnUpdate(BaseModel):
    work_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    tools: Optional[str] = None
    detected_at: Optional[str] = None
    cvss_vector: Optional[str] = None
    intruder_models: Optional[str] = None
    threat_codes: Optional[list[str]] = None
    interface_codes: Optional[list[str]] = None
    availability: Optional[str] = None
    ease: Optional[str] = None
    fstec_k: Optional[str] = None
    fstec_l: Optional[str] = None
    fstec_p: Optional[str] = None
    fstec_e: Optional[str] = None
    fstec_h: Optional[str] = None
    poc: Optional[str] = None
    exploitation_result: Optional[str] = None
    recommendations: Optional[str] = None
    order_index: Optional[int] = None
