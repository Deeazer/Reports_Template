"""Клиент к API Yonote (yonote.ru).

Yonote — это форк Outline, поэтому используется совместимое с Outline API:
все методы — POST /api/<group>.<action>, авторизация Bearer-токеном, тело и
ответ в JSON. Документы отдаются в Markdown (поле ``text``).

Нужные методы:
  - auth.info            — проверка токена, сведения о пользователе/команде;
  - collections.list     — список коллекций (разделов базы знаний);
  - documents.list       — список документов коллекции (для предпросмотра);
  - documents.info       — документ с полным текстом (Markdown) для импорта.
"""
from __future__ import annotations

import httpx


class YonoteError(Exception):
    """Ошибка обращения к Yonote (сеть, авторизация, ответ API)."""


class YonoteClient:
    def __init__(self, base_url: str, token: str, timeout: float = 20.0):
        if not base_url:
            raise YonoteError("Не указан адрес Yonote")
        if not token:
            raise YonoteError("Не указан API-токен Yonote")
        # base_url может быть задан как https://cyberbits.yonote.ru или с /api —
        # приводим к корню API
        root = base_url.strip().rstrip("/")
        if root.endswith("/api"):
            root = root[:-4]
        self.api = root + "/api"
        self.token = token.strip()
        self.timeout = timeout

    def _post(self, method: str, payload: dict | None = None) -> dict:
        url = f"{self.api}/{method}"
        try:
            r = httpx.post(url, json=payload or {}, timeout=self.timeout,
                           headers={"Authorization": f"Bearer {self.token}",
                                    "Content-Type": "application/json",
                                    "Accept": "application/json"})
        except httpx.HTTPError as e:
            raise YonoteError(f"Не удалось подключиться к Yonote: {e}") from e
        if r.status_code == 401:
            raise YonoteError("Yonote отклонил токен (401). Проверьте API-ключ.")
        if r.status_code == 403:
            raise YonoteError("Недостаточно прав для доступа к Yonote (403).")
        if r.status_code >= 400:
            msg = ""
            try:
                msg = r.json().get("message") or r.json().get("error") or ""
            except Exception:
                msg = (r.text or "")[:200]
            raise YonoteError(f"Yonote вернул ошибку {r.status_code}: {msg}".strip())
        try:
            return r.json()
        except ValueError as e:
            raise YonoteError("Yonote вернул не-JSON ответ") from e

    # --- методы API ---
    def auth_info(self) -> dict:
        data = self._post("auth.info").get("data", {})
        user = data.get("user") or {}
        team = data.get("team") or {}
        return {"user": user.get("name") or user.get("email") or "",
                "email": user.get("email") or "",
                "team": team.get("name") or "",
                "base_url": team.get("url") or ""}

    def collections(self) -> list[dict]:
        out, offset = [], 0
        while True:
            resp = self._post("collections.list", {"offset": offset, "limit": 100})
            batch = resp.get("data", []) or []
            for c in batch:
                out.append({"id": c.get("id"), "name": c.get("name", ""),
                            "description": c.get("description") or ""})
            if len(batch) < 100:
                break
            offset += len(batch)
        return out

    def documents(self, collection_id: str, top_level_only: bool = True) -> list[dict]:
        """Список документов коллекции (без тяжёлого текста — для предпросмотра)."""
        out, offset = [], 0
        while True:
            resp = self._post("documents.list",
                              {"collectionId": collection_id, "offset": offset, "limit": 100})
            batch = resp.get("data", []) or []
            for d in batch:
                if top_level_only and d.get("parentDocumentId"):
                    continue
                out.append({"id": d.get("id"), "title": d.get("title", ""),
                            "updatedAt": d.get("updatedAt"),
                            "collectionId": d.get("collectionId")})
            if len(batch) < 100:
                break
            offset += len(batch)
        return out

    def tree(self, collection_id: str) -> list[dict]:
        """Дерево документов коллекции: [{id, title, children:[...]}].
        Используется для навигации к документам-уязвимостям."""
        data = self._post("collections.documents", {"id": collection_id}).get("data", []) or []

        def norm(node):
            return {"id": node.get("id"), "title": node.get("title", ""),
                    "children": [norm(c) for c in (node.get("children") or [])]}
        return [norm(n) for n in data]

    def document(self, document_id: str) -> dict:
        """Документ с полным текстом (Markdown) по id."""
        d = self._post("documents.info", {"id": document_id}).get("data", {})
        return {"id": d.get("id"), "title": d.get("title", ""),
                "text": d.get("text", "") or "", "collectionId": d.get("collectionId"),
                "updatedAt": d.get("updatedAt")}
