r"""BloodHound toplama zip'i (users/groups/computers JSON) → graf verisi.

BloodHound JSON yapısı:
    {"meta": {"type": "users"|"groups"|...}, "data": [ {...}, ... ]}
Her nesne: ObjectIdentifier (SID), Properties.name, Aces (ACL hakları),
gruplar için Members (üyelik).

Kullanım: PathFinder graf üzerinden "bu hesap Domain Admin'e nasıl ulaşır?"
sorusunu networkx ile yanıtlar.
"""

import json
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.exceptions import ParseError

# Yetki yükseltme için "kötüye kullanılabilir" ACL hakları
DANGEROUS_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "Owns", "AddMember", "ForceChangePassword", "AllExtendedRights",
    "WriteProperty",
}


class AclEdge(BaseModel):
    source_sid: str
    source_name: str | None = None
    target_sid: str
    right: str
    is_dangerous: bool


class GraphData(BaseModel):
    edges: list[AclEdge] = Field(default_factory=list)
    sid_to_name: dict[str, str] = Field(default_factory=dict)
    user_sids: list[str] = Field(default_factory=list)   # users.json'daki hesaplar


def parse_bloodhound_zip(zip_path: Path) -> GraphData:
    graph = GraphData()
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    data = json.loads(zf.read(name))
                except json.JSONDecodeError:
                    continue
                _extract_from_collection(data, graph)
    except zipfile.BadZipFile as e:
        raise ParseError(f"Geçersiz BloodHound zip {zip_path}: {e}") from e
    return graph


def _extract_from_collection(data: dict, graph: GraphData) -> None:
    meta_type = (data.get("meta") or {}).get("type", "")

    for obj in data.get("data", []):
        obj_id = obj.get("ObjectIdentifier")
        obj_name = obj.get("Properties", {}).get("name")
        if obj_id and obj_name:
            graph.sid_to_name[obj_id] = obj_name
        if obj_id and meta_type == "users":
            graph.user_sids.append(obj_id)
        if not obj_id:
            continue

        # Aces: bu nesne üzerinde kimin hangi hakkı var
        for ace in obj.get("Aces", []) or []:
            right = ace.get("RightName")
            source = ace.get("PrincipalSID")
            if not right or not source:
                continue
            graph.edges.append(AclEdge(
                source_sid=source,
                source_name=ace.get("PrincipalName"),
                target_sid=obj_id,
                right=right,
                is_dangerous=right in DANGEROUS_RIGHTS,
            ))

        # Grup üyelikleri de birer "kenar" (Member -> Group, right=MemberOf)
        for member in obj.get("Members", []) or []:
            member_id = member.get("ObjectIdentifier")
            if not member_id:
                continue
            graph.edges.append(AclEdge(
                source_sid=member_id,
                source_name=member.get("Properties", {}).get("name"),
                target_sid=obj_id,
                right="MemberOf",
                is_dangerous=False,
            ))
