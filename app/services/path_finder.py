"""ACL/grup üyeliği grafiğinde yetki yükseltme yolu bulma (networkx).

Kenarlar: tehlikeli ACL hakları (GenericAll, AddMember ...) + MemberOf
(grup üyelikleri). Yol = "hesap --[hak]--> grup --[hak]--> DOMAIN ADMINS".
"""

import networkx as nx

from app.normalization.bloodhound_parser import GraphData


class PathFinder:
    """
    Ele geçirilen bir hesaptan (veya domaindeki herhangi bir kullanıcıdan)
    Domain Admins (veya başka bir hedef gruba) en kısa yolu bulur.
    """

    def __init__(self, graph_data: GraphData):
        self.sid_to_name = graph_data.sid_to_name
        self.user_sids = set(graph_data.user_sids)
        self.g = nx.DiGraph()
        for edge in graph_data.edges:
            # Sadece tehlikeli haklar + grup üyelikleri yol olarak sayılır
            if edge.is_dangerous or edge.right == "MemberOf":
                if not edge.source_sid or not edge.target_sid:
                    continue
                self.g.add_edge(
                    edge.source_sid, edge.target_sid,
                    right=edge.right, dangerous=edge.is_dangerous,
                )

    # ------------------------------------------------------------- isim bulma
    def find_name_sid(self, name: str) -> str | None:
        key = name.strip().upper()
        # 1) tam eşleşme: "DOMAIN ADMINS" ↔ "DOMAIN ADMINS@CORP.LOCAL"
        for sid, n in self.sid_to_name.items():
            if not n:
                continue
            nu = n.upper()
            if nu == key or nu.split("@")[0] == key:
                return sid
        # 2) önek eşleşme (esneklik)
        for sid, n in self.sid_to_name.items():
            if n and n.upper().startswith(key):
                return sid
        return None

    # ------------------------------------------------------------- yollar
    def _hops_for(self, path: list[str]) -> list[dict]:
        hops = []
        for i in range(len(path) - 1):
            edge_data = self.g.get_edge_data(path[i], path[i + 1])
            hops.append({
                "from": self.sid_to_name.get(path[i], path[i]),
                "from_sid": path[i],
                "to": self.sid_to_name.get(path[i + 1], path[i + 1]),
                "to_sid": path[i + 1],
                "right": edge_data["right"],
                "dangerous": edge_data["dangerous"],
            })
        return hops

    @staticmethod
    def _result(path: list[str], hops: list[dict], target_name: str) -> dict:
        return {
            "found": True,
            "start": hops[0]["from"] if hops else None,
            "target": target_name,
            "hop_count": len(hops),
            "hops": hops,
        }

    def shortest_path_to(self, start_name: str,
                         target_name: str = "DOMAIN ADMINS") -> dict:
        """Belirli bir başlangıç hesabından hedef gruba en kısa yol."""
        start_sid = self.find_name_sid(start_name)
        target_sid = self.find_name_sid(target_name)

        if not start_sid or not target_sid:
            return {"found": False,
                    "reason": "principal veya hedef grup bulunamadı "
                              f"({start_name!r} → {target_name!r})"}

        try:
            path = nx.shortest_path(self.g, start_sid, target_sid)
        except nx.NetworkXNoPath:
            return {"found": False,
                    "reason": "doğrudan bir yetki yükseltme yolu bulunamadı"}
        except nx.NodeNotFound as e:
            return {"found": False, "reason": f"grafte düğüm yok: {e}"}

        hops = self._hops_for(path)
        return self._result(path, hops, target_name)

    def shortest_path_from_users(self,
                                 target_name: str = "DOMAIN ADMINS") -> dict:
        """Domaindeki EN KOLAY hedefe ulaşan kullanıcıyı otomatik seçer.

        Tek BFS (hedefin ters grafiği) ile tüm mesafeler hesaplanır.
        Yalnız MemberOf zinciriyle hedefe ulaşan kullanıcılar (zaten
        gruba gömülü/önceden yetkili) elemine edilir — bunlar privesc
        değil, mevcut üyeliktir. Eleme sonrası kalan her yol en az bir
        tehlikeli ACL hakkı içerir.
        """
        target_sid = self.find_name_sid(target_name)
        if not target_sid:
            return {"found": False,
                    "reason": f"hedef grup bulunamadı ({target_name!r})"}
        if target_sid not in self.g:
            return {"found": False,
                    "reason": f"grafte {target_name!r} düğümü yok (toplama boş mu?)"}

        # hedefe olan TÜL mesafeler (tek BFS, ters yönlü)
        distances = nx.single_source_shortest_path_length(
            self.g.reverse(copy=False), target_sid
        )

        # sadece MemberOf kenarlarıyla ulaşanlar (zaten yetkili) → ele
        memb = nx.DiGraph(
            (u, v) for u, v, d in self.g.edges(data=True)
            if d["right"] == "MemberOf"
        )
        privileged: set[str] = set()
        if target_sid in memb:
            memb_dist = nx.single_source_shortest_path_length(
                memb.reverse(copy=False), target_sid
            )
            privileged = {s for s in self.user_sids if s in memb_dist}
        pool = [s for s in self.user_sids if s not in privileged] or list(
            self.user_sids
        )

        candidates = [
            (distances[sid], sid) for sid in pool if sid in distances
        ]
        if not candidates:
            return {"found": False,
                    "reason": "hiçbir kullanıcı hesabından hedefe yol yok"}

        _, best_sid = min(candidates, key=lambda t: t[0])
        path = nx.shortest_path(self.g, best_sid, target_sid)
        hops = self._hops_for(path)
        result = self._result(path, hops, target_name)
        result["excluded_privileged"] = len(privileged)
        return result
