"""Filtros de paquetes y perfiles de filtros guardables en JSON."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List

from .models import Packet

DIRECTIONS = ("All", "Send", "Recv")


@dataclass
class PacketFilter:
    """Un filtro individual. Los campos vacios no restringen."""

    direction: str = "All"  # 'All' | 'Send' | 'Recv'
    header: str = ""        # el paquete debe empezar por este texto (sin distinguir mayusculas)
    contains: str = ""      # el paquete debe contener este texto
    regex: str = ""         # el paquete debe cumplir esta expresion regular

    def matches(self, packet: Packet) -> bool:
        if self.direction != "All" and packet.direction != self.direction:
            return False
        data = packet.data
        if self.header and not data.upper().startswith(self.header.upper()):
            return False
        if self.contains and self.contains.upper() not in data.upper():
            return False
        if self.regex:
            try:
                if not re.search(self.regex, data, re.IGNORECASE):
                    return False
            except re.error:
                return False
        return True

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "header": self.header,
            "contains": self.contains,
            "regex": self.regex,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PacketFilter":
        return cls(
            direction=str(data.get("direction", "All")),
            header=str(data.get("header", "")),
            contains=str(data.get("contains", "")),
            regex=str(data.get("regex", "")),
        )


@dataclass
class FilterProfile:
    """Conjunto de filtros (se cumple si alguno coincide)."""

    name: str
    filters: List[PacketFilter] = field(default_factory=list)

    def matches(self, packet: Packet) -> bool:
        if not self.filters:
            return True
        return any(filt.matches(packet) for filt in self.filters)

    def to_dict(self) -> dict:
        return {"name": self.name, "filters": [f.to_dict() for f in self.filters]}

    @classmethod
    def from_dict(cls, data: dict) -> "FilterProfile":
        return cls(
            name=str(data.get("name", "perfil")),
            filters=[PacketFilter.from_dict(f) for f in data.get("filters", [])],
        )


class ProfileStore:
    """Carga, guarda y elimina perfiles de filtros en el directorio de perfiles."""

    def __init__(self, directory: str):
        self.directory = directory
        self.profiles: List[FilterProfile] = []
        os.makedirs(directory, exist_ok=True)
        self.load_all()

    def load_all(self) -> None:
        """Carga todos los perfiles `*.json` del directorio (se llaman al arrancar)."""
        self.profiles = []
        for filename in sorted(os.listdir(self.directory)):
            if not filename.lower().endswith(".json"):
                continue
            path = os.path.join(self.directory, filename)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    self.profiles.append(FilterProfile.from_dict(json.load(handle)))
            except (OSError, ValueError):
                continue

    def _path_for(self, name: str) -> str:
        safe = re.sub(r"[^\w\- ]", "_", name).strip() or "perfil"
        return os.path.join(self.directory, f"{safe}.json")

    def save(self, profile: FilterProfile) -> None:
        with open(self._path_for(profile.name), "w", encoding="utf-8") as handle:
            json.dump(profile.to_dict(), handle, indent=2, ensure_ascii=False)
        if profile.name not in {p.name for p in self.profiles}:
            self.profiles.append(profile)
        else:
            for index, existing in enumerate(self.profiles):
                if existing.name == profile.name:
                    self.profiles[index] = profile
                    break

    def delete(self, name: str) -> None:
        self.profiles = [p for p in self.profiles if p.name != name]
        path = self._path_for(name)
        if os.path.exists(path):
            os.remove(path)

    def get(self, name: str) -> FilterProfile | None:
        for profile in self.profiles:
            if profile.name == name:
                return profile
        return None

    def names(self) -> List[str]:
        return [p.name for p in self.profiles]
