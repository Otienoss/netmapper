from abc import ABC, abstractmethod
from typing import Any


class BaseScanner(ABC):
    name: str

    @abstractmethod
    async def scan(self, target: str, **kwargs) -> Any:
        """Taramayı çalıştırır, araca özgü ham sonucu döner."""
        raise NotImplementedError
