from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from shared.core.storage.inventory import Inventory
from shared.aws.provider.aws_provider import AwsProvider


class BaseCheck(ABC):
    def __init__(self, inventory: Inventory, provider: AwsProvider):
        self.inventory = inventory
        self.provider = provider

    @abstractmethod
    def execute(self) -> Optional[Dict[str, Any]]:
        pass


class RBACCheck(BaseCheck):
    pass


class ABACCheck(BaseCheck):
    pass