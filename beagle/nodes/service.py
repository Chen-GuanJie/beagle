from beagle.nodes.node import Node
from typing import Optional,Dict,List

class service(Node):
    __name__ = "service"
    __color__ = "#FF0000"
    ServiceName : Optional[str]
    ServiceFileName : Optional[str]
    ServiceType: Optional[str]
    ServiceStartType: Optional[str]
    ServiceAccount: Optional[str]
    key_fields: List[str] = ['ServiceName','ServiceFileName']
    hashes: Optional[Dict[str, str]] = {}
    def __init__(self) -> None:
        super().__init__()