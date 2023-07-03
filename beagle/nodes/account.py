from beagle.nodes.node import Node
from typing import Dict,Optional,List

class account(Node):
    __name__ = "service"
    __color__ = "#FF0000"
    TargetUserSid: Optional[str]
    TargetUserName: Optional[str]
    TargetDomainName: Optional[str]
    TargetLogonId: Optional[str]
    LogonType: Optional[str]
    LogonProcessName: Optional[str]
    AuthenticationPackageName: Optional[str]
    WorkstationName: Optional[str]
    LogonGuid: Optional[str]
    TransmittedServices: Optional[str]
    LmPackageName: Optional[str]
    KeyLength: Optional[str]
    ProcessId: Optional[str]
    ProcessName: Optional[str]
    IpAddress: Optional[str]
    IpPort: Optional[str]
    ImpersonationLevel: Optional[str]
    RestrictedAdminMode: Optional[str]
    TargetOutboundUserName: Optional[str]
    TargetOutboundDomainName: Optional[str]
    VirtualAccount: Optional[str]
    TargetLinkedLogonId: Optional[str]
    ElevatedToken: Optional[str]

    key_fields: List[str] = ['TargetUserSid','TargetLogonId','ProcessId']

    hashes: Optional[Dict[str, str]] = {}
    def __init__(self) -> None:
        super().__init__()