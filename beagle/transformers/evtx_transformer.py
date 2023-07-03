from typing import Dict, Optional, Tuple, Union

from beagle.common import logger, split_path
from beagle.constants import Protocols
from beagle.nodes import URI, Domain, File, IPAddress, Node, Process, RegistryKey, Alert
from beagle.transformers.base_transformer import Transformer


class WinEVTXTransformer(Transformer):

    name = "Win EVTX"

    def __init__(self, *args, **kwargs) -> None:

        super().__init__(*args, **kwargs)

        logger.info("Created Windows EVTX Transformer.")

    def transform(self, event: dict) -> Optional[Tuple]:

        # Track which processese we've seen
        self.seen_procs: Dict[int, Process] = {}

        event_id = int(event["eventid_qualifiers"])

        if event_id == 4688:
            return self.process_creation(event)
        elif event_id == 4656: # A handle to an object was requested
            return 
        elif event_id == 4624: # An account was successfully logged on
            return
        elif event_id == 5140: # A network share object was accessed
            return
        elif event_id == 4674: # An operation was attempted on a privileged object
            return
        elif event_id == 4657: # A registry value was modified
            return
        elif event_id == 4697: # A service was installed in the system
            return
        elif event_id == 4720: # A user account was created
            return
        elif event_id == 4726: # A user account was deleted
            return
        return None

    def process_creation(self, event: dict) -> Tuple[Process, File, Process]:
        """Transformers a process creation (event ID 4688) into a set of nodes.

        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688

        Parameters
        ----------
        event : dict
            [description]

        Returns
        -------
        Optional[Tuple[Process, File, Process, File]]
            [description]
        """

        # Get the parent PID
        parent_pid = int(event["data_name_processid"], 16)

        # Child PID
        child_pid = int(event["data_name_newprocessid"], 16)

        proc_name, proc_path = split_path(event["data_name_newprocessname"])

        child = Process(
            host=event["computer"],
            process_id=child_pid,
            user=event["data_name_subjectusername"],
            process_image=proc_name,
            process_image_path=proc_path,
            command_line=event.get("data_name_commandline"),
        )

        child_file = child.get_file_node()
        child_file.file_of[child]

        # Map the process for later
        self.seen_procs[child_pid] = child

        parent = self.seen_procs.get(parent_pid)

        if parent is None:
            # Create a dummy proc. If we haven't already seen the parent
            parent = Process(host=event["computer"], process_id=parent_pid)

        parent.launched[child].append(timestamp=event["timecreated_systemtime"])

        # Don't need to pull out the parent's file, as it will have always
        # been created before being put into seen_procs

        return (child, child_file, parent)

    def network_connection(
        self, event: dict
    ) -> Union[Tuple[Process, File, IPAddress], Tuple[Process, File, IPAddress, Domain]]:
        process_image, process_path = split_path(event["EventData_Image"])

        proc = Process(
            host=event["Computer"],
            user=event["EventData_User"],
            process_guid=event["EventData_ProcessGuid"],
            process_id=int(event["EventData_ProcessId"]),
            process_image=process_image,
            process_image_path=process_path,
        )
        proc_file = proc.get_file_node()
        proc_file.file_of[proc]

        dest_addr = IPAddress(ip_address=event["EventData_DestinationIp"])

        proc.connected_to[dest_addr].append(
            timestamp=event["EventData_UtcTime"],
            port=event["EventData_DestinationPort"],
            protocol=event["EventData_Protocol"],
        )

        if event.get("EventData_DestinationHostname"):
            hostname = Domain(event["EventData_DestinationHostname"])
            hostname.resolves_to[dest_addr].append(timestamp=event["EventData_UtcTime"])
            return (proc, proc_file, dest_addr, hostname)

        return (proc, proc_file, dest_addr)
    def registry_creation(self, event: dict) -> Optional[Tuple[Process, File, RegistryKey]]:
        '''
            - <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            - <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
            <EventID>4657</EventID> 
            <Version>0</Version> 
            <Level>0</Level> 
            <Task>12801</Task> 
            <Opcode>0</Opcode> 
            <Keywords>0x8020000000000000</Keywords> 
            <TimeCreated SystemTime="2015-09-24T01:28:43.639634100Z" /> 
            <EventRecordID>744725</EventRecordID> 
            <Correlation /> 
            <Execution ProcessID="4" ThreadID="4824" /> 
            <Channel>Security</Channel> 
            <Computer>DC01.contoso.local</Computer> 
            <Security /> 
            </System>
            - <EventData>
            <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
            <Data Name="SubjectUserName">dadmin</Data> 
            <Data Name="SubjectDomainName">CONTOSO</Data> 
            <Data Name="SubjectLogonId">0x364eb</Data> 
            <Data Name="ObjectName">\\REGISTRY\\MACHINE</Data> 
            <Data Name="ObjectValueName">Name\_New</Data> 
            <Data Name="HandleId">0x54</Data> 
            <Data Name="OperationType">%%1905</Data> 
            <Data Name="OldValueType">%%1873</Data> 
            <Data Name="OldValue" /> 
            <Data Name="NewValueType">%%1873</Data> 
            <Data Name="NewValue">Andrei</Data> 
            <Data Name="ProcessId">0xce4</Data> 
            <Data Name="ProcessName">C:\\Windows\\regedit.exe</Data> 
            </EventData>
            </Event>
        '''
        process_image, process_path = split_path(event["EventData_Image"])

        proc = Process(
            host=event["Computer"],
            user=event.get("EventData_User"),
            process_guid=event["EventData_ProcessGuid"],
            process_id=int(event["EventData_ProcessId"]),
            process_image=process_image,
            process_image_path=process_path,
        )
        proc_file = proc.get_file_node()
        proc_file.file_of[proc]

        key_path = event["EventData_TargetObject"]
        hive = key_path.split("\\")[1]
        key = key_path.split("\\")[-1]
        # Always has a leading \\ so split from 2:
        key_path = "\\".join(key_path.split("\\")[2:-1])

        key = RegistryKey(
            hive=hive,
            key=key,
            key_path=key_path,
            value=event.get("EventData_Details"),
            value_type="DWORD",
        )

        event_type = event["EventData_EventType"]
        if event_type == "SetValue":
            proc.changed_value[key].append(
                value=event.get("EventData_Details"), timestamp=event["EventData_UtcTime"]
            )
        elif event_type == "DeleteValue":
            proc.deleted_value[key].append(timestamp=event["EventData_UtcTime"])
        elif event_type == "CreateKey":
            proc.created_key[key].append(timestamp=event["EventData_UtcTime"])
        elif event_type == "DeleteKey":
            proc.deleted_key[key].append(timestamp=event["EventData_UtcTime"])

        return (proc, proc_file, key)
    def service_installed(self,event:dict):
        '''
            - <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            - <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
            <EventID>4697</EventID> 
            <Version>0</Version> 
            <Level>0</Level> 
            <Task>12289</Task> 
            <Opcode>0</Opcode> 
            <Keywords>0x8020000000000000</Keywords> 
            <TimeCreated SystemTime="2015-11-12T01:36:11.991070500Z" /> 
            <EventRecordID>2778</EventRecordID> 
            <Correlation ActivityID="{913FBE70-1CE6-0000-67BF-3F91E61CD101}" /> 
            <Execution ProcessID="736" ThreadID="2800" /> 
            <Channel>Security</Channel> 
            <Computer>WIN-GG82ULGC9GO.contoso.local</Computer> 
            <Security /> 
            </System>
            - <EventData>
            <Data Name="SubjectUserSid">S-1-5-18</Data> 
            <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data> 
            <Data Name="SubjectDomainName">CONTOSO</Data> 
            <Data Name="SubjectLogonId">0x3e7</Data> 
            <Data Name="ServiceName">AppHostSvc</Data> 
            <Data Name="ServiceFileName">%windir%\\system32\\svchost.exe -k apphost</Data> 
            <Data Name="ServiceType">0x20</Data> 
            <Data Name="ServiceStartType">2</Data> 
            <Data Name="ServiceAccount">localSystem</Data> 
            </EventData>
            </Event>
        '''