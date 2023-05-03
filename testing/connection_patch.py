import asyncio
import time
import socket
import traceback
from threading import Thread
from typing import Tuple

from mitmproxy.proxy import commands, events, server_hooks
from mitmproxy.connection import ConnectionState
from mitmproxy.utils import asyncio_utils
from mitmproxy.utils import human
from mitmproxy.proxy.server import ConnectionHandler


class _DNSLookupError(Exception):
    pass


class _SockConnect(Thread):
    """
    Establishes a TCP connection in a separate thread
    """
    def __init__(self, connection_address: Tuple[str, int]):
        """
        :param connection_address: The target domain and target port e.g. ('thinktribe.com', 443)
        """
        super().__init__()
        self._connection_address = connection_address
        self.socket = None
        self.dns_start = None
        self.dns_end = None
        self.connect_start = None
        self.connect_end = None
        self.err = None

    def run(self):
        """
        Adaptation of socket.create_connection to capture timings
        """
        host, port = self._connection_address
        self.dns_start = time.time()
        try:
            # Separate out the lookup time.
            # If asyncio.open_connection is left to create the socket then the measured connect time
            # will include the DNS lookup time.
            lookup_results = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            if not lookup_results:
                raise _DNSLookupError("No DNS lookup results returned")
        except Exception as e:
            self.err = e
            return
        finally:
            self.dns_end = time.time()

        for af, socktype, proto, canonname, sa in lookup_results:
            self.err = None
            try:
                self.socket = socket.socket(af, socktype, proto)
                self.connect_start = time.time()
                self.socket.connect(sa)
                break
            except Exception as e:
                self.err = e
                if self.socket:
                    self.socket.close()
        if self.connect_start:
            self.connect_end = time.time()


async def open_connection(self, command: commands.OpenConnection) -> None:
    # This patch was ported from a fork that doesn't have the latest upstream changes merged in
    if not command.connection.address:
        self.log(f"Cannot open connection, no hostname given.")
        self.server_event(
            events.OpenConnectionCompleted(command, f"Cannot open connection, no hostname given."))
        return

    hook_data = server_hooks.ServerConnectionHookData(
        client=self.client,
        server=command.connection
    )
    await self.handle_hook(server_hooks.ServerConnectHook(hook_data))
    if err := command.connection.error:
        self.log(
            f"server connection to {human.format_address(command.connection.address)} "
            f"killed before connect: {err}"
        )
        self.server_event(events.OpenConnectionCompleted(command, f"Connection killed: {err}"))
        return

    async with self.max_conns[command.connection.address]:
        try:
            socket_connection = _SockConnect(command.connection.address)
            socket_connection.start()
            # There's a big time gap between setting an asyncio Event and an await resolving it, so the best
            # I could do to not bloat out the time was periodically checking whether the thread is alive.
            while socket_connection.is_alive():
                await asyncio.sleep(0.005)
            command.connection.timestamp_start = socket_connection.connect_start
            command.connection.timestamp_tcp_setup = socket_connection.connect_end
            if socket_connection.err:
                raise socket_connection.err
            # Now make the socket non-blocking so we don't decrease performance
            socket_connection.socket.setblocking(False)
            # The actual implementation will need to record two different timestamps for when the TCP connection
            # is setup and when and the SSL/TLS handshake actually begins, otherwise the SSL/TLS time can
            # be significantly inflated.
            reader, writer = await asyncio.open_connection(sock=socket_connection.socket)
        except (IOError, asyncio.CancelledError) as e:
            err = str(e)
            if not err:  # str(CancelledError()) returns empty string.
                err = "connection cancelled"
            self.log(f"error establishing server connection: {err}")
            command.connection.error = err
            self.server_event(events.OpenConnectionCompleted(command, err))
            if isinstance(e, asyncio.CancelledError):
                # From https://docs.python.org/3/library/asyncio-exceptions.html
                # #asyncio.CancelledError:
                # > In almost all situations the exception must be re-raised.
                # It is not really defined what almost means here, but we play safe.
                raise
        except Exception as e:
            self.log(f"error establishing server connection: {e}\n{traceback.format_exc()}")
            raise
        else:
            command.connection.state = ConnectionState.OPEN
            command.connection.peername = writer.get_extra_info('peername')
            command.connection.sockname = writer.get_extra_info('sockname')
            self.transports[command.connection].reader = reader
            self.transports[command.connection].writer = writer

            assert command.connection.peername
            if command.connection.address[0] != command.connection.peername[0]:
                addr = (
                    f"{human.format_address(command.connection.address)}"
                    f" ({human.format_address(command.connection.peername)})"
                )
            else:
                addr = human.format_address(command.connection.address)
            self.log(f"server connect {addr}")
            connected_hook = asyncio_utils.create_task(
                self.handle_hook(server_hooks.ServerConnectedHook(hook_data)),
                name=f"handle_hook(server_connected) {addr}",
                client=self.client.peername,
            )
            if not connected_hook:
                return  # this should not be needed, see asyncio_utils.create_task

            self.server_event(events.OpenConnectionCompleted(command, None))

            # during connection opening, this function is the designated handler
            # that can be cancelled.
            # once we have a connection, we do want the teardown here to happen in any case, so we
            # reassign the handler to .handle_connection and then clean up here once that is done.
            new_handler = asyncio_utils.create_task(
                self.handle_connection(command.connection),
                name=f"server connection handler for {addr}",
                client=self.client.peername,
            )
            if not new_handler:
                return  # this should not be needed, see asyncio_utils.create_task
            self.transports[command.connection].handler = new_handler
            await asyncio.wait([new_handler])

            self.log(f"server disconnect {addr}")
            command.connection.timestamp_end = time.time()
            await connected_hook  # wait here for this so that closed always comes after connected.
            await self.handle_hook(server_hooks.ServerDisconnectedHook(hook_data))


ConnectionHandler.open_connection = open_connection
