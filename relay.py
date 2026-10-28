"""Bridge loopback -> private Unix socket; no credentials or listening TCP port."""
import os
import selectors
import socket
import socketserver
import threading

PATH = '/mail/imap.sock'
slots = threading.BoundedSemaphore(8)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if not slots.acquire(blocking=False):
            return
        try:
            with socket.create_connection(('127.0.0.1', 1143), timeout=15) as upstream:
                upstream.settimeout(30)
                with selectors.DefaultSelector() as select:
                    select.register(self.request, selectors.EVENT_READ, upstream)
                    select.register(upstream, selectors.EVENT_READ, self.request)
                    while True:
                        events = select.select(timeout=300)
                        if not events:
                            return
                        for key, _ in events:
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.sendall(data)
        finally:
            slots.release()


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        print('Bridge socket connection closed', flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    if os.path.exists(PATH):
        os.unlink(PATH)
    with Server(PATH, Handler) as server:
        print('Private Bridge socket ready', flush=True)
        server.serve_forever()
