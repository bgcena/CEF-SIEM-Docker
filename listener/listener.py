"""Test listener (Machine 2 in the guide): prints every TCP/UDP line it receives."""
import os
import socketserver
import sys
import threading

PORT = int(os.environ.get("LISTEN_PORT", "8080"))


def emit(peer, data):
    sys.stdout.write("[{}] {}\n".format(peer, data.decode("utf-8", "replace").rstrip()))
    sys.stdout.flush()


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            emit("tcp " + self.client_address[0], line)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        emit("udp " + self.client_address[0], self.request[0])


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    udp = socketserver.UDPServer(("0.0.0.0", PORT), UDPHandler)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    print("Listening on tcp/udp {}".format(PORT), flush=True)
    ThreadedTCP(("0.0.0.0", PORT), TCPHandler).serve_forever()
