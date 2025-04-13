# server.py

import socket
import ssl
import threading
from protocol import parse_request, build_response
import http.client

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    try:
        data = conn.recv(4096)
        req_type, req_data = parse_request(data)

        if req_type == "DNS":
            try:
                ip = socket.gethostbyname(req_data.strip())
                response = build_response(True, f"IP Address: {ip}")
            except socket.gaierror:
                response = build_response(False, "DNS Resolution Failed.")
            conn.sendall(response)

        elif req_type == "HTTP":
            url = req_data.strip()
            if not url.startswith("http"):
                url = "http://" + url

            try:
                if url.startswith("https://"):
                    conn_obj = http.client.HTTPSConnection(url.split("://")[1], timeout=5, context=ssl._create_unverified_context())
                else:
                    conn_obj = http.client.HTTPConnection(url.split("://")[1], timeout=5)
                
                conn_obj.request("GET", "/")
                res = conn_obj.getresponse()
                headers = "\n".join(f"{k}: {v}" for k, v in res.getheaders())
                status = f"Status: {res.status}"
                conn_obj.close()
                result = f"{status}\n\nHeaders:\n{headers}"
                response = build_response(True, result)
            except Exception as e:
                response = build_response(False, f"HTTP Request Failed: {str(e)}")

            conn.sendall(response)

    except Exception as e:
        conn.sendall(build_response(False, f"Server Error: {str(e)}"))
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")

def start_server(host="127.0.0.1", port=5050):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[🌐] Server started on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
