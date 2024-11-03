import argparse
import socket
import threading
import mimetypes
import os
import shutil
import base64
import json
import uuid
import re
from datetime import datetime, timedelta


class ResponseBuilder:
    def __init__(self):
        self.headers = []
        self.status = None
        self.content = None

    def add_headers(self, Key, Value):
        self.headers.append(f"{Key}: {Value}")

    def set_status(self, statusCode, statusMessage):
        self.status = f"HTTP/1.1 {statusCode} {statusMessage}"

    def set_content(self, content):
        if isinstance(content, (bytes, bytearray)):
            self.content = content
        else:
            self.content = content.encode("utf-8")

    def build(self):
        response = self.status + "\r\n"
        for header in self.headers:
            response += header + "\r\n"
        response += "\r\n"
        print(response)
        response = response.encode("utf-8")
        if self.content is not None:
            response += self.content

        return response

    def build_chunked_body(self):
        # 构建分块编码的正文
        if self.content is None:
            return b"0\r\n\r\n"  # 没有正文时发送一个大小为0的块表示结束

        response_body = []
        offset = 0
        chunk_size = 1024  # 你可以选择一个合适的块大小

        while offset < len(self.content):
            chunk = self.content[offset:offset + chunk_size]
            offset += chunk_size
            response_body.append(f"{len(chunk):X}\r\n".encode("utf-8"))  # 块大小的十六进制值
            response_body.append(chunk)  # 块数据本身
            response_body.append(b"\r\n")  # 块结束后的CRLF

        response_body.append(b"0\r\n\r\n")  # 所有块后面的0大小块和CRLF
        return b''.join(response_body)

    def build_chunked(self):
        # 构建完整的分块传输响应
        response_headers = self.status + "\r\n"
        for header in self.headers:
            response_headers += header + "\r\n"
        response_headers += "\r\n"
        print(response_headers)
        response_headers = response_headers.encode("utf-8")
        body = self.build_chunked_body()
        return response_headers + body


class HTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        # 创建一个socket对象
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.base_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        self.current_directories = {}  # 存储每个线程当前目录的字典
        self.user = {
            'client1': '123',
            'client2': '123',
            'client3': '123'
        }
        self.current_user = {}
        self.sessions = {}
        self.need_send_cookie = False

    def start(self):
        # 绑定IP和端口
        self.socket.bind((self.host, self.port))
        # 设置监听数量，即允许同时连接的最大客户端数量
        self.socket.listen(128)
        print(f"HTTP Server running on {self.host}:{self.port}")
        while True:
            conn, addr = self.socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn,))
            client_thread.start()

    def handle_client(self, client_socket):
        keep_alive = True
        try:
            while keep_alive:
                first_headers = b""
                while True:
                    request_data = client_socket.recv(4096)
                    first_headers += request_data
                    if b'\r\n\r\n' in first_headers:
                        break

                # 分离请求头和部分请求体
                head, body = first_headers.split(b'\r\n\r\n', 1)
                head = head.decode('utf-8')
                # 解析请求行
                lines = head.split('\r\n')
                request_line = lines[0]
                method, url, http_version = request_line.split()
                # 解析请求头
                headers = {}
                for line in lines[1:]:
                    if line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                    else:
                        break

                cookie = headers.get('Cookie', '')
                session_id = self.get_valid_session_id(cookie)

                # 验证是否有cookie
                if session_id:
                    self.current_user['username'] = self.sessions.get(session_id).get('username', 'Unknown')
                elif not self.authenticate_user(headers):  # 没有cookie则正常进入验证界面
                    self.send_error401(client_socket)
                    # keep_alive = False  # 若认证失败，关闭连接
                    continue

                # 若没有cookie，则创建一个新的
                if not session_id:
                    session_id = str(uuid.uuid4())
                    expiration_time = datetime.now() + timedelta(minutes=30)
                    self.sessions[session_id] = {'username': self.current_user['username'], 'expires': expiration_time}
                    self.need_send_cookie = True
                elif session_id not in self.sessions:
                    session_id = str(uuid.uuid4())
                    expiration_time = datetime.now() + timedelta(minutes=30)
                    self.sessions[session_id] = {'username': self.current_user['username'], 'expires': expiration_time}
                    self.send_error401(client_socket, session_id)
                elif self.sessions[session_id]['expires'] < datetime.now():
                    # 若超时需要删除旧的session_id
                    del self.sessions[session_id]
                    session_id = str(uuid.uuid4())
                    expiration_time = datetime.now() + timedelta(minutes=30)
                    self.sessions[session_id] = {'username': self.current_user['username'], 'expires': expiration_time}
                    self.send_error401(client_socket, session_id)

                # 处理请求
                thread_id = threading.get_ident()  # 获取当前线程ID
                self.current_directories[thread_id] = self.base_directory
                if method == 'GET':
                    self.handle_get(client_socket, url, session_id)
                    del self.current_directories[thread_id]
                elif method == 'HEAD':
                    self.handle_head(client_socket, url, session_id)
                elif method == 'POST':
                    content_length = int(headers.get('Content-Length', 0))
                    received_length = len(body)
                    while received_length < content_length:
                        more_body = client_socket.recv(4096)
                        body += more_body
                        received_length += len(more_body)
                        if received_length == content_length:
                            break
                    filename, file_data = self.parse_multipart(body, headers)
                    self.handle_post(client_socket, url, file_data, session_id, filename)
                    # client_socket.close()
                else:
                    self.send_error405(client_socket)
                # 检查Connection头部，决定是否保持连接
                if headers.get("Connection", "keep-alive").lower() == "close":
                    keep_alive = False
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

    def should_keep_alive(self, headers):
        return headers.get("Connection", "keep-alive").lower() != "close"

    def get_valid_session_id(self, cookie_header):
        # 分割cookie字符串并提取所有session-id
        cookies = cookie_header.split('; ')
        session_ids = [cookie.split('=')[1] for cookie in cookies if cookie.startswith('session-id=')]

        # 检查每个session-id是否有效
        for session_id in session_ids:
            if session_id in self.sessions and self.sessions[session_id]['expires'] > datetime.now():
                return session_id  # 返回第一个有效的session-id

        return None  # 如果没有有效的session-id，返回None

    def authenticate_user(self, headers):
        # 获取授权头部
        auth_header = headers.get('Authorization')
        if auth_header:
            # 提取Base64编码的用户名和密码
            encoded_credentials = auth_header.split(' ')[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':')
            # 验证用户名和密码
            if username in self.user and self.user[username] == password:
                # 如果认证成功，为当前线程设置current_user
                self.current_user['username'] = username
                return True
        return False

    def translate_path(self, path):
        # 移除查询参数和片段
        path, _, _ = path.partition('?')
        path = self.custom_unquote(path)
        words = path.split('/')
        words = filter(None, words)  # 移除空字符串
        thread_id = threading.get_ident()
        current_directory = self.current_directories.get(thread_id, self.base_directory)

        # 构建基于当前目录的完整路径
        for word in words:
            if word == os.pardir:
                # 如果是上级目录，回退一级
                current_directory = os.path.dirname(current_directory)
            elif word != os.curdir:
                # 如果不是当前目录，继续前进
                current_directory = os.path.join(current_directory, word)

        current_directory = os.path.normpath(current_directory)
        self.current_directories[thread_id] = current_directory  # 更新当前目录
        return current_directory

    def handle_get(self, client_socket, url, session_id):
        relative_path = url.lstrip('/')
        if url == 'Invalid URL':
            self.send_error400(client_socket)
            return
        path, _, query = url.partition('?')
        query_dict = dict(q.split('=') for q in query.split('&') if q)

        # 使用相对路径来定位文件
        local_path = self.translate_path(relative_path)
        if not os.path.exists(local_path):
            self.send_error404(client_socket)
            return

        if os.path.isdir(local_path):
            # 处理目录
            sustech_http = query_dict.get('SUSTech-HTTP', '0')
            if sustech_http == '0':
                # 返回 HTML 格式目录列表
                content = self.generate_directory_listing(local_path, relative_path).encode('utf-8')
                mime_type = 'text/html'
            elif sustech_http == '1':
                # 返回 JSON 格式目录列表
                items = os.listdir(local_path)
                files = [item + '/' if os.path.isdir(os.path.join(local_path, item)) else item for item in items]
                content = json.dumps({'files': files}).encode('utf-8')
                mime_type = 'application/json'
            else:
                self.send_error400(client_socket)
                return
        else:
            filename = os.path.basename(local_path)
            with open(local_path, 'rb') as file:
                content = file.read()
                mime_type = mimetypes.guess_type(local_path)[0] or 'application/octet-stream'
                content_disposition = f'attachment; filename="{filename}"'

        if mime_type.startswith("text/") or mime_type == "application/json":
            content_type_header = f"{mime_type}; charset=utf-8"
        else:
            content_type_header = mime_type

        builder = ResponseBuilder()
        # chunked part
        if query_dict.get('chunked') == '1':
            builder.set_status("200", "OK")
            builder.add_headers("Content-Type", content_type_header)
            builder.add_headers("Transfer-Encoding", "chunked")
            if not os.path.isdir(local_path):
                builder.add_headers("Content-Disposition", content_disposition)
            if self.need_send_cookie:
                builder.add_headers("Set-Cookie", f"session-id={session_id}")
                self.need_send_cookie = False
            builder.set_content(content)
            response = builder.build_chunked()
            client_socket.sendall(response)

        else:
            builder.set_status("200", "OK")
            builder.add_headers("Content-Type", content_type_header)
            builder.add_headers("Content-Length", str(len(content)))
            if not os.path.isdir(local_path):
                builder.add_headers("Content-Disposition", content_disposition)
            if self.need_send_cookie:
                builder.add_headers("Set-Cookie", f"session-id={session_id}")
                self.need_send_cookie = False
            builder.set_content(content)
            response = builder.build()
            client_socket.sendall(response)
        return

    def generate_directory_listing(self, current_path, relative_path=''):
        items = os.listdir(current_path)
        list_items = ''

        # 将相对路径中的反斜杠替换为正斜杠
        relative_path = relative_path.replace('\\', '/')
        if relative_path[-16:-1] == "/?SUSTech-HTTP=" or relative_path[:-1] == "?SUSTech-HTTP=":
            relative_path = relative_path[:-16]
        if relative_path:
            # 返回根目录和上级目录的链接
            list_items += '<li><a href="/">[/]</a></li>'  # 链接到根目录
            parent_path = os.path.dirname(relative_path.rstrip('/'))
            if parent_path:
                parent_path = '/' + parent_path
            else:
                parent_path = '/'
            list_items += '<li><a href="' + parent_path.replace('\\', '/') + '">[../]</a></li>'  # 返回上级目录

        for item in items:
            item_path = os.path.join(relative_path, item).replace('\\', '/')
            display_name = item + '/' if os.path.isdir(os.path.join(current_path, item)) else item
            link = self.custom_quote(item_path)
            list_items += f'<li><a href="/{link}">{display_name}</a></li>'

        return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Directory Listing of {relative_path}</title>
            </head>
            <body>
                <h2>Current Directory: ./data/{relative_path}</h2><ul>
                <ul>{list_items}</ul>
            </body>
            </html>
        '''

    def handle_head(self, client_socket, url, session_id):
        local_path = self.translate_path(url)

        if not os.path.exists(local_path):
            self.send_error404(client_socket)
            return

        if os.path.isdir(local_path):
            # 如果是目录，我们仅发送标头，不包括内容
            mime_type = 'text/html'
        else:
            with open(local_path, 'rb') as file:
                # 如果是文件，我们获取文件大小并发送适当的头部
                file_size = os.fstat(file.fileno()).st_size
                mime_type = mimetypes.guess_type(local_path)[0] or 'application/octet-stream'

        if mime_type.startswith("text/") or mime_type == "application/json":
            content_type_header = f"{mime_type}; charset=utf-8"
        else:
            content_type_header = mime_type

        builder = ResponseBuilder()
        builder.set_status("200", "OK")
        builder.add_headers("Content-Type", content_type_header)
        if not os.path.isdir(local_path):
            builder.add_headers("Content-Length", str(file_size))
        if self.need_send_cookie:
            builder.add_headers("Set-Cookie", f"session-id={session_id}")
            self.need_send_cookie = False
        response = builder.build()
        client_socket.sendall(response)

    def handle_post(self, client_socket, url, file_data, session_id, filename):
        # 解析路径
        if 'path=' in url:
            path = url.split('path=')[1]
            # path = path.split('&')[0]
            path_segment = path.lstrip('/')
            user = path_segment.split('/')[0] if path_segment else None
            if user != self.current_user['username']:
                self.send_error403(client_socket)
                return
        else:
            self.send_error400(client_socket)
            return

        # 判断是上传请求还是删除请求
        if url.startswith('/upload?'):

            if file_data is None:
                self.send_error400(client_socket)
                return

            full_path = os.path.join(self.base_directory, path.strip('/'))
            if not os.path.exists(full_path):
                self.send_error404(client_socket)
                return
            file_path = os.path.normpath(os.path.join(full_path, filename))
            with open(file_path, 'wb') as file:
                file.write(file_data)
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            if self.need_send_cookie:
                builder.add_headers("Set-Cookie", f"session-id={session_id}")
                self.need_send_cookie = False
            response = builder.build()
            client_socket.sendall(response)
            return

        elif url.startswith('/delete?'):
            full_path = os.path.normpath(os.path.join(self.base_directory, path.strip('/')))
            if not os.path.exists(full_path):
                self.send_error404(client_socket)
                return
            if os.path.isfile(full_path):
                os.remove(full_path)
                builder = ResponseBuilder()
                builder.set_status("200", "OK")
                if self.need_send_cookie:
                    builder.add_headers("Set-Cookie", f"session-id={session_id}")
                    self.need_send_cookie = False
                response = builder.build()
                client_socket.sendall(response)

                return
            elif os.path.isdir(full_path):
                shutil.rmtree(full_path)
                os.remove(full_path)
                builder = ResponseBuilder()
                builder.set_status("200", "OK")
                if self.need_send_cookie:
                    builder.add_headers("Set-Cookie", f"session-id={session_id}")
                    self.need_send_cookie = False
                response = builder.build()
                client_socket.sendall(response)
                return
            else:
                self.send_error400(client_socket)
                return
        else:
            # 无效的URL
            self.send_error400(client_socket)
            return

    def parse_multipart(self, body, headers):
        # 提取 boundary
        content_type_header = headers.get('Content-Type', '')
        boundary_match = re.search(r'boundary=([^\s;]+)', content_type_header)
        if not boundary_match:
            return None, None
        boundary = b'--' + boundary_match.group(1).encode()

        # 分割数据
        parts = body.split(b'--' + boundary)

        # 初始化文件名和数据
        filename = None
        file_data = None

        # 遍历每一部分
        for part in parts:
            # 如果该部分包含文件内容
            if b'filename=' in part:
                # 提取文件名
                filename_match = re.search(rb'filename="([^"]+)"', part)
                if filename_match:
                    filename = filename_match.group(1).decode('utf-8')
                # 提取数据
                file_data_start = part.find(b'\r\n\r\n') + 4  # 找到文件数据开始的位置
                file_data_end = part.rfind(b'\r\n--')  # 找到文件数据结束的位置
                if file_data_start != -1 and file_data_end != -1:
                    file_data = part[file_data_start:file_data_end]
                    break

        return filename, file_data

    def custom_unquote(self, url):
        result = ""
        i = 0
        while i < len(url):
            if url[i] == '%' and i + 2 < len(url):
                hex_part = url[i + 1:i + 3]
                try:
                    byte = int(hex_part, 16)
                    next_char = url[i + 3:i + 6] if i + 5 < len(url) else None
                    if byte >= 0xC0:
                        multibyte = bytes([byte])
                        while next_char and next_char.startswith('%'):
                            multibyte += bytes([int(next_char[1:], 16)])
                            i += 3
                            next_char = url[i + 3:i + 6] if i + 5 < len(url) else None
                        result += multibyte.decode('utf-8')
                        i += 2
                    else:
                        result += chr(byte)
                        i += 2
                except ValueError:
                    result += url[i]
            else:
                result += url[i]
            i += 1
        return result

    def custom_quote(self, s):
        result = []
        for char in s:
            if char.isalnum() or char in "-_.~":
                result.append(char)
            elif char == '/':
                result.append('/')  # 直接添加斜杠，不进行编码
            else:
                bytes_char = char.encode('utf-8')
                result.extend(['%' + format(b, '02X') for b in bytes_char])
        return ''.join(result)

    # 错误处理部分
    def send_error301(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("301", "Redirect")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>301 Redirect</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error400(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("400", "Bad Request")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>400 Bad Request</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error401(self, client_socket, session_id=None):
        builder = ResponseBuilder()
        builder.set_status("401", "Unauthorized")
        builder.add_headers("WWW-Authenticate", 'Basic realm="Authorization Required')
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        if session_id is not None:
            builder.add_headers("Set-Cookie", f"session-id={session_id}")
        body = f'<html><body>401 Unauthorized</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error403(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("403", "Forbidden")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>403 Forbidden</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error404(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("404", "Not Found")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>404 Not Found</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error405(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("405", "Method Not Allowed")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>405 Method Not Allowed</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error416(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("416", "Range Not Satisfiable")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>416 Range Not Satisfiable</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error502(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("502", "Bad Gateway")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>502 Bad Gateway</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)

    def send_error503(self, client_socket):
        builder = ResponseBuilder()
        builder.set_status("503", "Service Temporarily Unavailable")
        builder.add_headers("Content-Type", "text/html; charset=utf-8")
        body = f'<html><body>503 Service Temporarily Unavailable</body><html>'
        builder.set_content(body)
        response = builder.build()
        client_socket.sendall(response)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--host', default='localhost', help='Host address, default is localhost')
    parser.add_argument('-p', '--port', type=int, default=8081, help='Port number, default is 8080')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    server = HTTPServer(args.host, args.port)
    server.start()
