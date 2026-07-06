"""安全的「模拟」SQL 注入靶场 —— 仅用于演示 AuditAgentX 动态验证引擎。

它并不真正执行 SQL 或系统命令，而是当检测到注入特征时**返回模拟的漏洞响应**，
因此可以在任意环境安全运行，用来验证动态验证器的发包/判定/取证链路。
真正的动态利用应在隔离沙箱中针对真实靶场进行。
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静默
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        val = (qs.get("id", [""])[0])

        body = "<html><body>user list</body></html>"
        # 模拟 error-based SQLi：注入单引号时“泄露”数据库报错
        if "'" in val:
            body = ("You have an error in your SQL syntax near '"
                    + val + "'. admin@example.com")
        # 模拟布尔盲注：OR '1'='1 时返回更多“数据行”
        elif "or 1=1" in val.lower():
            body = "<html><body>" + "row " * 200 + "</body></html>"

        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
