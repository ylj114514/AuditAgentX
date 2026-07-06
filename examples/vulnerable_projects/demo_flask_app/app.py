"""故意包含漏洞的演示靶场（仅供 AuditAgentX 本地测试，切勿部署）。"""
import os
import sqlite3
import pickle

from flask import Flask, request

app = Flask(__name__)

# 硬编码密钥（Hardcoded Secret）
API_KEY = "sk-1234567890secretkey"
DB_PASSWORD = "admin123456"


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # SQL 注入：字符串拼接
    cur.execute("select * from users where id=" + uid)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # 命令注入：拼接进 os.system
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/load")
def load_data():
    blob = request.args.get("data")
    # 不安全的反序列化
    obj = pickle.loads(blob.encode())
    return str(obj)


if __name__ == "__main__":
    app.run(debug=True)
