from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user_info():
    # [!] 명확한 Source (오염원) 발생: 외부의 HTTP 요청 파라미터에서 값을 가져옴
    username = request.args.get('username') 
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # [!] 취약한 흐름: 오염된 값이 필터링 없이 쿼리 문자열에 포맷팅됨
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    # [!] Sink (위험한 목적지) 도착: 취약점 성립
    cursor.execute(query) 
    
    return str(cursor.fetchall())