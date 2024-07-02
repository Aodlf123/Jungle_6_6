import datetime
from functools import wraps

import jwt
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

client = MongoClient('mongodb://test:test@54.221.181.58',27017)
db = client.admin

# JWT 설정
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=15)  # Access Token 만료 시간 (15분)
app.config['REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)  # Refresh Token 만료 시간 (30일)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        refresh_token = request.cookies.get('refresh_token')

        if not access_token or not refresh_token:
            return redirect(url_for('login'))

        try:
            jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            # Access Token 만료 시 Refresh Token 사용하여 갱신
            try:
                decoded = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
                new_access_token = jwt.encode(
                    {'user_id': decoded['user_id'], 'exp': datetime.datetime.utcnow() + app.config['ACCESS_TOKEN_EXPIRES']},
                    app.config['SECRET_KEY'], algorithm="HS256")
                resp = make_response(f(*args, **kwargs))
                resp.set_cookie('access_token', new_access_token, httponly=True)
                return resp
            except jwt.ExpiredSignatureError:
                return redirect(url_for('login'))  # Refresh Token도 만료된 경우

        return f(*args, **kwargs)  # Access Token이 유효한 경우
    return decorated

# 회원가입 라우트
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if db.users.find_one({'username': username}):
            return jsonify({'message': 'Username already exists'}), 400

        hashed_password = generate_password_hash(password)
        user_data = {'username': username, 'password': hashed_password}
        db.users.insert_one(user_data)
        return jsonify({'message': 'User created successfully'}), 201
    return render_template('signup.html')

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.users.find_one({'username': username})
        print(username)
        print(list(db.users.find()))
        if not user:    # or not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid credentials'}), 401

        access_token = jwt.encode(
            {'user_id': username, 'exp': datetime.datetime.utcnow() + app.config['ACCESS_TOKEN_EXPIRES']},
            app.config['SECRET_KEY'], algorithm="HS256")
        refresh_token = jwt.encode(
            {'user_id': username, 'exp': datetime.datetime.utcnow() + app.config['REFRESH_TOKEN_EXPIRES']},
            app.config['SECRET_KEY'], algorithm="HS256")

        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('access_token', access_token, httponly=True)
        resp.set_cookie('refresh_token', refresh_token, httponly=True)
        return resp
    return render_template('login.html')

# Access Token 갱신 라우트
@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 401

    try:
        decoded = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        access_token = jwt.encode(
            {'user_id': decoded['user_id'], 'exp': datetime.datetime.utcnow() + app.config['ACCESS_TOKEN_EXPIRES']},
            app.config['SECRET_KEY'], algorithm="HS256")
        resp = jsonify({'access_token': access_token})
        resp.set_cookie('access_token', access_token, httponly=True)
        return resp
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired'}), 401
    except jwt.InvalidTokenError:
        # 토큰이 유효하지 않은 경우 처리
        return jsonify({'message': 'Invalid token Error'}), 401

# 로그아웃 라우트
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('access_token')
    resp.delete_cookie('refresh_token')
    return resp

# 메인 페이지 라우트 (로그인 필요)
@app.route('/')
def index():
    try:
        decorated_function = token_required(render_template)
        print('token is valid')
        return decorated_function('index.html')
    except Exception as e:  # token_required에서 발생하는 예외를 처리
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

if __name__ == '__main__':
    app.run('127.0.0.1', port=5000, debug=True)