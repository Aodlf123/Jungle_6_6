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
    return render_template('membership.html')

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.users.find_one({'username': username})

        if not user or not check_password_hash(user['password'], password):
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
    return render_template('main.html')

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

# 메인 페이지 라우트 (토큰 인증 필요)
@app.route('/')
def index():
    try:
        decorated_function = token_required(render_template)
        #print('token is valid')
        try:
            keyword_list = sorted(list(db.keywords.find({})), key=lambda x: x['count'], reverse=True)
            post_list = sorted(list(db.posts.find({})), key=lambda x: x['date'], reverse=True)
        
            return decorated_function('lobby.html', keywords = keyword_list, posts = post_list)
        except Exception as e:
            return jsonify({'message': 'db connection error'}), 400
    except Exception as e:  # token_required에서 발생하는 예외를 처리
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

<<<<<<< Updated upstream
=======
# 글 목록 페이지 라우트
@app.route('/posts/<int:page>')
def posts(page):
    decorated_function = token_required(render_template)
    
    try:
        first_date = datetime.datetime(2024, 6, 28, 0, 0, 0)
        if page == 0:
            last_date = first_date + datetime.timedelta(weeks=1)
        elif page ==1:
            first_date += datetime.timedelta(weeks=1)
            last_date = first_date + datetime.timedelta(weeks=3)
        elif page ==2:
            first_date += datetime.timedelta(weeks=4)
            last_date = first_date + datetime.timedelta(weeks=3)
        elif page ==3:
            first_date += datetime.timedelta(weeks=7)
            last_date = first_date + datetime.timedelta(weeks=4)
        elif page ==4:
            first_date += datetime.timedelta(weeks=11)
            last_date = first_date + datetime.timedelta(weeks=2)
        elif page ==5:
            first_date += datetime.timedelta(weeks=13)
            last_date = first_date + datetime.timedelta(weeks=5)
        else:
            first_date += datetime.timedelta(weeks=18)
            last_date = first_date + datetime.timedelta(weeks=1)

        curri_list = ['정글 입성', '컴퓨터 사고로의 전환', '탐험 준비', '정글 끝까지', '실력 다지기', '나만의 무기를 갖기', '세상으로 뛰어들기']
        keyword_list = sorted(list(db.keywords.find({'curri': page})), key=lambda x: x['count'], reverse=True)
        post_list = sorted(list(db.posts.find({'date': {'$gte': first_date, '$lte':last_date}})), key=lambda x: x['date'], reverse=True)
        
        return decorated_function('lobby.html', keywords = keyword_list, posts = post_list, categories = curri_list, selected_category = curri_list[page])
    except Exception as e:
        print(e)
        return jsonify({'message' : 'db connection error'}), 400
    
@app.route('/mypage', methods=['GET'])
def get_mypage():
    decorated_function = token_required(render_template)
    
    access_token = request.cookies.get('access_token')
    decoded = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
    author_id = decoded['user_id']
    
    try:
        post_list = sorted(list(db.posts.find({'author_id' : author_id})) , key=lambda x: x['date'], reverse=True)
        return decorated_function('my_page.html', posts = post_list)
    except Exception as e:
        print(e)
        return jsonify({'message' : 'db connection error'}), 400
    

# 글 작성 라우트
@app.route('/create_post', methods=['GET', 'POST'])
@token_required
def create_post():
    decorated_function = token_required(render_template)
    
    try:
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            access_token = request.cookies.get('access_token')
            
            decoded = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            post_data = {'title': title, 'text': content, 'author_id': decoded['user_id'], 'date' : datetime.datetime.now()}
            db.posts.insert_one(post_data)
            
            #키워드 count 처리
            field = title + content
            lowercase = field.lower()
            target_string = lowercase.strip().replace(" ", "")

            db.keywords.update_many(
                {"$expr": {"$regexMatch": {"input": target_string, "regex": "$word", "options": "i"}}},
                {"$inc": {"count": 1}}
            )

            return jsonify({'success': True})
    except Exception as e:
        print(e)
        return jsonify({'message' : 'db connection error'}, {'success': True}), 400
    return decorated_function('post_made.html')

@app.route('/post/<_id>', methods=['GET'])
@token_required
def get_post(_id):
    obj_id = ObjectId(_id)
    post = db.posts.find_one({'_id': obj_id})
    print(post)
    
    return render_template('post_in.html', title=post['title'], text=post['text'], date=post['date'])

@app.route('/comments')
@token_required
def comments():
    # 댓글 목록 조회
    referrer_url = request.referrer
    post_id = ObjectId(referrer_url.split('/')[-1])
    
    comments = sorted(list(db.comments.find({'post_id': post_id})), key=lambda x: x['date'], reverse=True)
    sorted_comments = sorted(comments, key=lambda x: x['likes'], reverse=True)
    
    return render_template('comments.html', comments=sorted_comments)    


@app.route('/get_posts', methods=['POST'])
@token_required
def get_posts():
    # 글 목록 조회
    selected_keyword = request.form['keyword']
    
    query = {
        "$or": [
            {"title": {"$regex": selected_keyword, "$options": "i"}},
            {"text": {"$regex": selected_keyword, "$options": "i"}}
        ]
    }
    
    posts = sorted(list(db.posts.find(query)), key=lambda x: x['date'], reverse=True)

    return render_template('post_list.html', posts=posts)


@app.route('/create_comment', methods=['POST'])
@token_required
def create_comment():
    try:
        content = request.form.get('content')
        referrer_url = request.referrer
        post_id = ObjectId(referrer_url.split('/')[-1])
        
        access_token = request.cookies.get('access_token')    
        decoded = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        
        comments_data = { 'user_id' : decoded['user_id'], 'content' : content, 'post_id' : post_id, 'likes' : 0, 'date' : datetime.datetime.now()}
        db.comments.insert_one(comments_data)
        
        return jsonify({'success': True})
    except Exception as e:
        print(e)
        return jsonify({'success': False})


@app.route('/like_comment', methods=['POST'])
def like_comment():
    try:
        comment_id = ObjectId(request.form['_id'])
        filter = {'_id': comment_id}
        update = {'$inc': {'likes': 1}}
        db.comments.update_one(filter, update)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})


>>>>>>> Stashed changes
if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
    
