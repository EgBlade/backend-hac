from flask import Flask, request, jsonify
import psycopg2
from passlib.hash import pbkdf2_sha256
import jwt
from datetime import datetime, timedelta
import secrets
import hashlib

app = Flask(__name__)
# Секретный ключ для токенов JWT
app.config['ACCESS_TOKEN_SECRET'] = 'your_access_token_secret_key'
app.config['REFRESH_TOKEN_SECRET'] = 'your_refresh_token_secret_key'
# подключение к базе данных PostgreSQL
conn = psycopg2.connect(database="postgres", user="postgres",
                        password="warta3514", host="localhost", port="5432")
            
# Создаем таблицу пользователей в базе данных
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        bio TEXT
    )
""")

# Создаем таблицу команд в базе данных
cur.execute("""
    CREATE TABLE IF NOT EXISTS teams (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        owner_id INTEGER REFERENCES users(id)
    )
""")


# Создать таблицу команд в базе данных
cur.execute('''
    CREATE TABLE IF NOT EXISTS teams (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW()
    )
''')
#таблица токенов
cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id SERIAL PRIMARY KEY,
        refresh_token TEXT UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
""")
conn.commit()
cur.close()

# API регистрации пользователей
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

   # Проверить, зарегистрирована ли уже электронная почта
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (data['email'],))
    user = cur.fetchone()
    cur.close()
    if user:
        return jsonify({'message': 'Электронная почта уже зарегистрирована'}), 400

    # Зашифровать пароль с помощью PBKDF2
    hashed_password = pbkdf2_sha256.hash(data['password'])

    # Добавляем пользователя в базу
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (data['email'], hashed_password))
    conn.commit()
    cur.close()
     # генерация токенов обновления и доступа
    access_token = generate_access_token(data['email'])
    refresh_token = generate_refresh_token(data['email'])
    user_id = get_user_id(data['email'])
    store_refresh_token(refresh_token, user_id)
    return jsonify({'message': 'Пользователь успешно зарегистрирован', 'access_token': access_token, 'refresh_token': refresh_token}), 201

# API входа пользователя
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Проверяем, существует ли электронная почта в базе данных
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (data['email'],))
    user = cur.fetchone()
    cur.close()
    if not user:
        return jsonify({'message': 'Электронная почта не зарегистрирована'}), 400

   # Проверяем правильность пароля
    if not pbkdf2_sha256.verify(data['password'], user[2]):
        return jsonify({'message': 'пароль неверный'}), 401

    # генерация   токенов обновления и доступа
    access_token = generate_access_token(data['email'])
    refresh_token = generate_refresh_token(data['email'])
    user_id = get_user_id(data['email'])
    update_refresh_token(refresh_token, user_id)

    return jsonify({'message': 'Успешный вход', 'access_token': access_token, 'refresh_token': refresh_token}), 200


# API обновления профиля пользователя
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.get_json()

    # Проверяем, существует ли пользователь в базе данных
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        return jsonify({'message': 'Пользователь не найден'}), 404

    # Обновить профиль пользователя в базе
    cur.execute("UPDATE users SET name=%s, bio=%s WHERE id=%s", (data['name'], data['bio'], user_id))
    conn.commit()
    cur.close()
    # генерация   токенов обновления и доступа
    access_token = generate_access_token(data['email'])
    refresh_token = generate_refresh_token(data['email'])
    user_id = get_user_id(data['email'])
    update_refresh_token(refresh_token, user_id)

    return jsonify({'message': 'Успешный обновление', 'access_token': access_token, 'refresh_token': refresh_token}), 200
# Создать командный API В ПРОЦЕССЕ
'''@app.route('/teams', methods=['POST'])
def create_team():
    data = request.get_json()

    #Проверьте, существует ли аутентифицированный пользователь
    # TODO: Реализовать аутентификацию и авторизацию JWT
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (1,))  # Replace 1 
    user = cur.fetchone()
    if not user:
        cur.close()
        return jsonify({'message': 'User not found'}), 404
    # Добавляем команду в базу
    cur.execute("INSERT INTO teams (name, description, owner_id) VALUES (%s, %s, %s) RETURNING id", (data['name'], data['description'], user[0]))
    team_id = cur
'''
# API обновы токена
@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.get_json()['refresh_token']
    user_id = get_user_id_by_refresh_token(refresh_token)
    if not user_id:
        return jsonify({'message': 'ошибка обновления токена'}), 401
    access_token = generate_access_token(get_user_email(user_id))
    return jsonify({'access_token': access_token}), 200

# генерация токена функции токена доступа
def generate_access_token(email):
    # Генерируем время истечения срока действия токена
    expire = datetime.utcnow() + timedelta(minutes=30)
    payload = {'email': email, 'exp': expire}
    # генерация токена через секретный токен
    token = jwt.encode(payload, app.config['ACCESS_TOKEN_SECRET'], algorithm='HS256')
    return token

# генерация функции токена обновления
def generate_refresh_token(email):
    # время
    expire = datetime.utcnow() + timedelta(days=30)
    # случайная строка
    token = secrets.token_hex(32)
    payload = {'email': email, 'exp': expire}
    # хеш через SHA256
    hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
    # добовляем  в базу 
    cur = conn.cursor()
    cur.execute("INSERT INTO tokens (refresh_token, user_id) VALUES (%s, %s)", (hashed_token, get_user_id(email)))
    conn.commit()
    cur.close()
    return token

# получение id по EMAIL
def get_user_id(email):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    user_id = cur.fetchone()[0]
    cur.close()
    return user_id

# получение email по id
def get_user_email(user_id):
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id=%s", (user_id,))
    email = cur.fetchone()[0]
    cur.close()
    return email

# сохранение токена обновления в базу
def store_refresh_token(token, user_id):
    hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
    cur = conn.cursor()
    cur.execute("INSERT INTO tokens (refresh_token, user_id) VALUES (%s, %s)", (hashed_token, user_id))
    conn.commit()
    cur.close()

# обновление токена  обновления
def update_refresh_token(token, user_id):
    # Hash the token using SHA256
    hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
    # Update the refresh token in the tokens table in the database
    cur = conn.cursor()
    cur.execute("UPDATE tokens SET refresh_token=%s, created_at=NOW() WHERE user_id=%s", (hashed_token, user_id))
    conn.commit()
    cur.close()

# получение id по токену обноления
def get_user_id_by_refresh_token(token):
    hashed_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM tokens WHERE refresh_token=%s", (hashed_token,))
    user_id = cur.fetchone()
    cur.close()
    if not user_id:
        return None
   



if __name__ == '__main__':
    app.run(debug=True)
