from flask import Flask, request, jsonify
import psycopg2
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)

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
conn.commit()
cur.close()
# Создаем таблицу команд в базе данных
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS teams (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        owner_id INTEGER REFERENCES users(id)
    )
""")
conn.commit()
cur.close()

# Создать таблицу team_members в базе данных
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS team_members (
        id SERIAL PRIMARY KEY,
        team_id INTEGER REFERENCES teams(id),
        user_id INTEGER REFERENCES users(id)
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

    return jsonify({'message': 'Пользователь успешно зарегистрирован'}), 201

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
    if pbkdf2_sha256.verify(data['password'], user[2]):
        # TODO: Создайте токен JWT и верните его
        return jsonify({'message': 'Вы успешно вошли в систему'})
    else:
        return jsonify({'message': 'Неверный пароль'}), 400

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

    # Проверяем, является ли аутентифицированный пользователь владельцем профиля
    # TODO: Реализовать аутентификацию и авторизацию JWT
    if user_id != 1:  # Replace 1
        cur.close()
        return jsonify({'message': 'У вас нет прав для обновления этого профиля пользователя'}), 403

    # Обновить профиль пользователя в базе
    cur.execute("UPDATE users SET name=%s, bio=%s WHERE id=%s", (data['name'], data['bio'], user_id))
    conn.commit()
    cur.close()

    return jsonify({'message': 'Профиль пользователя успешно обновлен'})
# Создать командный API
@app.route('/teams', methods=['POST'])
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





if __name__ == '__main__':
    app.run(debug=True)
