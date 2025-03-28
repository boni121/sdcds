from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
import re
import sqlite3
import os
import uuid
import time
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Important for sessions
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'apk'}
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/statistic.html')
def statistic():
    return render_template('statistic.html')


@app.route('/account-operations.html')
def account_operations():
    return render_template('account-operations.html')


@app.route('/deals.html')
def deals():
    return render_template('deals.html')


@app.route('/requisites.html')
def requisites():
    return render_template('requisites.html')


@app.route('/settings.html')
def settings():
    return render_template('settings.html')

@app.route('/devices.html')
def devices_page():
    return render_template('devices.html')

@app.route('/admin')
def admin_panel():
    return render_template('adminPanel.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Функция для валидации данных и UUID
def validate_input(data, fields):
    """Проверяет, что в data есть все нужные поля."""
    if not all(field in data for field in fields):
        return False

    # Проверка, что user_id - это валидный UUID
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
    if 'user_id' in data and not uuid_pattern.match(data['user_id']):
        return False

    return True


def fetch_data_from_table(table, user_id):
    try:
        # Подключаемся к базе данных
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Делаем запрос по user_id
        query = f"SELECT * FROM {table} WHERE user_id = ?"
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()  # Мы получаем только одну строку

        if row:  # Если строка найдена
            # Получаем названия всех столбцов для удобства
            columns = [description[0] for description in cursor.description]
            # Преобразуем данные в удобный формат — словарь
            result = dict(zip(columns, row))
        else:
            result = None  # Если строка не найдена

    except sqlite3.Error as e:
        print(f"Ошибка: {e}")
        return None

    finally:
        conn.close()

    return result

@app.route(f"/view_data", methods=['POST'])
def view_data():
    data = request.json
    user_id = data.get('user_id')  # Получаем user_id из запроса
    table_name = data.get('table_name')  # Получаем название таблицы

    # Получаем данные из базы по user_id
    data_from_bd = fetch_data_from_table(table_name, user_id)

    if data_from_bd:
        print(data_from_bd)
    else:
        print("Данные не найдены или произошла ошибка.")

    return jsonify(data_from_bd), 200


# Шаблоны функций для работы с данными

def add_variable(variable_name, user_id, new_value):
    return jsonify({"message": f"Variable '{variable_name}' added for user {user_id}"}), 201


def edit_variable(variable_name, user_id, new_value):
    return jsonify({"message": f"Variable '{variable_name}' updated for user {user_id}"}), 200


def delete_variable(variable_name, user_id):
    return jsonify({"message": f"Variable '{variable_name}' deleted for user {user_id}"}), 200


# Генерация роутов для всех операций и таблиц
TABLES = ['statistics', 'operations', 'withdrawals', 'deals', 'requisites']

# Функция для создания маршрутов с сохранением таблицы

def create_add_route(table):
    @app.route(f"/add/{table}", methods=['POST'], endpoint=f"add_to_{table}")
    def add_to_table():
        data = request.json

        if not validate_input(data, ['variable_name', 'user_id', 'value']):
            return jsonify({"error": "Missing or invalid fields"}), 400

        variable_name = data['variable_name']
        user_id = data['user_id']
        value = data['value']

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            # Проверяем, существует ли уже такая строка по user_id
            cursor.execute(f"SELECT 1 FROM {table} WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

            if row:
                # Если строка есть — обновляем данные в указанном столбце
                query = f"UPDATE {table} SET {variable_name} = ? WHERE user_id = ?"
                cursor.execute(query, (value, user_id))
            else:
                # Если строки нет — создаём новую с user_id и нужным столбцом
                query = f"INSERT INTO {table} (user_id, {variable_name}) VALUES (?, ?)"
                cursor.execute(query, (user_id, value))

            conn.commit()

        except sqlite3.Error as e:
            return jsonify({"error": str(e)}), 500

        finally:
            conn.close()

        return jsonify({'status': f'Data added/updated in {table}', 'data': data}), 200


def create_delete_route(table):
    @app.route(f"/delete/{table}", methods=['POST'], endpoint=f"delete_to_{table}")
    def delete_from_table():
        data = request.json

        # Проверяем входные данные
        if not validate_input(data, ['variable_name', 'user_id']):
            return jsonify({"error": "Missing or invalid fields"}), 400

        variable_name = data['variable_name']
        user_id = data['user_id']

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            # Проверяем, существует ли такая строка с user_id
            cursor.execute(f"SELECT {variable_name} FROM {table} WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

            if row is None:
                return jsonify({"error": "User not found"}), 404

            # Если значение уже NULL — возвращаем сообщение
            if row[0] is None:
                return jsonify({"status": "Value is already NULL"}), 200

            # Обнуляем значение в указанном столбце
            query = f"UPDATE {table} SET {variable_name} = NULL WHERE user_id = ?"
            cursor.execute(query, (user_id,))
            conn.commit()

        except sqlite3.Error as e:
            return jsonify({"error": str(e)}), 500

        finally:
            conn.close()

        return jsonify({'status': f'Data deleted in {table}', 'data': data}), 200


# Генерируем маршруты для каждой таблицы
for table in TABLES:
    create_add_route(table)
    create_delete_route(table)

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        cursor.execute("SELECT id, password FROM users WHERE login = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return jsonify({'success': True, 'message': 'Вход выполнен успешно'})

        return jsonify({'success': False, 'message': 'Неверное имя пользователя или пароль'}), 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success': False, 'message': 'Требуется указать имя пользователя и пароль'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT 1 FROM users WHERE login = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Имя пользователя уже существует'}), 400

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert the new user
        cursor.execute("INSERT INTO users (login, password) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Регистрация выполнена успешно'})

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# APK File Management
@app.route('/upload_apk/<device_id>', methods=['POST'])
def upload_apk(device_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Use device_id as part of the filename to make it unique
        saved_filename = f"{device_id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(file_path)

        # Store the file info in database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if device exists
        cursor.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Device not found'}), 404

        # Update device with APK file info
        cursor.execute("UPDATE devices SET apk_filename = ? WHERE id = ?",
                      (saved_filename, device_id))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'filename': saved_filename
        })

    return jsonify({'success': False, 'message': 'File type not allowed'}), 400

@app.route('/download_apk/<device_id>', methods=['GET'])
def download_apk(device_id):
    # Get the filename from the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT apk_filename FROM devices WHERE id = ?", (device_id,))
    result = cursor.fetchone()
    conn.close()

    if not result or not result[0]:
        return jsonify({'success': False, 'message': 'No APK file found for this device'}), 404

    filename = result[0]
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Device Management
@app.route('/devices', methods=['GET'])
def get_devices():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, last_online FROM devices")
    devices = cursor.fetchall()
    conn.close()

    device_list = []
    for device in devices:
        device_list.append({
            'id': device[0],
            'name': device[1],
            'last_online': device[2]
        })

    return jsonify({'success': True, 'devices': device_list})

@app.route('/devices', methods=['POST'])
def add_device():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    data = request.json
    name = data.get('name')

    if not name:
        return jsonify({'success': False, 'message': 'Device name is required'}), 400

    device_id = str(uuid.uuid4())

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("INSERT INTO devices (id, name) VALUES (?, ?)",
                  (device_id, name))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Device added successfully',
        'device_id': device_id
    })

# Invitation Token System
@app.route('/generate_token', methods=['POST'])
def generate_token():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    data = request.json
    max_uses = data.get('max_uses', 1)
    expiry_days = data.get('expiry_days', 7)

    # Generate a random token
    token = str(uuid.uuid4())
    user_id = session['user_id']
    expires_at = datetime.now() + timedelta(days=expiry_days)

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO invitation_tokens (token, user_id, max_uses, uses, expires_at) VALUES (?, ?, ?, ?, ?)",
        (token, user_id, max_uses, 0, expires_at.strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Token generated successfully',
        'token': token,
        'invite_link': f"{request.host_url}invite/{token}"
    })

@app.route('/invite/<token>')
def use_invite(token):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, user_id, max_uses, uses, expires_at FROM invitation_tokens WHERE token = ?",
        (token,)
    )
    token_data = cursor.fetchone()

    if not token_data:
        conn.close()
        flash('Invalid invitation token', 'error')
        return redirect(url_for('login'))

    token_id, user_id, max_uses, uses, expires_at = token_data

    # Check if token is expired
    if datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S') < datetime.now():
        conn.close()
        flash('Invitation token has expired', 'error')
        return redirect(url_for('login'))

    # Check if token has reached max uses
    if uses >= max_uses:
        conn.close()
        flash('Invitation token has reached maximum uses', 'error')
        return redirect(url_for('login'))

    # Update token uses
    cursor.execute(
        "UPDATE invitation_tokens SET uses = uses + 1 WHERE id = ?",
        (token_id,)
    )
    conn.commit()

    # Set the user session to auto-login
    session['user_id'] = user_id

    conn.close()
    flash('Successfully logged in with invitation token', 'success')
    return redirect(url_for('home'))

# Create necessary tables if they don't exist
def initialize_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create devices table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        apk_filename TEXT,
        last_online TIMESTAMP
    )
    ''')

    # Create invitation_tokens table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS invitation_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        max_uses INTEGER NOT NULL DEFAULT 1,
        uses INTEGER NOT NULL DEFAULT 0,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    conn.commit()
    conn.close()

# Initialize database when the app starts
initialize_database()

@app.route('/tokens.html')
def tokens_page():
    return render_template('tokens.html')

@app.route('/tokens')
def get_tokens():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, token, user_id, max_uses, uses, expires_at FROM invitation_tokens WHERE user_id = ?",
        (user_id,)
    )
    tokens_data = cursor.fetchall()
    conn.close()

    tokens = []
    for token in tokens_data:
        tokens.append({
            'id': token[0],
            'token': token[1],
            'user_id': token[2],
            'max_uses': token[3],
            'uses': token[4],
            'expires_at': token[5]
        })

    return jsonify({'success': True, 'tokens': tokens})

@app.route('/tokens/<int:token_id>', methods=['DELETE'])
def delete_token(token_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if token exists and belongs to user
    cursor.execute(
        "SELECT 1 FROM invitation_tokens WHERE id = ? AND user_id = ?",
        (token_id, user_id)
    )
    if not cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Token not found or not authorized'}), 404

    # Delete the token
    cursor.execute("DELETE FROM invitation_tokens WHERE id = ?", (token_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Token deleted successfully'})

# Initialize database when the app starts
initialize_database()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
