import MySQLdb
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from functools import wraps
import logging
from datetime import datetime, timedelta

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
# 🔹 Configurare cheie secretă
app.config['SECRET_KEY'] = ''

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})


#  Configurare MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = ''

mysql = MySQL(app)
bcrypt = Bcrypt(app)  # Pentru hash-ul parolelor

# Configurare Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"  # Redirecționare pentru utilizatorii neautentificați


#  Definire clasa User compatibila cu Flask-Login
class User(UserMixin):
    def __init__(self, id, name, role=None,):
        self.id = id
        self.name = name
        self.role = role # Atributul pentru rol


    @staticmethod
    def get(user_id):
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, full_name, role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if user:
            return User(user[0], user[1], user[2])  #  Acum role este setat
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Ruta Home
@app.route('/')
def home():
    return render_template('index.html')


# Ruta pentru verificare sesiune
@app.route('/check_session', methods=['GET'])
def check_session():
    print("Current user:", current_user) # Debugging

    if current_user.is_authenticated:
        print(f"User {current_user.id} - {current_user.role} -{current_user.name} is logged in")  # Debugging
        return jsonify({'success': True,
                        'user': {'id': current_user.id, 'name': current_user.name, 'role': current_user.role}}), 200

    print("User not logged in")  # Debugging
    return jsonify({'success': False, 'message': 'User not logged in'}), 401


# Ruta pentru înregistrare
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')
    gender = data.get('gender')

    if not full_name or not email or not password:
        return jsonify({'message': 'All fields are required!'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        cur = mysql.connection.cursor()


        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            return jsonify({'message': 'Email already registered!'}), 400

        #  Dacă nu exista, insereaza
        cur.execute("INSERT INTO users (full_name, email, password, gender) VALUES (%s, %s, %s, %s)",
                    (full_name, email, hashed_password, gender))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Registration successful!'}), 200

    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Controleaza daca exista deja mail-ul
@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.json
    email = data.get('email')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if user:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required!'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, full_name, password, role, created_at FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if user and bcrypt.check_password_hash(user[2], password):
        user_obj = User(user[0], user[1], user[3])
        login_user(user_obj, remember=False)

        # Verificam dacă utilizatorul este „nou”
        created_at = user[4]
        is_new_user = False
        if created_at:
            time_diff = datetime.now() - created_at
            if time_diff < timedelta(minutes=1):
                is_new_user = True

        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'role': user[3],
            'is_new_user': is_new_user
        }), 200

    return jsonify({'success': False, 'message': 'Invalid email or password'}), 401



# Ruta protejată pentru pagina Beginner
@app.route('/beginner')
@login_required
def beginner():
    return render_template("beginner.html", user_name=current_user.name)

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return redirect("http://127.0.0.1:5500/dashboard.html")


@app.route('/get_user_info', methods=['GET'])
@login_required
def get_user_info():
    cur = mysql.connection.cursor()
    cur.execute("SELECT full_name, email, gender FROM users WHERE id = %s", (current_user.id,))
    user = cur.fetchone()
    cur.close()

    if user:
        return jsonify({'success': True, 'full_name': user[0], 'email': user[1], 'gender': user[2]}), 200
    else:
        return jsonify({'success': False, 'message': 'User not found'}), 404


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'All fields are required!'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT password FROM users WHERE id = %s", (current_user.id,))
    user = cur.fetchone()

    if not user or not bcrypt.check_password_hash(user[0], current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (new_password_hash, current_user.id))
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True, 'message': 'Password changed successfully'}), 200


@app.route('/update_stats', methods=['POST'])
@login_required
def save_stats():
    data = request.json
    weight = data.get('weight')
    goal = data.get('goal')

    if weight is None or goal is None:
        return jsonify({'message': 'Weight and goal are required'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO user_stats (user_id, weight, goal) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE weight = VALUES(weight), goal = VALUES(goal)
        """, (current_user.id, weight, goal))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Statistics saved successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500


@app.route('/get_stats', methods=['GET'])
@login_required
def get_stats():
    cur = mysql.connection.cursor()
    cur.execute("SELECT weight, goal FROM user_stats WHERE user_id = %s", (current_user.id,))
    stats = cur.fetchone()
    cur.close()

    if stats:
        return jsonify({'weight': stats[0], 'goal': stats[1]}), 200
    else:
        return jsonify({'weight': None, 'goal': None}), 200

# Abonamente
@app.route('/check_subscription', methods=['GET'])
@login_required
def check_subscription():
    cur = mysql.connection.cursor()
    cur.execute("SELECT subscription FROM users WHERE id = %s", (current_user.id,))
    subscription = cur.fetchone()
    cur.close()

    if subscription and subscription[0]:
        return jsonify({'subscription': subscription[0]}), 200
    else:
        return jsonify({'subscription': None}), 200

@app.route('/update_subscription', methods=['POST'])
@login_required
def update_subscription():
    data = request.json
    new_subscription = data.get('subscription')

    if not new_subscription:
        return jsonify({'message': 'Subscription is required'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET subscription = %s WHERE id = %s", (new_subscription, current_user.id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Subscription updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500


@app.route('/get_subscription', methods=['GET'])
@login_required
def get_subscription():
    cur = mysql.connection.cursor()
    cur.execute("SELECT subscription, subscription_expiry FROM users WHERE id = %s", (current_user.id,))
    result = cur.fetchone()
    cur.close()

    subscription = result[0] if result else None
    expiry = result[1].strftime('%Y-%m-%d') if result and result[1] else None

    return jsonify({'subscription': subscription, 'expiry': expiry}), 200



@app.route('/initiate_payment', methods=['POST'])
@login_required
def initiate_payment():
    data = request.json
    subscription = data.get('subscription')

    if not subscription:
        return jsonify({'message': 'Subscription is required'}), 400

    session['pending_subscription'] = subscription  # Salvăm temporar alegerea
    return redirect(url_for('payment'))  # Redirecționam către pagina de plata


@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        subscription = session.get('pending_subscription')

        if not subscription:
            return redirect(url_for('dashboard'))

        expiry_date = datetime.now().date() + timedelta(days=30)

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                UPDATE users 
                SET subscription = %s, subscription_expiry = %s 
                WHERE id = %s
            """, (subscription, expiry_date, current_user.id))
            mysql.connection.commit()
            cur.close()

            session.pop('pending_subscription', None)  # Curățăm sesiunea
            return redirect(url_for('dashboard'))
        except Exception as e:
            return f"Error during payment processing: {str(e)}", 500

    return redirect("http://127.0.0.1:5500/payment.html") 
    # GET request -> Afișează pagina





# Admin

@app.route('/get_all_users', methods=['GET'])
@login_required
def get_all_users():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, full_name, email, subscription, role FROM users WHERE role != 'admin'")
    users = cur.fetchall()
    cur.close()

    users_list = [{'id': u[0], 'full_name': u[1], 'email': u[2], 'role': u[4],
                   'subscription': u[3] if u[3] else "No subscription"} for u in users]


    return jsonify({'success': True, 'users': users_list}), 200

@app.route('/update_user_subscription', methods=['POST'])
@login_required
def update_user_subscription():
    if current_user.role != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    data = request.json
    user_id = data.get('user_id')
    new_subscription = data.get('subscription')

    if not user_id or not new_subscription:
        return jsonify({'message': 'User ID and subscription are required'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET subscription = %s WHERE id = %s", (new_subscription, user_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Subscription updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Stergere User

@app.route('/get_users_to_Delete', methods=['GET'])
@login_required
def get_users_to_delete():
    if not current_user.is_authenticated or getattr(current_user, "role", None) != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Cursor tip dicționar
        cur.execute("SELECT id, full_name FROM users WHERE role != 'admin' OR role IS NULL")
        users = cur.fetchall()
        cur.close()

        return jsonify({'success': True, 'users': users}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    logging.info(f"ID utilizator primit pentru ștergere: {user_id}")

    if not current_user.is_authenticated or getattr(current_user, "role", None) != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cur:
            cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404

            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            mysql.connection.commit()

        return jsonify({'success': True, 'message': 'User deleted successfully'}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500




# Decorator pentru a permite accesul doar administratorilor
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            return redirect(url_for('index'))  # Redirecționeaza utilizatorii non-admin catre pagina beginner
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_template('admin.html')

# Ruta pentru logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# Pornirea serverului
if __name__ == '__main__':
    app.run(debug=True, port=5001)
