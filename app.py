from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import sqlite3
import qrcode
import os
from datetime import datetime, timedelta
import math
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = 'attendance.db'

# Initialize database
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL,
                  name TEXT NOT NULL,
                  email TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Folders table
    c.execute('''CREATE TABLE IF NOT EXISTS folders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  teacher_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (teacher_id) REFERENCES users (id))''')
    
    # Sections table
    c.execute('''CREATE TABLE IF NOT EXISTS sections
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  folder_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (folder_id) REFERENCES folders (id))''')
    
    # Classes table with expiry time
    c.execute('''CREATE TABLE IF NOT EXISTS classes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  subject TEXT NOT NULL,
                  date TEXT NOT NULL,
                  teacher_id INTEGER NOT NULL,
                  qr_code_path TEXT,
                  location_lat REAL,
                  location_lng REAL,
                  expiry_time TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1,
                  folder_id INTEGER,
                  section_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (teacher_id) REFERENCES users (id),
                  FOREIGN KEY (folder_id) REFERENCES folders (id),
                  FOREIGN KEY (section_id) REFERENCES sections (id))''')
    
    # Attendance table
    c.execute('''CREATE TABLE IF NOT EXISTS attendance
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id INTEGER NOT NULL,
                  class_id INTEGER NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  latitude REAL,
                  longitude REAL,
                  location_verified BOOLEAN,
                  FOREIGN KEY (student_id) REFERENCES users (id),
                  FOREIGN KEY (class_id) REFERENCES classes (id))''')
    
    # Insert admin user if not exists
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
                 ('admin', hashed_pw, 'admin', 'System Administrator'))
    
    # Insert sample teacher if not exists
    c.execute("SELECT * FROM users WHERE username='teacher'")
    if not c.fetchone():
        hashed_pw = generate_password_hash('teacher123')
        c.execute("INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
                 ('teacher', hashed_pw, 'teacher', 'Demo Teacher'))
    
    # Insert sample student if not exists
    c.execute("SELECT * FROM users WHERE username='student'")
    if not c.fetchone():
        hashed_pw = generate_password_hash('student123')
        c.execute("INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
                 ('student', hashed_pw, 'student', 'Demo Student'))
    
    conn.commit()
    conn.close()

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Haversine formula for distance calculation
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2) * math.sin(dlat/2) +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon/2) * math.sin(dlon/2))
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    distance = R * c * 1000  # Convert to meters
    return distance

# Login required decorator
def login_required(role=None):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Access denied!', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        role = session['role']
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        elif role == 'student':
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin')
@login_required(role='admin')
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@login_required(role='admin')
def create_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    name = request.form['name']
    email = request.form.get('email', '')
    
    hashed_pw = generate_password_hash(password)
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, role, name, email) VALUES (?, ?, ?, ?, ?)',
                    (username, hashed_pw, role, name, email))
        conn.commit()
        flash('User created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        flash('Cannot delete your own account!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    try:
        # First, check if user exists and get their role
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Delete user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash(f'User {user["username"]} deleted successfully!', 'success')
    except Exception as e:
        flash('Error deleting user!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Teacher routes - Folder Management
@app.route('/teacher/folders')
@login_required(role='teacher')
def manage_folders():
    teacher_id = session['user_id']
    conn = get_db_connection()
    
    folders = conn.execute('''
        SELECT f.*, 
               COUNT(s.id) as section_count,
               COUNT(DISTINCT c.id) as class_count
        FROM folders f
        LEFT JOIN sections s ON f.id = s.folder_id
        LEFT JOIN classes c ON f.id = c.folder_id
        WHERE f.teacher_id = ?
        GROUP BY f.id
        ORDER BY f.created_at DESC
    ''', (teacher_id,)).fetchall()
    
    conn.close()
    return render_template('manage_folders.html', folders=folders)

@app.route('/teacher/create_folder', methods=['POST'])
@login_required(role='teacher')
def create_folder():
    folder_name = request.form['folder_name']
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO folders (name, teacher_id) VALUES (?, ?)', 
                    (folder_name, teacher_id))
        conn.commit()
        flash(f'Folder "{folder_name}" created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Folder name already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_folders'))

@app.route('/teacher/folder/<int:folder_id>/sections')
@login_required(role='teacher')
def manage_sections(folder_id):
    teacher_id = session['user_id']
    conn = get_db_connection()
    
    # Verify folder belongs to teacher
    folder = conn.execute('SELECT * FROM folders WHERE id = ? AND teacher_id = ?', 
                         (folder_id, teacher_id)).fetchone()
    if not folder:
        flash('Folder not found!', 'error')
        return redirect(url_for('manage_folders'))
    
    sections = conn.execute('''
        SELECT s.*, COUNT(c.id) as class_count
        FROM sections s
        LEFT JOIN classes c ON s.id = c.section_id
        WHERE s.folder_id = ?
        GROUP BY s.id
        ORDER BY s.created_at DESC
    ''', (folder_id,)).fetchall()
    
    conn.close()
    return render_template('manage_sections.html', folder=folder, sections=sections)

@app.route('/teacher/create_section/<int:folder_id>', methods=['POST'])
@login_required(role='teacher')
def create_section(folder_id):
    section_name = request.form['section_name']
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    try:
        # Verify folder belongs to teacher
        folder = conn.execute('SELECT * FROM folders WHERE id = ? AND teacher_id = ?', 
                             (folder_id, teacher_id)).fetchone()
        if not folder:
            flash('Folder not found!', 'error')
            return redirect(url_for('manage_folders'))
        
        conn.execute('INSERT INTO sections (name, folder_id) VALUES (?, ?)', 
                    (section_name, folder_id))
        conn.commit()
        flash(f'Section "{section_name}" created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Section name already exists in this folder!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_sections', folder_id=folder_id))

# API ENDPOINT FOR FETCHING SECTIONS
@app.route('/api/folder/<int:folder_id>/sections')
@login_required(role='teacher')
def get_sections_by_folder(folder_id):
    teacher_id = session['user_id']
    conn = get_db_connection()
    
    # Verify folder belongs to teacher
    folder = conn.execute('SELECT * FROM folders WHERE id = ? AND teacher_id = ?', 
                         (folder_id, teacher_id)).fetchone()
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    
    sections = conn.execute('SELECT * FROM sections WHERE folder_id = ? ORDER BY name', 
                           (folder_id,)).fetchall()
    conn.close()
    
    sections_list = [{'id': section['id'], 'name': section['name']} for section in sections]
    return jsonify(sections_list)

@app.route('/teacher')
@login_required(role='teacher')
def teacher_dashboard():
    teacher_id = session['user_id']
    conn = get_db_connection()
    
    classes = conn.execute('''
        SELECT c.*, f.name as folder_name, s.name as section_name,
               CASE 
                   WHEN c.expiry_time > datetime('now') AND c.is_active = 1 THEN 'Active'
                   ELSE 'Expired'
               END as status,
               c.is_active
        FROM classes c
        LEFT JOIN folders f ON c.folder_id = f.id
        LEFT JOIN sections s ON c.section_id = s.id
        WHERE c.teacher_id = ?
        ORDER BY c.created_at DESC
    ''', (teacher_id,)).fetchall()
    
    folders = conn.execute('SELECT * FROM folders WHERE teacher_id = ?', (teacher_id,)).fetchall()
    conn.close()
    
    return render_template('teacher_dashboard.html', classes=classes, folders=folders)

@app.route('/teacher/create_class', methods=['POST'])
@login_required(role='teacher')
def create_class():
    subject = request.form['subject']
    date = request.form['date']
    location_lat = float(request.form.get('location_lat', 12.9716))
    location_lng = float(request.form.get('location_lng', 77.5946))
    expiry_minutes = int(request.form.get('expiry_minutes', 60))
    folder_id = request.form.get('folder_id')
    section_id = request.form.get('section_id')
    teacher_id = session['user_id']
    
    # Calculate expiry time
    expiry_time = datetime.now() + timedelta(minutes=expiry_minutes)
    
    # Generate QR code
    class_data = f"class_{teacher_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    
    # Create QR data with class information
    qr_data = {
        'class_id': class_data,
        'teacher_id': teacher_id,
        'subject': subject,
        'date': date,
        'expiry': expiry_time.isoformat()
    }
    qr.add_data(json.dumps(qr_data))
    qr.make(fit=True)
    
    # Create static folder if not exists
    if not os.path.exists('static/qr_codes'):
        os.makedirs('static/qr_codes')
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_path = f"qr_codes/{class_data}.png"
    full_qr_path = f"static/{qr_path}"
    qr_img.save(full_qr_path)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO classes (subject, date, teacher_id, qr_code_path, 
                      location_lat, location_lng, expiry_time, folder_id, section_id)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (subject, date, teacher_id, qr_path, location_lat, location_lng, 
                   expiry_time, folder_id, section_id))
    class_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    flash('Class created and QR code generated!', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/extend_time/<int:class_id>', methods=['POST'])
@login_required(role='teacher')
def extend_qr_time(class_id):
    additional_minutes = int(request.form['additional_minutes'])
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify class belongs to teacher
    class_obj = conn.execute('SELECT * FROM classes WHERE id = ? AND teacher_id = ?', 
                            (class_id, teacher_id)).fetchone()
    if not class_obj:
        flash('Class not found!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Calculate new expiry time
    if isinstance(class_obj['expiry_time'], str):
        current_expiry = datetime.strptime(class_obj['expiry_time'], '%Y-%m-%d %H:%M:%S.%f')
    else:
        current_expiry = datetime.fromisoformat(class_obj['expiry_time'])
    
    new_expiry = current_expiry + timedelta(minutes=additional_minutes)
    
    conn.execute('UPDATE classes SET expiry_time = ?, is_active = 1 WHERE id = ?', 
                (new_expiry, class_id))
    conn.commit()
    conn.close()
    
    flash(f'QR code time extended by {additional_minutes} minutes!', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/toggle_qr/<int:class_id>', methods=['POST'])
@login_required(role='teacher')
def toggle_qr_code(class_id):
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify class belongs to teacher
    class_obj = conn.execute('SELECT * FROM classes WHERE id = ? AND teacher_id = ?', 
                            (class_id, teacher_id)).fetchone()
    if not class_obj:
        flash('Class not found!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    new_status = not class_obj['is_active']
    conn.execute('UPDATE classes SET is_active = ? WHERE id = ?', (new_status, class_id))
    conn.commit()
    conn.close()
    
    status = "activated" if new_status else "deactivated"
    flash(f'QR code {status} successfully!', 'success')
    return redirect(url_for('teacher_dashboard'))

# Student routes
@app.route('/student')
@login_required(role='student')
def student_dashboard():
    student_id = session['user_id']
    conn = get_db_connection()
    attendance = conn.execute('''SELECT a.*, c.subject, c.date, u.name as teacher_name
                                FROM attendance a
                                JOIN classes c ON a.class_id = c.id
                                JOIN users u ON c.teacher_id = u.id
                                WHERE a.student_id = ?
                                ORDER BY a.timestamp DESC''', (student_id,)).fetchall()
    conn.close()
    
    return render_template('student_dashboard.html', attendance=attendance)

# QR code scanning route
@app.route('/scan_qr', methods=['POST'])
@login_required(role='student')
def scan_qr():
    student_id = session['user_id']
    data = request.get_json()
    
    if not data or 'qr_data' not in data:
        return jsonify({'success': False, 'message': 'No QR data provided'})
    
    try:
        # Parse QR code data
        qr_data = json.loads(data['qr_data'])
        class_id_str = qr_data.get('class_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not class_id_str:
            return jsonify({'success': False, 'message': 'Invalid QR code data'})
        
        conn = get_db_connection()
        
        # Find the class by matching part of the qr_code_path
        class_obj = conn.execute('''SELECT * FROM classes 
                                    WHERE qr_code_path LIKE ? 
                                    AND expiry_time > datetime('now') 
                                    AND is_active = 1''', 
                                (f'%{class_id_str}%',)).fetchone()
        
        if not class_obj:
            conn.close()
            return jsonify({'success': False, 'message': 'No active class found for this QR code or it has expired!'})
        
        # Check if already attended
        existing = conn.execute('SELECT * FROM attendance WHERE student_id = ? AND class_id = ?',
                               (student_id, class_obj['id'])).fetchone()
        
        if existing:
            conn.close()
            return jsonify({'success': False, 'message': 'Attendance already marked for this class'})
        
        # Verify location
        location_verified = False
        if class_obj['location_lat'] and class_obj['location_lng'] and latitude and longitude:
            distance = calculate_distance(float(latitude), float(longitude), 
                                        float(class_obj['location_lat']), float(class_obj['location_lng']))
            location_verified = distance <= 100  # Within 100 meters
        
        # Mark attendance
        conn.execute('''INSERT INTO attendance (student_id, class_id, latitude, longitude, location_verified)
                        VALUES (?, ?, ?, ?, ?)''',
                    (student_id, class_obj['id'], latitude, longitude, location_verified))
        conn.commit()
        
        # Get class details for response
        class_info = conn.execute('SELECT subject FROM classes WHERE id = ?', (class_obj['id'],)).fetchone()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': f'Attendance marked successfully for {class_info["subject"]}!',
            'location_verified': location_verified
        })
        
    except json.JSONDecodeError:
        return jsonify({'success': False, 'message': 'Invalid QR code format'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing QR code: {str(e)}'})

# Simple QR scan page for students
@app.route('/scan')
@login_required(role='student')
def scan_qr_page():
    return render_template('scan_qr.html')

# Teacher reports
@app.route('/teacher/reports')
@login_required(role='teacher')
def teacher_reports():
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Get all classes by this teacher with attendance counts
    classes = conn.execute('''SELECT c.*, f.name as folder_name, s.name as section_name,
                             (SELECT COUNT(*) FROM attendance a WHERE a.class_id = c.id) as attendance_count,
                             (SELECT COUNT(DISTINCT a.student_id) FROM attendance a WHERE a.class_id = c.id) as unique_students
                             FROM classes c
                             LEFT JOIN folders f ON c.folder_id = f.id
                             LEFT JOIN sections s ON c.section_id = s.id
                             WHERE c.teacher_id = ?
                             ORDER BY c.created_at DESC''', (teacher_id,)).fetchall()
    
    conn.close()
    
    return render_template('teacher_reports.html', classes=classes)

@app.route('/teacher/class_attendance/<int:class_id>')
@login_required(role='teacher')
def view_class_attendance(class_id):
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify the class belongs to this teacher
    class_info = conn.execute('''SELECT c.*, f.name as folder_name, s.name as section_name
                                FROM classes c
                                LEFT JOIN folders f ON c.folder_id = f.id
                                LEFT JOIN sections s ON c.section_id = s.id
                                WHERE c.id = ? AND c.teacher_id = ?''', 
                             (class_id, teacher_id)).fetchone()
    
    if not class_info:
        flash('Class not found or access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Get attendance records for this class
    attendance = conn.execute('''SELECT a.*, u.name as student_name, u.username, 
                                        a.timestamp, a.location_verified
                                 FROM attendance a
                                 JOIN users u ON a.student_id = u.id
                                 WHERE a.class_id = ?
                                 ORDER BY a.timestamp DESC''', (class_id,)).fetchall()
    
    # Count location verified and not verified
    verified_count = sum(1 for record in attendance if record['location_verified'])
    not_verified_count = len(attendance) - verified_count
    
    conn.close()
    
    return render_template('class_attendance.html', 
                         attendance=attendance, 
                         class_info=class_info,
                         total_students=len(attendance),
                         verified_count=verified_count,
                         not_verified_count=not_verified_count)

# Class Report Route
@app.route('/teacher/class_report/<int:class_id>')
@login_required(role='teacher')
def view_class_report(class_id):
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify the class belongs to this teacher
    class_info = conn.execute('''SELECT c.*, f.name as folder_name, s.name as section_name
                                FROM classes c
                                LEFT JOIN folders f ON c.folder_id = f.id
                                LEFT JOIN sections s ON c.section_id = s.id
                                WHERE c.id = ? AND c.teacher_id = ?''', 
                             (class_id, teacher_id)).fetchone()
    
    if not class_info:
        flash('Class not found or access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Get attendance records for this class with detailed information
    attendance = conn.execute('''SELECT a.*, u.name as student_name, u.username, 
                                        a.timestamp, a.location_verified,
                                        a.latitude, a.longitude
                                 FROM attendance a
                                 JOIN users u ON a.student_id = u.id
                                 WHERE a.class_id = ?
                                 ORDER BY a.timestamp DESC''', (class_id,)).fetchall()
    
    # Calculate detailed statistics
    total_attendance = len(attendance)
    unique_students = len(set(record['student_id'] for record in attendance))
    verified_count = sum(1 for record in attendance if record['location_verified'])
    not_verified_count = total_attendance - verified_count
    
    # Calculate attendance percentage
    total_students = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "student"').fetchone()['count']
    attendance_percentage = (unique_students / total_students * 100) if total_students > 0 else 0
    
    conn.close()
    
    return render_template('class_report.html', 
                         attendance=attendance, 
                         class_info=class_info,
                         total_attendance=total_attendance,
                         unique_students=unique_students,
                         verified_count=verified_count,
                         not_verified_count=not_verified_count,
                         attendance_percentage=attendance_percentage,
                         total_students=total_students)

# Section Report Route
@app.route('/teacher/section_report/<int:folder_id>/<int:section_id>')
@login_required(role='teacher')
def view_section_report(folder_id, section_id):
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify folder and section belong to teacher
    folder = conn.execute('SELECT * FROM folders WHERE id = ? AND teacher_id = ?', 
                         (folder_id, teacher_id)).fetchone()
    section = conn.execute('SELECT * FROM sections WHERE id = ? AND folder_id = ?', 
                          (section_id, folder_id)).fetchone()
    
    if not folder or not section:
        flash('Folder or section not found!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Get all classes for this section
    classes = conn.execute('''SELECT c.*, 
                             (SELECT COUNT(*) FROM attendance a WHERE a.class_id = c.id) as attendance_count,
                             (SELECT COUNT(DISTINCT a.student_id) FROM attendance a WHERE a.class_id = c.id) as unique_students
                             FROM classes c
                             WHERE c.folder_id = ? AND c.section_id = ?
                             ORDER BY c.date''', (folder_id, section_id)).fetchall()
    
    # Get all students
    students = conn.execute('SELECT * FROM users WHERE role = "student" ORDER BY name').fetchall()
    
    # Calculate section statistics
    total_classes = len(classes)
    total_attendance_records = sum(cls['attendance_count'] for cls in classes)
    total_unique_students = len(students)
    
    conn.close()
    
    return render_template('section_report.html', 
                         folder=folder,
                         section=section,
                         classes=classes,
                         students=students,
                         total_classes=total_classes,
                         total_attendance_records=total_attendance_records,
                         total_unique_students=total_unique_students)

# Excel report generation
@app.route('/teacher/export_attendance/<int:folder_id>/<int:section_id>')
@login_required(role='teacher')
def export_attendance(folder_id, section_id):
    teacher_id = session['user_id']
    
    conn = get_db_connection()
    
    # Verify folder and section belong to teacher
    folder = conn.execute('SELECT * FROM folders WHERE id = ? AND teacher_id = ?', 
                         (folder_id, teacher_id)).fetchone()
    section = conn.execute('SELECT * FROM sections WHERE id = ? AND folder_id = ?', 
                          (section_id, folder_id)).fetchone()
    
    if not folder or not section:
        flash('Folder or section not found!', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Get all classes for this section
    classes = conn.execute('''SELECT * FROM classes 
                             WHERE folder_id = ? AND section_id = ?
                             ORDER BY date''', (folder_id, section_id)).fetchall()
    
    # Get all students
    students = conn.execute('SELECT * FROM users WHERE role = "student" ORDER BY name').fetchall()
    
    # Create Excel data
    data = []
    headers = ['Student Name', 'Username', 'Total Classes', 'Classes Attended', 'Percentage']
    
    # Add class dates to headers
    class_dates = [cls['date'] for cls in classes]
    headers[2:2] = class_dates  # Insert class dates after username
    
    for student in students:
        row = [student['name'], student['username']]
        
        # Add attendance for each class date
        attendance_marks = []
        for cls in classes:
            attendance = conn.execute('''SELECT * FROM attendance 
                                       WHERE student_id = ? AND class_id = ?''', 
                                    (student['id'], cls['id'])).fetchone()
            attendance_marks.append('✅' if attendance else '❌')
        
        row[2:2] = attendance_marks  # Insert attendance marks after username
        
        # Calculate totals
        total_classes = len(classes)
        classes_attended = attendance_marks.count('✅')
        percentage = (classes_attended / total_classes * 100) if total_classes > 0 else 0
        
        row.extend([total_classes, classes_attended, f'{percentage:.1f}%'])
        data.append(row)
    
    conn.close()
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=headers)
    
    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Attendance Report', index=False)
        
        # Get workbook and worksheet
        workbook = writer.book
        worksheet = writer.sheets['Attendance Report']
        
        # Add header format
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#D7E4BC',
            'border': 1
        })
        
        # Apply header format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
    
    output.seek(0)
    
    return send_file(output, 
                    download_name=f'attendance_{folder["name"]}_{section["name"]}.xlsx', 
                    as_attachment=True)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
