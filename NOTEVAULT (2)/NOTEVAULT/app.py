from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, send_file, abort
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from io import BytesIO
from fpdf import FPDF
import os
import mimetypes
import random
import sys
import secrets
import string

try:
    from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
    from flask_mysqldb import MySQL
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install: python -m pip install flask flask-mysqldb werkzeug")
    sys.exit(1)

app = Flask(__name__)
# Set a strong secret key for production
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_urlsafe(32))
# -------- MySQL CONFIG ----------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'notevault_db'

mysql = MySQL(app)

# Upload config (create uploads folder next to this file)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
ALLOWED_EXTENSIONS = None  # Allow all file types

def get_db_connection():
    return mysql.connection

def allowed_file(filename):
    # Basic security: block dangerous extensions
    blocked = {'exe', 'bat', 'sh', 'js', 'php', 'py', 'pl', 'rb', 'jar', 'msi', 'cmd', 'scr'}
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext not in blocked

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def generate_share_token(length=32):
    """Generate a secure random token for sharing notes"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

# ---------------- ROUTES ---------------- #

@app.route('/')
def home():
    return render_template('home.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip().lower()
        raw_password = request.form.get('password','')

        if not username or not email or not raw_password:
            flash("Please fill all fields.", "danger")
            return redirect(url_for('signup'))

        password = generate_password_hash(raw_password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cursor.fetchone():
            flash("Username already exists!")
            cursor.close()
            return redirect(url_for('signup'))

        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already registered!")
            cursor.close()
            return redirect(url_for('signup'))

        cursor.execute("INSERT INTO users (username,email,password) VALUES (%s,%s,%s)",
                       (username,email,password))
        conn.commit()
        cursor.close()
        flash("Signup successful! Login now.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    # Clear old flashes not related to login
    session.pop('_flashes', None)

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, password FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()

        # user is tuple (id, username, email, password)
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password!")  # Only login-related
    return render_template('login.html')


# Dashboard
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Add new subject
    if request.method == 'POST':
        new_subject = request.form.get('new_subject','').strip()
        if new_subject:
            cursor.execute("INSERT INTO subjects (user_id, title) VALUES (%s, %s)",
                           (session['user_id'], new_subject))
            conn.commit()
            flash(f"Subject '{new_subject}' created successfully!", "success")
        else:
            flash("Subject name cannot be empty.", "warning")

    cursor.execute("SELECT id, title FROM subjects WHERE user_id=%s", (session['user_id'],))
    subjects = cursor.fetchall()
    cursor.close()

    # Random quote
    quotes = [
        "Organize your thoughts, one note at a time.",
        "Small steps every day lead to big results.",
        "Your notes are your power.",
        "Write it down, remember it forever.",
        "Ideas become reality when you note them."
    ]
    random_quote = random.choice(quotes)

    return render_template('dashboard.html', subjects=subjects, username=session.get('username'), quote=random_quote)

# Rename subject (POST)
@app.route('/rename_subject/<int:subject_id>', methods=['POST'])
@login_required
def rename_subject(subject_id):
    new_name = request.form.get('new_name','').strip()
    if new_name:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE subjects SET title=%s WHERE id=%s AND user_id=%s",
                       (new_name, subject_id, session['user_id']))
        conn.commit()
        cursor.close()
        return jsonify({"status":"success", "message":"Subject renamed successfully!"})
    return jsonify({"status":"error", "message":"Rename failed!"})

# Delete subject (POST)
@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
@login_required
def delete_subject(subject_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM subjects WHERE id=%s AND user_id=%s",
                   (subject_id, session['user_id']))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success", "message":"Subject deleted successfully!"})

# New: view a subject and list its units (endpoint name: view_subject)
@app.route('/subject/<int:subject_id>')
@login_required
def view_subject(subject_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM subjects WHERE id=%s AND user_id=%s", (subject_id, session['user_id']))
    subject = cursor.fetchone()
    if not subject:
        cursor.close()
        flash("Subject not found or you don't have permission.", "warning")
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT id, name FROM units WHERE subject_id=%s", (subject_id,))
    units = cursor.fetchall()
    cursor.close()
    return render_template('subject.html', subject=subject, units=units)

# Compatibility: keep a viewpage endpoint if templates call url_for('viewpage', subject_id=...)
# This prevents BuildError and simply renders the subject page.
@app.route('/viewpage/<int:subject_id>')
@login_required
def viewpage(subject_id):
    # simply reuse view_subject logic
    return view_subject(subject_id)

# Serve uploaded files
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Serve uploaded file with correct mimetype and inline disposition so images/PDFs open in-browser
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        abort(404)
    # Guess mimetype
    mimetype = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
    # send_file will set Content-Type and allow inline display when supported
    try:
        response = send_file(file_path, mimetype=mimetype, as_attachment=False)
        # Add cache headers so the browser caches this file for 30 days
        # This prevents re-downloading the same file on subsequent accesses
        response.headers['Cache-Control'] = 'public, max-age=2592000'  # 30 days
        response.headers['Pragma'] = 'public'
        return response
    except Exception:
        # Fallback to send_from_directory
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# View unit + add notes
@app.route('/unit/<int:unit_id>', methods=['GET', 'POST'])
@login_required
def view_unit(unit_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the subject_id + unit name for this unit
    cursor.execute("SELECT subject_id, name FROM units WHERE id = %s", (unit_id,))
    unit_data = cursor.fetchone()
    subject_id = unit_data[0] if unit_data else None
    unit_name = unit_data[1] if unit_data else f"Unit {unit_id}"

    if request.method == 'POST':
        user_id = session.get('user_id')
        title = request.form.get('title') or f"Unit {unit_id} Note"
        link_url = request.form.get('link','').strip()
        file = request.files.get('file')

        file_path = None
        note_type = None
        content = None

        # File upload logic
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("File type not allowed.", "warning")
                return redirect(url_for('view_unit', unit_id=unit_id))

            filename = secure_filename(file.filename)
            unique_name = f"{user_id}_{int(random.random()*1e9)}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            file.save(save_path)
            file_path = unique_name

            ext = filename.lower().rsplit('.', 1)[-1]
            if ext == 'pdf':
                note_type = 'pdf'
            elif ext in ['jpg', 'jpeg', 'png']:
                note_type = 'image'
            else:
                note_type = 'file'

        # Link type
        elif link_url:
            note_type = 'link'
        # Text note
        else:
            content = request.form.get('content', '').strip()
            note_type = 'text'

        cursor.execute("""
            INSERT INTO notes (unit_id, user_id, subject_id, title, content, file_path, link_url, note_type)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (unit_id, user_id, subject_id, title, content, file_path, link_url, note_type))
        conn.commit()
        flash("✅ Note added for this unit!", "success")
        return redirect(url_for('view_unit', unit_id=unit_id))

    # Show only notes for this unit
    cursor.execute("""
        SELECT id, title, content, file_path, link_url, note_type, created_at FROM notes
        WHERE unit_id = %s ORDER BY created_at DESC
    """, (unit_id,))
    notes = cursor.fetchall()
    cursor.close()

    return render_template('viewpage.html', notes=notes, unit_id=unit_id, unit_name=unit_name)

# Add text note
@app.route('/add_text_note/<int:unit_id>', methods=['POST'])
@login_required
def add_text_note(unit_id):
    subject_id = request.args.get('subject_id')
    note_title = request.form.get('note_title','Untitled')
    note_text = request.form.get('note_text','')
    
    if not note_text.strip():
        return jsonify({"status":"error","message":"Note cannot be empty"})
    
    # Verify the unit belongs to the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    cursor.execute("""INSERT INTO notes (unit_id,subject_id,user_id,note_type,content,title)
                      VALUES (%s,%s,%s,%s,%s,%s)""",
                   (unit_id, subject_id, session['user_id'], 'text', note_text, note_title))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Note saved"})

# ➕ Add Unit
@app.route('/add_unit/<int:subject_id>', methods=['POST'])
@login_required
def add_unit(subject_id):
    unit_name = request.form.get('unit_name','').strip()
    if not unit_name:
        return jsonify({"status":"error","message":"Unit name cannot be empty"})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify subject belongs to current user before adding unit
    cursor.execute("SELECT id FROM subjects WHERE id=%s AND user_id=%s", (subject_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Subject not found or unauthorized"})
    
    cursor.execute("INSERT INTO units (subject_id, name) VALUES (%s, %s)", (subject_id, unit_name))
    conn.commit()
    unit_id = cursor.lastrowid
    cursor.close()
    return jsonify({"status":"success","unit_id":unit_id,"unit_name":unit_name})

# 📝 Get Notes for Unit
@app.route('/get_notes/<int:unit_id>', methods=['GET'])
@login_required
def get_notes(unit_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify unit ownership before returning notes
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    cursor.execute("""SELECT id, title, content, file_path, link_url, note_type FROM notes 
                      WHERE unit_id=%s ORDER BY id DESC""", (unit_id,))
    notes = cursor.fetchall()
    cursor.close()
    notes_list = [{"id": n[0], "title": n[1], "content": n[2], "file_path": n[3], "link_url": n[4], "note_type": n[5]} for n in notes]
    return jsonify({"status":"success","notes":notes_list})

# 📤 Upload File Note
@app.route('/upload_note/<int:unit_id>', methods=['POST'])
@login_required
def upload_note(unit_id):
    subject_id = request.args.get('subject_id')
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({"status":"error","message":"No file selected"})
    
    if not allowed_file(file.filename):
        return jsonify({"status":"error","message":"File type not allowed"})
    
    # Verify unit ownership before allowing upload
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    filename = secure_filename(file.filename)
    # allow an optional title passed from client
    provided_title = request.form.get('title')
    unique_name = f"{session['user_id']}_{int(random.random()*1e9)}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(filepath)
    
    ext = filename.lower().rsplit('.', 1)[-1]
    if ext == 'pdf':
        note_type = 'pdf'
    elif ext in ['jpg', 'jpeg', 'png']:
        note_type = 'image'
    else:
        note_type = 'file'

    # use provided title if present, otherwise use the original filename
    title_to_save = provided_title.strip() if provided_title and provided_title.strip() else filename
    cursor.execute("""INSERT INTO notes (unit_id, subject_id, user_id, title, file_path, note_type)
                      VALUES (%s, %s, %s, %s, %s, %s)""",
                   (unit_id, subject_id, session['user_id'], title_to_save, unique_name, note_type))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"File uploaded"})

# 🔗 Add Link Note
@app.route('/add_link/<int:unit_id>', methods=['POST'])
@login_required
def add_link(unit_id):
    subject_id = request.args.get('subject_id')
    link_url = request.form.get('link_url','').strip()
    if not link_url:
        return jsonify({"status":"error","message":"Link cannot be empty"})
    # optional title for link
    link_title = request.form.get('title') or 'Link'

    # Verify unit ownership before allowing link addition
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    cursor.execute("""INSERT INTO notes (unit_id, subject_id, user_id, title, link_url, note_type)
                      VALUES (%s, %s, %s, %s, %s, %s)""",
                   (unit_id, subject_id, session['user_id'], link_title, link_url, 'link'))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Link added"})

# 🔄 Rename Unit
@app.route('/rename_unit/<int:unit_id>', methods=['POST'])
@login_required
def rename_unit(unit_id):
    new_name = request.form.get('new_name','').strip()
    if not new_name:
        return jsonify({"status":"error","message":"Unit name cannot be empty"})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify unit belongs to current user before renaming
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    cursor.execute("UPDATE units SET name=%s WHERE id=%s", (new_name, unit_id))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Unit renamed"})

# ❌ Delete Unit
@app.route('/delete_unit/<int:unit_id>', methods=['POST'])
@login_required
def delete_unit(unit_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify unit belongs to current user before deleting
    cursor.execute("""SELECT u.id FROM units u 
                      JOIN subjects s ON u.subject_id = s.id 
                      WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})
    
    cursor.execute("DELETE FROM units WHERE id=%s", (unit_id,))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Unit deleted"})

# ❌ Delete Note
@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify note belongs to current user before deleting
    cursor.execute("DELETE FROM notes WHERE id=%s AND user_id=%s", (note_id, session['user_id']))
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"status":"error","message":"Note not found or unauthorized"})
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Note deleted"})


# 📖 View Shared Note (Public - No Login Required)
@app.route('/shared/<share_token>')
def view_shared_note(share_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify share token exists
    cursor.execute("""SELECT n.id, n.title, n.content, n.file_path, n.link_url, n.note_type
                      FROM notes n
                      JOIN share_links s ON n.id = s.note_id
                      WHERE s.share_token=%s""", (share_token,))
    note = cursor.fetchone()
    cursor.close()
    
    if not note:
        flash("Shared link is invalid or has been removed.", "danger")
        return redirect(url_for('home'))
    
    # Return read-only view
    return render_template('shared_note.html', 
                          note_id=note[0], 
                          title=note[1], 
                          content=note[2], 
                          file_path=note[3], 
                          link_url=note[4], 
                          note_type=note[5],
                          is_shared=True)

@app.route('/share_unit/<int:unit_id>', methods=['POST'])
@login_required
def share_unit(unit_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify unit belongs to current user
    cursor.execute("""SELECT u.id FROM units u JOIN subjects s ON u.subject_id = s.id WHERE u.id=%s AND s.user_id=%s""", (unit_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Unit not found or unauthorized"})

    # Check if a share link already exists for this unit
    cursor.execute("SELECT share_token FROM page_share_links WHERE unit_id=%s", (unit_id,))
    row = cursor.fetchone()
    if row:
        share_token = row[0]
    else:
        share_token = generate_share_token()
        cursor.execute("INSERT INTO page_share_links (unit_id, share_token) VALUES (%s, %s)", (unit_id, share_token))
        conn.commit()
    cursor.close()
    share_url = url_for('view_shared_unit', share_token=share_token, _external=True)
    return jsonify({"status":"success","share_url":share_url})

# 📖 View Shared Unit/Notes Page (Public - No Login Required)
@app.route('/shared_page/<share_token>')
def view_shared_unit(share_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify share token exists and get unit info
    cursor.execute("""SELECT u.id, u.name, u.subject_id
                      FROM units u
                      JOIN page_share_links ps ON u.id = ps.unit_id
                      WHERE ps.share_token=%s""", (share_token,))
    unit_data = cursor.fetchone()
    
    if not unit_data:
        cursor.close()
        flash("Shared link is invalid or has been removed.", "danger")
        return redirect(url_for('home'))
    
    unit_id, unit_name, subject_id = unit_data
    
    # Get all notes for this unit
    cursor.execute("""SELECT id, title, content, file_path, link_url, note_type FROM notes 
                      WHERE unit_id=%s ORDER BY id DESC""", (unit_id,))
    notes = cursor.fetchall()
    cursor.close()
    
    # Convert to list of dicts
    notes_list = [{"id": n[0], "title": n[1], "content": n[2], "file_path": n[3], "link_url": n[4], "note_type": n[5]} for n in notes]
    
    # Return read-only view of entire unit
    return render_template('shared_unit_page.html', 
                          unit_name=unit_name, 
                          notes=notes_list,
                          is_shared=True)

# 🔄 Revoke Unit Share Link
@app.route('/revoke_unit_share/<int:link_id>', methods=['POST'])
@login_required
def revoke_unit_share(link_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify ownership before revoking
    cursor.execute("""SELECT ps.id FROM page_share_links ps
                      JOIN units u ON ps.unit_id = u.id
                      JOIN subjects s ON u.subject_id = s.id
                      WHERE ps.id=%s AND s.user_id=%s""", (link_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status":"error","message":"Share link not found or unauthorized"})
    
    cursor.execute("DELETE FROM page_share_links WHERE id=%s", (link_id,))
    conn.commit()
    cursor.close()
    return jsonify({"status":"success","message":"Share link revoked"})

# Export subject as PDF
@app.route('/export_subject_pdf/<int:subject_id>')
@login_required
def export_subject_pdf(subject_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Verify subject belongs to user
    cursor.execute("SELECT id, name FROM subjects WHERE id=%s AND user_id=%s", (subject_id, session['user_id']))
    subject = cursor.fetchone()
    if not subject:
        cursor.close()
        return abort(403)
    subject_name = subject[1]
    # Get all units
    cursor.execute("SELECT id, name FROM units WHERE subject_id=%s ORDER BY id", (subject_id,))
    units = cursor.fetchall()
    # Get all notes for each unit
    unit_notes = {}
    for unit in units:
        cursor.execute("SELECT title, content, file_path, link_url, note_type FROM notes WHERE unit_id=%s ORDER BY id", (unit[0],))
        unit_notes[unit[0]] = cursor.fetchall()
    cursor.close()
    # Generate PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"Subject: {subject_name}", ln=True)
    pdf.set_font("Arial", '', 12)
    for unit in units:
        pdf.ln(6)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, f"Unit: {unit[1]}", ln=True)
        pdf.set_font("Arial", '', 12)
        notes = unit_notes[unit[0]]
        if not notes:
            pdf.cell(0, 8, "No notes in this unit.", ln=True)
        for note in notes:
            title, content, file_path, link_url, note_type = note
            pdf.ln(2)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 8, f"Note: {title}", ln=True)
            pdf.set_font("Arial", '', 11)
            if note_type == 'text':
                pdf.multi_cell(0, 7, content or '')
            elif note_type == 'link':
                pdf.cell(0, 7, f"Link: {link_url}", ln=True)
            elif note_type == 'file' or note_type == 'pdf' or note_type == 'image':
                pdf.cell(0, 7, f"File: {file_path}", ln=True)
            pdf.ln(2)
    # Output PDF to memory
    pdf_bytes = BytesIO()
    pdf.output(pdf_bytes)
    pdf_bytes.seek(0)
    return send_file(pdf_bytes, as_attachment=True, download_name=f"{subject_name}.pdf", mimetype='application/pdf')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    # For production, use a WSGI server like Gunicorn or uWSGI
    # Example: gunicorn app:app
    app.run()
