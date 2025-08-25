from datetime import datetime, date
import os

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Security-related defaults
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

limiter = Limiter(get_remote_address, app=app, default_limits=[])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    notes = db.relationship('Note', backref='user', lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_date = db.Column(db.Date, nullable=False, index=True)
    content = db.Column(db.Text, default='', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'note_date', name='uq_user_date'),)


class LoginEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


_db_inited = False

@app.before_request
def init_db_once():
    global _db_inited
    if _db_inited:
        return
    db.create_all()
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(email=admin_email, is_admin=True)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
    _db_inited = True


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'error')
            return render_template('register.html')

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            try:
                event = LoginEvent(
                    user_id=user.id,
                    ip_address=request.headers.get('X-Forwarded-For', request.remote_addr),
                    user_agent=request.headers.get('User-Agent')
                )
                db.session.add(event)
                db.session.commit()
            except Exception:
                db.session.rollback()
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    today_iso = date.today().isoformat()
    return render_template('dashboard.html', today_iso=today_iso)


def parse_iso_date(date_str: str) -> date:
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        abort(400, description='Invalid date format. Use YYYY-MM-DD.')


@app.route('/note/<date_str>', methods=['GET', 'POST'])
@login_required
@limiter.limit("30/minute")
def note(date_str):
    note_date = parse_iso_date(date_str)
    note = Note.query.filter_by(user_id=current_user.id, note_date=note_date).first()
    if request.method == 'POST':
        content = request.form.get('content', '')
        if note is None:
            note = Note(user_id=current_user.id, note_date=note_date, content=content)
            db.session.add(note)
        else:
            note.content = content
        db.session.commit()
        flash('Note saved.', 'success')
        return redirect(url_for('note', date_str=note_date.isoformat()))
    if note is None:
        content = ''
    else:
        content = note.content
    return render_template('note.html', note_date=note_date, content=content)


def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@app.route('/admin')
@login_required
@limiter.limit("60/minute")
def admin():
    require_admin()
    users = User.query.order_by(User.created_at.desc()).all()
    notes = Note.query.order_by(Note.note_date.desc(), Note.updated_at.desc()).all()
    events = LoginEvent.query.order_by(LoginEvent.created_at.desc()).limit(100).all()
    return render_template('admin.html', users=users, notes=notes, events=events)


@app.route('/admin/reset_password', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def admin_reset_password():
    require_admin()
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password', '')
    if not user_id or not new_password:
        flash('User and new password required.', 'error')
        return redirect(url_for('admin'))
    user = User.query.get(int(user_id))
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    user.set_password(new_password)
    db.session.commit()
    flash(f'Password reset for {user.email}.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/delete_note', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def admin_delete_note():
    require_admin()
    note_id = request.form.get('note_id')
    if not note_id:
        flash('Note ID required.', 'error')
        return redirect(url_for('admin'))
    note = Note.query.get(int(note_id))
    if not note:
        flash('Note not found.', 'error')
        return redirect(url_for('admin'))
    user_email = note.user.email
    note_date = note.note_date.isoformat()
    db.session.delete(note)
    db.session.commit()
    flash(f'Note for {user_email} on {note_date} deleted.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    with app.app_context():
        init_db_once()
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        return response

    app.run(debug=False)


