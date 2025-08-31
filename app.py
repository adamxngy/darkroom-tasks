import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from sqlalchemy import func

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///darkroom.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    projects = db.relationship('Project', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(40), default='active')  # active, paused, archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    tasks = db.relationship('Task', backref='project', cascade="all, delete-orphan", lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(20), default='medium')  # low, medium, high
    done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(200), nullable=False)
    at = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------------------------------------------------------------------
# Forms
# ----------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'id': 'register-email'})
    display_name = StringField('Display Name', validators=[DataRequired(), Length(min=2, max=120)], render_kw={'id': 'register-display-name'})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)], render_kw={'id': 'register-password'})
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'id': 'register-confirm'})
    submit = SubmitField('Create Account', render_kw={'id': 'btn-register-submit'})


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'id': 'login-email'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'id': 'login-password'})
    remember = BooleanField('Remember me', render_kw={'id': 'login-remember'})
    submit = SubmitField('Sign In', render_kw={'id': 'btn-login-submit'})


class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired(), Length(max=140)], render_kw={'id': 'project-name'})
    description = TextAreaField('Description', render_kw={'id': 'project-description'})
    status = SelectField('Status', choices=[('active', 'Active'), ('paused', 'Paused'), ('archived', 'Archived')], render_kw={'id': 'project-status'})
    submit = SubmitField('Save Project', render_kw={'id': 'btn-project-save'})


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)], render_kw={'id': 'task-title'})
    details = TextAreaField('Details', render_kw={'id': 'task-details'})
    priority = SelectField('Priority', choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], render_kw={'id': 'task-priority'})
    done = BooleanField('Done', render_kw={'id': 'task-done'})
    submit = SubmitField('Save Task', render_kw={'id': 'btn-task-save'})

# ----------------------------------------------------------------------------
# Login Manager
# ----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def log(action):
    db.session.add(AuditLog(actor_id=current_user.id if current_user.is_authenticated else None, action=action))
    db.session.commit()

def register_routes(app):
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow()}

    # Landing
    @app.route('/')
    def index():
        return render_template('index.html')

    # Authentication
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data.lower()).first():
                flash('Email already registered.', 'danger')
                return redirect(url_for('register'))
            u = User(email=form.email.data.lower(), display_name=form.display_name.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            log(f"registered:{u.email}")
            flash('Account created. Please sign in.', 'success')
            return redirect(url_for('login'))
        return render_template('auth/register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            u = User.query.filter(func.lower(User.email) == form.email.data.lower()).first()
            if u and u.check_password(form.password.data):
                login_user(u, remember=form.remember.data)
                log(f"login:{u.email}")
                return redirect(url_for('dashboard'))
            flash('Invalid credentials.', 'danger')
        return render_template('auth/login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        log("logout")
        logout_user()
        flash('Signed out.', 'info')
        return redirect(url_for('index'))

    # Dashboard
    @app.route('/dashboard')
    @login_required
    def dashboard():
        q = request.args.get('q', '', type=str)
        status = request.args.get('status', '', type=str)
        projects = Project.query.filter_by(owner_id=current_user.id)
        if q:
            projects = projects.filter(Project.name.ilike(f"%{q}%"))
        if status:
            projects = projects.filter_by(status=status)
        projects = projects.order_by(Project.created_at.desc()).all()
        return render_template('app/dashboard.html', projects=projects, q=q, status=status)

    # Project CRUD
    @app.route('/project/new', methods=['GET', 'POST'])
    @login_required
    def project_new():
        form = ProjectForm()
        if form.validate_on_submit():
            p = Project(name=form.name.data, description=form.description.data, status=form.status.data, owner_id=current_user.id)
            db.session.add(p)
            db.session.commit()
            log(f"project:create:{p.id}")
            return redirect(url_for('project_detail', project_id=p.id))
        return render_template('app/project_form.html', form=form, mode='new')

    @app.route('/project/<int:project_id>', methods=['GET', 'POST'])
    @login_required
    def project_detail(project_id):
        project = Project.query.filter_by(id=project_id, owner_id=current_user.id).first_or_404()
        tform = TaskForm()
        if tform.validate_on_submit():
            t = Task(title=tform.title.data, details=tform.details.data, priority=tform.priority.data, done=tform.done.data, project_id=project.id)
            db.session.add(t)
            db.session.commit()
            log(f"task:create:{t.id}")
            return redirect(url_for('project_detail', project_id=project.id))
        tasks = Task.query.filter_by(project_id=project.id).order_by(Task.created_at.desc()).all()
        return render_template('app/project_detail.html', project=project, tform=tform, tasks=tasks)

    @app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
    @login_required
    def project_edit(project_id):
        project = Project.query.filter_by(id=project_id, owner_id=current_user.id).first_or_404()
        form = ProjectForm(obj=project)
        if form.validate_on_submit():
            project.name = form.name.data
            project.description = form.description.data
            project.status = form.status.data
            db.session.commit()
            log(f"project:update:{project.id}")
            return redirect(url_for('project_detail', project_id=project.id))
        return render_template('app/project_form.html', form=form, mode='edit', project=project)

    @app.route('/project/<int:project_id>/delete', methods=['POST'])
    @login_required
    def project_delete(project_id):
        project = Project.query.filter_by(id=project_id, owner_id=current_user.id).first_or_404()
        db.session.delete(project)
        db.session.commit()
        log(f"project:delete:{project.id}")
        flash('Project deleted.', 'warning')
        return redirect(url_for('dashboard'))

    # Task toggles and deletes (AJAX)
    @app.route('/task/<int:task_id>/toggle', methods=['POST'])
    @login_required
    def task_toggle(task_id):
        task = Task.query.join(Project).filter(Task.id==task_id, Project.owner_id==current_user.id).first_or_404()
        task.done = not task.done
        db.session.commit()
        log(f"task:toggle:{task.id}:{task.done}")
        return jsonify({'ok': True, 'done': task.done})

    @app.route('/task/<int:task_id>/delete', methods=['POST'])
    @login_required
    def task_delete(task_id):
        task = Task.query.join(Project).filter(Task.id==task_id, Project.owner_id==current_user.id).first_or_404()
        db.session.delete(task)
        db.session.commit()
        log(f"task:delete:{task.id}")
        return jsonify({'ok': True})

    # API for automation (tokenless demo)
    @app.route('/api/health')
    def api_health():
        return jsonify({'status': 'ok', 'time': datetime.utcnow().isoformat()})

    @app.route('/api/projects')
    @login_required
    def api_projects():
        projects = Project.query.filter_by(owner_id=current_user.id).order_by(Project.created_at.desc()).all()
        return jsonify([{'id': p.id, 'name': p.name, 'status': p.status} for p in projects])

    @app.route('/api/project/<int:project_id>/tasks')
    @login_required
    def api_project_tasks(project_id):
        project = Project.query.filter_by(id=project_id, owner_id=current_user.id).first_or_404()
        tasks = Task.query.filter_by(project_id=project.id).order_by(Task.created_at.desc()).all()
        return jsonify([{'id': t.id, 'title': t.title, 'priority': t.priority, 'done': t.done} for t in tasks])

# ----------------------------------------------------------------------------
# CLI utility to seed default user and sample data
# ----------------------------------------------------------------------------
def seed():
    """Create a default user and some demo data for testing."""
    email = os.environ.get('SEED_EMAIL', 'testuser@example.com')
    password = os.environ.get('SEED_PASSWORD', 'Password123!')
    name = os.environ.get('SEED_NAME', 'Test User')
    if not User.query.filter_by(email=email).first():
        u = User(email=email, display_name=name, is_admin=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        # Projects & tasks
        p1 = Project(name="Onboarding", description="Kick the tires of DarkRoom.", owner_id=u.id, status='active')
        p2 = Project(name="Regression Suite", description="End-to-end checks.", owner_id=u.id, status='paused')
        db.session.add_all([p1, p2]); db.session.commit()
        db.session.add_all([
            Task(title="Create account", details="Register a fresh account.", priority='high', project_id=p1.id),
            Task(title="Login/Logout flow", details="Validate session cookies.", priority='medium', project_id=p1.id, done=True),
            Task(title="Search projects", details="Try with no results.", priority='low', project_id=p2.id),
        ])
        db.session.commit()
        print(f"Seeded default user {email} / {password}")
    else:
        print("Default user already exists.")

# ----------------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------------
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        seed()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
