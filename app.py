from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change for production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securevote.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model for login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Candidate model
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    votes = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('vote'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('vote'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/vote')
@login_required
def vote():
    candidates = Candidate.query.all()
    return render_template('vote.html', candidates=candidates)

@app.route('/vote/<int:candidate_id>', methods=['POST'])
@login_required
def cast_vote(candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    candidate.votes += 1
    db.session.commit()
    flash(f'You voted for {candidate.name}!', 'success')
    return redirect(url_for('result'))

@app.route('/result')
@login_required
def result():
    candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
    return render_template('result.html', candidates=candidates)

# Admin panel
@app.route('/admin')
@login_required
def admin():
    if current_user.username != 'admin':
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('home'))
    candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
    return render_template('admin.html', candidates=candidates)

@app.route('/admin/reset_votes', methods=['POST'])
@login_required
def reset_votes():
    if current_user.username != 'admin':
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('home'))
    candidates = Candidate.query.all()
    for c in candidates:
        c.votes = 0
    db.session.commit()
    flash('Votes have been reset.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_candidate', methods=['POST'])
@login_required
def add_candidate():
    if current_user.username != 'admin':
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('home'))
    name = request.form.get('name')
    if name:
        existing = Candidate.query.filter_by(name=name).first()
        if existing:
            flash('Candidate already exists!', 'warning')
        else:
            new_candidate = Candidate(name=name)
            db.session.add(new_candidate)
            db.session.commit()
            flash(f'Candidate {name} added.', 'success')
    else:
        flash('Candidate name cannot be empty.', 'danger')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin123')  # Change password immediately!
            db.session.add(admin_user)
        # Create some default candidates
        if Candidate.query.count() == 0:
            db.session.add_all([
                Candidate(name='Alice'),
                Candidate(name='Bob'),
                Candidate(name='Charlie')
            ])
        db.session.commit()
    app.run(debug=True)
