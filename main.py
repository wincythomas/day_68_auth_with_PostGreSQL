import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

login_manager = LoginManager()
app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        user_c = User.query.get(int(user_id))
    return user_c


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name

# Line below only required once, when creating DB.
with app.app_context():
    db.create_all()


@app.route('/')
@app.route('/home')
def home():
    logout_user()
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        hash_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256',
                                                                 salt_length=16)
        new_user = User(email=request.form.get('email').lower(), name=request.form.get('name'), password=hash_password)
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        with app.app_context():
            user_l = User.query.filter_by(email=request.form.get('email').lower()).first()
        if user_l:
            if check_password_hash(user_l.password, request.form.get('password')):
                login_user(user_l)
                flash('You were successfully logged in')
                return redirect(url_for('secrets'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'
    return render_template("login.html", error=error, logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')



if __name__ == "__main__":
    app.run(debug=True, port=5001)
