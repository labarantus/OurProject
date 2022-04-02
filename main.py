from flask import Flask, request, render_template, redirect, flash, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, NumberRange
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
import re

import sqlite3
from werkzeug.utils import secure_filename
import os



ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static_dir\img'
# Прописываем модель приложения app, и прочие нужные штуки.

app = Flask(__name__, static_folder='static_dir')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'LongAndRandomSecretKeys'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)

# ..
# Реализация БД, здесь создаётся таблица Users,
# где id, email, passw, name - колонки


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    passw = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(35), nullable=False)
    date_reg = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen_film = db.Column(db.Integer, nullable=True)
    avatar_user = db.Column(db.LargeBinary, nullable=True)
    film_list = db.Column(db.String, default='')
    wish_list = db.Column(db.String, default='')
    archive = db.Column(db.String, default='')


    __tablename__ = 'users'

    def set_password(self, password):
        self.passw = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.passw, password)

    def verifyExt(self, filename):
        ext = filename.split(".", 1)[1]
        if ext == 'png' or ext == 'PNG':
            return True
        return False


class Film(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    film_name = db.Column(db.String(50), nullable=False)
    year = db.Column(db.String(50), nullable=True)
    descript = db.Column(db.String(512), nullable=True)
    poster = db.Column(db.LargeBinary, nullable=True)
    date_add = db.Column(db.DateTime(), default=datetime.utcnow)
    link = db.Column(db.String)
    user_id = db.Column(db.Integer, default=-1)

    def __repr__(self):
        return '<Film %r>' % self.id


class Serial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_name = db.Column(db.String(50), unique=True)
    year = db.Column(db.String(50), nullable=False)
    descript = db.Column(db.String(512), nullable=False)
    seasons = db.Column(db.Integer, nullable=False)
    series = db.Column(db.Integer, nullable=False)
    poster = db.Column(db.LargeBinary, nullable=True)
    link = db.Column(db.String)
    user_id = db.Column(db.Integer, default=-1)

    def __repr__(self):
        return '<Serial %r>' % self.id




# ..

db.create_all()


def validate_username(form, name):
    excluded_chars = "!@#$%^&*()_+{}[];'./,"
    for char in name.data:
        if char in excluded_chars:
            raise ValidationError(f"Обраружен запрещённый символ: {char}")


class RegistrationForm(FlaskForm):
    name = StringField(label='Имя пользователя', validators=[InputRequired('Пустое поле'), validate_username])
    email = StringField(label='Электронная почта',
                        validators=[DataRequired(), Email(message='Неверный адрес эл. почты')])
    password = PasswordField(label='Пароль', validators=[DataRequired(), Length(min=5, max=32,
                                                                                message="Пароль должен быть от %(min)d "
                                                                                        "до %(max)d")])
    submit = SubmitField(label='Регистрация')


class LoginForm(FlaskForm):
    name = StringField(label='Имя пользователя', validators=[InputRequired('Пустое поле'), validate_username])
    password = PasswordField(label='Пароль', validators=[DataRequired(), Length(min=5, max=32,
                                                                                message="Пароль должен быть от %(min)d "
                                                                                        "до %(max)d")])
    submit = SubmitField(label='Войти')

def max_year():
    now = datetime.now()
    return now.year + 5

class FilmForm(FlaskForm):
    film_name = StringField(label='Название фильма', validators=[InputRequired('Пустое поле')],
                            render_kw={"class": "form-control", "placeholder": "Введите название фильма"})
    year = IntegerField(label='Год выхода', validators=[NumberRange(min=1890, max=max_year(), message="Введите корректный год")],
                        render_kw={"class": "form-control", "placeholder": "Введите год"})
    descript = TextAreaField(label='Описание фильма', validators=[Length(max=700, message="Слишком большое описание")],
                             render_kw={"class": "form-control", "placeholder": "Введите описание"})
    poster = FileField('Добавить постер', render_kw={"class": "form-control-file"})
    submit = SubmitField(render_kw={"class": "btn-success", "value": "Добавить фильм"})

# ..
# Здесь  обработчики страниц непосредственно.

def last_add_film():
    films = Film.query.order_by(Film.date_add.desc()).all()
    for el in films:
        if el.user_id == current_user.id:
            current_user.film_list = str(current_user.film_list) + str(el.id) + ' '
            print('films list:', str(current_user.film_list))
            break


@app.route("/update-film-list", methods=("POST", "GET"))
def update_film_list():
    films = Film.query.order_by(Film.date_add.desc()).all()
    for el in films:
        if el.user_id == current_user.id:
            current_user.film_list = str(current_user.film_list) + str(el.id) + ' '
            print('films list:', str(current_user.film_list))
            break



@app.route("/films", methods=("POST", "GET"))
def films():
    # Код под комментарием восстанавливает список фильмов для пользователя
    # bet = User.query.order_by(User.id).all()
    # bet[1].film_list = "4 6 7 9 10 11"
    # db.session.commit()
    # print(bet[1].film_list)

    films = Film.query.order_by(Film.id).all()
    str_films = str.split(current_user.film_list) #преобразует строку с ид фильмов в список слов
    film_list = [int(el) for el in str_films] #преобразует список слов в массив чисел ид фильмов
    return render_template('films.html', films=films, film_list=enumerate(film_list, start=1))


@app.route("/add-film", methods=("POST", "GET"))
def add_film():
    form = FilmForm()
    if form.validate_on_submit():
        film_name = form.film_name.data
        year = form.year.data
        descript = form.descript.data
        poster = form.poster.data
        img = poster.read()
        user_id = current_user.id
        film = Film(film_name=film_name, year=year, descript=descript, poster=img, user_id=user_id)
        try:
            db.session.add(film)
            last_add_film()
            db.session.commit()
            return redirect('/')
        except:
            return "При добавлении фильма произошла ошибкаы"
    else:
        return render_template('add_film.html', form=form)


@app.route("/film-del/<int:id>", methods=("POST", "GET"))
def film_del(id):
    str_films = current_user.film_list
    film = str(id) + " "
    new_film_list = re.sub(str(film), "", str(str_films))
    print(str_films)
    print(film)
    print(new_film_list)
    current_user.film_list = new_film_list
    try:
        db.session.commit()
        return redirect( url_for('films'))
    except:
        return "При удалении фильма произошла ошибка"

@app.route('/')
def index():
    return render_template('base.html')


@app.route('/reg', methods=("POST", "GET"))
def reg():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.name.data
        email_user = form.email.data
        password = generate_password_hash(form.password.data)
        user = User(name=username, email=email_user, passw=password)
        db.session.add(user)
        db.session.commit()
    return render_template('registration.html', form=form)


@app.route("/login", methods=("POST", "GET"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    loginform = LoginForm()
    if loginform.validate_on_submit():
        user = db.session.query(User).filter(User.name == loginform.name.data).first()
        if user and user.check_password(loginform.password.data):
            login_user(user)
            return redirect(url_for('user_profile', id=current_user.id))
        flash("Неверное имя пользователя или пароль. Попробуйте снова.", 'error')
        return redirect(url_for('login'))
    return render_template('login.html', form=loginform)


@app.route("/logout", methods=("POST", "GET"))
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/user_profile/<id>", methods=("POST", "GET"))
def user_profile(id):
    return render_template('user_profile.html', id=id)


@app.route('/upload_avatar', methods=("POST", "GET"))
def upload_avatar():
    if request.method == "POST":
        file = request.files['file']
        if file:
            img = file.read()
            i = User.query.filter_by(id=current_user.id).first()
            i.avatar_user = img
            db.session.commit()
    return redirect(url_for('user_profile', id=current_user.id))


@app.route('/getposter/<int:id>')
def getposter(id):
    f = Film.query.all()
    img = f[id-1].poster
    if not img:
        return ""
    h = make_response(img)
    h.headers['Content-Type'] = 'image/img'
    return h


@app.route('/userava')
def userava():
    img = current_user.avatar_user
    if not img:
        return ""

    h = make_response(img)
    h.headers['Content-Type'] = 'image/img'
    return h


@app.route("/admin")
def admin():
    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    user_info = User.query.all()
    return render_template('admin.html', user_info=user_info)

# Это не трогать, иначе не будет работать. !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


if __name__ == "__main__":
    app.run()
