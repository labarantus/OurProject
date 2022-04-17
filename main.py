from flask import Flask, request, render_template, redirect, flash, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField, FileField, TextAreaField, URLField, RadioField
from flask_wtf.file import FileField, FileAllowed, FileRequired, FileSize
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError, \
                               NumberRange, URL, Regexp, HostnameValidation
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
import re
import sys

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


class URLcheck(Regexp):
    def __init__(self, require_tld=True, message=None):
        regex = (
            r"^[a-z]+://"
            r"(?P<host>[^\/\?:]+)"
            r"(?P<port>:[0-9]+)?"
            r"(?P<path>\/.*?)?"
            r"(?P<query>\?.*)?$"
        )
        super().__init__(regex, re.IGNORECASE, message)
        self.validate_hostname = HostnameValidation(
            require_tld=require_tld, allow_ip=True
        )

    def __call__(self, form, field):
        message = self.message
        if message is None:
            message = field.gettext("Invalid URL.")
        match = super().__call__(form, field, message)
        print(match)

        if match and not self.validate_hostname(match.group("host")):
            raise ValidationError(message)

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
    year = db.Column(db.String(50), nullable=False)
    descript = db.Column(db.String(512), nullable=True)
    length = db.Column(db.Integer, nullable=True, default=90)
    poster = db.Column(db.LargeBinary, nullable=True)
    date_add = db.Column(db.DateTime(), default=datetime.utcnow)
    user_id = db.Column(db.Integer, default=-1)

    def __repr__(self):
        return '<Film %r>' % self.id


class FilmInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False )
    film_id = db.Column(db.Integer, nullable=False)
    list_num = db.Column(db.Integer, default=1)
    last_move = db.Column(db.DateTime(), default=datetime.utcnow)
    link = db.Column(db.String, nullable=True, default="")
    score = db.Column(db.Float, nullable=True, default=0)
    review = db.Column(db.String, nullable=True)



class Serial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_name = db.Column(db.String(50), nullable=False)
    year = db.Column(db.String(50), nullable=False)
    descript = db.Column(db.String(512), nullable=True)
    seasons = db.Column(db.Integer, nullable=False)
    eps = db.Column(db.Integer, nullable=False)
    eps_length = db.Column(db.Integer, nullable=False)
    poster = db.Column(db.LargeBinary, nullable=True)
    date_add = db.Column(db.DateTime(), default=datetime.utcnow)
    user_id = db.Column(db.Integer, default=-1)

    def __repr__(self):
        return '<Serial %r>' % self.id


class SerialInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False )
    serial_id = db.Column(db.Integer, nullable=False)
    list_num = db.Column(db.Integer, default=1)
    last_move = db.Column(db.DateTime(), default=datetime.utcnow)
    link = db.Column(db.String, nullable=True, default="")
    score = db.Column(db.Float, nullable=True, default=0)
    review = db.Column(db.String, nullable=True)


class WatchCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    serial_id = db.Column(db.Integer, nullable=False)
    season_num = db.Column(db.Integer, nullable=False)
    eps_num = db.Column(db.Integer, nullable=False)
    watched = db.Column(db.Boolean(), default=False)




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
    film_name = StringField( label='Название фильма',  validators=[InputRequired('Пустое поле')],
                            render_kw={"class": "form-control", "placeholder": "Введите название фильма"})
    year = IntegerField(label='Год выхода', validators=[InputRequired('Пустое поле'),
                        NumberRange(min=1890, max=max_year(), message="Введите корректный год")],
                        render_kw={"class": "form-control", "placeholder": "Введите год"})
    descript = TextAreaField(label='Описание фильма', validators=[Length(max=700, message="Слишком большое описание")],
                             render_kw={"class": "form-control", "placeholder": "Введите описание"})
    link = URLField(label="Ссылка для просмотра", validators=[URLcheck(message='Введите корректный адрес')],
                    render_kw={"class": "form-control", "placeholder": "Введите адрес сайта для просмотра"})
    poster = FileField('Добавить постер', validators=[ FileAllowed(['jpg', 'png']),
                       FileSize(1024*1024, 1, "Слишком большой")], render_kw={"class": "form-control-file"})
    submit = SubmitField(render_kw={"class": "btn-success", "value": "Добавить фильм"})


class SerialForm(FlaskForm):
    serial_name = StringField( label='Название сериала', validators=[InputRequired('Пустое поле')],
                            render_kw={"class": "form-control", "placeholder": "Введите название сериала"})
    year = IntegerField(label='Год выхода', validators=[InputRequired('Пустое поле'),
                                                        NumberRange(min=1890, max=max_year(),
                                                                    message="Введите корректный год")],
                        render_kw={"class": "form-control", "placeholder": "Введите год"})
    descript = TextAreaField(label='Описание сериала',
                             validators=[Length(max=700, message="Слишком большое описание")],
                             render_kw={"class": "form-control", "placeholder": "Введите описание"})
    seasons = IntegerField(label='Количество сезонов', validators=[InputRequired('Пустое поле'),
                                                        NumberRange(min=1, max=20,
                                                                    message="Введите число от 1 до 20")],
                        render_kw={"class": "form-control", "placeholder": "Введите количество сезонов"})
    eps = IntegerField(label='Количество серий', validators=[InputRequired('Пустое поле'),
                                                                   NumberRange(min=1, max=100,
                                                                               message="Введите число от 1 до 100")],
                           render_kw={"class": "form-control", "placeholder": "Введите количество серий"})
    eps_length = IntegerField(label='Продолжительность серии', validators=[InputRequired('Пустое поле'),
                                                                   NumberRange(min=1, max=120,
                                                                               message="Введите число от 1 до 120")],
                           render_kw={"class": "form-control", "placeholder": "Введите продолжительность серии"})
    link = URLField(label="Ссылка для просмотра", validators=[URLcheck(message='Введите корректный адрес')],
                    render_kw={"class": "form-control", "placeholder": "Введите адрес сайта для просмотра"})
    poster = FileField('Добавить постер', validators=[FileAllowed(['jpg', 'png']),
                                                      FileSize(1024 * 1024, 1, "Слишком большой")],
                       render_kw={"class": "form-control-file"})
    submit = SubmitField(render_kw={"class": "btn-success", "value": "Добавить фильм"})

# ..
# Здесь  обработчики страниц непосредственно.


def last_add(n):
    if n == 1:
        films = Film.query.order_by(Film.date_add.desc()).all()
        for el in films:
            if el.user_id == current_user.id:
                return el.id
    elif n == 2:
        serials = Serial.query.order_by(Serial.date_add.desc()).all()
        for el in serials:
            if el.user_id == current_user.id:
                return el.id
    return 'Ошибка при поиске последнего добавленного фильма/сериала'

@app.route("/catalog", methods=("POST", "GET"))
def catalog():
    films = Film.query.filter(Film.user_id == -1).order_by(Film.id).all()
    serials = Serial.query.filter(Serial.user_id == -1).order_by(Serial.id).all()
    return render_template('catalog.html', films=films, serials=serials)


@app.route("/write_in_list/<int:id>/<int:type>", methods=("POST", "GET"))
def write_in_list(id, type):
    if type == 1:
        new_item = FilmInfo(user_id=current_user.id, film_id=id)
    if type == 2:
        new_item = SerialInfo(user_id=current_user.id, serial_id=id)
    try:
        db.session.add(new_item)
        db.session.commit()
    except:
        return "При добавлении фильма/сериала произошла ошибка"
    if type == 2:
        serial = Serial.query.get(id)
        try:
            for i in range(serial.seasons):
                for j in range(serial.eps):
                    watch_el = WatchCheck(user_id=current_user.id, serial_id=id, season_num=i + 1, eps_num=j + 1)
                    db.session.add(watch_el)
            db.session.commit()
        except: "При добавлении серий произошла ошибка"
    return catalog()


@app.route("/my-films/<int:list_num>", methods=("POST", "GET"))
def my_films(list_num):

    films = Film.query.order_by(Film.id).all()
    info = FilmInfo.query.filter(FilmInfo.user_id == current_user.id).order_by(FilmInfo.film_id).all()
    if request.method == "POST":
        print(request.form['origin_list'])
        origin_list = request.form['origin_list']
        try:
            film_id = request.form['film_id']
            score = 'simple-rating'+str(int(film_id)-1)
            film = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.film_id == film_id).first()
            film.score = request.form[str(score)]
            db.session.commit()
        except:
            return redirect( url_for('my_films', list_num=origin_list))
        return redirect(url_for('my_films', list_num=origin_list))
    current_films = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.list_num == 1).order_by(
        FilmInfo.last_move.desc()).all()
    wish_list = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.list_num == 2).order_by(
        FilmInfo.last_move.desc()).all()
    archive = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.list_num == 3).order_by(
        FilmInfo.last_move.desc()).all()
    return render_template('my_films.html', films=films, info=info, list_num=list_num,
                           current_films=enumerate(current_films, start=1),
                           wish_list=enumerate(wish_list, start=1),
                           archive=enumerate(archive, start=1))


@app.route('/get_len/<int:n>', methods=['GET', 'POST'])
def get_len(n):
    l = str(n)
    eps = int(request.form['eps_'+l])
    seasons = int(request.form['seasons_'+l])
    ser_id = int(request.form['ser_id_'+l])
    print("Кол-во серий:", eps)
    print("Кол-во сезонов:", seasons)
    print("ИД сериала: ", ser_id)
    for i in range(1, seasons+1):
        for j in range(1, eps+1):
            ep = WatchCheck.query.filter(WatchCheck.user_id == current_user.id, WatchCheck.serial_id == ser_id,
                                         WatchCheck.season_num == i, WatchCheck.eps_num == j).first()
            print("ИД серии: ", ep.id)
            s = 'simple-rating'+str(ser_id)+"_" + str(i) + "_" + str(j)
            print(s)

            rate = request.form[s]
            if int(rate) == 1:
                ep.watched = True
                print("watched: ", ep.watched)
                db.session.commit()
            else:
                ep.watched = False
                print("watched: ", ep.watched)
                db.session.commit()
            print(rate)
    return ''


@app.route("/my-serials/<int:list_num>", methods=("POST", "GET"))
def my_serials(list_num):

    serials = Serial.query.order_by(Serial.id).all()
    info = SerialInfo.query.filter(SerialInfo.user_id == current_user.id).order_by(SerialInfo.serial_id).all()
    for i in info:
        print(i.serial_id)
    if request.method == "POST":
        print(request.form['origin_list'])
        origin_list = request.form['origin_list']
        try:
            serial_id = request.form['serial_id']
            score = 'simple-rating'+str(int(serial_id)-1)
            serial = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.serial_id == serial_id).first()
            serial.score = request.form[str(score)]
            db.session.commit()
        except:
            return redirect( url_for('my_serials', list_num=origin_list))
        return redirect(url_for('my_serials', list_num=origin_list))
    current_serials = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.list_num == 1).order_by(
        SerialInfo.last_move.desc()).all()
    wish_list = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.list_num == 2).order_by(
        SerialInfo.last_move.desc()).all()
    archive = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.list_num == 3).order_by(
        SerialInfo.last_move.desc()).all()

    watch_check_1 = [None] * len(current_serials)
    print("cuurent_serials:", len(watch_check_1))
    for i in range(len(watch_check_1)):
        print(i)
        watch_check_1[i] = WatchCheck.query.filter(WatchCheck.user_id == current_user.id,
                                                   WatchCheck.serial_id == current_serials[i].serial_id).order_by(WatchCheck.season_num, WatchCheck.eps_num).all()
    watch_check_2 = [None] * len(wish_list)
    print("wishlist:", len(watch_check_2))
    for i in range(len(watch_check_2)):
        print(i)
        watch_check_2[i] = WatchCheck.query.filter(WatchCheck.user_id == current_user.id,
                                                   WatchCheck.serial_id == wish_list[i].serial_id).order_by(WatchCheck.season_num, WatchCheck.eps_num).all()
    watch_check_3 = [None] * len(archive)
    print("archive:", len(watch_check_3))
    for i in range(len(watch_check_3)):
        print(i)
        watch_check_3[i] = WatchCheck.query.filter(WatchCheck.user_id == current_user.id,
                                                   WatchCheck.serial_id == archive[i].serial_id).order_by(WatchCheck.season_num, WatchCheck.eps_num).all()
    print(watch_check_3)
    return render_template('my_serials.html', serials=serials, info=info, list_num=list_num,
                           current_serials=enumerate(current_serials, start=1),
                           wish_list=enumerate(wish_list, start=1),
                           archive=enumerate(archive, start=1),  watch_check_1=watch_check_1,
                           watch_check_2=watch_check_2, watch_check_3=watch_check_3)


@app.route("/add-film", methods=("POST", "GET"))
def add_film():
    form = FilmForm()
    if form.validate_on_submit():
        film_name = form.film_name.data
        year = form.year.data
        descript = form.descript.data
        if form.link.data:
            link = form.link.data
        poster = form.poster.data
        img = poster.read()
        user_id = current_user.id
        film = Film(film_name=film_name, year=year, descript=descript, poster=img, user_id=user_id)
        try:
            db.session.add(film)
            db.session.commit()
            if form.link.data:
                info = FilmInfo(user_id=user_id, film_id=last_add(1),  link=link)
            else:
                info = FilmInfo(user_id=user_id, film_id=last_add(1))
            db.session.add(info)
            db.session.commit()
            return redirect('/')
        except:
            return "При добавлении фильма произошла ошибкаы"
    else:
        return render_template('add_film.html', form=form)


@app.route("/add-serial", methods=("POST", "GET"))
def add_serial():
    form = SerialForm()
    if form.validate_on_submit():
        serial_name = form.serial_name.data
        year = form.year.data
        descript = form.descript.data
        if form.link.data:
            link = form.link.data
        seasons = form.seasons.data
        eps = form.eps.data
        eps_length = form.eps_length.data
        poster = form.poster.data
        img = poster.read()
        user_id = current_user.id
        serial = Serial(serial_name=serial_name, year=year, descript=descript, seasons=seasons, eps=eps,
                        eps_length=eps_length, poster=img, user_id=user_id)
        try:
            db.session.add(serial)
            db.session.commit()
            if form.link.data:
                info = SerialInfo(user_id=user_id, serial_id=last_add(2), link=link)
            else:
                info = SerialInfo(user_id=user_id, serial_id=last_add(2))
            db.session.add(info)
            db.session.commit()

            for i in range(seasons):
                for j in range(eps):
                    watch_el = WatchCheck(user_id=user_id, serial_id=last_add(2), season_num=i+1, eps_num=j+1)
                    db.session.add(watch_el)
            db.session.commit()
            return redirect('/')
        except:
            return "При добавлении фильма произошла ошибкаы"
    else:
        return render_template('add_serial.html', form=form)

@app.route("/my-films/<int:id>/update", methods=("POST", "GET"))
def film_update(id):
    form = FilmForm()
    film = Film.query.get(id)
    info = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.film_id == film.id).first()

    if request.method == 'GET':
        form.descript.data = film.descript
    if form.validate_on_submit():
        film.film_name = form.film_name.data
        film.year = form.year.data
        film.descript = form.descript.data
        info.link = form.link.data
        if form.poster.data:
            img = form.poster.data
            film.poster = img.read()
        try:
            db.session.commit()
            return redirect('/')
        except:
            return "При добавлении фильма произошла ошибкаы"
    else:
        return render_template('film_update.html', form=form, film=film, info=info)


def update_eps(id, eps, seasons, new_eps, new_seasons):
    if new_eps > eps:
        for i in range(1, seasons+1):
            for j in range(eps+1, new_eps+1):
                watch_el = WatchCheck(user_id=current_user.id, serial_id=id, season_num=i, eps_num=j)
                db.session.add(watch_el)
        db.session.commit()
        eps = new_eps
    if new_seasons > seasons:
        for i in range(seasons+1, new_seasons+1):
            for j in range(1, eps+1):
                watch_el = WatchCheck(user_id=current_user.id, serial_id=id, season_num=i, eps_num=j)
                db.session.add(watch_el)
        db.session.commit()
        seasons = new_seasons
    if new_seasons < seasons:
        for i in range(new_seasons+1, seasons+1):
            season = WatchCheck.query.filter(WatchCheck.user_id == current_user.id, WatchCheck.serial_id == id,
                                                   WatchCheck.season_num == i).all()
            try:
                for ep in season:
                    db.session.delete(ep)
                db.session.commit()
            except:
                return "При удалении эпизодов произошла ошибка"
        seasons = new_seasons
    if new_eps < eps:
        for i in range(1, seasons+1):
            for j in range(new_eps + 1, eps+1):
                ep = WatchCheck.query.filter(WatchCheck.user_id == current_user.id, WatchCheck.serial_id == id,
                                                   WatchCheck.season_num == i, WatchCheck.eps_num == j).first()
                try:
                    db.session.delete(ep)
                    db.session.commit()
                except:
                    return "При удалении эпизодов произошла ошибка"


@app.route("/my-serials/<int:id>/update", methods=("POST", "GET"))
def serial_update(id):
    form = SerialForm()
    serial = Serial.query.get(id)
    info = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.serial_id == serial.id).first()

    if request.method == 'GET':
        form.descript.data = serial.descript
    if form.validate_on_submit():
        serial.serial_name = form.serial_name.data
        serial.year = form.year.data
        serial.descript = form.descript.data
        update_eps(id, serial.eps, serial.seasons, form.eps.data, form.seasons.data)
        serial.seasons = form.seasons.data
        serial.eps = form.eps.data
        serial.eps_length = form.eps_length.data
        info.link = form.link.data
        if form.poster.data:
            img = form.poster.data
            serial.poster = img.read()
        try:
            db.session.commit()
            return redirect('/')
        except:
            return "При добавлении фильма произошла ошибкаы"
    else:
        return render_template('serial_update.html', form=form, serial=serial, info=info)


def del_eps(eps):
    try:
        for el in eps:
            db.session.delete(el)
        db.session.commit()
    except:
        return "При удалении эпизодов произошла ошибка"


@app.route("/del-item/<int:id>/<int:origin_list>/<int:type>", methods=("POST", "GET"))
def del_item(id, origin_list, type):
    if type == 1:
        info = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.film_id == id).first()
        page = 'my_films'
        s = 'фильма'
    elif type == 2:
        info = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.serial_id == id).first()
        page = 'my_serials'
        s = 'сериала'
        eps = WatchCheck.query.filter(WatchCheck.user_id == current_user.id, WatchCheck.serial_id == id).all()
    try:
        db.session.delete(info)
        if type == 2:
            del_eps(eps)
        db.session.commit()
        return redirect(url_for(page, list_num=origin_list))
    except:
        return "При удалении " + s + " произошла ошибка"


@app.route("/relocate/<int:id>/<int:dest_list>/<int:origin_list>/<int:type>", methods=("POST", "GET"))
def relocate(id, dest_list, origin_list, type):
    if type == 1:
        info = FilmInfo.query.filter(FilmInfo.user_id == current_user.id, FilmInfo.film_id == id).first()
        page = 'my_films'
    elif type == 2:
        info = SerialInfo.query.filter(SerialInfo.user_id == current_user.id, SerialInfo.serial_id == id).first()
        page = 'my_serials'
    info.list_num = dest_list
    info.last_move = datetime.now()
    db.session.commit()
    return redirect(url_for(page, list_num=origin_list))

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


@app.route('/getposter/<int:id>/<int:type>')
def getposter(id, type):
    if type == 1:
        f = Film.query.all()
    elif type == 2:
        f = Serial.query.all()
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
