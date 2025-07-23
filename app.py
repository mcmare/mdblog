from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import secrets
import markdown
import re
from PIL import Image
from threading import Thread
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Настройки почты (для разработки используем консоль)
app.config['MAIL_SERVER'] = 'smtp.yandex.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Папка для загрузки аватарок
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'
mail = Mail(app)

# Создаем папку для загрузок если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(200), default='default.png')
    is_active = db.Column(db.Boolean, default=False)
    activation_token = db.Column(db.String(100), nullable=True)
    # Для подтверждения смены email
    new_email = db.Column(db.String(120), nullable=True)
    email_change_token = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_activation_token(self):
        """Генерация токена для активации аккаунта"""
        return secrets.token_urlsafe(32)

    def get_email_change_token(self):
        """Генерация токена для смены email"""
        return secrets.token_urlsafe(32)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password')])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])


class PostForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Содержание', validators=[DataRequired()])


class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])


# Новая форма для смены аватарки и пароля
class SettingsForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    avatar = FileField('Аватарка', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Только изображения!')])
    current_password = PasswordField('Текущий пароль')
    new_password = PasswordField('Новый пароль')
    confirm_password = PasswordField('Подтвердите новый пароль', validators=[EqualTo('new_password', message='Пароли должны совпадать')])

    def validate_new_password(self, field):
        # Валидация длины пароля только если поле не пустое
        if field.data and len(field.data) < 6:
            raise ValidationError('Пароль должен быть не менее 6 символов')


# Загрузка пользователя для Flask-Login (исправленная версия)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Функция для асинхронной отправки email
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()


# Функция отправки письма активации
def send_activation_email(user):
    token = user.get_activation_token()
    user.activation_token = token
    db.session.commit()

    send_email(
        '[Мой блог] Подтвердите ваш email',
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=[user.email],
        text_body=render_template('email/activation.txt', user=user, token=token),
        html_body=render_template('email/activation.html', user=user, token=token)
    )


# Функция отправки письма для смены email
def send_email_change_email(user):
    token = user.get_email_change_token()
    user.email_change_token = token
    db.session.commit()

    send_email(
        '[Мой блог] Подтвердите смену email',
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=[user.new_email],
        text_body=render_template('email/email_change.txt', user=user, token=token),
        html_body=render_template('email/email_change.html', user=user, token=token)
    )


# Функция для сохранения аватарки
def save_avatar(form_avatar):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_avatar.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_fn)

    # Изменяем размер изображения
    output_size = (125, 125)
    i = Image.open(form_avatar)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


# Фильтры
@app.template_filter('markdown')
def markdown_to_html(markdown_text):
    """Фильтр для преобразования markdown в HTML"""
    md = markdown.Markdown(extensions=['codehilite', 'fenced_code', 'tables'])
    html = md.convert(markdown_text)
    return html


@app.template_filter('excerpt')
def get_excerpt(content, length=200):
    """Получение краткого содержания статьи"""
    # Преобразуем markdown в HTML если это markdown
    md = markdown.Markdown()
    html_content = md.convert(content)

    # Убираем HTML теги
    clean_content = re.sub(r'<[^>]+>', '', html_content)

    # Убираем лишние пробелы
    clean_content = re.sub(r'\s+', ' ', clean_content).strip()

    if len(clean_content) > length:
        # Обрезаем по последнему слову
        truncated = clean_content[:length]
        last_space = truncated.rfind(' ')
        if last_space > 0:
            truncated = truncated[:last_space]
        return truncated + '...'
    return clean_content


# Маршруты
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    # Проверяем, активирован ли аккаунт пользователя
    if not current_user.is_active:
        flash('Пожалуйста, подтвердите ваш email перед созданием статей.', 'warning')
        return redirect(url_for('index'))

    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        try:
            db.session.add(post)
            db.session.commit()
            flash('Статья успешно создана!', 'success')
            return redirect(url_for('post', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при создании статьи', 'error')
            print(f"Ошибка создания статьи: {e}")
    return render_template('create_post.html', form=form)


@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        flash('У вас нет прав для редактирования этой статьи', 'error')
        return redirect(url_for('post', post_id=post.id))

    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        try:
            db.session.commit()
            flash('Статья успешно обновлена!', 'success')
            return redirect(url_for('post', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении статьи', 'error')
            print(f"Ошибка обновления статьи: {e}")
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        flash('У вас нет прав для удаления этой статьи', 'error')
        return redirect(url_for('index'))

    try:
        db.session.delete(post)
        db.session.commit()
        flash('Статья успешно удалена!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении статьи', 'error')
        print(f"Ошибка удаления статьи: {e}")

    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверяем уникальность username и email (регистронезависимо)
        existing_user = User.query.filter(
            db.func.lower(User.username) == db.func.lower(form.username.data)
        ).first()

        if existing_user:
            flash('Пользователь с таким именем уже существует.', 'error')
            return render_template('register.html', form=form)

        existing_email = User.query.filter(
            db.func.lower(User.email) == db.func.lower(form.email.data)
        ).first()

        if existing_email:
            flash('Пользователь с таким email уже существует.', 'error')
            return render_template('register.html', form=form)

        user = User(username=form.username.data, email=form.email.data.lower())
        user.set_password(form.password.data)
        user.activation_token = user.get_activation_token()
        db.session.add(user)
        db.session.commit()

        # Отправляем письмо с подтверждением
        send_activation_email(user)

        flash('Вы успешно зарегистрировались! Пожалуйста, проверьте ваш email для подтверждения аккаунта.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/activate/<token>')
def activate_account(token):
    user = User.query.filter_by(activation_token=token).first()
    if user:
        user.is_active = True
        user.activation_token = None
        db.session.commit()
        flash('Ваш аккаунт успешно активирован! Теперь вы можете войти.', 'success')
    else:
        flash('Неверная ссылка активации.', 'error')
    return redirect(url_for('login'))


@app.route('/change-email/<token>')
def change_email(token):
    user = User.query.filter_by(email_change_token=token).first()
    if user and user.new_email:
        # Проверяем, не используется ли новый email другим пользователем
        existing_email = User.query.filter(
            db.func.lower(User.email) == db.func.lower(user.new_email)
        ).first()

        if existing_email and existing_email.id != user.id:
            flash('Этот email уже используется другим пользователем.', 'error')
        else:
            old_email = user.email
            user.email = user.new_email.lower()
            user.new_email = None
            user.email_change_token = None
            db.session.commit()
            flash('Ваш email успешно изменен!', 'success')
    else:
        flash('Неверная ссылка для смены email.', 'error')
    return redirect(url_for('settings'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        # Поиск пользователя регистронезависимо
        user = User.query.filter(
            db.func.lower(User.email) == db.func.lower(form.email.data)
        ).first()

        if user and user.check_password(form.password.data):
            if user.is_active:
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Пожалуйста, подтвердите ваш email перед входом. Проверьте вашу почту.', 'warning')
        else:
            flash('Неверный email или пароль', 'error')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    posts = Post.query.filter_by(author=current_user).order_by(Post.date_posted.desc()).all()
    return render_template('profile.html', posts=posts)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        # Проверяем, изменился ли username
        if form.username.data.lower() != current_user.username.lower():
            existing_user = User.query.filter(
                db.func.lower(User.username) == db.func.lower(form.username.data),
                User.id != current_user.id
            ).first()

            if existing_user:
                flash('Это имя пользователя уже используется другим пользователем.', 'error')
                return render_template('settings.html', form=form)
            current_user.username = form.username.data

        # Проверяем, изменился ли email
        if form.email.data.lower() != current_user.email.lower():
            # Проверяем, не используется ли новый email другим пользователем
            existing_email = User.query.filter(
                db.func.lower(User.email) == db.func.lower(form.email.data),
                User.id != current_user.id
            ).first()

            if existing_email:
                flash('Этот email уже используется другим пользователем.', 'error')
                return render_template('settings.html', form=form)

            # Сохраняем новый email во временное поле и отправляем подтверждение
            current_user.new_email = form.email.data.lower()
            send_email_change_email(current_user)
            flash('На новый email отправлено письмо для подтверждения смены адреса.', 'info')

        # Проверяем, загружена ли новая аватарка
        if form.avatar.data:
            try:
                picture_file = save_avatar(form.avatar.data)
                # Удаляем старую аватарку если это не дефолтная
                if current_user.avatar != 'default.png':
                    old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.avatar)
                    if os.path.exists(old_avatar_path):
                        os.remove(old_avatar_path)
                current_user.avatar = picture_file
                flash('Аватар успешно обновлен!', 'success')
            except Exception as e:
                flash('Ошибка при загрузке аватара', 'error')
                print(f"Ошибка загрузки аватара: {e}")

        # Проверяем, хочет ли пользователь сменить пароль
        if form.new_password.data:
            # Проверяем текущий пароль
            if not form.current_password.data:
                flash('Введите текущий пароль для смены пароля', 'error')
                return render_template('settings.html', form=form)

            if not current_user.check_password(form.current_password.data):
                flash('Неверный текущий пароль', 'error')
                return render_template('settings.html', form=form)

            # Устанавливаем новый пароль
            current_user.set_password(form.new_password.data)
            flash('Пароль успешно изменен!', 'success')

        try:
            db.session.commit()
            flash('Ваши настройки успешно обновлены!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении настроек', 'error')
            print(f"Ошибка обновления настроек: {e}")
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('settings.html', form=form)


# Создание таблиц
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)