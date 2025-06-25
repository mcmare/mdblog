from flask import (Blueprint, render_template, request, redirect, 
                   url_for, flash, send_from_directory, abort, 
                   current_app, jsonify)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app.models.pages import Page
from app.models.user import User
from app import db
from markdown import markdown
import os
from datetime import datetime
import shutil

main = Blueprint('main', __name__)

@main.route('/')
def index():
    pages = Page.query.filter_by(parent_id=None).all()
    return render_template('index.html', pages=pages)

@main.route('/<slug>')
def page(slug):
    page = Page.query.filter_by(slug=slug).first_or_404()
    content = markdown(page.content)
    return render_template('page.html', page=page, content=content)

@main.route('/edit/<slug>', methods=['GET', 'POST'])
@login_required
def edit_page(slug):
    page = Page.query.filter_by(slug=slug).first_or_404()
    if request.method == 'POST':
        page.title = request.form.get('title')
        page.slug = request.form.get('slug')
        page.content = request.form.get('content')
        page.is_category = request.form.get('is_category') == 'on'
        db.session.commit()
        flash('Page updated successfully!', 'success')
        return redirect(url_for('main.page', slug=page.slug))
    return render_template('editor.html', page=page)

@main.route('/create', methods=['GET', 'POST'])
@login_required
def create_page():
    if request.method == 'POST':
        title = request.form.get('title')
        slug = request.form.get('slug')
        content = request.form.get('content')
        is_category = request.form.get('is_category') == 'on'
        
        if not title or not slug or not content:
            flash('Title, slug, and content are required!', 'error')
            return redirect(url_for('main.create_page'))
        
        new_page = Page(
            title=title,
            slug=slug,
            content=content,
            is_category=is_category
        )
        db.session.add(new_page)
        db.session.commit()
        flash('Page created successfully!', 'success')
        return redirect(url_for('main.page', slug=slug))
    
    return render_template('editor.html', page=None)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        pages = Page.query.filter(Page.title.contains(query) | Page.content.contains(query)).all()
    else:
        pages = []
    return render_template('search.html', pages=pages, query=query)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@main.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'location': url_for('main.uploaded_file', filename=filename)})
    return jsonify({'error': 'File type not allowed'}), 400

@main.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@main.route('/backup')
@login_required
def backup():
    backup_dir = os.path.join(current_app.root_path, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = os.path.join(backup_dir, f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
    
    if current_app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///'):
        src_db = current_app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        shutil.copy2(src_db, backup_file)
    else:
        flash('Backup currently only supported for SQLite', 'error')
        return redirect(url_for('main.index'))
    
    uploads_backup = os.path.join(backup_dir, f'uploads_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
    shutil.copytree(current_app.config['UPLOAD_FOLDER'], uploads_backup)
    
    flash('Backup created successfully', 'success')
    return redirect(url_for('main.index'))
