from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # "writer", "reader", "admin"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)

    author = db.relationship('User', backref='comments')

class UserAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(100))
    action = db.Column(db.String(100))   # "write", "like", "read", "comment", etc.
    location = db.Column(db.String(100)) # "index", "post:5", etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, location):
    if current_user.is_authenticated:
        user_action = UserAction(user_id=current_user.id, username=current_user.username, action=action, location=location)
        db.session.add(user_action)
        db.session.commit()

@app.route('/')
def index():
    posts = Post.query.all()
    if current_user.is_authenticated:
        log_action('read', 'index')
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        # Админ-логин
        if username == "AdmWet" and request.form['password'] == "adm001":
            role = "admin"
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует')
            return redirect(url_for('register'))
        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверные данные')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_post():
    if current_user.role not in ['writer', 'admin']:
        flash('Только писатель может создавать статьи!')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, author_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        log_action('write', f'post:{post.id}')
        return redirect(url_for('index'))
    return render_template('add_post.html')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.is_authenticated:
        log_action('read', f'post:{post_id}')
    if request.method == 'POST' and current_user.is_authenticated:
        comment_content = request.form['comment']
        comment = Comment(content=comment_content, post_id=post.id, author_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        log_action('comment', f'post:{post_id}')
        return redirect(url_for('post_detail', post_id=post.id))
    comments = Comment.query.filter_by(post_id=post.id).all()
    return render_template('post_detail.html', post=post, comments=comments)

@app.route('/like_post/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.likes += 1
    db.session.commit()
    log_action('like', f'post:{post_id}')
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/dislike_post/<int:post_id>')
@login_required
def dislike_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.dislikes += 1
    db.session.commit()
    log_action('dislike', f'post:{post_id}')
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/like_comment/<int:comment_id>')
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.likes += 1
    db.session.commit()
    log_action('like', f'comment:{comment_id}')
    return redirect(url_for('post_detail', post_id=comment.post_id))

@app.route('/dislike_comment/<int:comment_id>')
@login_required
def dislike_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    comment.dislikes += 1
    db.session.commit()
    log_action('dislike', f'comment:{comment_id}')
    return redirect(url_for('post_detail', post_id=comment.post_id))

@app.route('/copy_post/<int:post_id>')
@login_required
def copy_post(post_id):
    if current_user.role not in ["writer", "admin"]:
        flash("Только писатель может копировать статьи!")
        return redirect(url_for('index'))
    post = Post.query.get_or_404(post_id)
    new_post = Post(title=post.title + " (копия)", content=post.content, author_id=current_user.id)
    db.session.add(new_post)
    db.session.commit()
    log_action('copy', f'post:{post.id}')
    return redirect(url_for('index'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.role not in ["writer", "admin"] or (post.author_id != current_user.id and current_user.role != "admin"):
        flash("Только писатель может изменять свои статьи!")
        return redirect(url_for('index'))
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        log_action('edit', f'post:{post.id}')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('edit_post.html', post=post)

@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.role != "admin":
        flash("Только админ может видеть эту страницу!")
        return redirect(url_for('index'))
    actions = UserAction.query.order_by(UserAction.timestamp.desc()).all()
    return render_template('admin_panel.html', actions=actions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
