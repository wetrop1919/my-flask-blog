from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # "writer", "reader", "admin", "sozdatel"
    is_banned = db.Column(db.Boolean, default=False)
    ban_expire = db.Column(db.DateTime)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy=True)

class LikeDislike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    value = db.Column(db.String(10)) # "like" or "dislike"

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
    action = db.Column(db.String(100))
    location = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = db.relationship('User', backref='support_messages')
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    response = db.Column(db.Text)
    response_timestamp = db.Column(db.DateTime)

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
        # Админ и Создатель
        if username == "AdmWet" and request.form['password'] == "adm001":
            role = "admin"
        if username == "Sozdatel" and request.form['password'] == "sozd001":
            role = "sozdatel"
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
            # Проверка на бан
            if user.is_banned:
                if user.ban_expire and user.ban_expire < datetime.utcnow():
                    user.is_banned = False
                    user.ban_expire = None
                    db.session.commit()
                else:
                    flash('Ваш аккаунт забанен!')
                    return render_template('login.html')
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
    if current_user.is_banned:
        flash('Вы забанены и не можете писать!')
        return redirect(url_for('index'))
    if current_user.role not in ['writer', 'admin', 'sozdatel']:
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
    # кто лайкнул/дизлайкнул
    likes = LikeDislike.query.filter_by(post_id=post.id, value="like").all()
    dislikes = LikeDislike.query.filter_by(post_id=post.id, value="dislike").all()
    return render_template('post_detail.html', post=post, comments=comments, likes=likes, dislikes=dislikes)

@app.route('/like_post/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing = LikeDislike.query.filter_by(post_id=post.id, user_id=current_user.id).first()
    if existing and existing.value == "like":
        flash('Вы уже поставили лайк!')
    else:
        if existing:
            db.session.delete(existing)
        like = LikeDislike(post_id=post.id, user_id=current_user.id, value="like")
        db.session.add(like)
        post.likes += 1
        db.session.commit()
        log_action('like', f'post:{post.id}')
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/dislike_post/<int:post_id>')
@login_required
def dislike_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing = LikeDislike.query.filter_by(post_id=post.id, user_id=current_user.id).first()
    if existing and existing.value == "dislike":
        flash('Вы уже поставили дизлайк!')
    else:
        if existing:
            db.session.delete(existing)
        dislike = LikeDislike(post_id=post.id, user_id=current_user.id, value="dislike")
        db.session.add(dislike)
        post.dislikes += 1
        db.session.commit()
        log_action('dislike', f'post:{post.id}')
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
    if current_user.role not in ["writer", "admin", "sozdatel"]:
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
    if current_user.role not in ["writer", "admin", "sozdatel"] or (post.author_id != current_user.id and current_user.role not in ["admin", "sozdatel"]):
        flash("Только писатель может изменять свои статьи!")
        return redirect(url_for('index'))
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        log_action('edit', f'post:{post.id}')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.role != 'sozdatel':
        flash('Удалять может только Создатель!')
        return redirect(url_for('index'))
    db.session.delete(post)
    db.session.commit()
    flash('Статья удалена!')
    return redirect(url_for('index'))

@app.route('/admin_panel')
@login_required
def admin_panel():
    if current_user.role not in ["admin", "sozdatel"]:
        flash("Только админ или создатель может видеть эту страницу!")
        return redirect(url_for('index'))
    actions = UserAction.query.order_by(UserAction.timestamp.desc()).all()
    users = User.query.all()
    return render_template('admin_panel.html', actions=actions, users=users)

@app.route('/admin_errors')
@login_required
def admin_errors():
    if current_user.role != 'admin':
        flash('Только админ может видеть эту страницу!')
        return redirect(url_for('index'))
    messages = SupportMessage.query.order_by(SupportMessage.timestamp.desc()).all()
    return render_template('admin_errors.html', messages=messages)

@app.route('/sozdatel_support', methods=['GET', 'POST'])
@login_required
def sozdatel_support():
    if current_user.role != 'sozdatel':
        flash('Только Создатель может видеть эту страницу!')
        return redirect(url_for('index'))
    messages = SupportMessage.query.order_by(SupportMessage.timestamp.desc()).all()
    if request.method == 'POST':
        msg_id = int(request.form['msg_id'])
        response = request.form['response']
        msg = SupportMessage.query.get(msg_id)
        msg.response = response
        msg.response_timestamp = datetime.utcnow()
        db.session.commit()
        flash('Ответ отправлен!')
        return redirect(url_for('sozdatel_support'))
    return render_template('sozdatel_support.html', messages=messages)

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    if current_user.role not in ['reader', 'writer']:
        flash('Только читатели и писатели могут отправлять обращения!')
        return redirect(url_for('index'))
    if request.method == 'POST':
        content = request.form['content']
        msg = SupportMessage(sender_id=current_user.id, content=content)
        db.session.add(msg)
        db.session.commit()
        flash('Ваше сообщение отправлено!')
        return redirect(url_for('index'))
    user_messages = SupportMessage.query.filter_by(sender_id=current_user.id).order_by(SupportMessage.timestamp.desc()).all()
    return render_template('support.html', user_messages=user_messages)

@app.route('/accounts')
@login_required
def accounts():
    if current_user.role != 'sozdatel':
        flash('Только Создатель видит все аккаунты!')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('accounts.html', users=users)

@app.route('/ban_user/<int:user_id>')
@login_required
def ban_user(user_id):
    if current_user.role != 'sozdatel':
        flash('Только Создатель может банить!')
        return redirect(url_for('accounts'))
    user = User.query.get_or_404(user_id)
    if user.role == 'sozdatel':
        flash('Нельзя банить Создателя!')
        return redirect(url_for('accounts'))
    user.is_banned = True
    db.session.commit()
    flash('Пользователь забанен!')
    return redirect(url_for('accounts'))

@app.route('/unban_user/<int:user_id>')
@login_required
def unban_user(user_id):
    if current_user.role != 'sozdatel':
        flash('Только Создатель может разбанивать!')
        return redirect(url_for('accounts'))
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_expire = None
    db.session.commit()
    flash('Пользователь разбанен!')
    return redirect(url_for('accounts'))

@app.route('/admin_ban/<int:user_id>')
@login_required
def admin_ban(user_id):
    if current_user.role != 'admin':
        flash('Только админ может временно банить!')
        return redirect(url_for('admin_panel'))
    user = User.query.get_or_404(user_id)
    if user.role in ['admin', 'sozdatel']:
        flash('Нельзя банить админа или создателя!')
        return redirect(url_for('admin_panel'))
    user.is_banned = True
    user.ban_expire = datetime.utcnow() + timedelta(days=1)
    db.session.commit()
    flash('Пользователь временно забанен!')
    return redirect(url_for('admin_panel'))

@app.route('/admin_unban/<int:user_id>')
@login_required
def admin_unban(user_id):
    if current_user.role != 'admin':
        flash('Только админ может разбанивать!')
        return redirect(url_for('admin_panel'))
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_expire = None
    db.session.commit()
    flash('Пользователь разбанен!')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
