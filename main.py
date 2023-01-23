from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, flash, url_for, request
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sessionstore import Session
from flask_session_captcha import FlaskSessionCaptcha
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_gravatar import Gravatar
from sqlalchemy.orm import relationship
from forms import RegisterForm, PostForm, LoginForm, CommentForm, edit_form
from datetime import date
from pymongo import MongoClient
from os import path, remove

db = SQLAlchemy()

app = Flask(__name__)

mongoClient = MongoClient('localhost', 27017)
app.config['CAPTCHA_ENABLE'] = True
app.config['CAPTCHA_LENGTH'] = 5
app.config['CAPTCHA_WIDTH'] = 160
app.config['CAPTCHA_HEIGHT'] = 60
app.config['SESSION_MONGODB'] = mongoClient
app.config['SESSION_TYPE'] = 'mongodb'
Session(app)
captcha = FlaskSessionCaptcha(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.session_protection = "strong"

app.config['SECRET_KEY'] = "5d5fr8f2s2w8o4l5r1c4t8w8p5x5g48t56s"

ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager.init_app(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100), unique=True)
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True, unique=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), nullable=False)
    category = db.Column(db.String(250), nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    img = db.Column(db.Text, nullable=False)

    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, unique=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False, unique=True)
    parent_post = relationship("Post", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    comment_time = db.Column(db.String, nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def index():
    posts = Post.query.all()
    return render_template("index.html", all_posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register_user():
    if current_user.is_authenticated:
        return login_manager.unauthorized()
    form = RegisterForm()
    if form.validate_on_submit():
        check = User.query.filter_by(email=escape(form.email.data)).first()
        check2 = User.query.filter_by(name=escape(form.username.data)).first()
        if check is None and check2 is None:
            if escape(form.password.data) == escape(form.rep_password.data):
                password_hash = generate_password_hash(escape(form.password.data), method='pbkdf2:sha256',
                                                       salt_length=8)
                new_user = User(
                    email=escape(form.email.data),
                    password=password_hash,
                    name=escape(form.username.data)
                )
                db.session.add(new_user)
                db.session.commit()
            else:
                flash("Password Fields dont match")
            return redirect("/login")
        else:
            flash('Email/name already in use!')
            return render_template("register.html", form=form)
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return login_manager.unauthorized()
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=escape(form.email.data)).first()
        if user and check_password_hash(user.password, escape(form.password.data)):
            login_user(user)
            return redirect(url_for("my_posts"))
        else:
            flash("incorrect      Email/Password")
    return render_template("login.html", form=form)


Upload_folder = './static/user_upload'
app.config['UPLOAD_FOLDER'] = Upload_folder


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    form = PostForm()
    if form.validate_on_submit():
        img_data = form.img.data
        img_path = path.join(app.config['UPLOAD_FOLDER'], img_data.filename)
        img_data.save(img_path)
        new_post = Post(
            title=escape(form.title.data),
            subtitle=escape(form.subtitle.data),
            body=form.body.data,
            img=img_data.filename,
            author=current_user,
            category=escape(form.category.data),
            date=date.today().strftime("%B %d, %Y"),
            price=escape(form.price.data)
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    post = Post.query.get(escape(post_id))
    if int(current_user.get_id()) == int(post.author_id):
        E_form = edit_form()
        if E_form.validate_on_submit():
            remove(f"static/user_upload/{post.img}")
            img_data = E_form.img.data
            img_path_e = path.join(app.config['UPLOAD_FOLDER'], img_data.filename)
            img_data.save(img_path_e)
            post.title = escape(E_form.title.data)
            post.subtitle = escape(E_form.subtitle.data)
            post.img = img_data.filename
            post.body = E_form.body.data
            post.category = E_form.category.data
            post.price = E_form.price.data
            db.session.commit()

            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=E_form)
    else:
        return redirect("/")


@app.route("/personal_page")
@login_required
def my_posts():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    query = db.session.execute(db.select(Post).filter_by(author_id=current_user.get_id())).scalars()
    return render_template("my_posts.html", posts=query)


@app.route("/personal_page/<int:author_id>")
def p_all_posts(author_id):
    if not current_user.is_authenticated:
        flash("Login to see this person's posts!")
        return redirect(url_for("login"))
    query = db.session.execute(db.select(Post).filter_by(author_id=escape(author_id))).scalars()
    return render_template("someones_posts.html", posts=query)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    post_to_delete = Post.query.get(escape(post_id))
    if post_to_delete is not None:
        if int(current_user.get_id()) == post_to_delete.author_id:
            img_path = post_to_delete.img
            remove(f"static/user_upload/{img_path}")
            db.session.delete(post_to_delete)
            db.session.commit()
            return redirect(url_for("p_all_posts", author_id=current_user.get_id()))
        else:
            return redirect(url_for("index"))
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    if not current_user.is_authenticated:
        flash("Login to see the post")
        return redirect(url_for("login"))
    form = CommentForm()
    if request.method == "POST":
        if form.validate_on_submit():
            if current_user.is_authenticated:
                if captcha.validate():
                    data = Comment(
                        text=escape(form.content.data),
                        post_id=escape(post_id),
                        author_id=int(current_user.get_id()),
                        comment_time=date.today().strftime("%B %d, %Y")
                    )
                    db.session.add(data)
                    db.session.commit()
                    return redirect(request.path)
                else:
                    flash("Captcha input incorrect!")
                    return redirect(f"/post/{escape(post_id)}")
            else:
                flash("You need to login or register")
                return redirect(url_for("register_user"))

    requested_post = Post.query.get(escape(post_id))
    author = False
    if requested_post is None:
        return redirect("/404")
    if (current_user.get_id()) == requested_post.author_id:
        author = True
    print(requested_post.img)
    return render_template("post.html", post=requested_post, author=author, form=form, gravatar=gravatar)


@app.route('/logout')
@login_required
def logout():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    logout_user()
    return redirect(url_for("login"))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def server_down(e):
    return render_template('500.html'), 500


@login_manager.unauthorized_handler
def unauthorized():
    return redirect("/")


@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Content-Security-Policy'] = "img-src 'self'"
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    response.headers['Content-Security-Policy'] = "style-src 'self'"
    response.headers['Content-Security-Policy'] = "connect-src 'self'"
    response.headers['Content-Security-Policy'] = "object-src 'self'"
    response.headers['Content-Security-Policy'] = "frame-src 'self'"
    response.headers['Content-Security-Policy'] = "child-src 'self'"
    response.headers['Content-Security-Policy'] = "form-action 'self'"
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    response.headers['Content-Security-Policy'] = "base-uri 'self'"
    response.headers['Content-Security-Policy'] = "worker-src 'none'"
    response.headers['Content-Security-Policy'] = "manifest-src 'none'"
    response.headers['Content-Security-Policy'] = "prefetch-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.set_cookie('snakes', '3', max_age=600)
    response.set_cookie('username', 'flask', secure=True, httponly=True, samesite='Lax')
    return response


if __name__ == "__main__":
    app.run(host='192.168.0.110', port=5000, debug=True)
