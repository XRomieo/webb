from datetime import date
from flask import Flask, abort, render_template, redirect, request, url_for, flash
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import bleach
from dotenv import load_dotenv
import os

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# Configure Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key-for-dev")

# Configure SQLAlchemy for Vercel
if os.environ.get("VERCEL_REGION"):
    # Running on Vercel - use tmp directory for SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///tmp/posts.db"
    app.instance_path = "/tmp"  # Vercel requires using /tmp
else:
    # Local development
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")

ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    def is_admin(self):
        return self.id == 1


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship(back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post", cascade="all, delete")

class Comment(db.Model):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    parent_post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def author_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = kwargs.get('post_id') or (args[0] if args else None)
        post = db.session.get(BlogPost, post_id)

        if not current_user.is_authenticated:
            abort(403)

        # ✅ Allow admin OR post author
        if current_user.id != 1 and post.author_id != current_user.id:
            abort(403)

        return f(*args, **kwargs)
    return decorated_function

# Create tables - with safeguard against multiple initialization
with app.app_context():
    try:
        # Check if tables already exist before creating
        inspector = db.inspect(db.engine)
        if not inspector.has_table('users'):
            db.create_all()
    except Exception as e:
        print(f"Error with database: {e}")


@app.route('/register',methods=["POST","GET"])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Try logging in.")
            return redirect(url_for('login'))


        secured_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        new_user = User(name=name, email=email, password=secured_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    else:
        print(form.errors)
    return render_template("register.html" , form=form)



@app.route('/login',methods=["POST","GET"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        password=form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("Incorrect email or password")
            return redirect(url_for('login'))
    return render_template("login.html" , form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))



@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = db.session.get(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
            
        cleaned_comment = bleach.clean(form.comment_text.data,tags=['p', 'b', 'i', 'u', 'em', 'strong', 'a', 'br'],attributes={'a': ['href', 'title']},strip=True)
        new_comment = Comment(text=cleaned_comment,comment_author=current_user, parent_post=post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))
    return render_template("post.html", post=post, form=form)

@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    if not current_user.is_admin():
        abort(403)
        
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)



@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@author_only
def edit_post(post_id):
    post = db.session.get(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=edit_form, is_edit=True, post=post)



@app.route("/delete/<int:post_id>")
@author_only
def delete_post(post_id):
    post_to_delete = db.session.get(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        # Process the form data here (e.g., send an email)
        return render_template("contact.html", msg_sent=True)
    return render_template("contact.html", msg_sent=False)


# This handler is needed for Vercel
@app.route('/<path:path>')
def catch_all(path):
    return redirect(url_for('get_all_posts'))

# Only run the app if this file is executed directly (not imported)
if __name__ == "__main__":
    app.run(debug=False)