from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import bleach
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# Configure Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key-for-dev")

# Explicitly disable SQLAlchemy track modifications warning
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure SQLAlchemy for Vercel
if os.environ.get("VERCEL_REGION"):
    # Running on Vercel - use tmp directory for SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/posts.db"
    app.instance_path = "/tmp"  # Vercel requires using /tmp
else:
    # Local development
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")

# Initialize extensions
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    posts = relationship("BlogPost", back_populates="author", cascade="all, delete-orphan")
    comments = relationship("Comment", back_populates="comment_author", cascade="all, delete-orphan")
    
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
    author = relationship("User", back_populates="posts")
    
    comments = relationship("Comment", back_populates="parent_post", cascade="all, delete-orphan")


class Comment(db.Model):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user: {e}")
        return None


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def author_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = kwargs.get('post_id')
        if not post_id:
            return abort(404)
            
        post = db.session.get(BlogPost, post_id)
        if not post:
            return abort(404)
            
        if not current_user.is_authenticated:
            return abort(403)
            
        # Allow admin OR post author
        if not current_user.is_admin() and post.author_id != current_user.id:
            return abort(403)
            
        return f(*args, **kwargs)
    return decorated_function


# Initialize the database tables
def init_db():
    with app.app_context():
        try:
            inspector = db.inspect(db.engine)
            if not inspector.has_table('users'):
                app.logger.info("Creating database tables...")
                db.create_all()
                app.logger.info("Database tables created successfully")
            else:
                app.logger.info("Database tables already exist")
        except Exception as e:
            app.logger.error(f"Database initialization error: {e}")


# Initialize DB during startup
init_db()


@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
        
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            name = form.name.data
            email = form.email.data
            password = form.password.data

            # Check if user already exists
            existing_user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
            if existing_user:
                flash("Email already registered. Try logging in.")
                return redirect(url_for('login'))

            # Create new user
            secured_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(name=name, email=email, password=secured_password)
            db.session.add(new_user)
            db.session.commit()
            
            # Log in the new user
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {e}")
            flash("An error occurred during registration. Please try again.")
    
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
        
    form = LoginForm()
    if form.validate_on_submit():
        try:
            email = form.email.data
            password = form.password.data
            
            # Find the user
            user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
            
            # Check credentials
            if user and check_password_hash(user.password, password):
                login_user(user)
                # Redirect to the page they were trying to access
                next_page = request.args.get('next')
                return redirect(next_page or url_for('get_all_posts'))
            else:
                flash("Invalid email or password")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash("An error occurred during login. Please try again.")
    
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    try:
        posts = db.session.execute(db.select(BlogPost).order_by(BlogPost.date.desc())).scalars().all()
        return render_template("index.html", all_posts=posts)
    except Exception as e:
        app.logger.error(f"Error retrieving posts: {e}")
        flash("An error occurred while loading posts.")
        return render_template("index.html", all_posts=[])


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    try:
        post = db.session.get(BlogPost, post_id)
        if not post:
            abort(404)
            
        form = CommentForm()
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("You need to login or register to comment.")
                return redirect(url_for("login", next=request.path))
                
            # Sanitize the comment text
            cleaned_comment = bleach.clean(
                form.comment_text.data,
                tags=['p', 'b', 'i', 'u', 'em', 'strong', 'a', 'br'],
                attributes={'a': ['href', 'title']},
                strip=True
            )
            
            # Create and save the comment
            new_comment = Comment(
                text=cleaned_comment,
                comment_author=current_user,
                parent_post=post
            )
            db.session.add(new_comment)
            db.session.commit()
            
            return redirect(url_for('show_post', post_id=post.id))
            
        return render_template("post.html", post=post, form=form)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in show_post: {e}")
        flash("An error occurred while loading the post.")
        return redirect(url_for('get_all_posts'))


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        try:
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
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating post: {e}")
            flash("An error occurred while creating the post.")
            
    return render_template("make-post.html", form=form)


@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
@author_only
def edit_post(post_id):
    try:
        post = db.session.get(BlogPost, post_id)
        if not post:
            abort(404)
            
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
            return redirect(url_for("show_post", post_id=post.id))
            
        return render_template("make-post.html", form=edit_form, is_edit=True, post=post)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error editing post: {e}")
        flash("An error occurred while editing the post.")
        return redirect(url_for('get_all_posts'))


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    try:
        post_to_delete = db.session.get(BlogPost, post_id)
        if not post_to_delete:
            abort(404)
            
        db.session.delete(post_to_delete)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting post: {e}")
        flash("An error occurred while deleting the post.")
        
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    msg_sent = False
    if request.method == "POST":
        # Process contact form submission (e.g., send email)
        # This is a placeholder for actual email sending logic
        msg_sent = True
        
    return render_template("contact.html", msg_sent=msg_sent)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"Server error: {e}")
    return render_template('500.html'), 500


# Catch-all route for Vercel to handle unknown routes
@app.route('/<path:path>')
def catch_all(path):
    app.logger.warning(f"Unknown route requested: {path}")
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")