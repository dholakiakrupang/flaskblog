from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
import os
import secrets
from flask_mail import Message
from forms import RequestResetForm, ResetPasswordForm 
from flask import redirect, url_for, flash, jsonify
from models import db, User, Post , Comment
from forms import RegistrationForm, LoginForm, PostForm , UpdateProfileForm
from flask_mail import Mail


# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'krupangdholakia143@gmail.com'
app.config['MAIL_PASSWORD'] = 'ojkn jbyi skhz aust'

mail = Mail(app)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except ValueError:
        return None

def save_profile_picture(form_picture):
    import os
    from flask import current_app
    from PIL import Image

    UPLOAD_FOLDER = os.path.join(current_app.root_path, 'static/profile_pics')
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)  # Create the folder if it doesn't exist

    picture_path = os.path.join(UPLOAD_FOLDER, form_picture.filename)
    form_picture.save(picture_path)

    return form_picture.filename


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.username = form.username.data
        current_user.email = form.email.data
        
        if form.picture.data:
            picture_file = save_profile_picture(form.picture.data)
            current_user.profile_picture = picture_file  # Ensure correct field name
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))

    # Pre-fill form with current user details
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.username.data = current_user.username
    form.email.data = current_user.email
    
    return render_template('profile.html', form=form, user=current_user)

@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)  # Get page number
    search_query = request.args.get('q', '')  # Get search query

    # Filter posts based on search query
    if search_query:
        posts = Post.query.filter(Post.title.ilike(f"%{search_query}%")) \
                .order_by(Post.timestamp.desc()) \
                .paginate(page=page, per_page=3, error_out=False)
    else:
        posts = Post.query.order_by(Post.timestamp.desc()) \
                .paginate(page=page, per_page=3, error_out=False)

    return render_template('home.html', posts=posts, search_query=search_query)



# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        filename = None
        if form.thumbnail.data:
            file = form.thumbnail.data
            filename = secure_filename(file.filename)

            # Ensure the upload directory exists
            upload_folder = os.path.join(app.root_path, 'static/uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            # Save the file
            file.save(os.path.join(upload_folder, filename))

        # Create and save the post
        post = Post(
            title=form.title.data,
            content=form.content.data,
            author_id=current_user.id,
            thumbnail=filename
        )
        db.session.add(post)
        db.session.commit()
        
        flash('Post created successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('add_post.html', form=form)

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.timestamp.desc()).all()

    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('You need to be logged in to comment.', 'danger')
            return redirect(url_for('login'))

        comment_content = request.form.get('comment')
        if comment_content:
            new_comment = Comment(content=comment_content, user_id=current_user.id, post_id=post.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Your comment has been added!', 'success')
            return redirect(url_for('post_detail', post_id=post.id))

    return render_template('post_detail.html', post=post, comments=comments)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Restrict access: Only the author can edit
    if post.author != current_user:
        abort(403)  # Forbidden access

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']

        # Check if a new thumbnail is uploaded
        if "thumbnail" in request.files:
            file = request.files["thumbnail"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                
                # Save new thumbnail
                file.save(file_path)
                
                # Remove old thumbnail if it exists
                if post.thumbnail:
                    old_file_path = os.path.join(app.config["UPLOAD_FOLDER"], post.thumbnail)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                post.thumbnail = filename  # Update the post with the new thumbnail filename

        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post_detail', post_id=post.id))

    return render_template('update_post.html', post=post)

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Restrict access: Only the author can delete
    if post.author != current_user:
        abort(403)

    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

def send_reset_email(user):
    token = secrets.token_hex(16)  # Generate a random token
    user.reset_token = token  # Store it in the User model
    db.session.commit()

    msg = Message("Password Reset Request", sender="noreply@demo.com", recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email.
'''
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash("An email has been sent with instructions to reset your password.", "info")
        else:
            flash("No account found with that email.", "danger")
        return redirect(url_for("login"))

    return render_template("reset_request.html", form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid or expired token", "warning")
        return redirect(url_for("reset_request"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user.password = hashed_password
        user.reset_token = None  # Clear the token after reset
        db.session.commit()
        flash("Your password has been updated! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_token.html", form=form)

@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user in post.likes:
        post.likes.remove(current_user)  # Unlike if already liked
    else:
        post.likes.append(current_user)  # Like the post
    db.session.commit()
    return jsonify({"likes": post.like_count()})



# Run Flask App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
