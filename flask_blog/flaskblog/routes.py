from flaskblog import app, db, bcrypt, mail
from flask import render_template, redirect, url_for, flash, request, abort
from flaskblog.forms import (RegisterForm, LoginForm, PostForm, AccountForm,
                             RequestResetForm, ResetPasswordForm)
from flaskblog.models import User, Post
from flask_login import login_user, logout_user, current_user, login_required
import os
import secrets
from PIL import Image
from flask_mail import Message


@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(
        Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("home.html", posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash(f'account created for {form.username.data}', 'success')
        return redirect(url_for('home'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        userByEmail = User.query.filter_by(
            email=form.username_email.data).first()
        userByUsername = User.query.filter_by(
            username=form.username_email.data).first()
        if userByEmail and bcrypt.check_password_hash(userByEmail.password, form.password.data):
            login_user(userByEmail, remember=form.remember.data)
            flash(f"succesful log in {form.username_email.data}", 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        elif userByUsername and bcrypt.check_password_hash(userByUsername.password, form.password.data):
            login_user(userByUsername, remember=form.remember.data)
            flash(f"succesful log in {form.username_email.data}", 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash("uncesseccful log in", 'danger')

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def save_picture(form_picture):
    # creating random name for the image.
    random_hex = secrets.token_hex(8)
    # we need to get the images file extension so we can save it as it is.well use os for that
    # we save extension in f_extension. form_picture.filename gives full name with extension
    _, f_extension = os.path.splitext(form_picture.filename)
    # creating the new name with extension
    picture_fn = random_hex + f_extension
    # creating path where it should be saved. basically its just a string
    picture_path = os.path.join(
        app.root_path, 'static/profile_pics', picture_fn)
    # resize it tho
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    # we saved it yay
    i.save(picture_path)
    # returning picture filename with extension for db
    return picture_fn


@app.route('/account', methods=["GET", "POST"])
@login_required
def account():
    form = AccountForm()

    if form.validate_on_submit():
        if form.picture.data:
            try:
                path = os.path.join(
                    app.root_path, 'static/profile_pics', current_user.image_file)
                os.remove(path)
            except:
                pass
            picture_name = save_picture(form.picture.data)
            current_user.image_file = picture_name
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash("successfully updated", 'success')
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', form=form)


@app.route('/create_post', methods=["GET", "POST"])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data,
                    content=form.content.data, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash("Post successfully created", 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', form=form, legend="Create a post")


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)

    return render_template('post.html', post=post)


@app.route('/post/<int:post_id>/update', methods=["GET", "POST"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content

    elif request.method == "POST":
        if form.validate_on_submit():
            post.title = form.title.data
            post.content = form.content.data
            db.session.commit()
            return redirect(url_for('post', post_id=post.id))

    return render_template('create_post.html', form=form, legend="Update post")


@app.route('/post/<int:post_id>/delete', methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("post has been deleted successfully", 'success')
    return redirect(url_for('home'))


@app.route('/user/<string:username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()

    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter_by(author=user).order_by(
        Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("user.html", posts=posts, user=user)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset Request',
                  sender='FlaskBlog', recipients=[user.email])
    msg.body = f'''Too reset your password visit the following link:
{url_for('reset_token',token=token,_external=True)}
If you did not make this request then simply ignore this email and no chnages will be made!
'''
    mail.send(msg)


@app.route('/reset_password', methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash("An email has been sent with instruction to reset your password!", 'info')
        return redirect(url_for('login'))

    return render_template('reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        login_user(user)
        flash(f'Your password was updated successfully', 'success')
        return redirect(url_for('home'))
    return render_template('reset_token.html', form=form)
