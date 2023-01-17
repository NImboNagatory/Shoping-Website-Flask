from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField, FileField
from wtforms.validators import DataRequired, Length, Regexp
from flask_ckeditor import CKEditorField


class PostForm(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img = FileField("upload Image", validators=[DataRequired()])
    body = CKEditorField("Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    username = StringField("Username :", validators=[DataRequired()])
    email = EmailField("Email :", validators=[DataRequired()])
    password = PasswordField("Password :", validators=[DataRequired(), Length(min=8)])
    rep_password = PasswordField("Repeat password :", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Sign up")


class LoginForm(FlaskForm):
    email = StringField("Email :", validators=[DataRequired()])
    password = PasswordField("Password :", validators=[DataRequired(), Length(min=8), Regexp('^[\w-]+$',
                                                                                             message='Username can contain only alphanumeric characters (and _, -).')])

    submit = SubmitField("Log in")


class CommentForm(FlaskForm):
    content = CKEditorField("Add a comment:", validators=[DataRequired()])
    submit = SubmitField("Add")
