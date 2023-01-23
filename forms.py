from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField, FileField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Regexp, Email
from flask_ckeditor import CKEditorField
from wtforms.fields import EmailField


class edit_form(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img = FileField("upload Image", validators=[DataRequired()])
    category = SelectField('Select Category:',
                           choices=['Cpu', 'Ram', 'Motherboard', 'Power Supply', 'Case', "Gpu", 'Storage Device'])
    body = CKEditorField("Content", validators=[DataRequired()])
    price = IntegerField("Price:", validators=[DataRequired()])
    submit = SubmitField("Submit Post")
class PostForm(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img = FileField("upload Image", validators=[DataRequired()])
    category = SelectField('Select Category:',
                           choices=['Cpu', 'Ram', 'Motherboard', 'Power Supply', 'Case', "Gpu", 'Storage Device'])
    body = CKEditorField("Content", validators=[DataRequired()])
    price = IntegerField("Price:", validators=[DataRequired()])
    submit = SubmitField("Submit Post")



class RegisterForm(FlaskForm):
    username = StringField("Username :", validators=[DataRequired(), Regexp('^[\w-]+$',
                                                                            message='Field only can contain alphanumeric characters (and _, -).')])
    email = EmailField("Email :", validators=[DataRequired(), Email("Incorrect email format!")])
    password = PasswordField("Password :", validators=[DataRequired(), Length(min=8), Regexp('^[\w-]+$',
                                                                                             message='Field only can contain alphanumeric characters (and _, -).')])
    rep_password = PasswordField("Repeat password :", validators=[DataRequired(), Length(min=8), Regexp('^[\w-]+$',
                                                                                                        message='Field only can contain alphanumeric characters (and _, -).')])
    submit = SubmitField("Sign up")


class LoginForm(FlaskForm):
    email = EmailField("Email :", validators=[DataRequired(), Email("Incorrect email format!")])
    password = PasswordField("Password :", validators=[DataRequired(), Length(min=8), Regexp('^[\w-]+$',
                                                                                             message='Field only can contain alphanumeric characters (and _, -).')])
    submit = SubmitField("Log in")


class CommentForm(FlaskForm):
    content = CKEditorField("Add a comment:", validators=[DataRequired(), Regexp('^[\w-]+$',
                                                                                 message='Field only can contain alphanumeric characters (and _, -).')])
    submit = SubmitField("Comment")
