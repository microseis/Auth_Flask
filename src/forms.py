from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import (EqualTo, InputRequired, Length, Regexp,
                                ValidationError)

from db_models import User


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(
                min=4,
                max=20,
                message="Your username should be more than 4 digits and less than 20",
            ),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Некорректное имя пользователя",
            ),
        ],
        render_kw={"placeholder": "Имя пользователя"},
    )
    password = PasswordField(
        "New Password",
        [InputRequired(), EqualTo("confirm", message="Пароли должны совпадать")],
        render_kw={"placeholder": "Введите пароль"},
    )
    confirm = PasswordField(
        "Repeat Password", render_kw={"placeholder": "Повторите пароль"}
    )

    submit = SubmitField("Зарегистрироваться")

    def validate_username(self, username):
        existing_user = User.query.filter_by(login=username.data).first()

        if existing_user:
            self.form_errors += (ValidationError("Имя пользователя уже занято!"),)
            raise ValidationError("Имя пользователя уже занято!")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(min=4, max=20),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Некорректное имя пользователя",
            ),
        ],
        render_kw={"placeholder": "Имя пользователя"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Пароль"},
    )
    submit = SubmitField("Войти")
