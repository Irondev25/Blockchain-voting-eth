from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.fields.simple import SubmitField

class EmailForm(FlaskForm):
    email = StringField('Email')
    submit = SubmitField('Send Private Key')