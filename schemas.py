# schemas.py
from flask_marshmallow import Marshmallow
from marshmallow import fields, validate

ma = Marshmallow()

# Define the UserSchema
class UserSchema(ma.Schema):
    name = fields.String(required=True, validate=validate.Length(min=2))
    email = fields.Email(required=True)
    phone = fields.String(required=True, validate=validate.Regexp(r'^\+?1?\d{9,15}$'))
    password = fields.String(required=True, validate=validate.Length(min=6))

# Single user schema instance
user_schema = UserSchema()

# Many users schema instance
users_schema = UserSchema(many=True)
