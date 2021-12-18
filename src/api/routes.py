"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from argon2 import PasswordHasher
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)
ph = PasswordHasher()

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route('/register', methods=['POST'])
def register_user():
    data = request.get_json(force=True)
    email = data['email']
    password = ph.hash(data['password'])

    user = User(email=email, password=password, is_active=True)
    db.session.add(user)
    db.session.commit()

    return "", 204


@api.route('/login', methods=['POST'])
def login_user():
    data = request.get_json(force=True)
    email = data['email']
    password = data['password']

    # Find the iser in the DB by email
    user = User.query.filter(User.email == email).first()
    if user is None:
        return "", 404

    #check encrypted password vs. request password
    try:
        ph.verify(user.password, password)
    except:
        return "", 403

    #Send a token to the user
    access_token = create_access_token(identity=user.id)
    return jsonify({ "token": access_token })


@api.route('/userinfo', methods=['GET'])
@jwt_required()
def user_info():
    current_user_id = get_jwt_identity()
    user = User.query.filter(User.id == current_user_id).first()

    return jsonify(user.serialize())
