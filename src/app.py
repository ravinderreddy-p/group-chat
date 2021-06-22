import os
from flask import Flask, request, jsonify, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, current_user
from src.models import User, db, db_setup

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["JWT_SECRET_KEY"] = "super-secret"
db_setup(app)
jwt = JWTManager(app)


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route("/", methods=["GET"])
def index():
    return "Welcome to Home page"


# Only ADMIN can add users, so this API should be accessed only by ADMIN users.
@app.route('/user', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(name=username).first()
    if user:
        return jsonify({
            "status": "fail",
            "message": user.name + " already exists"
        })

    user = User(name=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        "user": username,
        "status": "success"
    })


@app.route('/user', methods=['PATCH'])
def update_user():
    # username = request.json.get('username')
    role = request.json.get('role')
    user = User(role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({
        "message": "user updated"
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(name=username).first()
    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm = "User does not exist !!"'}
        )
    if user.check_password(password):
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token)
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


@app.route('/logout')
@jwt_required
def logout():
    return 'User logged out successfully'


@app.route("/who_am_i", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        name=current_user.name,
        role=current_user.role,
        pwd=current_user.password_hash,
    )


if __name__ == "__main__":
    app.run()
