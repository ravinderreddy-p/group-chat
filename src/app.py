import os
from flask import Flask, request, jsonify, make_response, abort
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
@jwt_required()
def new_user():
    role = current_user.role
    if role == 'admin':
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
    return jsonify({
        "status": "fail",
        "message": "only admin can add new user"
    })


@app.route('/user', methods=['PATCH'])
@jwt_required()
def update_user():
    role = current_user.role
    if role == 'admin':
        body = request.get_json()
        if 'username' not in body:
            abort(404)
        user = User.query.filter_by(name=body['username']).one_or_none()
        if user is None:
            abort(404)
        if 'role' in body:
            user.role = body['role']
        if 'password' in body:
            password = body['password']
            user.password_hash = user.generate_password_hash(password)

        db.session.add(user)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "user updated"
        })
    return jsonify({
        "status": "fail",
        "message": "Only Admin can update user details"
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
@jwt_required()
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
