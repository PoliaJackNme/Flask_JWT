from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt, set_access_cookies
)
from datetime import timedelta

app = Flask(__name__)

# ======== CONFIGURATION DES COOKIES POUR LE JWT =========
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Ma clé privée
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)  # Validité de 24 heures
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # Stocker le token dans un Cookie
app.config["JWT_COOKIE_SECURE"] = False  # En développement (True en production avec HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Désactivé pour simplifier l'exemple

jwt = JWTManager(app)

@app.route('/')
def index():
    return render_template('accueil.html')

# ======== ROUTE DE CONNEXION AVEC FORMULAIRE =========
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')
    
    # Pour une soumission POST, récupérer les informations du formulaire
    username = request.form.get("username", None)
    password = request.form.get("password", None)
    
    # Vérification simple de l'utilisateur (pour cet exemple, "test" et "admin" existent)
    if (username not in ["test", "admin"]) or password != "test":
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # Définir le rôle en fonction du nom d'utilisateur
    role = "admin" if username == "admin" else "user"
    
    # Ajout du champ "roles" dans le payload du token
    additional_claims = {"roles": role}
    access_token = create_access_token(identity=username, additional_claims=additional_claims)
    
    # Création de la réponse et stockage du token dans un cookie
    response = redirect(url_for("welcome")) if username == "test" else jsonify({"msg": "Login réussi"})
    set_access_cookies(response, access_token)
    return response

# ======== ROUTE PROTÉGÉE ACCÉDANT AU TOKEN DANS LE COOKIE =========
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# ======== ROUTE ADMIN =========
@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    claims = get_jwt()
    if claims.get("roles") != "admin":
        return jsonify({"msg": "Accès interdit : vous n'avez pas les droits d'administration"}), 403
    return jsonify({"msg": "Bienvenue dans la zone admin"}), 200

# ======== ROUTE WELCOME POUR L'UTILISATEUR "test" =========
@app.route("/welcome", methods=["GET"])
@jwt_required()
def welcome():
    # Vérifier que l'utilisateur est "test" pour afficher la page spéciale
    if get_jwt_identity() != "test":
        return redirect(url_for("index"))
    return render_template('welcome.html')

if __name__ == "__main__":
    app.run(debug=True)
