import os
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURAÇÃO ---

app = Flask(__name__, static_folder='static')

# Configuração do CORS para permitir requisições da API
# A API continuará acessível de qualquer origem
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# Configuração do Banco de Dados (SQLite)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração do JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'uma-chave-secreta-muito-forte-padrao')

# Inicialização das extensões
db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MODELO DO BANCO DE DADOS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    tier = db.Column(db.String(50), nullable=False, default='gratuito')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- ROTAS PARA SERVIR O FRONTEND ---

@app.route('/')
def serve_index():
    """Serve o arquivo principal do frontend."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve outros arquivos estáticos (se houver, como CSS ou imagens)."""
    # Esta rota é um "catch-all" para garantir que o refresh da página funcione.
    # Se o caminho não for um arquivo, ele serve o index.html para o roteamento do lado do cliente.
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


# --- ROTAS DA API ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Email e senha são obrigatórios."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Este email já está em uso."}), 409

    new_user = User(email=email)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Usuário registrado com sucesso."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity={'email': user.email, 'tier': user.tier})
        return jsonify(access_token=access_token)
    
    return jsonify({"msg": "Email ou senha inválidos."}), 401

# --- EXECUÇÃO ---

# Cria o banco de dados e as tabelas se não existirem
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Esta parte é para rodar localmente. O Render usará o Gunicorn.
    app.run(debug=False)
