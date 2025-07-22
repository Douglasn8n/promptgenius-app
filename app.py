import os
import stripe
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURAÇÃO ---

app = Flask(__name__, static_folder='static', static_url_path='')

# Configuração do CORS
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# Configuração do Banco de Dados
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração do JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')

# Configuração do Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
app.config['STRIPE_BASIC_PLAN_ID'] = os.environ.get('STRIPE_BASIC_PLAN_ID')
app.config['STRIPE_PRO_PLAN_ID'] = os.environ.get('STRIPE_PRO_PLAN_ID')
app.config['STRIPE_WEBHOOK_SECRET'] = os.environ.get('STRIPE_WEBHOOK_SECRET')
app.config['DOMAIN_URL'] = os.environ.get('DOMAIN_URL', 'http://127.0.0.1:5000')


# Inicialização das extensões
db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MODELO DO BANCO DE DADOS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    tier = db.Column(db.String(50), nullable=False, default='gratuito')
    stripe_customer_id = db.Column(db.String(120), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- ROTAS PARA SERVIR O FRONTEND ---

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# --- ROTAS DA API DE AUTENTICAÇÃO ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Email e senha são obrigatórios."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Este email já está em uso."}), 409

    # Cria um cliente no Stripe para o novo utilizador
    try:
        customer = stripe.Customer.create(email=email)
    except Exception as e:
        return jsonify({"msg": "Erro ao criar cliente no sistema de pagamento.", "error": str(e)}), 500

    new_user = User(email=email, stripe_customer_id=customer.id)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Utilizador registado com sucesso."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity={'email': user.email, 'tier': user.tier, 'id': user.id})
        return jsonify(access_token=access_token)
    
    return jsonify({"msg": "Email ou senha inválidos."}), 401

@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user_data():
    """Retorna dados do utilizador logado, incluindo o seu tier."""
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])
    if user:
        return jsonify({
            "email": user.email,
            "tier": user.tier
        })
    return jsonify({"msg": "Utilizador não encontrado"}), 404


# --- ROTAS DA API DE PAGAMENTOS (STRIPE) ---

@app.route('/api/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    """Cria uma sessão de checkout no Stripe para o utilizador subscrever um plano."""
    data = request.get_json()
    plan_id = data.get('planId')
    
    user_identity = get_jwt_identity()
    user = User.query.get(user_identity['id'])

    if not user or not user.stripe_customer_id:
        return jsonify({"msg": "Utilizador ou cliente de pagamento não encontrado."}), 404

    try:
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': plan_id, 'quantity': 1}],
            mode='subscription',
            success_url=app.config['DOMAIN_URL'] + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=app.config['DOMAIN_URL'],
            metadata={'user_id': user.id} # Passa o ID do utilizador para o webhook
        )
        return jsonify({'sessionId': checkout_session.id, 'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': {'message': str(e)}}), 500


@app.route('/api/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """Endpoint que recebe eventos do Stripe."""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = app.config['STRIPE_WEBHOOK_SECRET']
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Lida com o evento checkout.session.completed
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        
        if user_id:
            user = User.query.get(user_id)
            if user:
                # Obtém o ID do preço da subscrição
                line_item = session.get('line_items', {}).get('data', [{}])[0]
                price_id = line_item.get('price', {}).get('id')

                # Atualiza o tier do utilizador com base no plano subscrito
                if price_id == app.config['STRIPE_BASIC_PLAN_ID']:
                    user.tier = 'basico'
                elif price_id == app.config['STRIPE_PRO_PLAN_ID']:
                    user.tier = 'profissional'
                
                db.session.commit()
                print(f"Utilizador {user.email} atualizado para o tier {user.tier}")

    return 'Success', 200


# --- EXECUÇÃO ---

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
