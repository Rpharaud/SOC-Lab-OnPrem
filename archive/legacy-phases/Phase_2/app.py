from flask import Flask, request, jsonify, Response
from functools import wraps
from flask_cors import CORS
import jwt
import datetime
import logging
from dotenv import load_dotenv
import os
import redis

load_dotenv()

# Load RSA keys
with open("private.pem", "r") as pk:
        PRIVATE_KEY = pk.read()
with open("public.pem", "r") as pubk:
        PUBLIC_KEY = pubk.read()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
CORS(app, resources={r"/*": {"origins": "http://localhost"}})  # Restrictive CORS


# Connect to Redis server
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Setup logging to file
logging.basicConfig(filename='api_events.log', level=logging.INFO)

# Simple in-memory store for rate limiting
request_counts = {}

# JWT auth decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
            jti = decoded.get("jti")
            if redis_client.get("jti"):
              return jsonify({'message': 'Token has been revoked!'}), 401
              request.user_id = decoded['user_id']
        except jwt.ExpiredSignatureError:
              return jsonify({'message': 'Token Expired!'}), 401
        except Exception:
              return jsonify({'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.before_request
def rate_limit_and_check_verb():
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1
    if request_counts[ip] > 300:
        logging.warning(f"Rate limit exceeded by {ip}")
        return jsonify({'error': 'Too many requests'}), 429

    # Check for suspicious verbs
    if request.headers.get('X-HTTP-Method-Override'):
        logging.warning(f"Suspicious HTTP Method Override by {ip}")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'admin':
        payload = {
		'user_id': 1,
		'exp': datetime.dateime.utcnow() + datetime.timedelta(minutes=30), # Time Expiration
		'jti': 'token-' + str(datetime.datetime.utcnow().timestamp()) # Unique token ID
}
        token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
        return jsonify({'token': token})
    logging.info(f"Failed login attempt for {username} from {request.remote_addr}")
    return jsonify({'message': 'Bad credentials'}), 401

@app.route('/', methods=['GET'])
def index():
    return "Welcome to the hardened test API"

@app.route('/data', methods=['GET', 'POST', 'DELETE'])
@token_required
def data():
    if request.method == 'GET':
        return jsonify({'message': 'Secure data GET.'})
    elif request.method == 'POST':
        return jsonify({'message': 'Secure data POST.'})
    elif request.method == 'DELETE':
        return jsonify({'message': 'Secure data DELETE.'})

@app.route('/user/<userid>', methods=['GET'])
@token_required
def get_user(userid):
    if int(userid) != request.user_id:
        logging.warning(f"BOLA attempt: user {request.user_id} tried to access user {userid}")
        return jsonify({'error': 'Unauthorized access'}), 403
    return jsonify({'message': f'You requested your own user info: {userid}'})

@app.route('/search', methods=['POST'])
@token_required
def search():
    query = request.json.get('query')
    if "'" in query or "--" in query:
        logging.warning(f"Potential SQLi input detected: {query}")
        return jsonify({'error': 'Potential SQLi detected'}), 400
    return jsonify({'message': f'Searched for: {query}'})

@app.route('/logout', methods=['POST'])
@token_required
def logout():
    token = request.headers.get('x-access-token')
    decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    jti = decoded.get("jti")
    exp_timestamp = decoded.get("exp")
    ttl = exp_timestamp - datetime.datetime.utcnow().timestamp()
    redis_client.setex(jti, int(ttl), "revoked")
    return jsonify({'message': 'Token revoked'})

@app.after_request
def set_security_headers(response: Response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Server'] = ''
    return response

@app.route('/vuln_test')
def vuln_test():
    return 'Vulnerable test endpoint'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
