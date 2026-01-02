import os
import secrets
import hashlib
import jwt
import subprocess
import docker
import redis
import psutil
import asyncio
import aiohttp
import uuid
import json
import base64
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, request, jsonify, render_template_string, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import bleach
import re
import logging
from logging.handlers import RotatingFileHandler
import socket
import sys
import platform
from threading import Thread
import queue
from prometheus_flask_exporter import PrometheusMetrics
import pytz
from dateutil import parser
import zipfile
import tarfile
import io

# ==================== CONFIGURATION ====================
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(64))
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///bot_hosting.db')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    DOCKER_NETWORK = os.environ.get('DOCKER_NETWORK', 'botnet')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_FOLDER = '/tmp/bot_uploads'
    ALLOWED_EXTENSIONS = {'py', 'txt', 'json', 'yml', 'yaml', 'env'}
    SESSION_TIMEOUT = 3600  # 1 hour
    API_RATE_LIMIT = "1000 per day, 200 per hour"
    JWT_ALGORITHM = "HS512"
    ENCRYPTION_KEY = Fernet.generate_key()
    BACKUP_INTERVAL = 3600  # 1 hour
    MONITORING_INTERVAL = 60  # 1 minute
    
    # Security headers
    CSP = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'font-src': "'self' data:",
        'img-src': "'self' data: https:"
    }

# ==================== INITIALIZATION ====================
app = Flask(__name__, static_folder=None)
app.config.from_object(Config)

# Security middleware
CORS(app, resources={r"/api/*": {"origins": ["https://yourdomain.com"]}})
Talisman(app, content_security_policy=Config.CSP, force_https=False)

# Monitoring
metrics = PrometheusMetrics(app)
metrics.info('app_info', 'Telegram Bot Hosting Platform', version='2.0.0')

# Rate limiting with Redis
redis_client = redis.from_url(Config.REDIS_URL)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.API_RATE_LIMIT],
    storage_uri=Config.REDIS_URL,
    strategy="fixed-window",
    default_limits_exempt_when=lambda: request.path == '/health'
)

# Database setup with SQLAlchemy
Base = declarative_base()
engine = create_engine(Config.DATABASE_URL)
Session = sessionmaker(bind=engine)

# Docker client
try:
    docker_client = docker.from_env()
    docker_client.ping()
    DOCKER_AVAILABLE = True
except:
    docker_client = None
    DOCKER_AVAILABLE = False

# Logging
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(client_ip)s]'
)
log_handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Bot worker queue
bot_queue = queue.Queue(maxsize=1000)
bot_workers = []

# ==================== DATABASE MODELS ====================
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    api_key = Column(String(64), unique=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(64))
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(32))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    subscription_tier = Column(String(20), default='free')  # free, pro, enterprise
    subscription_ends = Column(DateTime)
    bots = relationship('Bot', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = relationship('AuditLog', backref='user', lazy='dynamic')
    
class Bot(Base):
    __tablename__ = 'bots'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    bot_name = Column(String(64), nullable=False, index=True)
    bot_token_encrypted = Column(Text, nullable=False)
    webhook_url = Column(String(256))
    container_id = Column(String(64), index=True)
    container_name = Column(String(64))
    image_name = Column(String(256))
    status = Column(String(20), default='stopped', index=True)  # stopped, running, error, deploying
    cpu_limit = Column(Integer, default=50)  # CPU percentage
    memory_limit = Column(Integer, default=128)  # MB
    storage_limit = Column(Integer, default=512)  # MB
    network_mode = Column(String(20), default='bridge')
    restart_policy = Column(String(20), default='unless-stopped')
    environment_vars = Column(Text)  # JSON encoded
    volumes = Column(Text)  # JSON encoded
    ports = Column(Text)  # JSON encoded
    health_check = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_activity = Column(DateTime)
    metrics = relationship('BotMetrics', backref='bot', lazy='dynamic', cascade='all, delete-orphan')
    backups = relationship('BotBackup', backref='bot', lazy='dynamic', cascade='all, delete-orphan')
    
class BotMetrics(Base):
    __tablename__ = 'bot_metrics'
    id = Column(Integer, primary_key=True)
    bot_id = Column(Integer, ForeignKey('bots.id'), nullable=False, index=True)
    cpu_usage = Column(Integer)  # percentage
    memory_usage = Column(Integer)  # MB
    network_rx = Column(Integer)  # bytes
    network_tx = Column(Integer)  # bytes
    disk_usage = Column(Integer)  # bytes
    request_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    uptime = Column(Integer)  # seconds
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)
    
class BotBackup(Base):
    __tablename__ = 'bot_backups'
    id = Column(Integer, primary_key=True)
    bot_id = Column(Integer, ForeignKey('bots.id'), nullable=False, index=True)
    backup_type = Column(String(20))  # full, incremental, config
    backup_data = Column(Text)  # Encrypted backup
    backup_size = Column(Integer)  # bytes
    checksum = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    action = Column(String(64), nullable=False)
    resource_type = Column(String(32))
    resource_id = Column(Integer)
    ip_address = Column(String(45))
    user_agent = Column(String(256))
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
class APIKey(Base):
    __tablename__ = 'api_keys'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    key_name = Column(String(64))
    key_hash = Column(String(128), unique=True, nullable=False, index=True)
    permissions = Column(Text)  # JSON encoded
    last_used = Column(DateTime)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
# Create tables
Base.metadata.create_all(engine)

# ==================== ENCRYPTION SERVICE ====================
class EncryptionService:
    def __init__(self):
        self.fernet = Fernet(Config.ENCRYPTION_KEY)
    
    def encrypt(self, data: str) -> str:
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def hash_api_key(self, api_key: str) -> str:
        return hashlib.sha512(api_key.encode()).hexdigest()
    
    def generate_totp_secret(self) -> str:
        return base64.b32encode(os.urandom(20)).decode()
    
encryption_service = EncryptionService()

# ==================== VALIDATION SERVICE ====================
class ValidationService:
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_bot_token(token: str) -> bool:
        pattern = r'^\d+:[A-Za-z0-9_-]{35}$'
        return bool(re.match(pattern, token))
    
    @staticmethod
    def validate_webhook_url(url: str) -> bool:
        pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        if not text:
            return ''
        text = str(text)[:max_length]
        text = bleach.clean(text, tags=[], strip=True)
        return text.strip()
    
validation_service = ValidationService()

# ==================== AUTHENTICATION SERVICE ====================
class AuthService:
    @staticmethod
    def generate_jwt(user_id: int, is_2fa: bool = False) -> str:
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow(),
            'is_2fa': is_2fa,
            'jti': str(uuid.uuid4())
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    
    @staticmethod
    def verify_jwt(token: str) -> dict:
        try:
            payload = jwt.decode(
                token, 
                Config.SECRET_KEY, 
                algorithms=[Config.JWT_ALGORITHM],
                options={'require': ['exp', 'iat', 'user_id']}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
    
    @staticmethod
    def require_auth(require_2fa: bool = False):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'Authorization header missing or invalid'}), 401
                
                token = auth_header[7:]
                try:
                    payload = AuthService.verify_jwt(token)
                    if require_2fa and not payload.get('is_2fa'):
                        return jsonify({'error': '2FA required'}), 403
                    
                    # Check if user exists and is active
                    session = Session()
                    user = session.query(User).filter_by(id=payload['user_id']).first()
                    session.close()
                    
                    if not user or not user.is_verified:
                        return jsonify({'error': 'User not found or not verified'}), 401
                    
                    return f(user, *args, **kwargs)
                except ValueError as e:
                    return jsonify({'error': str(e)}), 401
            return decorated
        return decorator

auth_service = AuthService()

# ==================== BOT DEPLOYMENT SERVICE ====================
class BotDeploymentService:
    def __init__(self):
        self.docker_client = docker_client
        self.base_image = "python:3.11-slim"
        self.worker_count = 3
        
    async def deploy_bot(self, bot_id: int, code: str, dependencies: str = None):
        """Deploy bot in isolated Docker container"""
        try:
            session = Session()
            bot = session.query(Bot).filter_by(id=bot_id).first()
            if not bot:
                return {'success': False, 'error': 'Bot not found'}
            
            # Update bot status
            bot.status = 'deploying'
            session.commit()
            
            # Generate Dockerfile
            dockerfile = self._generate_dockerfile(code, dependencies)
            
            # Create Docker image
            image_tag = f"bot-{bot_id}:{datetime.now().strftime('%Y%m%d%H%M%S')}"
            await self._build_image(dockerfile, image_tag)
            
            # Decrypt bot token
            token = encryption_service.decrypt(bot.bot_token_encrypted)
            
            # Prepare environment variables
            env_vars = {
                'BOT_TOKEN': token,
                'BOT_NAME': bot.bot_name,
                'PYTHONUNBUFFERED': '1'
            }
            
            if bot.environment_vars:
                env_vars.update(json.loads(bot.environment_vars))
            
            # Prepare volumes
            volumes = {}
            if bot.volumes:
                volumes = json.loads(bot.volumes)
            
            # Create and start container
            container = await self._create_container(
                image_tag=image_tag,
                bot_name=bot.bot_name,
                env_vars=env_vars,
                volumes=volumes,
                cpu_limit=bot.cpu_limit,
                memory_limit=bot.memory_limit * 1024 * 1024  # Convert MB to bytes
            )
            
            # Update bot record
            bot.container_id = container.id
            bot.container_name = container.name
            bot.image_name = image_tag
            bot.status = 'running'
            bot.updated_at = datetime.utcnow()
            session.commit()
            
            # Start monitoring
            asyncio.create_task(self._monitor_bot(bot_id))
            
            return {'success': True, 'container_id': container.id}
            
        except Exception as e:
            app.logger.error(f"Deployment failed for bot {bot_id}: {str(e)}")
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    async def stop_bot(self, bot_id: int):
        """Stop bot container"""
        try:
            session = Session()
            bot = session.query(Bot).filter_by(id=bot_id).first()
            
            if bot.container_id:
                container = self.docker_client.containers.get(bot.container_id)
                container.stop()
                container.remove()
            
            bot.status = 'stopped'
            bot.container_id = None
            session.commit()
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def _generate_dockerfile(self, code: str, dependencies: str) -> str:
        """Generate optimized Dockerfile for bot"""
        deps = dependencies or "python-telegram-bot>=20.0 aiohttp"
        
        dockerfile = f"""
FROM {self.base_image}
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    python3-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bot code
COPY bot.py .
COPY config.json .

# Create non-root user
RUN useradd -m -u 1000 botuser && chown -R botuser:botuser /app
USER botuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('localhost', 8080))" || exit 1

CMD ["python", "bot.py"]
"""
        
        return dockerfile
    
    async def _build_image(self, dockerfile: str, tag: str):
        """Build Docker image asynchronously"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self.docker_client.images.build(
                fileobj=io.BytesIO(dockerfile.encode()),
                tag=tag,
                rm=True,
                forcerm=True
            )
        )
    
    async def _create_container(self, **kwargs):
        """Create Docker container with resource limits"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.docker_client.containers.run(
                kwargs['image_tag'],
                name=f"bot-{kwargs['bot_name']}-{uuid.uuid4().hex[:8]}",
                environment=kwargs['env_vars'],
                volumes=kwargs.get('volumes', {}),
                network=Config.DOCKER_NETWORK,
                detach=True,
                auto_remove=True,
                restart_policy={"Name": kwargs.get('restart_policy', 'unless-stopped')},
                mem_limit=kwargs.get('memory_limit', 128 * 1024 * 1024),
                memswap_limit=kwargs.get('memory_limit', 128 * 1024 * 1024),
                cpu_quota=int(kwargs.get('cpu_limit', 50) * 1000),  # Convert % to CPU quota
                cpu_period=100000,  # Default CPU period
                read_only=True,  # Security: read-only filesystem
                cap_drop=['ALL'],  # Drop all capabilities
                security_opt=['no-new-privileges:true']
            )
        )
    
    async def _monitor_bot(self, bot_id: int):
        """Monitor bot container metrics"""
        while True:
            try:
                session = Session()
                bot = session.query(Bot).filter_by(id=bot_id).first()
                
                if not bot or bot.status != 'running' or not bot.container_id:
                    break
                
                # Get container stats
                container = self.docker_client.containers.get(bot.container_id)
                stats = container.stats(stream=False)
                
                # Parse metrics
                cpu_stats = self._calculate_cpu_percent(stats)
                memory_stats = self._calculate_memory_usage(stats)
                network_stats = self._calculate_network_io(stats)
                
                # Store metrics
                metrics = BotMetrics(
                    bot_id=bot_id,
                    cpu_usage=cpu_stats,
                    memory_usage=memory_stats,
                    network_rx=network_stats['rx'],
                    network_tx=network_stats['tx'],
                    recorded_at=datetime.utcnow()
                )
                
                session.add(metrics)
                
                # Update bot last activity
                bot.last_activity = datetime.utcnow()
                
                # Check for issues
                if cpu_stats > 90 or memory_stats > bot.memory_limit * 0.9:
                    app.logger.warning(f"High resource usage for bot {bot_id}")
                
                session.commit()
                session.close()
                
                await asyncio.sleep(60)  # Monitor every minute
                
            except Exception as e:
                app.logger.error(f"Monitoring error for bot {bot_id}: {str(e)}")
                await asyncio.sleep(60)
    
    def _calculate_cpu_percent(self, stats):
        """Calculate CPU percentage from Docker stats"""
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
        
        if system_delta > 0 and cpu_delta > 0:
            return (cpu_delta / system_delta) * 100.0 * stats['cpu_stats']['online_cpus']
        return 0
    
    def _calculate_memory_usage(self, stats):
        """Calculate memory usage in MB"""
        return stats['memory_stats']['usage'] / (1024 * 1024)
    
    def _calculate_network_io(self, stats):
        """Calculate network I/O"""
        networks = stats.get('networks', {})
        rx = sum(network.get('rx_bytes', 0) for network in networks.values())
        tx = sum(network.get('tx_bytes', 0) for network in networks.values())
        return {'rx': rx, 'tx': tx}

bot_deployment_service = BotDeploymentService()

# ==================== BACKUP SERVICE ====================
class BackupService:
    async def create_backup(self, bot_id: int, backup_type: str = 'full'):
        """Create backup of bot configuration and data"""
        try:
            session = Session()
            bot = session.query(Bot).filter_by(id=bot_id).first()
            
            if not bot:
                return {'success': False, 'error': 'Bot not found'}
            
            # Get bot data
            bot_data = {
                'id': bot.id,
                'name': bot.bot_name,
                'config': {
                    'cpu_limit': bot.cpu_limit,
                    'memory_limit': bot.memory_limit,
                    'environment_vars': json.loads(bot.environment_vars) if bot.environment_vars else {},
                    'volumes': json.loads(bot.volumes) if bot.volumes else {},
                    'ports': json.loads(bot.ports) if bot.ports else {}
                },
                'created_at': bot.created_at.isoformat(),
                'updated_at': bot.updated_at.isoformat()
            }
            
            # If container is running, backup container data
            container_data = {}
            if bot.container_id and bot.status == 'running':
                container = docker_client.containers.get(bot.container_id)
                
                # Get container logs
                logs = container.logs(tail=1000).decode('utf-8', errors='ignore')
                
                # Get container inspect data
                inspect_data = container.attrs
                
                container_data = {
                    'logs': logs[:10000],  # Limit log size
                    'state': inspect_data['State'],
                    'config': inspect_data['Config']
                }
            
            # Combine all data
            backup_data = {
                'bot': bot_data,
                'container': container_data,
                'backup_type': backup_type,
                'created_at': datetime.utcnow().isoformat(),
                'version': '2.0.0'
            }
            
            # Encrypt backup data
            encrypted_data = encryption_service.encrypt(json.dumps(backup_data))
            
            # Calculate checksum
            checksum = hashlib.sha256(encrypted_data.encode()).hexdigest()
            
            # Store backup
            backup = BotBackup(
                bot_id=bot_id,
                backup_type=backup_type,
                backup_data=encrypted_data,
                backup_size=len(encrypted_data),
                checksum=checksum
            )
            
            session.add(backup)
            session.commit()
            
            return {
                'success': True,
                'backup_id': backup.id,
                'size': backup.backup_size,
                'checksum': checksum
            }
            
        except Exception as e:
            app.logger.error(f"Backup failed for bot {bot_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    async def restore_backup(self, backup_id: int):
        """Restore bot from backup"""
        try:
            session = Session()
            backup = session.query(BotBackup).filter_by(id=backup_id).first()
            
            if not backup:
                return {'success': False, 'error': 'Backup not found'}
            
            # Decrypt backup data
            decrypted_data = encryption_service.decrypt(backup.backup_data)
            backup_info = json.loads(decrypted_data)
            
            # Verify checksum
            current_checksum = hashlib.sha256(backup.backup_data.encode()).hexdigest()
            if current_checksum != backup.checksum:
                return {'success': False, 'error': 'Backup corrupted'}
            
            # Restore bot configuration
            bot = session.query(Bot).filter_by(id=backup.bot_id).first()
            bot_config = backup_info['bot']['config']
            
            bot.cpu_limit = bot_config.get('cpu_limit', 50)
            bot.memory_limit = bot_config.get('memory_limit', 128)
            bot.environment_vars = json.dumps(bot_config.get('environment_vars', {}))
            bot.volumes = json.dumps(bot_config.get('volumes', {}))
            bot.ports = json.dumps(bot_config.get('ports', {}))
            
            session.commit()
            
            # Redeploy bot with restored configuration
            if backup_info.get('container'):
                # Stop current container if running
                if bot.container_id:
                    try:
                        container = docker_client.containers.get(bot.container_id)
                        container.stop()
                    except:
                        pass
                
                # Redeploy
                await bot_deployment_service.deploy_bot(
                    bot_id=bot.id,
                    code="",  # Code would need to be stored separately
                    dependencies=""
                )
            
            return {'success': True, 'bot_id': bot.id}
            
        except Exception as e:
            app.logger.error(f"Restore failed for backup {backup_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()

backup_service = BackupService()

# ==================== AUDIT LOGGER ====================
class AuditLogger:
    @staticmethod
    def log(user_id: int, action: str, resource_type: str = None, 
            resource_id: int = None, details: str = None):
        """Log security-sensitive actions"""
        try:
            session = Session()
            
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                details=details
            )
            
            session.add(audit_log)
            session.commit()
            session.close()
            
        except Exception as e:
            app.logger.error(f"Failed to log audit: {str(e)}")

# ==================== API ROUTES ====================
@app.route('/')
def index():
    """Serve frontend interface"""
    with open('templates/index.html', 'r') as f:
        return render_template_string(f.read())

@app.route('/api/v1/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """Register new user"""
    try:
        data = request.get_json()
        
        username = validation_service.sanitize_input(data.get('username'))
        email = validation_service.sanitize_input(data.get('email'))
        password = data.get('password')
        
        # Validation
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if not validation_service.validate_email(email):
            return jsonify({'error': 'Invalid email address'}), 400
        
        if len(password) < 12:
            return jsonify({'error': 'Password must be at least 12 characters'}), 400
        
        # Check if user exists
        session = Session()
        existing_user = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 409
        
        # Create user
        password_hash = generate_password_hash(password, method='pbkdf2:sha512')
        api_key = secrets.token_urlsafe(48)
        verification_token = secrets.token_urlsafe(32)
        
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            api_key=api_key,
            verification_token=verification_token
        )
        
        session.add(user)
        session.commit()
        
        # Send verification email (in production)
        # await send_verification_email(email, verification_token)
        
        # Log registration
        AuditLogger.log(user.id, 'user_registered', 'user', user.id)
        
        return jsonify({
            'message': 'Registration successful. Please check your email for verification.',
            'user_id': user.id
        }), 201
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        session.close()

@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """User login with optional 2FA"""
    try:
        data = request.get_json()
        
        username = validation_service.sanitize_input(data.get('username'))
        password = data.get('password')
        totp_code = data.get('totp_code')
        
        session = Session()
        user = session.query(User).filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if 2FA is required
        is_2fa_verified = False
        if user.two_factor_enabled:
            if not totp_code:
                return jsonify({
                    'error': '2FA required',
                    'requires_2fa': True
                }), 403
            
            # Verify TOTP code (implementation needed)
            # is_2fa_verified = verify_totp(user.two_factor_secret, totp_code)
            # if not is_2fa_verified:
            #     return jsonify({'error': 'Invalid 2FA code'}), 401
        else:
            is_2fa_verified = True
        
        # Update last login
        user.last_login = datetime.utcnow()
        session.commit()
        
        # Generate JWT
        token = auth_service.generate_jwt(user.id, is_2fa_verified)
        
        # Log login
        AuditLogger.log(user.id, 'user_login', 'user', user.id)
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'subscription_tier': user.subscription_tier,
                'is_2fa_enabled': user.two_factor_enabled
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500
    finally:
        session.close()

@app.route('/api/v1/bots', methods=['POST'])
@auth_service.require_auth()
def create_bot(user):
    """Create and deploy new bot"""
    try:
        if not DOCKER_AVAILABLE:
            return jsonify({'error': 'Docker service unavailable'}), 503
        
        data = request.get_json()
        
        bot_name = validation_service.sanitize_input(data.get('bot_name'))
        bot_token = data.get('bot_token')
        bot_code = data.get('bot_code')
        dependencies = data.get('dependencies', '')
        
        # Validation
        if not validation_service.validate_bot_token(bot_token):
            return jsonify({'error': 'Invalid bot token format'}), 400
        
        if len(bot_code) > 50000:  # 50KB limit
            return jsonify({'error': 'Bot code too large'}), 400
        
        # Check bot limit based on subscription
        session = Session()
        bot_count = session.query(Bot).filter_by(user_id=user.id).count()
        
        max_bots = {
            'free': 1,
            'pro': 10,
            'enterprise': 100
        }.get(user.subscription_tier, 1)
        
        if bot_count >= max_bots:
            return jsonify({'error': f'Bot limit reached for {user.subscription_tier} tier'}), 403
        
        # Encrypt bot token
        encrypted_token = encryption_service.encrypt(bot_token)
        
        # Create bot record
        bot = Bot(
            user_id=user.id,
            bot_name=bot_name,
            bot_token_encrypted=encrypted_token,
            status='deploying'
        )
        
        session.add(bot)
        session.commit()
        
        # Start deployment in background
        asyncio.run(bot_deployment_service.deploy_bot(bot.id, bot_code, dependencies))
        
        # Log creation
        AuditLogger.log(user.id, 'bot_created', 'bot', bot.id, f"Name: {bot_name}")
        
        return jsonify({
            'message': 'Bot deployment started',
            'bot_id': bot.id,
            'status': 'deploying'
        }), 202
        
    except Exception as e:
        app.logger.error(f"Bot creation error: {str(e)}")
        return jsonify({'error': 'Bot creation failed'}), 500
    finally:
        session.close()

@app.route('/api/v1/bots/<int:bot_id>/control', methods=['POST'])
@auth_service.require_auth()
def control_bot(user, bot_id):
    """Control bot (start/stop/restart)"""
    try:
        data = request.get_json()
        action = data.get('action')  # start, stop, restart
        
        session = Session()
        bot = session.query(Bot).filter_by(id=bot_id, user_id=user.id).first()
        
        if not bot:
            return jsonify({'error': 'Bot not found'}), 404
        
        # Perform action
        if action == 'start':
            if bot.status == 'running':
                return jsonify({'error': 'Bot already running'}), 400
            result = asyncio.run(bot_deployment_service.deploy_bot(bot.id, "", ""))
        
        elif action == 'stop':
            result = asyncio.run(bot_deployment_service.stop_bot(bot.id))
        
        elif action == 'restart':
            await bot_deployment_service.stop_bot(bot.id)
            result = await bot_deployment_service.deploy_bot(bot.id, "", "")
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        if result['success']:
            AuditLogger.log(user.id, f'bot_{action}ed', 'bot', bot.id)
            return jsonify({'message': f'Bot {action}ed successfully'}), 200
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        app.logger.error(f"Bot control error: {str(e)}")
        return jsonify({'error': 'Operation failed'}), 500
    finally:
        session.close()

@app.route('/api/v1/bots/<int:bot_id>/metrics', methods=['GET'])
@auth_service.require_auth()
def get_bot_metrics(user, bot_id):
    """Get bot performance metrics"""
    try:
        session = Session()
        bot = session.query(Bot).filter_by(id=bot_id, user_id=user.id).first()
        
        if not bot:
            return jsonify({'error': 'Bot not found'}), 404
        
        # Get metrics from last 24 hours
        cutoff = datetime.utcnow() - timedelta(hours=24)
        metrics = session.query(BotMetrics).filter(
            BotMetrics.bot_id == bot_id,
            BotMetrics.recorded_at >= cutoff
        ).order_by(BotMetrics.recorded_at.desc()).limit(100).all()
        
        # Get container stats if running
        container_stats = {}
        if bot.status == 'running' and bot.container_id:
            try:
                container = docker_client.containers.get(bot.container_id)
                stats = container.stats(stream=False)
                
                container_stats = {
                    'cpu_percent': bot_deployment_service._calculate_cpu_percent(stats),
                    'memory_usage': bot_deployment_service._calculate_memory_usage(stats),
                    'network_io': bot_deployment_service._calculate_network_io(stats)
                }
            except:
                pass
        
        return jsonify({
            'bot_id': bot.id,
            'status': bot.status,
            'metrics': [{
                'timestamp': m.recorded_at.isoformat(),
                'cpu_usage': m.cpu_usage,
                'memory_usage': m.memory_usage,
                'network_rx': m.network_rx,
                'network_tx': m.network_tx
            } for m in metrics],
            'current_stats': container_stats,
            'limits': {
                'cpu': f"{bot.cpu_limit}%",
                'memory': f"{bot.memory_limit}MB",
                'storage': f"{bot.storage_limit}MB"
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Metrics error: {str(e)}")
        return jsonify({'error': 'Failed to get metrics'}), 500
    finally:
        session.close()

@app.route('/api/v1/bots/<int:bot_id>/backup', methods=['POST'])
@auth_service.require_auth()
def create_backup(user, bot_id):
    """Create backup of bot"""
    try:
        session = Session()
        bot = session.query(Bot).filter_by(id=bot_id, user_id=user.id).first()
        
        if not bot:
            return jsonify({'error': 'Bot not found'}), 404
        
        # Create backup
        result = asyncio.run(backup_service.create_backup(bot_id))
        
        if result['success']:
            AuditLogger.log(user.id, 'backup_created', 'bot', bot.id)
            return jsonify({
                'message': 'Backup created successfully',
                'backup_id': result['backup_id']
            }), 201
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        app.logger.error(f"Backup error: {str(e)}")
        return jsonify({'error': 'Backup failed'}), 500
    finally:
        session.close()

@app.route('/api/v1/bots/<int:bot_id>/logs', methods=['GET'])
@auth_service.require_auth()
def get_bot_logs(user, bot_id):
    """Get bot container logs"""
    try:
        session = Session()
        bot = session.query(Bot).filter_by(id=bot_id, user_id=user.id).first()
        
        if not bot:
            return jsonify({'error': 'Bot not found'}), 404
        
        if not bot.container_id:
            return jsonify({'logs': [], 'message': 'Bot not running'}), 200
        
        # Get container logs
        container = docker_client.containers.get(bot.container_id)
        logs = container.logs(tail=1000, timestamps=True).decode('utf-8', errors='ignore')
        
        return jsonify({
            'bot_id': bot.id,
            'bot_name': bot.bot_name,
            'logs': logs.split('\n')[-100:]  # Last 100 lines
        }), 200
        
    except Exception as e:
        app.logger.error(f"Log retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to get logs'}), 500
    finally:
        session.close()

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database
        session = Session()
        session.execute('SELECT 1')
        session.close()
        
        # Check Redis
        redis_client.ping()
        
        # Check Docker
        if DOCKER_AVAILABLE:
            docker_client.ping()
        
        # System metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'uptime': psutil.boot_time()
            },
            'services': {
                'database': 'connected',
                'redis': 'connected',
                'docker': 'available' if DOCKER_AVAILABLE else 'unavailable'
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/api/v1/audit', methods=['GET'])
@auth_service.require_auth()
def get_audit_logs(user):
    """Get audit logs (admin only)"""
    try:
        # Only allow admin users
        if user.subscription_tier != 'enterprise':
            return jsonify({'error': 'Unauthorized'}), 403
        
        session = Session()
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # Filter by date
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = session.query(AuditLog)
        
        if start_date:
            start = parser.parse(start_date)
            query = query.filter(AuditLog.created_at >= start)
        
        if end_date:
            end = parser.parse(end_date)
            query = query.filter(AuditLog.created_at <= end)
        
        # Execute query
        logs = query.order_by(AuditLog.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'logs': [{
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'ip_address': log.ip_address,
                'timestamp': log.created_at.isoformat(),
                'details': log.details
            } for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        app.logger.error(f"Audit log error: {str(e)}")
        return jsonify({'error': 'Failed to get audit logs'}), 500
    finally:
        session.close()

# ==================== ADMIN ENDPOINTS ====================
@app.route('/api/v1/admin/users', methods=['GET'])
@auth_service.require_auth(require_2fa=True)
def admin_get_users(user):
    """Admin: Get all users"""
    if user.subscription_tier != 'enterprise':
        return jsonify({'error': 'Unauthorized'}), 403
    
    session = Session()
    users = session.query(User).all()
    
    return jsonify({
        'users': [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'subscription_tier': u.subscription_tier,
            'created_at': u.created_at.isoformat(),
            'last_login': u.last_login.isoformat() if u.last_login else None,
            'bot_count': u.bots.count()
        } for u in users]
    }), 200

@app.route('/api/v1/admin/system', methods=['GET'])
@auth_service.require_auth(require_2fa=True)
def admin_system_stats(user):
    """Admin: Get system statistics"""
    if user.subscription_tier != 'enterprise':
        return jsonify({'error': 'Unauthorized'}), 403
    
    session = Session()
    
    # Get counts
    total_users = session.query(User).count()
    total_bots = session.query(Bot).count()
    running_bots = session.query(Bot).filter_by(status='running').count()
    
    # Get recent activities
    recent_logs = session.query(AuditLog).order_by(
        AuditLog.created_at.desc()
    ).limit(20).all()
    
    # Docker info
    docker_info = {}
    if DOCKER_AVAILABLE:
        containers = docker_client.containers.list(all=True)
        docker_info = {
            'total_containers': len(containers),
            'running_containers': len([c for c in containers if c.status == 'running']),
            'images': len(docker_client.images.list())
        }
    
    return jsonify({
        'system': {
            'total_users': total_users,
            'total_bots': total_bots,
            'running_bots': running_bots,
            'uptime': psutil.boot_time()
        },
        'docker': docker_info,
        'recent_activities': [{
            'action': log.action,
            'user_id': log.user_id,
            'timestamp': log.created_at.isoformat()
        } for log in recent_logs]
    }), 200

# ==================== WEBHOOK HANDLER ====================
@app.route('/webhook/<string:bot_token_hash>', methods=['POST'])
def webhook_handler(bot_token_hash):
    """Handle Telegram webhook calls"""
    try:
        # Find bot by token hash
        session = Session()
        bots = session.query(Bot).all()
        
        target_bot = None
        for bot in bots:
            token_hash = hashlib.sha256(bot.bot_token_encrypted.encode()).hexdigest()
            if token_hash == bot_token_hash:
                target_bot = bot
                break
        
        if not target_bot or target_bot.status != 'running':
            return jsonify({'error': 'Bot not found or not running'}), 404
        
        # Forward to bot container
        if target_bot.container_id:
            # In production, this would forward to the bot's webhook endpoint
            pass
        
        return jsonify({'status': 'received'}), 200
        
    except Exception as e:
        app.logger.error(f"Webhook error: {str(e)}")
        return jsonify({'error': 'Webhook processing failed'}), 500
    finally:
        session.close()

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def ratelimit_error(error):
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': error.description.split(' ')[-1]
    }), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# ==================== BACKGROUND TASKS ====================
def start_background_tasks():
    """Start background maintenance tasks"""
    
    def backup_scheduler():
        """Schedule regular backups"""
        while True:
            try:
                session = Session()
                # Backup bots that have been active in last 24 hours
                active_bots = session.query(Bot).filter(
                    Bot.status == 'running',
                    Bot.last_activity >= datetime.utcnow() - timedelta(hours=24)
                ).all()
                
                for bot in active_bots:
                    asyncio.run(backup_service.create_backup(bot.id, 'incremental'))
                
                session.close()
                time.sleep(Config.BACKUP_INTERVAL)
                
            except Exception as e:
                app.logger.error(f"Backup scheduler error: {str(e)}")
                time.sleep(300)  # Retry after 5 minutes
    
    def cleanup_scheduler():
        """Cleanup old data"""
        while True:
            try:
                session = Session()
                
                # Delete old metrics (older than 30 days)
                cutoff = datetime.utcnow() - timedelta(days=30)
                session.query(BotMetrics).filter(
                    BotMetrics.recorded_at < cutoff
                ).delete()
                
                # Delete old audit logs (older than 90 days)
                cutoff = datetime.utcnow() - timedelta(days=90)
                session.query(AuditLog).filter(
                    AuditLog.created_at < cutoff
                ).delete()
                
                session.commit()
                session.close()
                
                time.sleep(3600)  # Run every hour
                
            except Exception as e:
                app.logger.error(f"Cleanup scheduler error: {str(e)}")
                time.sleep(300)
    
    # Start background threads
    backup_thread = Thread(target=backup_scheduler, daemon=True)
    cleanup_thread = Thread(target=cleanup_scheduler, daemon=True)
    
    backup_thread.start()
    cleanup_thread.start()

# ==================== DEPLOYMENT CONFIG ====================
if __name__ == '__main__':
    # Create upload directory
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Start background tasks
    start_background_tasks()
    
    # Print startup info
    print("=" * 60)
    print("🤖 Telegram Bot Hosting Platform v2.0")
    print("=" * 60)
    print(f"Mode: {'PRODUCTION' if not app.debug else 'DEVELOPMENT'}")
    print(f"Docker: {'AVAILABLE' if DOCKER_AVAILABLE else 'UNAVAILABLE'}")
    print(f"Database: {Config.DATABASE_URL}")
    print(f"Redis: {Config.REDIS_URL}")
    print(f"API Rate Limit: {Config.API_RATE_LIMIT}")
    print("=" * 60)
    
    # Run application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        use_reloader=False
    )
