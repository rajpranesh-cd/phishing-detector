#!/usr/bin/env python3
"""
Production setup script for the AI Phishing Detection System.
"""
import os
import sys
import subprocess
import secrets
import base64
from pathlib import Path

def generate_secrets():
    """Generate secure secrets for production."""
    secrets_dict = {
        'JWT_SECRET_KEY': secrets.token_urlsafe(32),
        'ENCRYPTION_KEY': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        'WEBHOOK_SECRET': secrets.token_urlsafe(32),
        'API_KEY': secrets.token_urlsafe(32)
    }
    
    print("Generated secrets (store these securely):")
    for key, value in secrets_dict.items():
        print(f"{key}={value}")
    
    return secrets_dict

def setup_database():
    """Setup production database."""
    print("Setting up production database...")
    
    # Run database migrations
    try:
        subprocess.run([
            "python", "-m", "alembic", "upgrade", "head"
        ], check=True)
        print("✓ Database migrations completed")
    except subprocess.CalledProcessError:
        print("✗ Database migration failed")
        return False
    
    return True

def setup_ssl_certificates():
    """Setup SSL certificates for HTTPS."""
    print("Setting up SSL certificates...")
    
    # Check if certificates exist
    cert_path = Path("/etc/ssl/certs/phishing-detector.crt")
    key_path = Path("/etc/ssl/private/phishing-detector.key")
    
    if not cert_path.exists() or not key_path.exists():
        print("SSL certificates not found. Please install valid certificates.")
        print(f"Certificate path: {cert_path}")
        print(f"Private key path: {key_path}")
        return False
    
    print("✓ SSL certificates found")
    return True

def setup_monitoring():
    """Setup monitoring and logging."""
    print("Setting up monitoring...")
    
    # Create log directories
    log_dirs = [
        "/var/log/phishing-detector",
        "/var/log/phishing-detector/audit",
        "/var/log/phishing-detector/security"
    ]
    
    for log_dir in log_dirs:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o750)
    
    print("✓ Log directories created")
    return True

def setup_firewall():
    """Setup basic firewall rules."""
    print("Setting up firewall rules...")
    
    firewall_rules = [
        "ufw --force enable",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw allow 22/tcp",  # SSH
        "ufw allow 80/tcp",  # HTTP
        "ufw allow 443/tcp", # HTTPS
        "ufw allow from 10.0.0.0/8 to any port 5432",  # PostgreSQL (internal)
        "ufw allow from 10.0.0.0/8 to any port 6379",  # Redis (internal)
    ]
    
    for rule in firewall_rules:
        try:
            subprocess.run(rule.split(), check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Firewall rule failed: {rule}")
            print(f"Error: {e.stderr.decode()}")
    
    print("✓ Firewall rules configured")
    return True

def create_systemd_services():
    """Create systemd service files."""
    print("Creating systemd services...")
    
    # API service
    api_service = """[Unit]
Description=Phishing Detector API
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=phishing-detector
Group=phishing-detector
WorkingDirectory=/opt/phishing-detector
Environment=PATH=/opt/phishing-detector/venv/bin
ExecStart=/opt/phishing-detector/venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    # Worker service
    worker_service = """[Unit]
Description=Phishing Detector Worker
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=phishing-detector
Group=phishing-detector
WorkingDirectory=/opt/phishing-detector
Environment=PATH=/opt/phishing-detector/venv/bin
ExecStart=/opt/phishing-detector/venv/bin/celery worker -A src.workers.celery_app --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    # Write service files
    with open("/etc/systemd/system/phishing-detector-api.service", "w") as f:
        f.write(api_service)
    
    with open("/etc/systemd/system/phishing-detector-worker.service", "w") as f:
        f.write(worker_service)
    
    # Reload systemd and enable services
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "phishing-detector-api"], check=True)
    subprocess.run(["systemctl", "enable", "phishing-detector-worker"], check=True)
    
    print("✓ Systemd services created and enabled")
    return True

def main():
    """Main setup function."""
    print("🔒 AI Phishing Detection System - Production Setup")
    print("=" * 50)
    
    if os.geteuid() != 0:
        print("This script must be run as root for production setup.")
        sys.exit(1)
    
    # Generate secrets
    secrets_dict = generate_secrets()
    
    # Setup components
    setup_steps = [
        ("Database", setup_database),
        ("SSL Certificates", setup_ssl_certificates),
        ("Monitoring", setup_monitoring),
        ("Firewall", setup_firewall),
        ("Systemd Services", create_systemd_services)
    ]
    
    for step_name, step_func in setup_steps:
        print(f"\n📋 {step_name}...")
        if not step_func():
            print(f"❌ {step_name} setup failed!")
            sys.exit(1)
    
    print("\n✅ Production setup completed successfully!")
    print("\nNext steps:")
    print("1. Update environment variables with generated secrets")
    print("2. Configure Microsoft Graph API credentials")
    print("3. Start services: systemctl start phishing-detector-api phishing-detector-worker")
    print("4. Configure reverse proxy (nginx/apache) for HTTPS")
    print("5. Set up backup procedures for database")

if __name__ == "__main__":
    main()
