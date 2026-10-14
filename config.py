import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / 'instance'
INSTANCE_DIR.mkdir(exist_ok=True)
DATABASE = os.environ.get('CLASSPULSE_DATABASE', str(INSTANCE_DIR / 'classpulse.db'))
SECRET_KEY = os.environ.get('CLASSPULSE_SECRET_KEY', 'change-this-local-development-secret-before-deployment')
ADMIN_LOGIN = os.environ.get('CLASSPULSE_ADMIN_LOGIN', 'admin')
ADMIN_PASSWORD = os.environ.get('CLASSPULSE_ADMIN_PASSWORD', 'Admin@12345')
DEMO_MODE = False  # Fresh database contains no demo students, teams, or activities.
