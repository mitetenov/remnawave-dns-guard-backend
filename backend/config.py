import os
from dataclasses import dataclass

@dataclass
class Config:
    username: str
    password: str
    app_secret: str
    agent_token: str
    database_path: str = '/data/guard.db'
    cookie_secure: bool = True
    public_origin: str = 'https://guard.example.com'
    cloudflare_api_token: str = ''
    remnawave_url: str = ''
    remnawave_api_token: str = ''

    @classmethod
    def from_env(cls):
        c = cls(username=os.getenv('ADMIN_USERNAME', ''), password=os.getenv('ADMIN_PASSWORD', ''),
                app_secret=os.getenv('APP_SECRET', ''), agent_token=os.getenv('AGENT_TOKEN', ''),
                database_path=os.getenv('DATABASE_PATH', '/data/guard.db'),
                cookie_secure=os.getenv('COOKIE_SECURE', 'true').lower() == 'true',
                public_origin=os.getenv('PUBLIC_ORIGIN', 'https://guard.example.com').rstrip('/'),
                cloudflare_api_token=os.getenv('CLOUDFLARE_API_TOKEN', ''),
                remnawave_url=os.getenv('REMNAWAVE_URL', ''),
                remnawave_api_token=os.getenv('REMNAWAVE_API_TOKEN', ''))
        c.validate()
        return c

    def validate(self):
        if not self.username or not self.password or len(self.app_secret) < 32 or len(self.agent_token) < 32:
            raise RuntimeError('Set ADMIN_USERNAME, ADMIN_PASSWORD, APP_SECRET and AGENT_TOKEN; secrets must contain at least 32 characters')
        if not self.public_origin.startswith(('https://', 'http://')):
            raise RuntimeError('PUBLIC_ORIGIN must be an HTTP(S) origin')
