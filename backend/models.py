import ipaddress
import re
from uuid import UUID
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class Model(BaseModel):
    model_config = ConfigDict(extra='forbid')

def public_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip.version != 4 or not ip.is_global or ip.is_multicast:
            raise ValueError()
    except ValueError:
        raise ValueError('A public IPv4 address is required')
    return str(ip)

class ProbeProfile(Model):
    port: int = Field(ge=1, le=65535)
    uuid: str
    transport: Literal['tcp', 'xhttp']
    security: Literal['reality', 'tls']
    server_name: str = Field(max_length=253)
    public_key: str = Field(default='', max_length=43)
    short_id: str = Field(default='', max_length=16)
    flow: Literal['', 'xtls-rprx-vision'] = ''
    fingerprint: Literal['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'] = 'chrome'
    path: str = Field(default='/', max_length=2048)
    host: str = Field(default='', max_length=253)
    xhttp_mode: Literal['auto','packet-up','stream-up','stream-one'] = 'auto'

    @field_validator('uuid')
    @classmethod
    def valid_uuid(cls, value):
        return str(UUID(value))

    @model_validator(mode='after')
    def valid_security(self):
        def valid_host(value):
            return bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value)) and all(label and len(label) <= 63 and not label.startswith('-') and not label.endswith('-') for label in value.split('.'))
        if not valid_host(self.server_name) or (self.host and not valid_host(self.host)):
            raise ValueError('A valid TLS/REALITY server_name is required')
        if self.security == 'reality' and not re.fullmatch(r'[A-Za-z0-9_-]{43}', self.public_key):
            raise ValueError('REALITY public_key must be a 43-character base64url key')
        if self.short_id and (len(self.short_id) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', self.short_id)):
            raise ValueError('short_id must contain an even number of hexadecimal digits')
        if self.transport == 'xhttp' and self.flow:
            raise ValueError('flow is not supported with xhttp')
        if not self.path.startswith('/') or self.path.startswith('//') or any(ord(c) < 32 or ord(c) == 127 for c in self.path + self.host + self.public_key):
            raise ValueError('Invalid path or host')
        return self

class PoolCreate(Model):
    name: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=253)
    zone_id: str = Field(min_length=1, max_length=100)
    ttl: int = Field(default=120, ge=60, le=86400)
    interval_seconds: int = Field(default=60, ge=10, le=86400)
    failure_threshold: int = Field(default=3, ge=1, le=100)
    recovery_threshold: int = Field(default=5, ge=1, le=100)
    automation_enabled: bool = False

    @field_validator('hostname')
    @classmethod
    def valid_hostname(cls, value):
        value = value.rstrip('.').lower()
        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
            raise ValueError('A valid DNS hostname is required')
        return value

class PoolPatch(Model):
    name: str | None = None
    hostname: str | None = None
    zone_id: str | None = None
    ttl: int | None = None
    interval_seconds: int | None = None
    failure_threshold: int | None = None
    recovery_threshold: int | None = None
    automation_enabled: bool | None = None

class TargetCreate(Model):
    name: str = Field(min_length=1, max_length=100)
    ip: str
    remnawave_uuid: str | None = None
    _ip = field_validator('ip')(public_ipv4)

class Login(Model):
    username: str = Field(max_length=200)
    password: str = Field(max_length=1000)

class Settings(Model):
    cloudflare_api_token: str | None = Field(default=None, max_length=4096)
    remnawave_url: str | None = Field(default=None, max_length=2048)
    remnawave_api_token: str | None = Field(default=None, max_length=4096)

class Poll(Model):
    agent_id: str = Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_.-]+$')
    version: str = Field(max_length=100)
    control_ok: bool
    control_error: str | None = Field(default=None, max_length=1000)

class Result(Model):
    job_id: str = Field(max_length=100)
    ok: bool
    latency_ms: float | None = Field(default=None, ge=0, le=180000, allow_inf_nan=False)
    error: str | None = Field(default=None, max_length=1000)

class Results(Model):
    agent_id: str = Field(min_length=1, max_length=100)
    results: list[Result] = Field(max_length=4)
