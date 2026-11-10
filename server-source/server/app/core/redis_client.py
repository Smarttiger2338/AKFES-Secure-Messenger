from pathlib import Path
import redis.asyncio as redis
from app.core.config import settings


def _required(path: str, label: str) -> str:
    p = Path(path)
    if not path or not p.is_file():
        raise RuntimeError(f'{label} is missing: {path!r}')
    return str(p)


def redis_connection_kwargs() -> dict:
    kwargs = {
        'socket_connect_timeout': 1.0,
        'socket_timeout': 2.0,
        'health_check_interval': 30,
        'decode_responses': True,
    }
    if settings.REDIS_TLS_ENABLED:
        kwargs.update({
            'ssl_ca_certs': _required(settings.REDIS_TLS_CA_FILE, 'REDIS_TLS_CA_FILE'),
            'ssl_certfile': _required(settings.REDIS_TLS_CERT_FILE, 'REDIS_TLS_CERT_FILE'),
            'ssl_keyfile': _required(settings.REDIS_TLS_KEY_FILE, 'REDIS_TLS_KEY_FILE'),
            'ssl_cert_reqs': 'required',
            'ssl_check_hostname': True,
        })
    return kwargs


def _url(purpose: str) -> str:
    if purpose == 'realtime':
        return settings.REDIS_REALTIME_URL or settings.REDIS_URL
    if purpose == 'security':
        return settings.REDIS_SECURITY_URL or settings.REDIS_URL
    raise ValueError(f'unknown Redis purpose: {purpose}')


def make_redis_client(*, purpose: str = 'security', **overrides) -> redis.Redis:
    kwargs = redis_connection_kwargs()
    kwargs.update(overrides)
    return redis.from_url(_url(purpose), **kwargs)
