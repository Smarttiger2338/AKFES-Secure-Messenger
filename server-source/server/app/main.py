import asyncio, logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI,Request,Response,status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import settings
from app.core.database import AsyncSessionLocal,database_ready,init_db
from app.core.redis_client import make_redis_client
from app.routers import admin,arduino,auth,conversations,devices,files,keys,profile,security,social,users,ws
from app.realtime import event_bus

logger=logging.getLogger(__name__)

async def stale_upload_cleanup_worker():
    while True:
        try:
            async with AsyncSessionLocal() as db:
                await files.cleanup_stale_pending(db);await db.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception('Stale encrypted upload cleanup failed')
        await asyncio.sleep(3600)

def validate_production_security():
    if settings.DEBUG:return
    if len(settings.SECRET_KEY)<32 or settings.SECRET_KEY.startswith('change-me-'):
        raise RuntimeError('Production SECRET_KEY must be a provisioned shared random secret')
    if settings.ROUTE_PROFILE not in {'auth','api','realtime'}:raise RuntimeError('Production ROUTE_PROFILE must be auth, api, or realtime')
    if settings.JWT_ALGORITHM!='RS256' or not settings.JWT_PUBLIC_KEY_FILE:raise RuntimeError('Production JWT verification must use RS256 public key')
    if settings.ROUTE_PROFILE=='auth':
        if not settings.AUTH_ISSUER_ENABLED or not settings.JWT_PRIVATE_KEY_FILE:raise RuntimeError('Auth profile requires JWT issuer private key')
        if not settings.ARDUINO_VERIFIER_ENABLED or len(settings.ARDUINO_MASTER_SECRET)<32 or settings.ARDUINO_MASTER_SECRET.startswith('CHANGE-ME'):raise RuntimeError('Auth profile requires provisioned Arduino master secret')
        if settings.FILES_ENABLED:raise RuntimeError('Auth profile must not mount file service')
        if settings.CONTROL_PLANE_ENABLED:raise RuntimeError('Auth profile must not mount the control-plane REST API')
        if settings.REDIS_REALTIME_SUBSCRIBE_ENABLED:raise RuntimeError('Auth profile must publish revocations without subscribing to realtime traffic')
    if settings.ROUTE_PROFILE=='api':
        if settings.AUTH_ISSUER_ENABLED or settings.ARDUINO_VERIFIER_ENABLED:raise RuntimeError('General API profile must not hold issuer or Arduino verifier privileges')
        if settings.JWT_PRIVATE_KEY_FILE:raise RuntimeError('General API profile must not receive JWT private key')
        if settings.CONTROL_PLANE_ENABLED and not settings.FILES_ENABLED:raise RuntimeError('Node1 control-plane API must mount the encrypted file service')
        if not settings.CONTROL_PLANE_ENABLED and settings.FILES_ENABLED:raise RuntimeError('Data-plane API must not mount the encrypted file service')
        if settings.REDIS_REALTIME_SUBSCRIBE_ENABLED:raise RuntimeError('General API publishes realtime events but must not subscribe to user channels')
    if settings.ROUTE_PROFILE=='realtime':
        if settings.AUTH_ISSUER_ENABLED or settings.ARDUINO_VERIFIER_ENABLED:raise RuntimeError('Realtime profile must not hold issuer or Arduino verifier privileges')
        if settings.CONTROL_PLANE_ENABLED or settings.FILES_ENABLED:raise RuntimeError('Realtime profile must not mount REST control-plane or file capabilities')
        if settings.AUTO_CREATE_SCHEMA:raise RuntimeError('Realtime profile must use a read-only database role')
        if settings.JWT_PRIVATE_KEY_FILE:raise RuntimeError('Realtime profile must not receive JWT private key')
        if not settings.REDIS_REALTIME_SUBSCRIBE_ENABLED:raise RuntimeError('Realtime profile must subscribe to user event channels')
    if settings.DATABASE_URL.startswith('postgresql+') and not settings.DB_TLS_ENABLED:raise RuntimeError('PostgreSQL TLS must be enabled')
    if not settings.REDIS_TLS_ENABLED or not settings.RATE_LIMIT_FAIL_CLOSED:raise RuntimeError('Redis TLS and fail-closed security rate limiting are required')
    if not settings.REDIS_SECURITY_URL or not settings.REDIS_REALTIME_URL:raise RuntimeError('Production requires separate security and realtime Redis URLs')
    if settings.REDIS_SECURITY_URL==settings.REDIS_REALTIME_URL:raise RuntimeError('Security Redis and realtime Redis must be isolated in production')
    if not settings.REQUIRE_DEVICE_POP:raise RuntimeError('Production device proof-of-possession must be enabled')
    if len(settings.REGISTRATION_INVITE_SHA256)!=64:raise RuntimeError('Registration invite digest is required')
    if settings.ADMIN_USERNAMES:
        if len(settings.ADMIN_MFA_ENCRYPTION_KEY)<32:raise RuntimeError('ADMIN_MFA_ENCRYPTION_KEY must be provisioned for administrators')
        if not settings.ADMIN_WEBAUTHN_ORIGIN.startswith('https://'):raise RuntimeError('Administrator passkeys require an HTTPS origin')
        if settings.ADMIN_WEBAUTHN_RP_ID not in settings.ADMIN_WEBAUTHN_ORIGIN:raise RuntimeError('Administrator passkey RP ID must match its origin')
    if settings.WS_MAX_FRAME_BYTES>64*1024:raise RuntimeError('WebSocket frame limit too large for the receive-only control channel')
    if '*' in settings.CORS_ORIGINS or '*' in settings.TRUSTED_HOSTS or '*' in settings.WS_ALLOWED_ORIGINS:raise RuntimeError('Wildcard production origins/hosts are forbidden')
validate_production_security()

@asynccontextmanager
async def lifespan(app):
    if settings.FILES_ENABLED:Path(settings.FILES_DIR).mkdir(parents=True,exist_ok=True)
    await init_db();await event_bus.start()
    cleanup_task=asyncio.create_task(stale_upload_cleanup_worker()) if settings.FILES_ENABLED else None
    try:yield
    finally:
        if cleanup_task is not None:
            cleanup_task.cancel()
            try:await cleanup_task
            except asyncio.CancelledError:pass
        await event_bus.stop()

app=FastAPI(title='AKFES Secure Messenger API',version='1',description='AKFES service API',lifespan=lifespan,
    docs_url='/docs' if settings.DEBUG else None,redoc_url='/redoc' if settings.DEBUG else None,openapi_url='/openapi.json' if settings.DEBUG else None)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=settings.TRUSTED_HOSTS)
app.add_middleware(CORSMiddleware,allow_origins=settings.CORS_ORIGINS,allow_credentials=False,allow_methods=['GET','POST','PATCH','DELETE','OPTIONS'],allow_headers=['Authorization','Content-Type','X-Arduino-Grant','X-Admin-Step-Up'])

@app.middleware('http')
async def hardening(request:Request,call_next):
    ct=request.headers.get('content-type','').lower();cl=request.headers.get('content-length')
    if 'application/json' in ct and cl:
        try:
            if int(cl)>settings.MAX_JSON_BODY_BYTES:return Response(status_code=413)
        except ValueError:return Response(status_code=400)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Permissions-Policy':'camera=(), display-capture=(), microphone=(), geolocation=()','Cross-Origin-Opener-Policy':'same-origin','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"})
    if not settings.DEBUG:response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return response

if settings.ROUTE_PROFILE in {'all','auth'}:
    app.include_router(auth.router,prefix='/api/auth',tags=['auth']);app.include_router(arduino.router,prefix='/api/arduino',tags=['arduino'])
if settings.ROUTE_PROFILE in {'all','realtime'}:
    app.include_router(ws.router,tags=['websocket'])
if settings.ROUTE_PROFILE in {'all','api'} and (settings.CONTROL_PLANE_ENABLED or settings.DEBUG):
    app.include_router(users.router,prefix='/api/users',tags=['users']);app.include_router(devices.router,prefix='/api/devices',tags=['devices'])
    app.include_router(conversations.router,prefix='/api/conversations',tags=['conversations']);app.include_router(keys.router,prefix='/api/keys',tags=['keys'])
    app.include_router(files.router,prefix='/api/files',tags=['files']);app.include_router(security.router,prefix='/api/security',tags=['security'])
    app.include_router(profile.router,prefix='/api/profile',tags=['profile']);app.include_router(admin.router,prefix='/api/admin',tags=['admin'])
    app.include_router(social.router,prefix='/api/social',tags=['social'])

@app.get('/health')
@app.get('/health/live')
async def health_live():
    result={'status':'ok','service':'akfes-messenger'}
    if settings.DEBUG:result['profile']=settings.ROUTE_PROFILE
    return result
@app.get('/health/ready')
async def health_ready(response:Response):
    db_ok=await database_ready(); security_ok=False; realtime_ok=not settings.REDIS_REALTIME_ENABLED
    security_client=make_redis_client(purpose='security',socket_connect_timeout=1,socket_timeout=1)
    try: security_ok=bool(await security_client.ping())
    except Exception: security_ok=False
    finally:
        try: await security_client.aclose()
        except Exception: pass
    if settings.REDIS_REALTIME_ENABLED:
        realtime_client=make_redis_client(purpose='realtime',socket_connect_timeout=1,socket_timeout=1)
        try: realtime_ok=bool(await realtime_client.ping())
        except Exception: realtime_ok=False
        finally:
            try: await realtime_client.aclose()
            except Exception: pass
    redis_ok=security_ok and realtime_ok
    ready=db_ok and (redis_ok or not settings.REDIS_REQUIRED_FOR_READY)
    if not ready:response.status_code=status.HTTP_503_SERVICE_UNAVAILABLE
    if settings.DEBUG:return {'status':'ready' if ready else 'not-ready','database':'ok' if db_ok else 'error','security_redis':'ok' if security_ok else 'error','realtime_redis':'ok' if realtime_ok else 'error','profile':settings.ROUTE_PROFILE}
    return {'status':'ready' if ready else 'not-ready'}
