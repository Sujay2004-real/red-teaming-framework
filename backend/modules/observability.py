"""Request correlation and bounded uploads without logging secrets or bodies."""
import json
import logging
import time
import uuid
from fastapi import HTTPException
from starlette.responses import JSONResponse

logger = logging.getLogger('access')
MAX_BODY = 5 * 1024 * 1024 + 65536


class RequestObservability:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex
        started = time.monotonic()
        size, status = 0, 500
        headers = dict(scope.get('headers', []))
        try:
            oversized = int(headers.get(b'content-length', b'0')) > MAX_BODY
        except ValueError:
            oversized = True
        if oversized:
            return await JSONResponse({'detail': 'Request body exceeds 5 MB upload limit'}, status_code=413)(scope, receive, send)

        async def bounded_receive():
            nonlocal size
            message = await receive()
            size += len(message.get('body', b''))
            if size > MAX_BODY:
                raise HTTPException(413, 'Request body exceeds upload limit')
            return message

        async def timed_send(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
                message.setdefault('headers', []).extend([(b'x-request-id', request_id.encode()),
                    (b'x-content-type-options', b'nosniff')])
            await send(message)
        try:
            await self.app(scope, bounded_receive, timed_send)
        finally:
            route = scope.get('route')
            logger.info(json.dumps({'request_id': request_id, 'method': scope['method'],
                'route': getattr(route, 'path', 'unmatched'), 'status': status,
                'duration_ms': round((time.monotonic() - started) * 1000)}))
