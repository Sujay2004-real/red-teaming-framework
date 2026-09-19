"""Thread-local pooled provider transport with bounded responses and telemetry."""
import json
import logging
import threading
import time
import requests

logger = logging.getLogger(__name__)
_local = threading.local()
MAX_RESPONSE = 2 * 1024 * 1024


def metadata():
    return dict(getattr(_local, 'metadata', {}))


class Transport:
    RequestException = requests.RequestException

    def post(self, url, **kwargs):
        if not hasattr(_local, 'session'):
            _local.session = requests.Session()
            _local.session.trust_env = False
        started = time.monotonic()
        _local.metadata = {'model': kwargs.get('json', {}).get('model', ''), 'status': 'failed'}
        timeout = kwargs.pop('timeout', 60)
        try:
            with _local.session.post(url, timeout=(10, timeout), stream=True, allow_redirects=False, **kwargs) as response:
                response.raise_for_status()
                if response.is_redirect:
                    raise ValueError('Provider redirects are not permitted')
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_RESPONSE or time.monotonic() - started > timeout:
                        raise ValueError('Provider response exceeded its budget')
                    chunks.append(chunk)
                response._content = b''.join(chunks)
                response._content_consumed = True
                data = response.json()
                _local.metadata.update(status='completed', usage=data.get('usage', {}))
                return response
        except Exception as exc:
            _local.metadata['fallback_reason'] = type(exc).__name__
            raise
        finally:
            _local.metadata['duration_ms'] = round((time.monotonic() - started) * 1000)
            logger.info('provider_request %s', json.dumps(_local.metadata))


transport = Transport()
