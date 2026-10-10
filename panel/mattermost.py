import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .transactions import OperationError


def validate_webhook_url(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise OperationError('Укажите URL Mattermost webhook длиной до 2048 символов.')
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise OperationError('Укажите корректный HTTP или HTTPS URL Mattermost webhook.') from error
    if parsed.scheme not in {'https', 'http'} or not hostname or parsed.username or parsed.password or parsed.fragment:
        raise OperationError('Webhook должен быть корректным HTTP или HTTPS URL без учётных данных и fragment.')
    return value


def send_webhook_message(webhook_url, message):
    request = Request(
        validate_webhook_url(webhook_url),
        data=json.dumps({'text': message}, ensure_ascii=False).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urlopen(request, timeout=10) as response:
            if not 200 <= response.status < 300:
                raise OperationError(f'Mattermost webhook вернул HTTP {response.status}.')
    except HTTPError as error:
        raise OperationError(f'Mattermost webhook вернул HTTP {error.code}.') from None
    except OperationError:
        raise
    except Exception:
        raise OperationError('Не удалось подключиться к Mattermost webhook.') from None