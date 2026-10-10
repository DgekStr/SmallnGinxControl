import json
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from .mattermost import send_webhook_message, validate_webhook_url
from .transactions import OperationError


class MattermostWebhookTests(SimpleTestCase):
    def test_webhook_url_requires_http_scheme_and_hostname(self):
        self.assertEqual(validate_webhook_url('https://mattermost.example/hooks/token'), 'https://mattermost.example/hooks/token')
        for value in ('', 'mattermost.example/hooks/token', 'ftp://mattermost.example/hooks/token', 'https://user:pass@mattermost.example/hooks/token', 'https://mattermost.example/hooks/token#fragment'):
            with self.subTest(value=value), self.assertRaises(OperationError):
                validate_webhook_url(value)

    @patch('panel.mattermost.urlopen')
    def test_sends_mattermost_text_payload_as_utf8_json(self, urlopen):
        response = Mock()
        response.status = 200
        urlopen.return_value.__enter__.return_value = response

        send_webhook_message('https://mattermost.example/hooks/token', 'Проверка')

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header('Content-type'), 'application/json')
        self.assertEqual(json.loads(request.data.decode('utf-8')), {'text': 'Проверка'})
        urlopen.assert_called_once_with(request, timeout=10)