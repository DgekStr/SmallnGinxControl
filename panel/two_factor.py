import base64
import io
import re

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage


def generate_totp_secret():
    return pyotp.random_base32()


def provisioning_uri(secret, account_name):
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name='SmallnGinxControl')


def qr_data_uri(uri):
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=5, border=4)
    code.add_data(uri)
    code.make(fit=True)
    image = code.make_image(image_factory=SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    encoded = base64.b64encode(output.getvalue()).decode('ascii')
    return 'data:image/svg+xml;base64,' + encoded


def verify_totp(secret, code):
    token = str(code or '').strip().replace(' ', '')
    return bool(re.fullmatch(r'\d{6}', token)) and pyotp.TOTP(secret).verify(token, valid_window=1)