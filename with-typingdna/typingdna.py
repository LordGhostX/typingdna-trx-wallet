import base64
import hashlib
import requests


class TypingDNA:
    def __init__(self, apiKey, apiSecret):
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        self.base_url = "https://api.typingdna.com"

        authstring = f"{apiKey}:{apiSecret}"
        self.headers = {
            "Authorization": "Basic " + base64.encodebytes(authstring.encode()).decode().replace("\n", ""),
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def auto(self, id, tp, custom_field=None):
        url = f"{self.base_url}/auto/{id}"
        data = {
            "tp": tp,
            "custom_field": custom_field
        }
        return requests.post(url, headers=self.headers, data=data)

    def check_user(self, id, pattern_type=None, text_id=None, custom_field=None):
        url = f"{self.base_url}/user/{id}"
        params = {
            "type": pattern_type,
            "text_id": text_id,
            "custom_field": custom_field
        }
        return requests.get(url, headers=self.headers, params=params)

    def hash_text(self, text):
        reversed_text = text[::-1]
        text_to_hash = text + reversed_text
        return hashlib.sha512(text_to_hash.encode()).hexdigest()
