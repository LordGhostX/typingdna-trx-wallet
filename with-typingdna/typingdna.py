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
    
    def hash_text(self, text):
        return hashlib.sha1((text + text[::-1]).encode()).hexdigest()
