import base64
import requests


class TypingDNA:
    def __init__(self, apiKey, apiSecret):
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        self.base_url = "https://api.typingdna.com"

        authstring = f"{apiKey}:{apiSecret}"
        self.headers = {
            "Authorization": "Basic " + base64.encodestring(authstring.encode()).decode().replace("\n", ""),
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def save(self, id, tp, custom_field=None):
        url = f"{self.base_url}/save/{id}"
        data = {
            "tp": tp,
            "custom_field": custom_field
        }
        return requests.post(url, headers=self.headers, data=data)

    def verify(self, id, tp, quality, device_similarity_only=None, position_only=None, custom_field=None):
        url = f"{self.base_url}/verify/{id}"
        data = {
            "tp": tp,
            "quality": quality,
            "device_similarity_only": device_similarity_only,
            "position_only": position_only,
            "custom_field": custom_field
        }
        return requests.post(url, headers=self.headers, data=data)
