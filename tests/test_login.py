import requests
from requests.structures import CaseInsensitiveDict


def test_get_token():
    payload = {"username": "johndoe", "password": "secret"}
    ret = requests.post("http://127.0.0.1:5000/token", data=payload)

    assert ret.status_code == 200


def test_user_data():
    payload = {"username": "johndoe", "password": "secret"}
    ret = requests.post("http://127.0.0.1:5000/token", data=payload).json()
    token = ret["access_token"]

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {token}"

    ret = requests.get("http://127.0.0.1:5000/process_me", headers=headers)

    assert ret.status_code == 200
