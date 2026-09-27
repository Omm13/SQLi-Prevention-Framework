import requests


BASE_URL = "http://127.0.0.1:5000"

SQLI_USERNAME = "' OR '1'='1' /*"
SQLI_PASSWORD = "test"


def test_vulnerable_endpoint_accepts_sqli():
    response = requests.post(
        f"{BASE_URL}/vulnerable-login",
        data={
            "username": SQLI_USERNAME,
            "password": SQLI_PASSWORD
        }
    )

    assert response.status_code == 200


def test_secure_endpoint_blocks_sqli():
    response = requests.post(
        f"{BASE_URL}/secure-login",
        data={
            "username": SQLI_USERNAME,
            "password": SQLI_PASSWORD
        }
    )

    assert response.status_code == 401