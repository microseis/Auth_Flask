from http import HTTPStatus

from flask import url_for
from flask.testing import Client
from db.helper import UserTokens
from tests.functional.src.data import test_data


def test_register(client: Client) -> None:
    access = client.post(
        url_for("Auth.register_user"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    res = client.get(
        url_for("Auth.get_all_roles"),
    )

    assert access.status_code == HTTPStatus.OK
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_login(client: Client) -> None:
    access = client.post(
        url_for("Auth.login"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    res = client.get(
        url_for("Auth.get_all_roles"),
    )

    assert access.status_code == HTTPStatus.OK
    assert res.status_code == HTTPStatus.UNAUTHORIZED


def test_logout(client: Client) -> None:
    access = client.post(
        url_for("Auth.login"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    tokens = UserTokens(**access.json)
    logout = client.post(
        url_for("Auth.user_logout"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert access.status_code == HTTPStatus.OK
    assert logout.status_code == HTTPStatus.OK


def test_change_password(client: Client) -> None:
    access = client.post(
        url_for("Auth.login"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    tokens = UserTokens(**access.json)
    route = client.post(
        url_for("Auth.change_password"),
        json=test_data.CHANGE_PASSWORD,
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert access.status_code == HTTPStatus.OK
    assert route.status_code == HTTPStatus.OK


def test_get_user_history(client: Client) -> None:
    access = client.post(
        url_for("Auth.login"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    tokens = UserTokens(**access.json)
    route = client.get(
        url_for("Auth.get_user_history"),
        json=test_data.CHANGE_PASSWORD,
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert access.status_code == HTTPStatus.OK
    assert route.status_code == HTTPStatus.OK


def test_refresh(client: Client) -> None:
    access = client.post(
        url_for("Auth.login"),
        json={
            "login": test_data.TEST_USER_LOGIN,
            "password": test_data.TEST_USER_PASSWORD,
        },
    )
    tokens = UserTokens(**access.json)
    route = client.post(
        url_for("Auth.refresh"),
        json=tokens.json(),
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert access.status_code == HTTPStatus.OK
    assert route.status_code == HTTPStatus.OK
