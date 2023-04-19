from http import HTTPStatus

import pytest
from flask import url_for

from db.helper import UserTokens
from tests.functional.src.data import test_data


def test_get_all_roles(client):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.get(
        url_for("Auth.get_all_roles"),
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert res.status_code == HTTPStatus.OK


def test_create_roles(client):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.post(
        url_for("Auth.add_role"),
        headers={"Authorization": "Bearer " + tokens.access_token},
        json=test_data.ROLE_TO_CREATE_AND_DELETE,
    )

    assert res.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "test_login, expected",
    [(test_data.TEST_LOGIN, HTTPStatus.OK), ("someuser", HTTPStatus.UNAUTHORIZED)],
)
def test_login(client, test_login, expected):
    res = client.post(
        url_for("Auth.login"),
        json={"login": test_login, "password": test_data.TEST_PASSWORD},
    )

    assert res.status_code == expected


def test_get_role_by_id(client):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.get(
        url_for("Auth.get_role_by_id", id=1),
        headers={"Authorization": "Bearer " + tokens.access_token},
    )

    assert res.status_code == HTTPStatus.OK


def test_update_role_by_id(client):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.put(
        url_for("Auth.get_role_by_id", id=1),
        headers={"Authorization": "Bearer " + tokens.access_token},
        json={"is_privileged": True, "is_superuser": True, "name": "Admin"},
    )

    assert res.status_code == HTTPStatus.OK


def test_delete_role_by_id(client):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.delete(
        url_for("Auth.get_role_by_id", id=4),
        headers={"Authorization": "Bearer " + tokens.access_token},
        json=test_data.ROLE_TO_CREATE_AND_DELETE,
    )

    assert res.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "test_role, expected",
    [("Admin", HTTPStatus.OK), ("SomeRole", HTTPStatus.BAD_REQUEST)],
)
def test_update_user_role_by_id(client, test_role, expected):
    access = client.post(
        url_for("Auth.login"),
        json={"login": test_data.TEST_LOGIN, "password": test_data.TEST_PASSWORD},
    )
    tokens = UserTokens(**access.json)
    res = client.put(
        url_for("Auth.update_user_role_by_id", user_id=test_data.TEST_USER_ID),
        headers={"Authorization": "Bearer " + tokens.access_token},
        json={"role_name": test_role},
    )

    assert res.status_code == expected
