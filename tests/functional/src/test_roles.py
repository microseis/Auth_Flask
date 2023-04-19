from http import HTTPStatus

from flask import url_for

from db.helper import UserTokens


def test_get_all_roles(client):
    access = client.post(
        url_for("Auth.login"), json={"login": "string", "password": "string"}
    )
    tokens = UserTokens(**access.json)
    res = client.get(
        url_for("Auth.get_all_roles"),
        headers={"Authorization": "Bearer " + tokens.access_token},
    )
    print(res)

    assert res.status_code == HTTPStatus.OK
