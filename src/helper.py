import re


def password_check(password):
    # calculating the length
    length_error = len(password) < 5

    # overall result
    password_ok = not length_error

    return {
        'password_ok': password_ok,
        'length_error': length_error,
    }


def login_check(login):
    # calculating the length
    length_error = len(login) < 3

    # searching for symbols
    symbol_error = re.search("^[A-Za-z][A-Za-z0-9_.]*$", login) is None

    # overall result
    login_ok = not length_error

    return {
        'login_ok': login_ok,
        'length_error': length_error,
        'symbol_error': symbol_error,
    }
