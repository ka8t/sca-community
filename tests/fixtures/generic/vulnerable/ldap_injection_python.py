# @audit-fixture
# @rule: taint_ldap
# @expected: detected
# Fixture vulnérable : LDAP injection Python — entrée HTTP concaténée dans le filtre
import ldap

from flask import request


def find_user():
    username = request.args.get("user")
    conn = ldap.initialize("ldap://localhost")
    conn.simple_bind_s("cn=admin", "password")
    result = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")
    return result


# Multi-ligne : search_s avec concaténation sur plusieurs lignes
def find_user_multiline():
    username = request.args.get("user")
    conn = ldap.initialize("ldap://localhost")
    conn.simple_bind_s("cn=admin", "password")
    result = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        "(uid=" + username + ")"
    )
    return result
