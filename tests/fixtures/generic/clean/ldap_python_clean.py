# Fixture clean : LDAP Python avec filtre paramétré
import ldap
from ldap.filter import filter_format

def find_user(username):
    conn = ldap.initialize("ldap://localhost")
    conn.simple_bind_s("cn=admin", "password")
    safe_filter = filter_format("(uid=%s)", [username])
    result = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, safe_filter)
    return result
