# @audit-fixture
# @rule: missing_mfa_python
# @category: security
# @expected: clean
# Régression customer-project : un OVERRIDE de framework (def authenticate + appel
# super().authenticate) n'est PAS un point de login maison. Même sans mot-clé
# MFA dans ce fichier (le MFA vit ailleurs dans le projet), il ne doit pas
# déclencher « Missing MFA » — le `has` exclut désormais les définitions et les
# appels `.authenticate` (super/self).
from typing import Optional


class UserManager:
    async def authenticate(self, credentials) -> Optional["User"]:
        """Override : bloque les comptes non approuvés."""
        user = await super().authenticate(credentials)
        if user is None:
            return None
        return user

    def _delegate(self, creds):
        return self.authenticate(creds)
