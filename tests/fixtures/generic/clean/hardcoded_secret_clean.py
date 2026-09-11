# @audit-fixture
# @rule: hardcoded_secret
# @category: security
# @expected: clean
import os
API_KEY = os.environ.get('API_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY')
