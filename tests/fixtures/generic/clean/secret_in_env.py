# CLEAN: Secret loaded from environment variable
# Expected: Should NOT trigger Secret hardcode detection

import os

password = os.getenv("DB_PASSWORD")
api_key = os.environ.get("API_KEY")
