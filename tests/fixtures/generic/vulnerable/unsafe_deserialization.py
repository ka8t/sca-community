# @audit-fixture
# @rule: taint_deserialization
# @category: security
# @expected: detected
# VULNERABLE: désérialisation de données non fiables issues d'une requête (CWE-502)

import pickle
import yaml
from flask import request


def load_user_data():
    raw_bytes = request.data
    return pickle.loads(raw_bytes)


def load_config():
    user_input = request.form["config"]
    return yaml.load(user_input)
