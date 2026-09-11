# @audit-fixture
# @rule: taint_rce
# @category: security
# @expected: clean
from wtforms import Form, StringField, validators
class F(Form): name = StringField('Name', [validators.Length(min=1, max=100)])
