# @audit-fixture
# @rule: dangerous_eval
# @category: security
# @expected: clean
import ast
def safe_eval(expr): return ast.literal_eval(expr)
