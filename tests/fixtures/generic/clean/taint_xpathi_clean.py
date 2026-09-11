# @audit-fixture
# @rule: taint_xpathi
# @category: security
# @expected: clean
from flask import request
from lxml import etree
@app.route("/search")
def search():
    query = int(request.args.get("id"))
    tree.xpath(f"//item[@id={query}]")
