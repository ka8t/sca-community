# @audit-fixture
# @rule: taint_xpathi
# @category: security
# @expected: detected
from flask import request
from lxml import etree
@app.route("/search")
def search():
    query = request.args.get("q")
    tree.xpath(f"//item[name='{query}']")
