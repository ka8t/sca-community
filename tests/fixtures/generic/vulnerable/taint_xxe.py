# @audit-fixture
# @rule: taint_xxe
# @category: security
# @expected: detected
from flask import request
from lxml import etree
@app.route("/parse")
def parse():
    xml = request.data
    etree.fromstring(xml)
