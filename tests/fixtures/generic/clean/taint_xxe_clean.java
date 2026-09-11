// @audit-fixture
// @rule: taint_xxe
// @category: security
// @expected: clean
import defusedxml.ElementTree as ET
from flask import request
@app.route("/parse")
def parse():
    xml = request.data
    ET.fromstring(xml)
