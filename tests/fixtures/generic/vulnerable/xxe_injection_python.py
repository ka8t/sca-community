# @audit-fixture
# @rule: xxe_injection_python
# @category: security
# @expected: detected
# VULNERABLE: parser XML avec resolve_entities=True consommant du XML utilisateur (CWE-611)
from lxml import etree
from flask import request

def parse_xml():
    xml_string = request.data
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_string, parser)
