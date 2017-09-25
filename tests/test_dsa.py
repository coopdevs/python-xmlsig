import unittest
from os import path

from OpenSSL import crypto

import xmlsig
from lxml import etree
from tests.base import parse_xml, BASE_DIR


class TestDSASignature(unittest.TestCase):
    def test_dsa(self):
        root = parse_xml("data/sign-dsa-in.xml")
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        self.assertIsNotNone(sign)
        ctx = xmlsig.SignatureContext()
        with open(path.join(BASE_DIR, "data/dsacred.p12"), "rb") as key_file:
            ctx.load_pcks12(crypto.load_pkcs12(key_file.read()))
        ctx.sign(sign)
        ctx.verify(sign)

    def test_verify(self):
        ctx = xmlsig.SignatureContext()
        root = parse_xml("data/sign-dsa-out.xml")
        sign = root.xpath(
            '//ds:Signature', namespaces={'ds': xmlsig.constants.DSigNs}
        )[0]
        ctx.verify(sign)
