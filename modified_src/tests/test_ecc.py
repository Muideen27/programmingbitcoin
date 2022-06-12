#!/usr/bin/python3
"""`test_ecc` - Unit test module for ecc.py

Modified from original code base developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

from unittest import TestCase
from unittest import main
from random import randint

from ecc import (
    FinFieldElem,
    ECPoint,
    SECP256K1,
    S256FieldElem,
    S256Point,
    PublicKey,
    Signature,
    PrivateKey,
)


class SongTestFinFieldElem(TestCase):
    """From Song's original unit tests for FieldElement methods.

    """
    def test_ne(self):
        a = FinFieldElem(2, 31)
        b = FinFieldElem(2, 31)
        c = FinFieldElem(15, 31)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FinFieldElem(2, 31)
        b = FinFieldElem(15, 31)
        self.assertEqual(a + b, FinFieldElem(17, 31))
        a = FinFieldElem(17, 31)
        b = FinFieldElem(21, 31)
        self.assertEqual(a + b, FinFieldElem(7, 31))

    def test_sub(self):
        a = FinFieldElem(29, 31)
        b = FinFieldElem(4, 31)
        self.assertEqual(a - b, FinFieldElem(25, 31))
        a = FinFieldElem(15, 31)
        b = FinFieldElem(30, 31)
        self.assertEqual(a - b, FinFieldElem(16, 31))

    def test_mul(self):
        a = FinFieldElem(24, 31)
        b = FinFieldElem(19, 31)
        self.assertEqual(a * b, FinFieldElem(22, 31))

    def test_rmul(self):
        a = FinFieldElem(24, 31)
        b = 2
        self.assertEqual(b * a, a + a)

    def test_pow(self):
        a = FinFieldElem(17, 31)
        self.assertEqual(a**3, FinFieldElem(15, 31))
        a = FinFieldElem(5, 31)
        b = FinFieldElem(18, 31)
        self.assertEqual(a**5 * b, FinFieldElem(16, 31))

    def test_div(self):
        a = FinFieldElem(3, 31)
        b = FinFieldElem(24, 31)
        self.assertEqual(a / b, FinFieldElem(4, 31))
        a = FinFieldElem(17, 31)
        self.assertEqual(a**-3, FinFieldElem(29, 31))
        a = FinFieldElem(4, 31)
        b = FinFieldElem(11, 31)
        self.assertEqual(a**-4 * b, FinFieldElem(13, 31))


class SongTestECPoint(TestCase):
    """From Song's original unit tests for Point methods.

    """
    def test_ne(self):
        a = ECPoint(x=3, y=-7, a=5, b=7)
        b = ECPoint(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_on_curve(self):
        with self.assertRaises(ValueError):
            ECPoint(x=-2, y=4, a=5, b=7)
        # these should not raise an error
        ECPoint(x=3, y=-7, a=5, b=7)
        ECPoint(x=18, y=77, a=5, b=7)

    def test_add0(self):
        a = ECPoint(x=None, y=None, a=5, b=7)
        b = ECPoint(x=2, y=5, a=5, b=7)
        c = ECPoint(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = ECPoint(x=3, y=7, a=5, b=7)
        b = ECPoint(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, ECPoint(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = ECPoint(x=-1, y=1, a=5, b=7)
        self.assertEqual(a + a, ECPoint(x=18, y=-77, a=5, b=7))


class SongTestECC(TestCase):
    """From Song's original unit tests for Points with FieldElement coordinates.

    """
    def test_on_curve(self):
        # tests the following points for whether they are on the curve or not -
        # on curve y^2=x^3-7 over F_223:
        # (192,105) (17,56) (200,119) (1,193) (42,99)
        # any that aren't should raise a ValueError
        prime = 223
        a = FinFieldElem(0, prime)
        b = FinFieldElem(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x_raw, y_raw in valid_points:
            x = FinFieldElem(x_raw, prime)
            y = FinFieldElem(y_raw, prime)
            # Creating the point should not result in an error
            ECPoint(x, y, a, b)
        for x_raw, y_raw in invalid_points:
            x = FinFieldElem(x_raw, prime)
            y = FinFieldElem(y_raw, prime)
            with self.assertRaises(ValueError):
                ECPoint(x, y, a, b)

    def test_add(self):
        # tests the following additions on curve y^2=x^3-7 over F_223:
        # (192,105) + (17,56)
        # (47,71) + (117,141)
        # (143,98) + (76,66)
        prime = 223
        a = FinFieldElem(0, prime)
        b = FinFieldElem(7, prime)
        additions = (
            # (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        )
        for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in additions:
            x1 = FinFieldElem(x1_raw, prime)
            y1 = FinFieldElem(y1_raw, prime)
            p1 = ECPoint(x1, y1, a, b)
            x2 = FinFieldElem(x2_raw, prime)
            y2 = FinFieldElem(y2_raw, prime)
            p2 = ECPoint(x2, y2, a, b)
            x3 = FinFieldElem(x3_raw, prime)
            y3 = FinFieldElem(y3_raw, prime)
            p3 = ECPoint(x3, y3, a, b)
            self.assertEqual(p1 + p2, p3)

    def test_rmul(self):
        # tests the following scalar multiplications
        # 2*(192,105)
        # 2*(143,98)
        # 2*(47,71)
        # 4*(47,71)
        # 8*(47,71)
        # 21*(47,71)
        prime = 223
        a = FinFieldElem(0, prime)
        b = FinFieldElem(7, prime)
        multiplications = (
            # (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
            (21, 47, 71, None, None),
        )
        for coefficient, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
            x1 = FinFieldElem(x1_raw, prime)
            y1 = FinFieldElem(y1_raw, prime)
            p1 = ECPoint(x1, y1, a, b)
            # x and y of None initialize the point at infinity
            if x2_raw is None:
                p2 = ECPoint(None, None, a, b)
            else:
                x2 = FinFieldElem(x2_raw, prime)
                y2 = FinFieldElem(y2_raw, prime)
                p2 = ECPoint(x2, y2, a, b)
            # check that the product is equal to the expected point
            self.assertEqual(coefficient * p1, p2)


class SongTestPublicKey(TestCase):
    """From Song's original unit tests for S256Point when used as a public key.

    """
    def test_order(self):
        point = PublicKey.N * PublicKey.G
        self.assertIsNone(point.x)

    def test_pubpoint(self):
        points = (
            # secret, x, y
            (7,
             0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc,
             0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da
            ),
            (1485,
             0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda,
             0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55
            ),
            (2**128,
             0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da,
             0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82
            ),
            (2**240 + 2**31,
             0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116,
             0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053
            ),
        )
        for secret, x, y in points:
            point = S256Point(x, y)
            self.assertEqual(secret * PublicKey.G, point)

    def test_verify(self):
        pubkey = PublicKey(
            0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
            0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(pubkey.verify(z, Signature(r, s)))
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(pubkey.verify(z, Signature(r, s)))

    def test_sec(self):
        coefficient = 999**3
        uncompressed = '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c'+\
        '9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245a'+\
        'ea7f3f911f9'
        compressed = '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9d'+\
        'e234496808d5'
        point = coefficient * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(pubkey.sec(compressed=False),
                         bytes.fromhex(uncompressed))
        self.assertEqual(pubkey.sec(compressed=True),
                         bytes.fromhex(compressed))
        coefficient = 123
        uncompressed = '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf'+\
        '4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026'+\
        'dbd2d864e6b'
        compressed = '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c'+\
        '1e665c1fe9b5'
        point = coefficient * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(pubkey.sec(compressed=False),
                         bytes.fromhex(uncompressed))
        self.assertEqual(pubkey.sec(compressed=True),
                         bytes.fromhex(compressed))
        coefficient = 42424242
        uncompressed = '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fe'+\
        'e0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c'+\
        '91fb7da54a3'
        compressed = '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0'+\
        'f20614066f8e'
        point = coefficient * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(pubkey.sec(compressed=False),
                         bytes.fromhex(uncompressed))
        self.assertEqual(pubkey.sec(compressed=True),
                         bytes.fromhex(compressed))

    def test_address(self):
        secret = 888**3
        mainnet_address = '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'
        testnet_address = 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'
        point = secret * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(
            pubkey.address(compressed=True, testnet=False), mainnet_address)
        self.assertEqual(
            pubkey.address(compressed=True, testnet=True), testnet_address)
        secret = 321
        mainnet_address = '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj'
        testnet_address = 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP'
        point = secret * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(
            pubkey.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            pubkey.address(compressed=False, testnet=True), testnet_address)
        secret = 4242424242
        mainnet_address = '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb'
        testnet_address = 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s'
        point = secret * PublicKey.G
        pubkey = PublicKey(x=point.x, y=point.y)
        self.assertEqual(
            pubkey.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            pubkey.address(compressed=False, testnet=True), testnet_address)


class SongTestSignature(TestCase):
    """From Song's original unit tests for signatures.

    """
    def test_der(self):
        testcases = (
            (1, 2),
            (randint(0, 2**256), randint(0, 2**255)),
            (randint(0, 2**256), randint(0, 2**255)),
        )
        for r, s in testcases:
            sig = Signature(r, s)
            der = sig.der()
            sig2 = Signature.from_der(der)
            self.assertEqual(sig2.r, r)
            self.assertEqual(sig2.s, s)


class SongTestPrivateKey(TestCase):
    """From Song's original unit tests for private keys.

    """
    def test_sign(self):
        pk = PrivateKey(randint(0, PrivateKey.N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_wif(self):
        pk = PrivateKey(2**256 - 2**199)
        expected = 'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'
        self.assertEqual(pk.wif(compressed=True, testnet=False), expected)
        pk = PrivateKey(2**256 - 2**201)
        expected = '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'
        self.assertEqual(pk.wif(compressed=False, testnet=True), expected)
        pk = PrivateKey(
            0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d)
        expected = '5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty'
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)
        pk = PrivateKey(
            0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f)
        expected = 'cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg'
        self.assertEqual(pk.wif(compressed=True, testnet=True), expected)


"""

class TestFinFieldElem(TestCase):
    ""Refactored unit tests for FinFieldElem object methods.

    ""
    def test_init(self):
        # instantiate valid field element
        a = FinFieldElem(2, 31)
        self.assertTrue(a.num == 2 and a.prime == 31)
        # Error for negative num values
        self.assertRaises(ValueError, FinFieldElem, -1, 31)
        # Error for num values >= order(prime)
        self.assertRaises(ValueError, FinFieldElem, 31, 31)

    def test_repr(self):
        a = FinFieldElem(2, 31)
        self.assertEqual(a.__repr__(), '{}_{}({})'.format(
            a.__class__, a.prime, a.num))

    def test_eq(self):
        a = FinFieldElem(2, 31)
        b = FinFieldElem(2, 31)
        c = FinFieldElem(2, 10)
        # Addition with member of same field
        self.assertEqual(a, b)
        # Comparing to non-field element types always inequal
        self.assertFalse(a == 2)
        # Comparing to members of other fields always inequal
        self.assertFalse(a == c)

    def test_ne(self):
        a = FinFieldElem(2, 31)
        b = FinFieldElem(2, 31)
        c = FinFieldElem(15, 31)
        d = FinFieldElem(2, 10)
        self.assertEqual(a, b)
        # Inequal elements of same field
        self.assertTrue(a != c)
        # Equal elements of same field
        self.assertFalse(a != b)
        # Comparing to non-field element types always inequal
        self.assertTrue(a != 2)
        # Comparing to members of other fields always inequal
        self.assertTrue(a != d)

    def test_add(self):
        a = FinFieldElem(2, 31)
        b = FinFieldElem(15, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FinFieldElem.__add__, a,
                          FinFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FinFieldElem.__add__, a, 2)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FinFieldElem(17, 31))
        a = FinFieldElem(17, 31)
        b = FinFieldElem(21, 31)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FinFieldElem(7, 31))

    def test_sub(self):
        a = FinFieldElem(29, 31)
        b = FinFieldElem(4, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FinFieldElem.__sub__, a,
                          FinFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FinFieldElem.__sub__, a, 2)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FinFieldElem(25, 31))
        a = FinFieldElem(15, 31)
        b = FinFieldElem(30, 31)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FinFieldElem(16, 31))

    def test_mul(self):
        a = FinFieldElem(24, 31)
        b = FinFieldElem(19, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FinFieldElem.__mul__, a,
                          FinFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FinFieldElem.__mul__, a, 2)
        # a *f b == (a * b) % p
        self.assertEqual(a * b, FinFieldElem(22, 31))

    def test_pow(self):
        a = FinFieldElem(17, 31)
        # a **f b == (a ** b) % p
        self.assertEqual(a**3, FinFieldElem(15, 31))
        a = FinFieldElem(5, 31)
        b = FinFieldElem(18, 31)
        # a **f 5 *f b == (a**5 * b) % p
        self.assertEqual(a**5 * b, FinFieldElem(16, 31))
        a = FinFieldElem(17, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-3, FinFieldElem(29, 31))
        a = FinFieldElem(4, 31)
        b = FinFieldElem(11, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-4 * b, FinFieldElem(13, 31))

    def test_div(self):
        # Note: __truediv__ implemented, not __floordiv__
        a = FinFieldElem(3, 31)
        b = FinFieldElem(24, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FinFieldElem.__truediv__, a,
                          FinFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FinFieldElem.__truediv__, a, 2)
        # a /f b == a /f (b **f (p - 2))
        self.assertEqual(a / b, FinFieldElem(4, 31))


class TestECPoint(TestCase):
    ""Refactored unit tests for ECPoint object methods.

    ""
    def test_init(self):
        with self.assertRaises(ValueError):
            ECPoint(x=-2, y=4, a=5, b=7)
        # These should not raise an error
        ECPoint(x=3, y=-7, a=5, b=7)
        ECPoint(x=18, y=77, a=5, b=7)

    # def test_repr(self):

    def test_ne(self):
        # Implicitly tests __eq__
        a = ECPoint(x=3, y=-7, a=5, b=7)
        b = ECPoint(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_add_properties(self):
        a = ECPoint(x=None, y=None, a=5, b=7)
        b = ECPoint(x=2, y=5, a=5, b=7)
        c = ECPoint(x=2, y=-5, a=5, b=7)
        # Additive identity test
        self.assertEqual(a + b, b)
        # Commutativity test
        self.assertEqual(b + a, b)
        # Invertability test
        self.assertEqual(b + c, a)
        # Associativity test
        self.assertEqual((a + b) + c, a + (b + c))

    def test_add_inequal_points_sum_on_curve(self):
        a = ECPoint(x=3, y=7, a=5, b=7)
        b = ECPoint(x=-1, y=-1, a=5, b=7)
        # a.x != b.x and a.y != b.y, sum is on the curve
        self.assertEqual(a + b, ECPoint(x=2, y=-5, a=5, b=7))

    def test_add_equal_points_sum_on_curve(self):
        a = ECPoint(x=-1, y=-1, a=5, b=7)
        # non-vertical tangent, doubling of point is on the curve
        self.assertEqual(a + a, ECPoint(x=18, y=77, a=5, b=7))
"""


if __name__ == '__main__':
    main()
