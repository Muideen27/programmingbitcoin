#!/usr/bin/python3
"""Unit test module for ecc.py

Modified from original code base developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

from unittest import TestCase
from unittest import main
from random import randint

# Normally unsafe
from ecc import *


class TestFiniteFieldElem(TestCase):
    """Unit tests for FiniteFieldElem object methods.

    """
    def test_init(self):
        # instantiate valid field element
        a = FiniteFieldElem(2, 31)
        self.assertTrue(a.num == 2 and a.prime == 31)
        # Error for negative num values
        self.assertRaises(ValueError, FiniteFieldElem, -1, 31)
        # Error for num values >= order(prime)
        self.assertRaises(ValueError, FiniteFieldElem, 31, 31)

    def test_repr(self):
        a = FiniteFieldElem(2, 31)
        self.assertEqual(a.__repr__(), '{}_{}({})'.format(
            a.__class__, a.prime, a.num))

    def test_eq(self):
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(2, 31)
        c = FiniteFieldElem(2, 10)
        # Addition with member of same field
        self.assertEqual(a, b)
        # Comparing to non-field element types always inequal
        self.assertFalse(a == 2)
        # Comparing to members of other fields always inequal
        self.assertFalse(a == c)

    def test_ne(self):
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(2, 31)
        c = FiniteFieldElem(15, 31)
        d = FiniteFieldElem(2, 10)
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
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(15, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__add__, a,
                          FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__add__, a, 2)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FiniteFieldElem(17, 31))
        a = FiniteFieldElem(17, 31)
        b = FiniteFieldElem(21, 31)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FiniteFieldElem(7, 31))

    def test_sub(self):
        a = FiniteFieldElem(29, 31)
        b = FiniteFieldElem(4, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__sub__, a,
                          FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__sub__, a, 2)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FiniteFieldElem(25, 31))
        a = FiniteFieldElem(15, 31)
        b = FiniteFieldElem(30, 31)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FiniteFieldElem(16, 31))

    def test_mul(self):
        a = FiniteFieldElem(24, 31)
        b = FiniteFieldElem(19, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__mul__, a,
                          FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__mul__, a, 2)
        # a *f b == (a * b) % p
        self.assertEqual(a * b, FiniteFieldElem(22, 31))

    def test_pow(self):
        a = FiniteFieldElem(17, 31)
        # a **f b == (a ** b) % p
        self.assertEqual(a**3, FiniteFieldElem(15, 31))
        a = FiniteFieldElem(5, 31)
        b = FiniteFieldElem(18, 31)
        # a **f 5 *f b == (a**5 * b) % p
        self.assertEqual(a**5 * b, FiniteFieldElem(16, 31))
        a = FiniteFieldElem(17, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-3, FiniteFieldElem(29, 31))
        a = FiniteFieldElem(4, 31)
        b = FiniteFieldElem(11, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-4 * b, FiniteFieldElem(13, 31))

    def test_div(self):
        # Note: __truediv__ implemented, not __floordiv__
        a = FiniteFieldElem(3, 31)
        b = FiniteFieldElem(24, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__truediv__, a,
                          FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__truediv__, a, 2)
        # a /f b == a /f (b **f (p - 2))
        self.assertEqual(a / b, FiniteFieldElem(4, 31))


class ECPointTest(TestCase):
    """Unit tests for ECPoint object methods.

    """
    def test_init(self):
        with self.assertRaises(ValueError):
            ECPoint(x=-2, y=4, a=5, b=7)
        # These should not raise an error
        ECPoint(x=3, y=-7, a=5, b=7)
        ECPoint(x=18, y=77, a=5, b=7)

#    def test_repr(self):

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


class ECCTest(TestCase):
    """Unit tests for ECPoint objects with FiniteFieldElem values.

    """
    def test_on_curve(self):
        prime = 223
        a = FiniteFieldElem(0, prime)
        b = FiniteFieldElem(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x_raw, y_raw in valid_points:
            x = FiniteFieldElem(x_raw, prime)
            y = FiniteFieldElem(y_raw, prime)
            ECPoint(x, y, a, b)
        for x_raw, y_raw in invalid_points:
            x = FiniteFieldElem(x_raw, prime)
            y = FiniteFieldElem(y_raw, prime)
            with self.assertRaises(ValueError):
                ECPoint(x, y, a, b)

    def test_add(self):
        # tests the following additions on curve y^2=x^3-7 over F_223:
        # (192,105) + (17,56)
        # (47,71) + (117,141)
        # (143,98) + (76,66)
        prime = 223
        a = FiniteFieldElem(0, prime)
        b = FiniteFieldElem(7, prime)
        additions = (
            # (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        )
        for coords in additions:
            p1 = ECPoint(FiniteFieldElem(coords[0], prime),
                         FiniteFieldElem(coords[1], prime), a, b)
            p2 = ECPoint(FiniteFieldElem(coords[2], prime),
                         FiniteFieldElem(coords[3], prime), a, b)
            self.assertEqual(p1 + p2,
                             ECPoint(FiniteFieldElem(coords[4], prime),
                                     FiniteFieldElem(coords[5], prime),
                                     a, b))

    def test_rmul(self):
        # tests the following scalar multiplications
        # 2*(192,105)
        # 2*(143,98)
        # 2*(47,71)
        # 4*(47,71)
        # 8*(47,71)
        # 21*(47,71)
        prime = 223
        a = FiniteFieldElem(0, prime)
        b = FiniteFieldElem(7, prime)
        multiplications = (
            # (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
            (21, 47, 71, None, None),
        )
        for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
            x1 = FiniteFieldElem(x1_raw, prime)
            y1 = FiniteFieldElem(y1_raw, prime)
            p1 = ECPoint(x1, y1, a, b)
            # pass through None if p2 is infinity point
            if x2_raw is None:
                p2 = ECPoint(None, None, a, b)
            else:
                x2 = FiniteFieldElem(x2_raw, prime)
                y2 = FiniteFieldElem(y2_raw, prime)
                p2 = ECPoint(x2, y2, a, b)
            self.assertEqual(s * p1, p2)


class S256Test(TestCase):
    """Unit tests for S256Point properties and methods.

    """
    def test_order(self):
        # nG = "0" = infinity point
        point = SECP256K1.N * S256Point(SECP256K1.Gx, SECP256K1.Gy)
        self.assertIsNone(point.x)

    def test_rmul(self):
        # Scalar multiplication against group generator G, or eG = P
        points = (
            # secret, x, y
            (7,
             0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc,
             0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
            (1485,
             0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda,
             0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
            (2**128,
             0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da,
             0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
            (2**240 + 2**31,
             0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116,
             0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053)
        )

        G = S256Point(SECP256K1.Gx, SECP256K1.Gy)
        for secret, x, y in points:
            # initialize the secp256k1 point P
            point = S256Point(x, y)
            # check secret*G == point, or eG = P
            self.assertEqual(secret * G, point)


class PublicKeyTest(TestCase):
    """Unit tests for PublicKey methods.

    """
    def test_verify_sig(self):
        pub_key = PublicKey(
            0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
            0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(pub_key.verify_sig(z, Signature(r, s)))
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(pub_key.verify_sig(z, Signature(r, s)))


class PrivateKeyTest(TestCase):
    """Unit tests for PrivateKey methods.

    """
    def test_sign(self):
        pri_key = PrivateKey(randint(0, SECP256K1.N))
        z = randint(0, 2**256)
        sig = pri_key.sign(z)
        self.assertTrue(pri_key.pub_key.verify_sig(z, sig))


if __name__ == '__main__':
    unittest.main()
