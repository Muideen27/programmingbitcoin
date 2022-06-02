#!/usr/bin/python3

"""`ecc` - Elliptic Curve Cryptography module

Contains classes and constants necessary for implementing an educational mockup
of the secp256k1 ECC and ECDSA used in the Bitcoin mainnet.

Modified from original repository developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""
from collections import namedtuple
from hashlib import sha256
import hmac


class FiniteFieldElem:
    """Representation of a finite field element.

    A value in a set of integers from 0 to a prime - 1, for which arithmetic
    operations are defined with a modulo so that any resulting values are
    also in the set.

    Attributes:
        num   (int): value in the finite field set
        prime (int): prime number that is the upper bound of the set, also
            known as its "order"

    """
    def __init__(self, num, prime):
        """Instantiate a FiniteFieldElem object.

        Args:
            num   (int): finite field member
            prime (int): finite field order

        Note:
            Currently there is no validation of prime as a prime number,
            ideally a ValueError would be thrown if not.

        """
        if num >= prime or num < 0:
            raise ValueError(
                'Num {} not in field range 0 to {}'.format(
                    num, prime - 1))
        self.num = num
        self.prime = prime

    def __repr__(self):
        """Generates string representation of FiniteFieldElem.

        Returns:
            (str): representation of self

        """
        return '{}_{}({})'.format(self.__class__, self.prime, self.num)

    def __eq__(self, other):
        """Evaulates equality of finite field elements.

        Args:
            other (self.__class__): element to compare

        Returns:
            bool: True if equal, False otherwise

        """
        if type(other) is not self.__class__:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        """Evaulates inequality of finite field elements.

        Args:
            other (self.__class__): element to compare

        Returns:
            bool: True if inequal, False otherwise

        """
        if type(other) is not self.__class__:
            return True
        return self.num != other.num or self.prime != other.prime

    def __add__(self, other):
        """Adds one finite field element to another.

        Args:
            other (self.__class__): element to add

        Returns:
            (self.__class__): sum of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError('Can only add other elements in the same field')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        """Subtracts one finite field element from another.

        Args:
            other (self.__class__): element to subtract

        Returns:
            (self.__class__): difference of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError(
                'Can only subtract other elements in the same field')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        """Multiplies one finite field element by another.

        Args:
            other (self.__class__): multiplier element

        Returns:
            (self.__class__): product of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError(
                'Can only multiply by other elements in the same field')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        """Exponentiates a finite field element.

        Args:
            other (int): exponent (only base needs to be inside the field)

        Returns:
            (self.__class__): product of elements

        """
        # Fermat's Little Theorem: a**(P-1) = 1, so only the modulo matters.
        #   This makes all exponents positive, and greatly reduces larger ones.
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        """Divides one finite field element by another.

        To arrive at a means of finite field division, we can combine Fermat's
        Little Theorem, or:

            n**(p - 1) % p == 1 for p > n > 0

        with expressing division as multiplication by the inverse:

            a / b == a * (1/b) == a * b**-1

        such that:

            b**-1 == b**-1 * (b**(p - 1) % p) == b**(p - 2) % p

        and so:

            a /f b = (a * (b**(p - 2) % p)) % p

        Args:
            other (self.__class__): divisor element

        Returns:
            (self.__class__): quotient of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError(
                'Can only divide by other elements in the same field')
        num = (self.num * pow(other.num, other.prime - 2, other.prime)) % \
            self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient):
        """Scalar multiplication of finite field element, from right to left.

        Args:
            coefficient (int): scalar to multiply EC point

        Returns:
            self.__class__: product of field element and coefficient

        """
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


class ECPoint:
    """Representation of a point on an elliptic curve.

    A member of a set of (x, y) coordinates which satisfy:

        y**2 == x**3 + a * x + b

    for constants a and b. Such a set of points should have many of the
    properties of addition:

       Identity:
           A point exists such that adding it to another point does not change
           the point's values. Here the identity is called the infinity point,
           represented by x and y values of `None`.
       Invertability:
           For every point on the curve, there is a point to which adding it
           results in the identity.
       Commutativity:
           P1 + P2 == P2 + P1
       Associativity:
           (P1 + P2) + P3 == P1 + (P2 + P3)

    EC points can also construct groups, where the first in the group is an
    arbitrary point on the curve, called the generator, and each member of the
    group is multiplied by a scalar {G, 2G, 3G, ... nG} such that (n + 1)G is
    the infinity point. n + 1 is the order of the group (see __rmul__.)

    Attributes:
        a (int/FiniteFieldElem): first constant
        b (int/FiniteFieldElem): second constant
        x (int/FiniteFieldElem): x coordinate
        y (int/FiniteFieldElem): y coordinate

    """
    def __init__(self, x, y, a, b):
        """Instantiate an ECPoint object.

        Args:
            a (int/FiniteFieldElem): first constant
            b (int/FiniteFieldElem): second constant
            x (int/FiniteFieldElem): x coordinate
            y (int/FiniteFieldElem): y coordinate

        """
        # No need to evaluate infinity point (None, None)
        if x is not None and y is not None and y**2 != x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))
        self.a = a
        self.b = b
        self.x = x
        self.y = y

    def __repr__(self):
        """Generates string representation of elliptic curve point.

        Returns:
            (str): representation of self

        """
        if self.x is None:
            return 'ECPoint(infinity)'
        else:
            return 'ECPoint({},{})_{}_{}'.format(self.x, self.y,
                                                 self.a, self.b)

    def __eq__(self, other):
        """Evaulates equality of elliptic curve points.

        Args:
            other (self.__class__): point to compare

        Returns:
            bool: True if equal, False otherwise

        """
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        """Evaulates inequality of elliptic curve points.

        Args:
            other (self.__class__): point to compare

        Returns:
            bool: True if inequal, False otherwise

        """
        return not self == other

    def __add__(self, other):
        """Adds one elliptic curve point to another.

        Any two elliptic curve points and their sum point can be considered as
        a line intersecting the curve. These lines come in several varieties:

            Intersecting at three points:
                The sum of the points is the third intersection of the curve by
                a line desrcibed by P1 and P2.
            Intersecting at two points:
                Vertical line (P1.x == P2.x):
                    P2 is the inverse of P1; sum is the identity, or infinity
                    point.
                Line tangent to curve:
                    P1 == P2, sum is a different point on the curve.
            Intersecting at one point:
                Vertical tangent to curve (y coordinate is 0):
                    Sum is infinity point, as with other vertical intersecting
                    lines.
                Line is not vertical:
                    P1 + identity == P1; P2 + identity == P2.

        Args:
            other (self.__class__): point to add

        Returns:
            (self.__class__): sum of points

        """
        if self.a != other.a or self.b != other.b:
            raise TypeError(
                'Points {}, {} are not on the same curve'.format(self, other))

        # Any point added to identity is itself
        if self.x is None:
            return other
        if other.x is None:
            return self

        if self == other:
            # Multiplying by 0 avoids explicit definition of identity
            if (self.y == 0 * self.x):
                # Vertical line intersecting at 1 point, sum is infinity point
                return self.__class__(None, None, self.a, self.b)
            # Line is tangent to the curve, intersecting at two points
            slope = (3 * self.x**2 + self.a) / (2 * self.y)
            x = slope**2 - 2 * self.x
            y = slope * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        elif self.x == other.x:
            # Vertical line intersecting at two points, sum is infinity point
            return self.__class__(None, None, self.a, self.b)
        else:
            # Intersection at three points
            slope = (other.y - self.y) / (other.x - self.x)
            x = slope**2 - self.x - other.x
            y = slope * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        """Scalar multiplication of elliptic curve point, from right to left.

        Multiplication of a point can here be considered serial addition,
        but is expedited by using binary expansion.

        Args:
            coefficient (int): scalar to multiply EC point

        Returns:
            ECPoint: product of elliptic curve point and coefficient

        """
        coef = coefficient
        doubling = self
        product = self.__class__(None, None, self.a, self.b)  # "0"
        while coef > 0:
            if coef & 1:
                product += doubling
            doubling += doubling
            coef >>= 1
        return product


ECCProfile = namedtuple('ECCProfile', ['name', 'P', 'A', 'B', 'Gx', 'Gy', 'N'])
"""(namedtuple): Elliptic curve cryptography profile type, containing constants
needed to define a curve over a finite field, and to create a group to relate
public and private keys.

Note: Attributes of namedtuple and subclasses are not reassignable, and new
attributes may not be added.

Attributes:
    name (str): name of profile
    P (int):    prime, order of finite field
    A (int):    first constant of elliptic curve
    B (int):    second constant of elliptic curve
    Gx (int):   x coordinate of group generator point on elliptic curve
    Gy (int):   y coordinate of group generator point on elliptic curve
    N (int):    order of group

"""


SECP256K1 = ECCProfile(
    name='secp256k1', P=2**256 - 2**32 - 977, A=0, B=7,
    Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
"""(ECCProfile): Elliptic curve cryptography profile for secp256k1, the curve
used in Bitcoin.

"""


class S256FieldElem(FiniteFieldElem):
    """A secp256k1 finite field element.

    """
    def __init__(self, num, prime=None):
        """Instantiate a S256FieldElem object.

        Args:
            num   (int): finite field member

        """
        super().__init__(num=num, prime=SECP256K1.P)

    def __repr__(self):
        """Generates string representation of S256FieldElem.

        Returns:
            (str): representation of self

        """
        return '{:x}'.format(self.num).zfill(64)


class S256Point(ECPoint):
    """Representation of a point on the elliptic curve secp256k1.

    Attributes:
        A (int): first secp256k1 elliptic curve constant
        B (int): second secp256k1 elliptic curve constant
        N (int): secp256k1 group order

    """
    A = SECP256K1.A
    B = SECP256K1.B
    N = SECP256K1.N

    def __init__(self, x, y, a=None, b=None):
        """Instantiate a S256Point object.

        Args:
            x (int/S256FieldElement): x coordinate
            y (int/S256FieldElement): y coordinate

        """
        a, b = S256FieldElem(self.A), S256FieldElem(self.B)
        # x and y of None (infinity point) or field elements pass through
        if type(x) == int and type(y) == int:
            super().__init__(x=S256FieldElem(x), y=S256FieldElem(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        """Generates string representation of S256Point.

        Returns:
            (str): representation of self

        """
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        """Scalar multiplication of secp256k1 elliptic curve point, from right
        to left.

        Args:
            coefficient (int): scalar to multiply point

        Returns:
            S256Point: product of point and coefficient

        """
        # Scalar * N = 0, so only consider scalar mod N
        coef = coefficient % self.N
        return super().__rmul__(coef)


# ECCProfile.__repr__
def __repr__(self):
    """Generates string representation of an Elliptic Curve Cryptography
    profile of constants.

    """
    return "ECCProfile(name={}, P={:x}, A={:x}, B={:x}, G={}, N={:x})".format(
        self.name, self.P, self.A, self.B,
        S256Point(self.Gx, self.Gy), self.N).zfill(64)


setattr(ECCProfile, '__repr__', __repr__)
__repr__ = None  # Make uncallable outside ECCProfile


class PublicKey(S256Point):
    """A secp256k1 elliptic curve point P used in relation to private key e.

    Attributes:
        G (S256Point): secp256k1 group generator point

    """
    # super() does not work outside methods
    G = S256Point(SECP256K1.Gx, SECP256K1.Gy)

    # Originally defined __init__ to prevent creating public keys == infinity
    #   point, but this caused failure when verify_sig's `v * self` eventually
    #   calls ECPoint.__rmul__, and `product = self.__class__(None, None,
    #   self.a, self.b)`

    def __repr__(self):
        """Generates string representation of PublicKey.

        Returns:
            (str): representation of self

        """
        return 'PublicKey({}, {})'.format(self.x, self.y)

    def verify_sig(self, z, sig):
        """Verifies a secp256k1 ECDSA signature when point is a public key.

        Added to Song's code are two safety checks from:
        https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm.

        Args:
            z (int):         32-byte sha256 hash of the message that was signed
            sig (Signature): r and s values generated when signing a message
                             with the corresponding private key

        Returns:
            Bool: True if signature is verified by public key, False
            otherwise

        """
        # BTC wiki: ECDSA: Verify that both r and s are between 1 and n-1
        if not all([sig.r > 0, sig.r < self.N,
                    sig.s > 0, sig.s < self.N]):
            return False
        # Fermat's Little Theorem: 1/s == pow(s, N-2, N)
        s_inv = pow(sig.s, self.N - 2, self.N)
        # u = z / s
        u = z * s_inv % self.N
        # v = r / s
        v = sig.r * s_inv % self.N
        # u*G + v*P should equal R, ie have r as the x coordinate
        R = u * self.G + v * self
        # BTC wiki: ECDSA: Verify that R is not infinity point
        if R == 0 * self.G:
            return False
        return R.x.num == sig.r


class Signature:
    """Contains values derived from signing a message with the ECDSA
    algorithm, using secp256k1.

    Attributes:
        r (int): x coordinate of point kG
        s (int): signature calculated with hash of message and private key

    """
    def __init__(self, r, s):
        """Instantiate a Signature object.

        Args:
            r (int): x coordinate of point kG
            s (int): signature calculated with hash of message and private key

        """
        # x coordinate of R, from kG = R
        self.r = r
        # s = (z + r*e) / k
        self.s = s

    def __repr__(self):
        """Generates string representation of Signature.

        Returns:
            (str): representation of self

        """
        return 'Signature({:x},{:x})'.format(self.r, self.s)


class PrivateKey:
    """Representation of a secp256k1 private key.

    Attributes:
        N (int):             secp256k1 group order
        G (S256Point):       secp256k1 group generator point
        e (int):             private key; e in eG = P
        pub_key (S256Point): public key; P in eG = P

    """
    N = SECP256K1.N
    G = S256Point(SECP256K1.Gx, SECP256K1.Gy)

    def __init__(self, secret):
        """Instantiate a PrivateKey object.

        Args:
            secret (int): scalar to mulitply generator point

        """
        self.e = secret
        eG = self.e * self.G
        self.pub_key = PublicKey(eG.x, eG.y)

    def hex(self):
        """Represent private key as hexadecimal string.

        Returns:
            str: private key as 64 digit zero-padded hex string

        """
        return '{:x}'.format(self.e).zfill(64)

    def sign(self, z):
        """Generate an ECDSA secp256k1 signature for a message hash.

        Song's notation of calculating the signature, or s:

            uG + vP = R = kG
            uG + veG = kG
            u + ve = k, u = z/s, v = r/s
            z/s + re/s = k
            (z = re)/s = k
            s = (z + re)/k

        Note: Bitcoin wiki on ECDSA differs a bit, see comments. From:
        https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm.

        Args:
            z (int): expects a 32-byte sha256 hash of the data to sign

        Returns:
            Signature: contains s, and the r used in its calculation

        """
        # k needs to be sufficiently random, but also unique per signature
        k = self.deterministic_k(z)
        # r is the x coordinate of point kG
        # BTC wiki: ECDSA: need 0 < r < N:
        #   r = R.x % N
        #   if r = 0, generate another random k and start over
        r = (k * self.G).x.num
        # Fermat's Little Theorem: 1/k == pow(k, N-2, N)
        k_inv = pow(k, self.N - 2, self.N)
        # s = (z + r*e)/k
        s = (z + r * self.e) * k_inv % self.N
        # BTC wiki: ECDSA: need 0 < s < N:
        #   if s = 0, generate another random k and start over
        # TBD: Is this why Song makes this last modification of s? ch03 p70:
        #   "... using the low-s value will get nodes to relay our
        #   transactions. This is for malleability reasons."
        if s > self.N / 2:
            s = self.N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        """Derives a k value using a hash of the message and a private key.

        ECDSA requires k values that are pseudorandom, but also unique to each
        signature. Here a deterministic k is generated with an algorithm
        specified in RFC 6979 (see https://tools.ietf.org/html/rfc6979).

        Args:
            z (int): expects a 32-byte sha256 hash of the data to sign

        Returns:
            int: s, or the signature value

        """
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > self.N:
            z -= self.N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.e.to_bytes(32, 'big')
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, sha256).digest()
        v = hmac.new(k, v, sha256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, sha256).digest()
        v = hmac.new(k, v, sha256).digest()
        while True:
            v = hmac.new(k, v, sha256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < self.N:
                return candidate
            k = hmac.new(k, v + b'\x00', sha256).digest()
            v = hmac.new(k, v, sha256).digest()
