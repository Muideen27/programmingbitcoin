#!/usr/bin/python3
"""`ecc` - Elliptic Curve Cryptography module

Contains classes and constants necessary for implementing an educational mockup
of the secp256k1 ECC and ECDSA used in Bitcoin circa 2019.

Modified from original repository developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

from collections import namedtuple
from hashlib import sha256
from io import BytesIO
import hmac

from helper import encode_base58_checksum, decode_base58_checksum, hash160


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

# redefine ECCProfile.__repr__
def __repr__(self):
    """Generates string representation of an Elliptic Curve Cryptography
    profile of constants.

    """
    fmt = "ECCProfile(name={}, P={:#0x}, A={}, B={}, G=({:#0x}, "+\
        "{:#0x}) N={:#0x})"
    return fmt.format(self.name, self.P, self.A, self.B,
                      self.Gx, self.Gy, self.N)


setattr(ECCProfile, '__repr__', __repr__)
__repr__ = None  # Make uncallable outside ECCProfile


class FinFieldElem:
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
        """Instantiates a FinFieldElem object.

        Args:
            num   (int): finite field member
            prime (int): finite field order

        """
        # Song p.76, in Compressed SEC Format section: prime cannot be 2
        if prime < 3:
            raise ValueError('prime must be greater than 2')
        # While it would be costly to validate prime as a prime number,
        #    ideally that would also be enforced with a ValueError
        if num >= prime or num < 0:
            raise ValueError(
                'num {} not in field range 0 to {}'.format(
                    num, prime - 1))
        self.num = num
        self.prime = prime

    def __repr__(self):
        """Generates string representation of FinFieldElem.

        Returns:
            (str): developer-oriented representation of self

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
            self.__class__: sum of elements

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
            self.__class__: difference of elements

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
            self.__class__: product of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError(
                'Can only multiply by other elements in the same field')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        """Exponentiates a finite field element.

        Args:
            exponent (int): only base needs to be inside the field

        Returns:
            self.__class__: product of elements

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
            self.__class__: quotient of elements

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
            coefficient (int): scalar to multiply EC point, need not be in field

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
        a (int): first constant
        b (int): second constant
        x (FinFieldElem): x coordinate
        y (FinFieldElem): y coordinate

    """
    def __init__(self, x, y, a, b):
        """Instantiate an ECPoint object.

        Args:
            a (int): first constant
            b (int): second constant
            x (FinFieldElem): x coordinate
            y (FinFieldElem): y coordinate

       """
        # No need to evaluate infinity point (None, None)
        if x is not None and y is not None and y**2 != x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))
        self.a = a
        self.b = b
        self.x = x
        self.y = y

    def __repr__(self):
        """Generates string representation of ECPoint.

        Returns:
            str: developer-oriented representation of self

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

        Using the curve over real numbers as an example, any two elliptic curve
        points and their sum point can be visualized as describing a line
        intersecting the curve. These lines come in several varieties:

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
            self.__class__: sum of points

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

        Multiplication of a point can here be considered serial addition, but
        is expedited by using binary expansion.

        Args:
            coefficient (int): scalar to multiply EC point

        Returns:
            self.__class__: product of elliptic curve point and coefficient

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


class S256FieldElem(FinFieldElem):
    """A secp256k1 finite field element.

    Attributes:
        P (int): secp256k1 finite field order, or 2**256 - 2**32 - 977

    """
    P = SECP256K1.P

    def __init__(self, num, prime=None):
        """Instantiate a S256FieldElem object.

        Args:
            num (int): finite field member

        """
        super().__init__(num=num, prime=self.P)

    def __repr__(self):
        """Generates string representation of S256FieldElem.

        Returns:
            str: developer-oriented representation of self

        """
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        """Derives square root of a secp256k1 finite field element.

        One of the characteristics of secp256k1 is that P % 4 = 3, so
        (P + 1) % 4 = 0, thus (P + 1)/4 is an integer.

        Looking for the square root, or w**2 = v, can be transformed via
        Fermat's Little Theorem to w**(P - 1) % P = 1, so:

            w**2 = w**2 * 1 = w**2 * w**(P - 1) = w**(P + 1)

        Any prime greater than 2 divided 2 mod P should equal an integer, so
        for w**2 = w**(P + 1) we can divide both exponents by 2 to get
        w = w**(P + 1)/2.

        Further, if (P + 1)/4 is established to be an integer, then:

            w = w**(P + 1)/2 = w**2(P + 1)/4 = (w**2)**(P + 1)/4 = v**(P+1)/4,
                or w = v**(P + 1)/4 if P % 4 = 3

        Returns:
            self.__class__: square root of self

        """
        return self**((self.P + 1) // 4)


class S256Point(ECPoint):
    """Representation of a point on the elliptic curve secp256k1.

    The a and b values used for this curve simplify y**2 = x**3 + x*a + b to:

        y**2 = x**3 + 7

    Attributes:
        A (int): first secp256k1 elliptic curve constant
        B (int): second secp256k1 elliptic curve constant
        N (int): secp256k1 group order
        x (S256FieldElem): x coordinate of point
        y (S256FieldElem): y coordinate of point

    """
    A = SECP256K1.A
    B = SECP256K1.B
    N = SECP256K1.N

    def __init__(self, x, y, a=None, b=None):
        """Instantiate a S256Point object.

        Args:
            x (int/S256FieldElem): x coordinate
            y (int/S256FieldElem): y coordinate

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
            str: developer-oriented representation of self

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
        # N * any point = 0(identity,) so only consider scalar mod N
        coef = coefficient % self.N
        return super().__rmul__(coef)


class PublicKey(S256Point):
    """A secp256k1 elliptic curve point P used in relation to private key e.

    Attributes:
        G (S256Point): secp256k1 group generator point

    """
    # super() does not work outside methods
    G = S256Point(SECP256K1.Gx, SECP256K1.Gy)

    # TBD:
    # Originally defined __init__ to prevent creating public keys == infinity
    #   point, but this caused failure when verify_sig's `v * self` eventually
    #   calls ECPoint.__rmul__, and `product = self.__class__(None, None,
    #   self.a, self.b)`

    def __repr__(self):
        """Generates string representation of PublicKey.

        Returns:
            (str): developer-oriented representation of self

        """
        return 'PublicKey({}, {})'.format(self.x, self.y)

    def verify(self, z, sig):
        """Verifies a secp256k1 ECDSA signature made with the same public key.

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

    def sec(self, compressed=True):
        """Encodes a public key in compressed or uncompressed SEC format.

        SEC, for Standards for Efficient Cryptography, is the standard for
        serializing ECDSA public keys, see:
        https://secg.org/sec1-v2.pdf#subsubsection.2.3.3

        Uncompressed SEC format can be encoded like so:
            1. Start with prefix byte 0x04
            2. Append the pubkey x coordinate (32 bytes big endian)
            3. Append the pubkey y coordinate (32 bytes big endian)

        The format can alternatively be compressed by leveraging some
        characteristics of elliptic curves and finite fields. We know y can
        can be computed from x with the elliptic curve formula, which for
        secp256k1 simplifies to y**2 == x**3 + 7. So for any given x, there can
        only either be one or two y values, which for the curve across real
        numbers, would be y and -y.

        However, since this is over a finite field, instead we could consider
        them as y % P and (P - y) % P. Differentiating these two now becomes a
        matter of evenness rather than sign. As a prime greater than 2, P must
        be odd, so if y is even, p - y is odd, and if y is odd, p - y is even.

        So when data size is a consideration, only the x coordinate and the
        evenness of y are needed - compressed SEC is encoded like so:
            1. Prefix byte: 0x02 if y is even, 0x03 if y is odd
            2. Append pubkey x coordinate in 32-byte big endian

        Args:
            compressed (bool): use compressed format if True, otherwise
                uncompressed

        Returns:
            bytes: SEC encoded public key

        """
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + \
                self.y.num.to_bytes(32, 'big')

    @classmethod
    def from_sec(cls, sec_bin):
        """Parses a public key from a SEC-formatted byte sequence.

        See PublicKey.sec for description of SEC encoding format.

        Args:
            sec_bin (bytes): public key in SEC encoded bytes

        Returns:
            self.__class__: deserialized public key

        """
        compressed = True
        if sec_bin[0] == 0x04:  # b'\x04'
            compressed = False
        elif sec_bin[0] == 0x02:  # b'\x02'
            y_even = True
        elif sec_bin[0] == 0x03:  # b'\x03'
            y_even = False
        else:
            raise ValueError(
                "Invalid SEC prefix byte of {:x}".format(sec_bin[0]))
        x = S256FieldElem(int.from_bytes(sec_bin[1:33], 'big'))
        if not compressed:
            return S256Point(
                x=x, y=S256FieldElem(int.from_bytes(sec_bin[33:65], 'big')))
        # right side of the equation y**2 = x**3 + 7
        alpha = x**3 + S256FieldElem(super().B)
        # solve for left side
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256FieldElem(S256FieldElem.P - beta.num)
        else:
            even_beta = S256FieldElem(S256FieldElem.P - beta.num)
            odd_beta = beta
        return cls(x=x, y=even_beta if y_even else odd_beta)

    def address(self, compressed=True, testnet=False):
        """Encodes a public key in Bitcoin address format.

        Bitcoin address format is a shortened and obfuscated form of a public
        key, used as a party identifier in transactions.

        Bitcoin addresses are encoded as follows:
            1. For mainnet prefix 0x00, testnet 0x6f
            2. Create a hash160 of the public key (key in SEC format > sha256 >
                ripemd160)
            3. Combine #1 and #2
            4. Take first four bytes of hash256 (sha256 twice) of #3
            5. Encode #3 and #4 in base58

        Note: Given the variables testnet and compressed, up to 4 addresses
        could be derived from a single public key.

        Args:
            compressed (bool): use compressed SEC format if True, otherwise
                uncompressed
            testnet (bool): address for testnet if True, for mainnet if False

        Returns:
            str: address value in base 58 encoded string

        """
        h160 = hash160(self.sec(compressed))
        prefix = b'\x6f' if testnet else b'\x00'
        # Resulting address is 21 bytes
        return encode_base58_checksum(prefix + h160)

    # TBD - cannot reverse due to hashing, but can get prefix to check network
    # @classmethod
    # def from_address(address):


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
            str: developer-oriented representation of self

        """
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        """Encodes a signature in DER format.

        DER, or Distinguished Encoding Rules, is likely taken from early
        Bitcoin's use of OpenSSL, and is still used to encode signatures.

        Both r and s need to be encoded, as s cannot solely be derived from r.
        DER can be sequenced as follows:
            1. Prefix of 0x30
            2. Length of the encoded signature to follow, in bytes (always
                single byte, so endianness not relevant)
            3. Marker byte 0x02
            4. r in big-endian, with minimum amount of leading null bytes
                necessary to prevent the vaue being interpreted as negative.
                Prepend length of resulting value in bytes.
            5. Marker byte 0x02
            6. s in big-endian, with minimum amount of leading null bytes
                necessary to prevent the vaue being interpreted as negative.
                Prepend length of resulting value in bytes.

        Returns:
            bytes: DER encoded signature

        """
        rbin = self.r.to_bytes(32, byteorder='big')
        sbin = self.s.to_bytes(32, byteorder='big')
        result = b''
        for _bin in (rbin, sbin):
            # remove all null bytes at the beginning
            _bin = _bin.lstrip(b'\x00')
            # add back null byte if stripped bytes interpreted as negative
            if _bin[0] & 0x80:
                _bin = b'\x00' + _bin
            # add prefix byte and length in bytes
            result += bytes([0x02, len(_bin)]) + _bin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def from_der(cls, signature_bin):
        """Decodes a signature from DER encoding.

        See Signature.der for a description of the DER format.

        Args:
            signature_bin (bytes): DER encoded signature

        Returns:
            self.__class__: deserialized signature

        """
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)


class PrivateKey:
    """Representation of a secp256k1 private key.

    Attributes:
        N (int):           secp256k1 group order
        G (S256Point):     secp256k1 group generator point
        secret (int):      private key; e in eG = P
        point (S256Point): public key; P in eG = P

    """
    N = SECP256K1.N
    G = S256Point(SECP256K1.Gx, SECP256K1.Gy)

    def __init__(self, secret):
        """Instantiate a PrivateKey object.

        Args:
            secret (int): scalar to mulitply generator point

        """
        self.secret = secret
        eG = self.secret * self.G
        self.point = PublicKey(eG.x, eG.y)

    def hex(self):
        """Represent private key as hexadecimal string.

        Returns:
            str: private key as 64 digit zero-padded hex string

        """
        return '{:x}'.format(self.secret).zfill(64)

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
            z (int): expects a 32-byte sha256 hash of the data to sign (?)...
                see comment below

        Returns:
            Signature: contains s, and the r used in its calculation

        """
        # TBD: Song p.64 calls this the "signature hash" - assuming hash256?
        if type(z) is bytes:
            z = int.from_bytes(z, 'big')
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
        s = (z + r * self.secret) * k_inv % self.N
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

        ECDSA requires k values that are pseudorandom, and keeping the
        private key secret requires a unique k for each signature. Here a
        deterministic k is generated with an algorithm specified in
        RFC 6979 (see https://tools.ietf.org/html/rfc6979).

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
        secret_bytes = self.secret.to_bytes(32, 'big')
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

    def wif(self, compressed=True, testnet=False):
        """Encodes private key in WIF.

        WIF, or Wallet Import Format, is Bitcoin's current means of serializing
        private keys, see:
        https://en.bitcoin.it/wiki/Wallet_import_format

        WIF can be serialized as follows. Note that the process requires
        awareness of the SEC compression used in whatever address is paired
        with private key:
            1. Prefix of 0x80 for mainnet, 0xef for testnet
            2. Secret encoded in 32 byte big endian
            3. If SEC for public key was compressed, use suffix 0x01
            4. Combine #1, #2, and #3
            5. Take first 4 bytes of hash256 (sha256 twice) of #4
            6. Encode #4 and #5 in base 58.

        Args:
            compressed (bool): compressed SEC format used if True,
                otherwise uncompressed
            testnet (bool): for testnet if True, for mainnet if False

        Returns:
            str: encoded private key

        """
        secret_bytes = self.secret.to_bytes(32, 'big')
        prefix = b'\xef' if testnet else b'\x80'
        suffix = b'\x01' if compressed else b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)

    @classmethod
    def from_wif(cls, wif_bin):
        """Decodes a private key from WIF.

        WIF, or Wallet Import Format, is Bitcoin's current means of serializing
        private keys. See PrivateKey.wif for more info.

        Args:
            wif_bin (bytes): encoded private key

        Returns:
            self.__class__: new deserialized private key

        """
        combined = decode_base58_checksum(wif_bin)
        # note: slices of bytes are bytes, but single elements are ints
        if combined[0] == 0xef:
            testnet = True
        elif combined[0] == 0x80:
            testnet = False
        else:
            raise SyntaxError(f"invalid prefix: 0x{combined[0]:x}")
        if len(combined) == 34:
            compressed = True
        elif len(combined) == 33:
            compressed = False
        else:
            raise SyntaxError(f"invalid data length: {len(combined)}")
        if compressed:
            if combined[-1:] != b'\x01':
                raise SyntaxError(f"invalid suffix: {combined[-1:]}")
            secret_bin = combined[1:-1]
        else:
            secret_bin = combined[1:]
        # TBD: how are compressed and testnet communicated beyond this function?
        #   verified? Need they be? testnet at least could be checked against a
        #   supplied address.
        return cls(int.from_bytes(secret_bin, 'big'))
