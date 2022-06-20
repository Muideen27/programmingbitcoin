#!/usr/bin/python3
"""`tx` - module for Bitcoin transactions.

Contains classes necessary for storing transaction data.

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

"""

from io import BytesIO
import json
import requests

from helper import (
    hash256,
    encode_varint,
    read_varint,
)
from script import Script


class TxFetcher:
    """Bundles methods for fetching and caching Bitcoin transaction data
    from blockstream.info.

    Attributes:
        cache (dict): transactions stored in memory, indexed by transaction id

    """
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        """Generates proper URI for transaction data retrieval.

        Returns:
            str: URI for retreiving transaction data
            testnet (bool): use testnet if True

        """
        subdomain = 'testnet/' if testnet else ''
        return f'https://blockstream.info/{subdomain}api/'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        """Retrieves transaction data from Bitcoin network to store in memory.

        Args:
            tx_id (bytes): hash of transaction contents used as identifier
            testnet (bool): use testnet if True
            fresh (bool): if True, redownload new data even if tx in cache

        Returns:
            Tx: transaction object corresponding to tx_id

        """
        if fresh or (tx_id not in cls.cache):
            url = f'{cls.get_url(testnet)}/tx/{tx_id}/hex'
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f'unexpected response: {response.text}')
            # parse Segwit serializations like legacy serializations
            # see: https://github.com/jimmysong/programmingbitcoin/issues/190
            # TBD: (update after Segwit addressed in chapter 13)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = int.from_bytes(raw[-4:], 'little')
            else:
                tx = Tx.parse(BytesIO(raw))
            if tx.id() != tx_id:
                raise ValueError('fetched id does not match requested: '
                                 f'{tx.id()} vs {tx_id}')
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        """Loads transaction cache from disk into memory.

        Args:
            filename (str): name of local cache file, defaults to `../tx.cache`

        """
        with open(filename, 'r') as f:
            disk_cache = json.loads(f.read())
            for k, raw_hex in disk_cache.items():
                raw = bytes.fromhex(raw_hex)
                # see comment on same conditional in fetch
                # TBD: (update after Segwit addressed in chapter 13)
                if raw[4] == 0:
                    raw = raw[:4] + raw[6:]
                    tx = Tx.deserialize(BytesIO(raw))
                    tx.locktime = int.from_bytes(raw[-4:], 'little')
                else:
                    tx = Tx.deserialize(BytesIO(raw))
                cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        """Saves transaction cache from memory to disk.

        Args:
            filename (str): name of local cache file, defaults to `../tx.cache`

        """
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    """Representation of Bitcoin Core transaction.

    Attributes:
        version (int): generally 1, but may be 2 when transaction uses Script
            opcode OP_CHECKSEQUENCEVERIFY, see BIP0112
        tx_ins (list(TxIn)): transaction inputs
        tx_outs (list(TxOut)): transaction outputs
        locktime (int): time delay on a transaction entering the blockchain:
            locktimes of less than 500,000,000 are a block number, higher are
            a UNIX timestamp
        testnet (bool): using testnet if True

    """
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        """Instantiates a Tx object.

        Args:
            version (int): determines what features are available to transaction
            tx_ins (list(TxIn)): transaction inputs
            tx_outs (list(TxOut)): transaction outputs
            locktime (int): time at which transaction can enter the blockchain
            testnet (bool): using testnet if True

        """
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        """Developer-oriented representation of a transaction.

        Returns:
            str: representation of transaction

        """
        t = '    '
        tx_ins = t + t + ('\n' + t + t).join(
            [tx_in.__repr__() for tx_in in self.tx_ins])
        tx_outs = t + t + ('\n' + t + t).join(
            [tx_out.__repr__() for tx_out in self.tx_outs])
        return '\n'.join([
            f'tx: {self.id()}',
            t + f'version: {self.version}',
            t + 'tx_ins:', tx_ins,
            t + 'tx_outs:', tx_outs,
            t + f'locktime: {self.locktime}'
        ])

    def id(self):
        """Human-readable hexadecimal of the transaction hash.

        Returns
            str: hash hex string

        """
        return self.hash().hex()

    def hash(self):
        """Binary hash of the legacy serialization.

        Returns:
            bytes: little-endian hash of self
        """
        # TBD: double-check all hash byte order reversals
        # Reversed as hash digests are big-endian, and needs to be swapped to
        #   network byte order (little-endian) to match Bitcoin convention
        return hash256(self.serialize())[::-1]

    def serialize(self):
        """Byte serialization of the transaction.

        Transaction serialization format:
            1. version (32B, little endian)
            2. transaction input count (varint)
            3. transaction inputs in series
            4. transaction output count (varint)
            5. transaction outputs in series
            6. locktime (32B, little endian)

        Returns:
            bytes: serialization of self

        """
        result = self.version.to_bytes(4, 'little')
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += self.locktime.to_bytes(4, 'little')
        return result

    @classmethod
    def deserialize(cls, s, testnet=False):
        """Parses stream input to deserialize a transaction.

        See Tx.serialize for encoding scheme.

        Args:
            s (_io.*): stream to read
            testnet (bool): using testnet if True

        Returns:
            Tx: parsed transaction

        """
        version = int.from_bytes(s.read(4), 'little')
        num_inputs = read_varint(s)
        tx_ins = []
        for _ in range(num_inputs):
            tx_ins.append(TxIn.deserialize(s))
        num_outputs = read_varint(s)
        tx_outs = []
        for _ in range(num_outputs):
            tx_outs.append(TxOut.deserialize(s))
        locktime = int.from_bytes(s.read(4), 'little')
        return cls(version, tx_ins, tx_outs, locktime, testnet)

    def fee(self):
        """Transaction fee in satoshi (1/100,000,000 BTC.)

        Vastly simplifies how transaction fees actually work in Bitcoin Core,
        where network traffic and market forces affect the fee rate, or satoshis
        per transaction byte. Further, as opposed to how input surplus is paid
        as a fee in this mockup, normally in Bitcoin most of the leftover
        "change" would be sent back to the sender as a new input.

        TBD: ^ this may be addressed in ch07 and with Segwit in ch13

        Returns:
            int: amount that inputs exceed outputs

        """
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum


class TxIn:
    """Representation of transaction input.

    All valid transaction inputs are references to what are known as UTXOs,
    or unspent outputs of previous transactions on the blockchain.

    Attributes:
        prev_tx (bytes): ID (hash) of transaction containing UTXO
        prev_index (int): UTXO index in prev_tx tx_outs
        script_sig (deque(int|bytes)): Script to be executed before
            TxOut.script_pubkey, as the second half of a Script smart contract
            for transaction validation
        sequence (int): value used with locktime in certain Script operations

    """
    def __init__(self, prev_tx, prev_index,
                 script_sig=None, sequence=0xffffffff):
        """Instantiates TxIn object.

        Args:
            prev_tx (bytes): ID (hash) of transaction containing UTXO
            prev_index (int): UTXO index in prev_tx tx_outs
            script_sig (Script): hash of transaction containing UTXO
            prev_tx (bytes): hash of transaction containing UTXO

        """
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.script_sig = Script() if script_sig is None else script_sig
        self.sequence = sequence

    def __repr__(self):
        """Developer-oriented string representation of a TxIn.

        Returns:
            str: representation of self

        """
        return f'{self.prev_tx.hex()}:{self.prev_index}'

    def serialize(self):
        """Returns the byte serialization of the transaction input

        Transaction inputs are currently serialized as follows:
            1. ID (hash256) of previous transaction (tx generating output used
                 as input) (in reverse of hash byte order, as if little endian)
            2. Index in list of outputs of previous transaction (4 bytes
                 little endian)
            3. ScriptSig - Script language smart contract prefix, preceeded by
                 varint indicating serialization length in bytes
            4. Sequence - used with Replace-By-Fee (RBF) and
                 OP_CHECKSEQUENCEVERIFY (4 bytes little endian)

        Returns:
            bytes: serialized transaction input

        """
        # TBD: double-check all hash byte order reversals
        # encode prev tx id in network byte order
        return self.prev_tx[::-1] + \
            self.prev_index.to_bytes(4, 'little') + \
            self.script_sig.serialize() + \
            self.sequence.to_bytes(4, 'little')

    @classmethod
    def deserialize(cls, s):
        """Parses stream input to deserialize a transaction input.

        See TxIn.serialize for encoding scheme.

        Args:
            s (_io.*): stream to read

        Returns:
            TxIn: parsed transaction input

        """
        # TBD: double-check all hash byte order reversals
        # prev tx id encoded in network byte order, reverse of hash byte order
        prev_tx = s.read(32)[::-1]
        prev_index = int.from_bytes(s.read(4), 'little')
        script_sig = Script.deserialize(s)
        sequence = int.from_bytes(s.read(4), 'little')
        return cls(prev_tx, prev_index, script_sig, sequence)

    def fetch_prev_tx(self, testnet=False):
        """Gets input origin transaction data.

        Args:
            testnet (bool): using testnet if True

        Returns:
            Tx: output transaction for input

        """
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        """Get the origin transaction output amount by looking up the hash/ID.

        Args:
            testnet (bool): using testnet if True

        Returns:
            int: amount in satoshi

        """
        prev_tx = self.fetch_prev_tx(testnet=testnet)
        return prev_tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        """Get the origin transaction output ScriptPubKey by looking up the
        hash/ID.

        Args:
            testnet (bool): using testnet if True

        Returns:
            Script: ScriptPubKey

        """
        prev_tx = self.fetch_prev_tx(testnet=testnet)
        return prev_tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    """Representation of transaction output.

    Attributes:
        amount (int): amount in satoshis (1/100,000,000 BTC,) up to a max of
            2.1e+15 BTC, or 2.1+e23 satoshis
        script_pubkey (Script): evaluated as second half of Script
            smart contract, after TxIn.script_sig. Can be considered a
            "lockbox" that can receive deposits from any party, but only be
            opened by one. Variable length field,

    """
    def __init__(self, amount, script_pubkey):
        """Instantiate a TxOut object.

        Args:
            amount (int): output amount in satoshi (1/100,000,000 BTC)
            script_pubkey: Script commands to be executed after TxIn.script_sig

        """
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        """Developer-oriented string representation of a TxOut.

        Returns:
            str: representation of self

        """
        return f'{self.amount}:{self.script_pubkey}'

    def serialize(self):
        """Returns the byte serialization of the transaction output

        Transaction outputs are serialized as follows:
            1. amount (8 bytes little endian)
            2. ScriptPubKey, preceeded by varint containing length in bytes
                (see Script.serialize)

        Returns:
            bytes: TxOut serialization

        """
        result = self.amount.to_bytes(8, 'little')
        result += self.script_pubkey.serialize()
        return result

    @classmethod
    def deserialize(cls, s):
        """Parses stream input to deserialize a transaction output.

        See TxOut.serialize for encoding scheme.

        Args:
            s (_io.*): stream to read

        Returns:
            TxOut: parsed transaction output

        """
        amount = int.from_bytes(s.read(8), 'little')
        script_pubkey = Script.deserialize(s)
        return cls(amount, script_pubkey)
