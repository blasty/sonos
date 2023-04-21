#!/usr/bin/env python3

"""sonostool
usage:
    sonostool -m <mdp_file> -o <otp_file> download <outputdir>
    sonostool -m <mdp_file> -o <otp_file> decrypt_update <inputfile> <outputdir>
    sonostool -m <mdp_file> -o <otp_file> luks_key <keybytes>
    sonostool -h

options:
    -h, --help         display this help output
"""

import sys
import struct
import binascii
import hashlib
import requests
import hmac
import io

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from docopt import docopt


GCM_TAG_SIZE = 16
GCM_IV_SIZE = 12


MAGIC_MDP3 = b"\xf0\x79\xa9\xcb"
MAGIC_FSKEY = b"\xe8\x4d\x8c\x61"
MAGIC_UNK1 = b"\x62\x1d\xa7\x4d"
MAGIC_RSAKEY = b"\x8d\xc6\xcc\xf4"
MAGIC_FW_BLOB = b"\x88\x64\x99\xca"
MAGIC_UPD = b"\x49\x7f\x16\x35"


OTP_LENGTH = 0x100
MDP_LENGTH = 0x4000

MDP_OFFSET_JFFS_KEY = 0x0580
MDP_OFFSET_ROOTFS_KEY = 0x0680
MDP_OFFSET_MODEL_PRIVATE_KEY = 0x0780

UPDATE_URI_BASE = "https://update.sonos.com"

BLOB_MAGIC = 0x35167F49
BLOB_TYPE_BASE_URI = 0x7
BLOB_TYPE_MANIFEST_URI = 0xE

# hardcoded for tupelo
SONOS_MODEL = 26
SONOS_SUBMODEL = 1

HTTP_CHUNKSIZE = 1024 * 128


class SONOSTool:
    def __init__(self, mdp_data, otp_data):
        if len(otp_data) != OTP_LENGTH:
            self.err("wrong OTP length")
        if len(mdp_data) != MDP_LENGTH:
            self.err("wrong MDP length")

        self.mdp_data = mdp_data
        self.otp_data = otp_data

        if self.mdp_data[0:4] != MAGIC_MDP3:
            self.err("invalid MDP data")

        self.rootfs_key = self.decrypt_rootfs_key()
        self.jffs_key = self.decrypt_jffs_key()
        self.model_rsakey = self.decrypt_model_rsakey()

    def xor(self, a, b):
        o = b""
        for i in range(len(a)):
            o += bytes([a[i % len(a)] ^ b[i % len(b)]])
        return o

    def err(self, s):
        print("ERROR: %s" % s)
        exit(-1)

    def mdp_field(self, offset, magic):
        if self.mdp_data[offset : offset + 4] != magic:
            self.err("invalid magic!")
        blob_len = struct.unpack("<L", self.mdp_data[offset + 4 : offset + 8])[0]
        return self.mdp_data[offset + 12 : offset + 12 + blob_len]

    def check_padding(self, s):
        if len(s) < 0x20 or len(s) % 0x10 != 0:
            return False
        padbyte = s[-1]
        if padbyte > 0x10:
            return False
        return s[-padbyte:] == bytes([padbyte]) * padbyte

    def unpad(self, s):
        if len(s) < 0x20 or len(s) % 0x10 != 0:
            return False
        padbyte = s[-1]
        if padbyte > 0x10:
            return False
        return s[0 : len(s) - padbyte]

    def sonos_blob_encdec(self, blob, keymod):
        if len(keymod) < 8:
            keymod += b"\x00" * (8 - len(keymod))

        aes_key = hashlib.sha256(self.otp_data[0xD0:0xE0]).digest()[0:0x10]

        ciphertext_len = len(blob) - GCM_IV_SIZE - GCM_TAG_SIZE
        if ciphertext_len % 0x10 != 0:
            self.err("blob body not aligned to aes block size")

        ciphertext = blob[0:ciphertext_len]
        iv = blob[ciphertext_len : ciphertext_len + GCM_IV_SIZE]
        iv = self.xor(iv, keymod)

        b = b""
        for i in range(ciphertext_len // 0x10):
            b += iv + struct.pack(">L", 2 + i)
        cipher = AES.new(aes_key, mode=AES.MODE_ECB)
        decrypted = self.xor(cipher.encrypt(b), ciphertext)
        if not self.check_padding(decrypted):
            self.err("invalid padding")
        return self.unpad(decrypted)

    def sonos_blob_deserialize(self, fh, type_whitelist=None):
        o = {}
        while True:
            hdr = fh.read(0x10)
            if len(hdr) != 0x10:
                break
            magic, etype, size, unk0 = struct.unpack("<LLLL", hdr)
            assert magic == BLOB_MAGIC
            assert size >= 0x10

            if type_whitelist is not None:
                if etype not in type_whitelist:
                    fh.seek(size - 0x10, 1)
                    continue

            body = fh.read(size - 0x10)
            if etype not in o.keys():
                o[etype] = []
            o[etype].append(body)
        return o

    def decrypt_rootfs_key(self):
        rootfs_key = self.mdp_field(MDP_OFFSET_ROOTFS_KEY, MAGIC_FSKEY)
        return self.sonos_blob_encdec(rootfs_key, b"rootfs")

    def decrypt_jffs_key(self):
        rootfs_key = self.mdp_field(MDP_OFFSET_JFFS_KEY, MAGIC_FSKEY)
        return self.sonos_blob_encdec(rootfs_key, b"ubifs")

    def decrypt_model_rsakey(self):
        model_rsakey = self.mdp_field(MDP_OFFSET_MODEL_PRIVATE_KEY, MAGIC_RSAKEY)
        return self.sonos_blob_encdec(model_rsakey, b"model")

    def sonos_luks_key(self, key_in):
        if len(key_in) != 0x20:
            self.err("bad input key length")

        if key_in[0:16] != b"\x00" * 16 and key_in[0:16] != b"\xff" * 16:
            self.err("sentinel value not found")

        key_mdp = None
        if key_in[0] == 0:
            key_mdp = self.jffs_key
        else:
            key_mdp = self.rootfs_key

        a = b"sonos luks" + key_in
        h = hmac.new(key_mdp, a, hashlib.sha256)
        return hmac.new(key_mdp, h.digest() + a, hashlib.sha256).digest()

    def download_firmware(self, outdir):
        query_string = (
            "cmaj=%d&cmin=%d&cbld=%d&subm=%d&rev=%d&reg=%d&serial=%s&sonosid=%s&householdid=%s"
            % (4, 1, 1, 100, 1, 2, "1", "111111111", "X")
        )

        uri = "%s/firmware/latest/default-1-1.ups?%s" % (UPDATE_URI_BASE, query_string)
        print("> downloading metadata")
        r = requests.get(uri)

        if r.status_code != 200:
            print(r.status_code)
            self.err("error fetching update metadata")

        fh = io.BytesIO(r.content)

        uri_info = self.sonos_blob_deserialize(
            fh, [BLOB_TYPE_BASE_URI, BLOB_TYPE_MANIFEST_URI]
        )

        if BLOB_TYPE_BASE_URI not in uri_info.keys():
            self.err("could not find base uri in update metadata")
        if BLOB_TYPE_MANIFEST_URI not in uri_info.keys():
            self.err("could not find manifest uri in update metadata")

        base_uri = uri_info[BLOB_TYPE_BASE_URI][0].replace(b"\x00", b"").decode()
        manifest_uri = (
            uri_info[BLOB_TYPE_MANIFEST_URI][0].replace(b"\x00", b"").decode()
        )

        update_uri = "%s-%d-%d.upd" % (
            base_uri.replace("/^", "/"),
            SONOS_SUBMODEL,
            SONOS_MODEL,
        )

        out_filename = "%s/%s" % (outdir, update_uri.split("/")[-1])
        with open(out_filename, "wb") as fo:
            print("> downloading %s" % update_uri)
            r = requests.get(update_uri, stream=True)
            ntotal = r.headers.get("content-length")
            if ntotal is not None:
                ntotal = int(ntotal)
            nread = 0
            for chunk in r.iter_content(chunk_size=HTTP_CHUNKSIZE):
                fo.write(chunk)
                if ntotal is None:
                    continue
                nread += len(chunk)
                done = int(50 * nread / ntotal)
                sys.stdout.write(
                    "\rleech [%s%s] 0x%08x/0x%08x"
                    % ("*" * done, "." * (50 - done), nread, ntotal)
                )
                sys.stdout.flush()
            print("\n\ndone!\n")

    def decrypt_firmware(self, filename, outdir):
        rsa_key = RSA.importKey(self.model_rsakey)
        cnt = 0
        with open(filename, "rb") as fi:
            while True:
                cnt += 1
                hdr = fi.read(0x10)
                if len(hdr) != 0x10:
                    break
                magic, etype, size, unk0 = struct.unpack("<LLLL", hdr)
                assert magic == struct.unpack("<L", MAGIC_UPD)[0]
                assert size >= 0x10
                body = fi.read(size - 0x10)
                if body[0:4] != MAGIC_FW_BLOB:
                    continue

                rsa_blob = body[0x32:0x132]
                rsa = PKCS1_OAEP.new(rsa_key)
                aes_key = rsa.decrypt(rsa_blob)
                if len(aes_key) != 0x10:
                    self.err("failed to RSA decrypt AES key.")
                print(
                    "entry #%02d is encrypted fw blob! key: %s"
                    % (cnt, binascii.hexlify(aes_key).decode())
                )
                aes_body = body[0x13A:]
                if len(aes_body) % 0x10 != 0:
                    self.err("aes body is not multiple of blocksize")
                c = AES.new(aes_key, AES.MODE_CBC, b"\x00" * 16)
                ofn = "%s/%02d.bin" % (outdir, cnt)
                with open(ofn, "wb") as fo:
                    plain = c.decrypt(aes_body)
                    fo.write(self.unpad(plain[0x10:]))
        print("done")


if __name__ == "__main__":
    args = docopt(__doc__)
    # print(args)

    mdp_data = open(args["<mdp_file>"], "rb").read()
    otp_data = open(args["<otp_file>"], "rb").read()

    tool = SONOSTool(mdp_data, otp_data)

    if args["download"]:
        tool.download_firmware(args["<outputdir>"])
    elif args["decrypt_update"]:
        tool.decrypt_firmware(args["<inputfile>"], args["<outputdir>"])
    elif args["luks_key"]:
        keybytes = binascii.unhexlify(args["<keybytes>"])
        luks_key = tool.sonos_luks_key(keybytes)
        luks_keytype = "rootfs"
        if keybytes[0] == 0:
            luks_keytype = "jffs"
        print(
            "LUKS AES KEY: %s (%s)"
            % (binascii.hexlify(luks_key).decode(), luks_keytype)
        )
