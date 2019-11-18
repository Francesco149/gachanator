# this is free and unencumbered software released into the public domain
# for more information, please refer to <http://unlicense.org/>

from . import plugins
import multiprocessing as mp
import importlib
import shutil
import random
import os.path
import logging
import struct
import appdirs
import time
import uuid
import json
import re
import io
import os
import hashlib
import hmac
import sys
import argparse
import signal
import queue
import sqlite3
from tendo import colorer
from tendo.singleton import SingleInstance
from base64 import b64decode, standard_b64encode
from xml.dom import minidom
from urllib.request import Request, urlopen
from urllib.parse import quote
from oscrypto.asymmetric import load_public_key, dump_public_key
from oscrypto.asymmetric import rsa_oaep_encrypt, rsa_pkcs1v15_encrypt
from pyasn1_modules import rfc2315
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from zipfile import ZipFile


__appname = "gachanator"
__author = "lolisamurai"
logger = logging.getLogger(__name__.rsplit(".", 1)[1])


def cache_dir(relpath=""):
  """
  return the full path for a relative path inside the cache directory.
  also creates the directory structure if it doesn't exist

  relpath plugin_name/hash.json is reserved for the built-in updater.
  relpath plugin_name/config.json is reserved for the default config file
  """
  d = appdirs.user_cache_dir(__appname, __author)
  res = os.path.join(d, relpath)
  try:
    os.makedirs(os.path.dirname(res))
  except FileExistsError:
    pass
  return res


def data_dir(relpath=""):
  """
  return the full path for a relative path inside the data directory.
  also creates the directory structure if it doesn't exist

  relpath database.db is reserved for the database
  """
  d = appdirs.user_data_dir(__appname, __author)
  res = os.path.join(d, relpath)
  try:
    os.makedirs(os.path.dirname(res))
  except FileExistsError:
    pass
  return res


def cache_open(relpath="", mode="r"):
  """opens cache_dir(relpath), returns file-like object"""
  return open(cache_dir(repath), mode)


def data_open(relpath="", mode="r"):
  """opens data_dir(relpath), returns file-like object"""
  return open(data_dir(repath), mode)


def b64encode(s):
  """base64 encode without splitting the output into multiple lines"""
  return standard_b64encode(s).replace(b"\n", b"")


def i8(x):
  """truncates x to a 8-bit integer"""
  return x & 0xFF


def i32(x):
  """truncates x to a 32-bit integer"""
  return x & 0xFFFFFFFF


def array_xor(a, b):
  """
  xors all elements of a with elements of b. outout is truncated to
  the shortest of the two arrays
  """
  return bytes([x ^ y for x, y in zip(a, b)])


def iter2(arr):
  """generator that returns every two elements of arr as tuples"""
  it = iter(arr)
  for x in it:
    yield x, next(it)


def array_to_dict(arr):
  """
  converts [k1, v1, k2, v2] to {k1: v1, k2: v2}

  see iter2 for iterating arrays on the fly as tuples
  """
  return {x: next(it) for x in iter(arr)}


def randsleep(ms, spread=0.10):
  """sleeps for ms milliseconds plus or minus spread * ms, randomly"""
  max_offset = int(spread * ms)
  time.sleep((ms + random.randint(-max_offset, max_offset)) / 1000.0)


def md5(s):
  """returns the md5 hash of string s as a hex string"""
  return hashlib.md5(s.encode("utf-8")).hexdigest()


def gen_google_play_service_id():
  """generates a service id that matches google play's format"""
  return "a_" + "".join([random.choice("0123456789") for _ in range(19)])


def sha1_file(f, bufsize=16000000):
  """
  computes sha-1 from a file obj, intended for large files.
  returns hex string hash
  """
  sha1 = hashlib.sha1()
  while True:
    buf = f.read(bufsize)
    if len(buf) == 0:
      break
    sha1.update(buf)
  return sha1.hexdigest()


def file_hashes(f, bufsize=16000000):
  """
  computes md5, sha1, sha256 from a file obj.  intended for large files.
  returns 3-tuple of hexstrings
  """
  md5 = hashlib.md5()
  sha1 = hashlib.sha1()
  sha256 = hashlib.sha256()
  while True:
    buf = f.read(bufsize)
    if len(buf) == 0:
      break
    md5.update(buf)
    sha1.update(buf)
    sha256.update(buf)
  return (md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())


# references used to figure this out:
# https://github.com/tdoly/apk_parse/blob/master/apk.py#L221
# https://github.com/etingof/pyasn1-modules/blob/master/tools/pkcs7dump.py
def apk_signatures(cert_file_object):
  """
  returns a 3-tuple with the hexstring md5, sha1, sha256 hashes of the
  first certificate of a pkcs7 signature, intended for apk signatures

  cert_file_object is a file-like object in binary mode
  """
  # TODO zipfile objects don't have the b in the mode even though they are
  # binary so we can't check mode
  content_info, _ = der_decoder.decode(
      cert_file_object.read(),
      asn1Spec=rfc2315.ContentInfo()
  )
  content_type = content_info.getComponentByName("contentType")
  content_info_map = {
      (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
      (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
      (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
      (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
      (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
      (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
  }
  content, _ = der_decoder.decode(
      content_info.getComponentByName("content"),
      asn1Spec=content_info_map[content_type]
  )
  certs = content.getComponentByName("certificates")
  der = der_encoder.encode(certs[0])
  return file_hashes(io.BytesIO(der))


def hmac_sha1(key, s):
  """
  returns the hmac-sha1 signature of key and string s.

  key: bytes or bytearray
  s: any type supported by hashlib
  """
  hmacsha1 = hmac.new(key, digestmod=hashlib.sha1)
  hmacsha1.update(s)
  return hmacsha1.hexdigest()


def public_encrypt(key, data, oaep):
  """
  public key encryption using rsa with pkcs1-oaep padding.
  returns the base64-encoded encrypted data

  data: the data to be encrypted, bytes
  key: pem-formatted key string or bytes
  oaep: whether to use oaep padding or not
  """
  if isinstance(key, str):
    key = key.encode("ascii")
  pubkey = load_public_key(key)
  if oaep:
    encrypted = rsa_oaep_encrypt(pubkey, data)
  else:
    encrypted = rsa_pkcs1v15_encrypt(pubkey, data)
  return b64encode(encrypted).decode("ascii")


def gen_sequential_id():
  """generator for a trivial sequential id"""
  n = 0
  while True:
    n += 1
    yield n


def gen_randomized_sequential_id():
  """
  generator for a sequential id with 16 random hex characters prepended
  """
  n = 0
  while True:
    n += 1
    yield "%s%d" % (bytearray(os.urandom(8)).hex(), n)


def millitime():
  """returns current unix timestamp in milliseconds"""
  return int(round(time.time() * 1000))


def jsonable(x):
  """returns whether x is json-serializable"""
  try:
    json.dumps(x)
  except TypeError:
    return False
  return True


def json_lossy_dumps(x, **kwargs):
  """encode x as a json string, discarding any value that isn't jsonable"""
  try:
    x = vars(x)
  except TypeError:
    pass
  return json.dumps({k: v for k, v in x.items() if jsonable(v)}, **kwargs)


class KlabHttpApi:
  """
  keeps track of http api state and formats requests for klab games

  fields:
  user_id: set this to associate an user id to the requests. set to None
           for unauthenticated requests
  session_key: the session key used to sign requests (bytes)
  temporary_session_key: if not None, it overrides session_key
  master_version: pretty much every game uses this mv string in the query
                  parameters, it's usually received from the server in
                  game-dependent ways
  gen_id: generator function for the request id
  oaep: whether to use oaep rsa padding or not in gen_mask
  """

  @staticmethod
  def builder(**kwargs):
    """
    returns a function that creates an instance of KlabHttpApi with the
    given arguments
    """
    log = KlabHttpApi.__getlogger(**kwargs)
    log.debug("\n" + json_lossy_dumps(kwargs, indent=2))
    return lambda: KlabHttpApi(**kwargs)

  @staticmethod
  def __getlogger(log=None, **kwargs):
    log = "" if log is None else "[{}]".format(log)
    return logging.getLogger("KlabHttpApi{}".format(log))

  def __init__(
      self, endpoint, startup_key, pubkey, il2cpp_hashes,
      jackpot_core_hashes, package_signatures, log=None,
      gen_id=gen_sequential_id, time_multiplier=1000, oaep=True,
      language=None, *args, **kwargs
  ):
    """
    initialize state

    endpoint: the base api url for example
              "https://gl-game.tsubasa-dreamteam.com/ep73"
    startup_key: initial session key (bytes)
    pubkey: pem-formatted public key. used by gen_mask()
    il2cpp_hashes: 3-tuple with the md5, sha1, sha256 hashes of
                   libil2cpp.so as hexstrings. see file_hashes()
    jackpot_core_hashes: 3-tuple with the md5, sha1, sha256 hashes of
                         libjackpot-core.so as exstrings. see file_hashes()
    package_signatures: 3-type with the md5, sha1, sha256 hashes of the
                        apk signature. see apk_signatures()
    log: logging tag
    gen_id: generator function that returns request id's
    time_multiplier: the base timestamp is in unix seconds. some games use
                     milliseconds, others use seconds. change this to 1 for
                     seconds
    """
    self.__log = self.__getlogger(log)
    self.__endpoint = endpoint
    if not isinstance(startup_key, bytes):
      startup_key = startup_key.encode("utf-8")
    self.__startup_key = startup_key
    self.__gen_id = gen_id
    self.__pubkey = pubkey
    self.__il2cpp_hashes = [bytes.fromhex(x) for x in il2cpp_hashes]
    self.__jackpot_core_hashes = [
        bytes.fromhex(x) for x in jackpot_core_hashes
    ]
    self.__package_signatures = package_signatures
    self.__time_multiplier = time_multiplier
    self.language = language
    self.oaep = oaep
    self.reset()

  def reset(self):
    """
    reset state. this should be called when you're terminating a session
    """
    self.user_id = None
    self.__id = self.__gen_id()
    self.session_key = self.__startup_key
    self.temporary_session_key = None
    self.master_version = None
    self.__last_response_time = None
    self.__random_bytes = None
    self.__last_response = None

  def __time(self):
    return int(round(time.time() * self.__time_multiplier))

  def gen_mask(self, random_bytes=None):
    """
    generates mask bytes for a signed request, returns base64-encoded
    string. if you need the unencrypted bytes, call mask_bytes after
    calling this

    random_bytes: if you need to force certain "random" bytes for testing
    or other reasons, pass them through this parameter
    """
    self.__random_bytes = random_bytes or os.urandom(32)
    return public_encrypt(self.__pubkey, self.__random_bytes, self.oaep)

  def mask_bytes(self):
    """get the last random bytes used in a signed request"""
    return self.__random_bytes[:]

  def response(self):
    """
    returns the full array for the last response

    the format is usually [timestamp,x,0,body,hash] where x is
    game-dependent. on some games it's used to send the master_version back
    while in other games it's unused
    """
    return self.__last_response

  def call(self, path, payload=None, headers={}):
    """
    call path with payload as the json body. if payload is a dict or None,
    it will be automatically serialized to json.

    payload: must be either a dict or a string
    headers: any additional http headers as a dict
    """
    if isinstance(payload, dict) or payload is None:
      payload = json.dumps(payload, separators=(',', ':'))
    elif not isinstance(payload, str):
      raise ValueError("payload must be either a str or a dict")
    path_with_query = path + "?p=a"
    if self.master_version:
      path_with_query += "&mv={}".format(self.master_version)
    path_with_query += "&id={}".format(next(self.__id))
    if self.user_id:
      path_with_query += "&u={}".format(self.user_id)
    if self.__last_response_time:
      path_with_query += "&t={}".format(self.__time())
    if self.language:
      path_with_query += "&lang={}".format(self.language)
    self.__log.debug(path_with_query)
    digest_data = path_with_query + " " + payload
    key = self.temporary_session_key or self.session_key
    digest = hmac_sha1(key, digest_data.encode("utf-8"))
    body = '[%s,"%s"]' % (payload, digest)
    self.__log.debug(body)
    for i in range(20):
      try:
        req = Request(
            url=self.__endpoint + path_with_query,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json", **headers}
        )
        with urlopen(req) as resp:
          self.__log.debug("-> %d" % resp.status)
          for name, val in resp.getheaders():
            self.__log.debug("{}: {}".format(name, val))
          resp_data = resp.read()
          self.__log.debug(resp_data.decode("utf-8"))
          # [timestamp,x,0,body,hash]
          # x is master_version in some games, in other games it's
          # hardcoded to 1
          arr = json.loads(resp_data)
          self.__last_response = arr
          if isinstance(arr[0], int):
            self.__last_response_time = arr[0]
          else:
            self.__log.warning(
                "expected int response time, got " + type(arr[0])
            )
            self.__last_response_time = self.__time()
          for x in arr:
            if isinstance(x, dict):
              return x
          raise RuntimeError("expected dict body, got " + type(arr[1]))
      except KeyboardInterrupt:
        break
      except Exception as e:
        self.__log.error(
            "error in call with path={} payload={}".format(path, payload),
            exc_info=e
        )
        time.sleep(2)
    return None

  def asset_state_v2(self, data):
    """
    this value is used in some klab games in fields such as asset_state.
    for this to be correct you must supply the correct libil2cpp and
    libjackpot-core hashes as well as the package signatures

    data: this is game-dependent. for example, sifas passes in the base64
    encoded random_bytes used in gem_mask, while dream team passes digits
    from the user id shuffled around
    """
    first_char_odd = data[0] & 1
    lib_hash_char = first_char_odd + 1
    lib_hash_type = data[lib_hash_char] % 3
    pkg_hash_char = 2 - first_char_odd
    pkg_hash_type = data[pkg_hash_char] % 3
    xored_hashes = array_xor(
        self.__jackpot_core_hashes[lib_hash_type],
        self.__il2cpp_hashes[lib_hash_type]
    )
    package_signature = self.__package_signatures[pkg_hash_type]
    left, right = xored_hashes.hex(), package_signature
    if first_char_odd != 0:
      left, right = right, left
    signatures = "{}-{}".format(left, right)
    xorkey = (
        data[0]
        | (data[1] << 8)
        | (data[2] << 16)
        | (data[3] << 24)
    ) ^ 0x12d8af36
    a = 0
    b = 0
    c = 0x2bd57287
    d = 0
    e = 0x202c9ea2
    f = 0
    g = 0x139da385
    h = 0
    i = 0
    j = 0
    k = 0
    for _ in range(10):
      h = g
      i = f
      j = e
      k = d
      g = c
      f = b
      a = (i32(a << 11) | (xorkey >> 21)) ^ a
      xorkey ^= i32(xorkey << 11)
      c = ((g >> 19) | i32(k << 13)) ^ xorkey ^ g
      c ^= (xorkey >> 8) | i32(a << 24)
      d = (k >> 19) ^ a ^ k ^ (a >> 8)
      xorkey = j
      a = i
      b = k
      e = h
    num = len(signatures)
    xor_bytes = bytearray(num)
    for idx in range(num):
      a = g
      xorkey = f
      b = (i32(i << 11) | (j >> 21)) ^ i
      j ^= i32(j << 11)
      e = ((c >> 19) | i32(d << 13)) ^ j
      e ^= c ^ ((j >> 8) | i32(b << 24))
      xor_bytes[idx] = i8(e)
      f = k
      g = c
      k = d
      j = h
      i = xorkey
      c = e
      d = (d >> 19) ^ b ^ d ^ (b >> 8)
      h = a
    data = array_xor(signatures.encode("ascii"), bytes(xor_bytes))
    return b64encode(data).decode("ascii")


def gen_resemara(package_name, advertising_id=None):
  """
  generate a random resemara detection id. used in some klab games.
  it's just the md5 hash of a random uuid which is supposed to be your
  google advertising id

  advertising_id: advertising uuid string. random by default
  """
  if advertising_id is None:
    advertising_id = uuid.uuid4()
  return md5(str(advertising_id) + package_name)


def __zopen(z, zpath, mode):
  ZIP_EXTS = [".zip", ".apk", ".xapk"]
  zpath = os.path.normpath(zpath)
  split = zpath.split(os.sep)
  for i, segment in enumerate(split):
    name, ext = os.path.splitext(segment)
    if ext in ZIP_EXTS:
      if z is not None:
        with z.open(os.sep.join(split[:i + 1])) as fnested:
          z = ZipFile(io.BytesIO(fnested.read()))
      else:
        z = ZipFile(os.sep.join(split[:i + 1]))
      return __zopen(z, os.sep.join(split[i + 1:]), mode)
  if z is not None:
    return z.open(zpath)
  return open(zpath, mode + "b")


def zopen(zpath, mode="r"):
  """
  open a file inside arbitrarily nested zip files.
  zpath is the path including the nested zip files, for example
  a.zip/b/c/d.zip/foo.txt

  returns a file-like object in binary mode

  if zpath is a file-like object, it will be returned as is as long as
  its mode matches mode (b part is ignored), otherwise a ValueError is
  raised. this is useful for functions that can accept either paths or
  file-like objects
  """
  if isinstance(zpath, io.IOBase):
    if hasattr(zpath, "mode") and zpath.mode[0] != mode[0]:
      raise ValueError("mode {} doesn't match {}".format(zpath.mode, mode))
    return zpath
  if mode not in ["r", "w"]:
    raise ValueError("invalid mode " + mode)
  return __zopen(None, zpath, mode)


class Il2CppMetadata:
  """
  parses il2cpp's global-metadata.dat. currently, only string data is
  implemented
  """

  def __init__(self, metadata_file):
    """
    metadata_file can be either a file-like object or a path.
    in either case, the file object will be closed when calling close()
    or automatically when using a when block.

    when metadata_file is a path, it will be opened using zopen(), which
    means that it can be a path inside arbitrarily nested zip's
    """
    f = zopen(metadata_file)
    magic, _ = struct.unpack("II", f.read(8))
    if magic != 0xfab11baf:
      raise ValueError("not a valid metadata file")
    strings, strings_size, string_data = struct.unpack("III", f.read(12))
    f.seek(strings)
    s = [struct.unpack("II", f.read(8)) for _ in range(strings_size // 8)]
    self.__strings_table = s
    self.__f = f
    self.__string_data = string_data

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.close()

  def close(self):
    """closes the underlying file object"""
    self.__f.close()

  def strings(self):
    """generator that returns utf-8 strings from the strings table"""
    f = self.__f
    for length, index in self.__strings_table:
      f.seek(self.__string_data + index)
      yield f.read(length).decode("utf-8")


class Downloader:
  """
  abstract interface for a downloader. these are used to implement apk
  downloaders for different sources
  """

  def hash(self):
    """
    return hash of the latest available apk, ideally without having to
    download the whole thing. this is used to check if new updates are
    available. does not have to be a specific type of hash as long as
    it's a consistent unique value for each version of the apk
    """
    raise NotImplementedError("Downloader.hash must be implemented")

  def download(self):
    """
    download the latest apk, returns a tuple with the filename and a
    file-like object. it's recommended to return a filename that is unique
    for each version
    """
    raise NotImplementedError("Downloader.download must be implemented")

  def verify(self, file_path, expected_hash):
    """returns True if expected_hash matches for the file at file_path"""
    return True


DESKTOP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) "
DESKTOP_USER_AGENT += "Gecko/20100101 Firefox/70.0"
DESKTOP_ACCEPT = ["text/html,application/xhtml+xml,application/xml",
                  "q=0.9,*/*", "q=0.8"]
DESKTOP_HEADERS = {
    "User-Agent": DESKTOP_USER_AGENT,
    "Accept": ";".join(DESKTOP_ACCEPT),
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}


class ApkPureDownloader(Downloader):
  """downloads apks and xapks from apkpure. see Downloader"""

  def __init__(self, game_name, package_name):
    """initialize a downloader for apkpure.com/game_name/package_name"""
    self.__log = logging.getLogger("ApkPureDownloader|%s" % package_name)
    self.__url = "https://apkpure.com/" + quote(game_name) + "/"
    self.__url += quote(package_name)
    self.__log.debug(self.__url)
    cfd = "".join([random.choice("0123456789abcdef") for _ in range(43)])
    hdrs = {**DESKTOP_HEADERS}
    hdrs["Cookie"] = "__cfduid=" + cfd + "; apkpure__lang=en"
    self.__hdrs = hdrs
    self.__sha1re = re.compile(r"<strong>File SHA1: </strong>([a-f0-9]+)")
    dlre = re.compile(r'https://download\.apkpure\.com/b/x?apk/[^"]*')
    self.__dlre = dlre

  def __open(self, path="", url=None, hdrs={}):
    if not url:
      url = self.__url + "/" + path
    req = Request(url=url, headers={**self.__hdrs, **hdrs})
    self.__lastcall = url
    return urlopen(req)

  def hash(self):
    with self.__open("versions") as resp:
      match = self.__sha1re.search(resp.read().decode("utf-8"))
      if not match:
        raise ValueError("couldn't extract sha1")
      remote_hash = match.group(1)
      return remote_hash

  def download(self):
    with self.__open("download?from=versions") as resp:
      match = self.__dlre.search(resp.read().decode("utf-8"))
      if not match:
        raise ValueError("couldn't extract download url")
      url = match.group(0)
    res = self.__open(url=url, hdrs={"Referer": self.__lastcall})
    # urllib does not handle different encoding in content-disposition
    # and always assumes iso-8859-1, so we get the raw bytes back
    # and assume it's utf-8. there's no small maintained library that
    # handles this properly. rfc6266 used to work but relies on lepl which
    # is a huge parser combinator that is unmaintained and doesn't work
    # on py 3.5+
    disposition = res.getheader("content-disposition")
    fname = res.info().get_filename()
    fname = fname.encode("iso-8859-1").decode("utf-8")
    return fname, res

  def verify(self, file_path, expected_hash):
    self.__log.info("verifying...")
    with open(file_path, "rb") as f:
      actual_hash = sha1_file(f)
    self.__log.info("     got {}".format(actual_hash))
    self.__log.info("expected {}".format(expected_hash))
    return actual_hash == expected_hash


def minidom_get_text(nodelist):
  """
  gets the text in a minidom nodelist for something like
  <tag>this text</tag>

  nodelist: the childNodes field of the minidom node
  """
  rc = []
  for node in nodelist:
    if node.nodeType == node.TEXT_NODE:
      rc.append(node.data)
  return "".join(rc)


def minidom_b64decode(nodelist):
  """gets text with minidom_get_text() and base64-decodes it"""
  s = minidom_get_text(nodelist)
  return b64decode(s)


def read_unpack(fmt, f):
  """
  calls struct.unpack with fmt reading bytes as necessary from f

  if struct.unpack only returns 1 value, the tuple is unpacked into a
  single return value
  """
  size = struct.calcsize(fmt)
  tup = struct.unpack(fmt, f.read(size))
  if len(tup) == 1:
    return tup[0]
  return tup


# pem -> xml code adapted from https://github.com/MisterDaneel/PemToXml

def pubkey_xml_to_der(xml):
  """
  convert a rsa public key from .net xml format to der.
  xml: file-like object or a path for zopen()
  """
  dom = minidom.parse(zopen(xml))
  modulus_nodes = dom.getElementsByTagName("Modulus")[0].childNodes
  modulus = minidom_b64decode(modulus_nodes)
  exponent_nodes = dom.getElementsByTagName("Exponent")[0].childNodes
  exponent = minidom_b64decode(exponent_nodes)
  # header for a 1024-bit modulus
  der_data = b64decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC======")
  # this one is the header for 2048 bit, keeping it just in case
  # der_data = b64decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")
  der_data += modulus
  der_data += b"\x02\x03"  # 3-byte integer exponent
  der_data += exponent
  return der_data


def pubkey_xml_to_pem(xml):
  der = pubkey_xml_to_der(xml)
  b64 = b64encode(der).decode("ascii")
  pem = "\n".join([
      "-----BEGIN PUBLIC KEY-----",
      *re.findall(r".{1,64}", b64),
      "-----END PUBLIC KEY-----"
  ])
  # load and dump as both a form of validation and normalization
  pem = pem.encode("ascii")
  bpem = dump_public_key(load_public_key(pem), encoding="pem")
  return bpem.decode("ascii")


class Plugin:
  """
  generic plugin interface. implement this for your specific game

  all methods except the functions returned by tasks() are called from the
  same thread/process as the constructor
  """

  def __init__(self):
    """
    tries to load config and/or process a pre-downloaded update if not
    present
    """
    self.log = logging.getLogger(self.tag())
    self.__try_load_config() or self.__try_init_config()

  def on_db_ready(self):
    """called when the database is up and running"""

  def on_config_loaded(self, j):
    """
    called when config.json is loaded. you can hold onto any config params
    here

    j: dict of the object in config.json
    """

  def downloader(self):
    """
    the downloader used to update this plugin. can be None for no updates.
    returns an object that implements the Downloader interface
    """

  def on_update(self, path):
    """
    called when an update is downloaded.
    path is the path to the downloaded file

    returns a dict that will be written to config.json, or None to avoid
    writing anything
    """

  def tasks(self):
    """
    returns a dict like {"name": function}. each function will be started
    in its own child process/thread. you should put things like account
    creation loops, login loops, etc in here

    tasks will be executed in a loop. if you need a task to stop, you can
    just stop returning it

    this function will be re-called every time a task terminates. the dict
    can change in between calls if you wish to dynamically change tasks
    """
    return []

  def add_arguments(self, parser):
    """
    adds any plugin-specific command line options

    parser: main argparse parser
    """

  def handle_arguments(self, args):
    """
    handles any plugin-specific command line options

    args: argparse arguments object. this includes all args for all plugins
    """

  def __try_load_config(self):
    try:
      self.load_config()
    except FileNotFoundError:
      return False
    return True

  def __try_init_config(self):
    self.log.debug("initializing config")
    try:
      with self.cache_open("hash.json") as f:
        apk = self.cache_dir(json.load(f)["filename"])
    except FileNotFoundError:
      return False
    config = self.on_update(apk)
    self.write_config(config)
    self.load_config()
    return True

  def load_config(self):
    """load config.json and pass deserialized dict to on_config_loaded"""
    with self.cache_open("config.json") as config_file:
      j = json.load(config_file)
      self.on_config_loaded(j)

  def write_config(self, config):
    """write config (dict) to config.json. no-op if config is None"""
    if config is not None:
      with self.cache_open("config.json", "w") as config_file:
        json.dump(config, config_file)

  def tag(self):
    """
    returns a unique tag, a short name that will be used in logs and
    to distinguish storage from other plugins. by default, this is just
    the base filename of the plugin
    """
    subclass_file = sys.modules[self.__module__].__file__
    s, _ = os.path.splitext(os.path.basename(subclass_file))
    return s

  def cache_dir(self, relpath):
    """prepends tag to relpath and calls cache_dir(). see cache_dir"""
    return cache_dir(os.path.join(self.tag(), relpath))

  def cache_open(self, relpath, mode="r"):
    """same as cache_dir() but also opens the file"""
    return open(self.cache_dir(relpath), mode)

  def update(self):
    """
    checks for updates and updates if necessary

    this is called automatically and you don't want to call this directly.
    if you override this, keep in mind that it's called from a different
    process

    returns True if config file should be reloaded
    """
    logger.debug("updating " + self.tag())
    try:
      with self.cache_open("hash.json") as f:
        local_hash = json.load(f)
    except FileNotFoundError:
      local_hash = None
    logger.debug("local hash is {}".format(local_hash))
    dl = self.downloader()
    if dl is None:
      logger.debug("no downloader, skipping")
      return False
    if not isinstance(dl, Downloader):
      raise ValueError("not a Downloader")
    remote_hash = dl.hash()
    if local_hash is not None and remote_hash == local_hash["hash"]:
      return False
    filename, f = dl.download()
    if f is None:
      logger.debug("got None file from downloader")
      return False
    if filename is None:
      raise ValueError("Downloader returned empty filename")
    logger.info("downloading " + filename)
    with self.cache_open(filename, "wb") as dst:
      shutil.copyfileobj(f, dst)
    f.close()
    file_path = self.cache_dir(filename)
    if dl.verify(file_path, remote_hash):
      with self.cache_open("hash.json", "w") as f:
        json.dump({"hash": remote_hash, "filename": filename}, f)
      return True
    return False


# -------------------------------------------------------------------------


__db_queue = mp.Queue()
__db_result_queue = mp.Queue()


def __db_loop():
  db_file = data_dir("database.db")
  db = sqlite3.connect(db_file)
  db.row_factory = sqlite3.Row
  db.isolation_level = None
  db.cursor().execute("pragma synchronous=NORMAL")
  db.cursor().execute("pragma journal_mode=WAL")
  while True:
    try:
      should_reply, fun, kwargs = __db_queue.get()
      cursor = db.cursor()
      cursor.execute("begin")
      res = fun(cursor, **kwargs)
      cursor.execute("commit")
    except Exception as e:
      logger.error("error in database queue", exc_info=e)
      res = e
      cursor.execute("rollback")
    if should_reply:
      __db_result_queue.put(res)


def db_enqueue(fun, **kwargs):
  """
  enqueue fun to be called from the database worker and block until it
  returns

  fun should take one argument which is the sqlite cursor

  the fun call is wrapped in a begin/commit block and rolls back if any
  exception occurs

  returns the value returned by fun or an Exeception
  """
  __db_queue.put((True, fun, kwargs))
  return __db_result_queue.get()


def __simple_query(cursor, sql, kwargs):
  cursor.execute(sql, kwargs)
  return [dict(x) for x in cursor.fetchall()]


def db_query(sql, **kwargs):
  """
  enqueue sql to be executed, wait for result, return rows as an array
  of dicts
  """
  return db_enqueue(__simple_query, sql=sql, kwargs=kwargs)


def __simple_execute(cursor, sql, kwargs):
  cursor.execute(sql, kwargs)


def db_exec(sql, **kwargs):
  """enqueue sql to be executed, returns immediately"""
  __db_queue.put((False, __simple_execute, {"sql": sql, "kwargs": kwargs}))


def db_exec_wait(sql, **kwargs):
  """enqueue sql to be executed and wait until it's done"""
  return db_enqueue(__simple_execute, sql=sql, kwargs=kwargs)


# -------------------------------------------------------------------------


__plugins = {}


def __load_plugins(path):
  global plugins
  py_re = re.compile(r"[^_].*\.py", re.IGNORECASE)
  files = filter(py_re.match, os.listdir(path))
  modules = map(lambda x: "." + os.path.splitext(x)[0], files)
  for module in modules:
    mod = importlib.import_module(module, package=plugins.__name__)
    __plugins[mod] = mod.__plugin__


def __worker(name, f, *args, **kwargs):
  logger.info("task {} starting".format(name))
  tstart = time.time()
  try:
    f(*args, **kwargs)
  except KeyboardInterrupt:
    logger.error("task {} interrupted".format(name))
  except Exception as e:
    logger.error("task {} encountered an error".format(name), exc_info=e)
    time.sleep(10)
  logger.info("task {} ran for {} s".format(name, time.time() - tstart))


# threading diagram
#
#             [ui_backend]<-.
#  [run]    [plugin_task1]<-.
#    ^      [plugin_task2]<--> [database]
#    |      [plugin_task3]<-'
# [update]  [plugin_task4]<-'
#           ...


def run(argv):
  """
  runs the main loop, blocking

  argv: arguments for argparse
  """
  me = SingleInstance()

  logging.basicConfig(level=logging.CRITICAL + 1)
  parser = argparse.ArgumentParser(description="extensible gacha client")
  levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
  desc = "enable logging for specific tags. syntax is tag:level "
  desc += "where level is one of: " + " ".join(levels) + " . "
  desc += "if level is not provided, it defaults to DEBUG. "
  desc += "all loggers are disabled by default. use tag all to enable "
  desc += "every logger"
  parser.add_argument("--log", nargs="*", metavar="", help=desc)
  desc = "write logs to this file"
  parser.add_argument("--log-file", help=desc, default=None)

  # parse args that should be in effect before loading plugins
  # but ignore help so the help shows plugin args later
  helparg = ["-h", "--help"]
  args, _ = parser.parse_known_args([x for x in argv if x not in helparg])

  if args.log_file:
    logging.getLogger().addHandler(logging.FileHandler(args.log_file))

  for log in args.log or []:
    split = log.rsplit(":", 1)
    tag = split[0]
    level = levels[0] if len(split) <= 1 else split[1].upper()
    if level not in levels:
      tag += ":" + level
      level = levels[0]
    if tag.lower() == "all":
      logging.getLogger().setLevel(level)
      break
    logging.getLogger(tag).setLevel(level)

  __load_plugins(plugins.__path__[0])
  instances = [x() for x in __plugins.values()]

  for x in instances:
    x.add_arguments(parser)
  args = parser.parse_args(argv)
  for x in instances:
    x.handle_arguments(args)

  # { plugin_type: { task_name: process } }
  plugin_processes = {k: {} for k in __plugins.values()}
  gachanator_processes = []

  main_thread = os.getpid()

  def kill_handler(sig, frame):
    if os.getpid() == main_thread:
      print("############## caught signal, killing all children")
      for _, processes in plugin_processes.items():
        for _, process in processes.items():
          if process is not None and process.is_alive():
            process.terminate()
      for process in gachanator_processes:
        if process is not None and process.is_alive():
          process.terminate()
    sys.exit(0)

  # replace signal handler to it kills all child processes
  signal.signal(signal.SIGINT, kill_handler)
  signal.signal(signal.SIGTERM, kill_handler)

  q = mp.Queue()

  def update_all():
    while True:
      for plugin in instances:
        res = plugin.update()
        q.put((type(plugin), res))
      time.sleep(60)

  updater_process = mp.Process(
      target=__worker,
      args=("gachanator_updater", update_all)
  )
  updater_process.start()
  gachanator_processes.append(updater_process)

  database_process = mp.Process(
      target=__worker,
      args=("gachanator_database", __db_loop)
  )
  database_process.start()
  gachanator_processes.append(database_process)

  for x in instances:
    x.on_db_ready()

  while True:
    # poll for completed updates
    try:
      plugin_t, load_config = q.get_nowait()
      plugin = next((x for x in instances if type(x) == plugin_t), None)
      if plugin is None:
        raise RuntimeError("got update signal for unknown plugin type")
      if load_config:
        config = plugin.on_update(file_path)
        plugin.write_config(config)
        plugin.load_config()
    except queue.Empty:
      pass
    except Exception as e:
      logger.debug("error updating {}".format(plugin_t), exc_info=e)

    # check all running tasks and restart as needed
    def restarted(plugin, processes):
      if not len(processes):
        processes = {k: None for k in plugin.tasks().keys()}
      for name, process in processes.items():
        if not process or not process.is_alive():
          tasks = plugin.tasks()
          try:
            func = tasks[name]
          except KeyError:
            continue
          fullname = "{}.{}".format(type(plugin), name)
          new_process = mp.Process(target=__worker, args=(fullname, func))
          new_process.start()
          yield name, new_process
        else:
          yield name, process

    for plugin in instances:
      t = type(plugin)
      processes = plugin_processes[t]
      plugin_processes[t] = {k: v for k, v in restarted(plugin, processes)}

    time.sleep(1)


def run_cli():
  """calls run(sys.argv[1:]) and catches KeyboardInterrupt"""
  try:
    run(sys.argv[1:])
  except KeyboardInterrupt:
    pass
