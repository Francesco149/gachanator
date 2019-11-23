from gachanator import KlabHttpApi, Plugin, QooAppDownloader
from gachanator import Il2CppMetadata
from gachanator import pubkey_xml_to_pem, zopen
from gachanator import apk_signatures, file_hashes
import re
import io


# INCOMPLETE PLUGIN
# this doesn't do anything other than updating parsing the apk yet

class AllStarsJpPlugin(Plugin):
  def on_config_loaded(self, j):
    self.api_builder = KlabHttpApi.builder(**j, log=self.tag())

  def downloader(self):
    return QooAppDownloader(package_name="com.klab.lovelive.allstars")

  def on_update(self, apks):
    dl = self.downloader()

    apk = dl.find_apk(apks)
    if not apk:
      raise RuntimeError(f"couldn't find base apk")
    md = "/assets/bin/Data/Managed/Metadata/global-metadata.dat"
    with Il2CppMetadata(apk + md) as il2cpp:
      endpoint_re = re.compile(r"https://.*.klabgames.net/ep[0-9]+")
      strings = il2cpp.strings()
      for s in strings:
        if s.startswith("<RSAKeyValue><Modulus"):
          pubkey = pubkey_xml_to_pem(io.StringIO(s))
        elif endpoint_re.match(s):
          break
      endpoint = s
      startup_key = next(strings)

    apk = dl.find_apk(apks, config=r"armeabi_v7a")
    if not apk:
      raise RuntimeError(f"couldn't find arm apk")
    lib = "/lib/armeabi-v7a/"
    with zopen(apk + lib + "libil2cpp.so") as f:
      il2cpp_hashes = file_hashes(f)
    with zopen(apk + lib + "libjackpot-core.so") as f:
      jackpot_core_hashes = file_hashes(f)
    with zopen(apk + "/META-INF/CERT.RSA") as f:
      package_signatures = apk_signatures(f)

    return {
        "endpoint": endpoint,
        "startup_key": startup_key,
        "pubkey": pubkey,
        "il2cpp_hashes": il2cpp_hashes,
        "jackpot_core_hashes": jackpot_core_hashes,
        "package_signatures": package_signatures,
        "sender_id": 581776171271
    }

  def tasks(self):
    return {}

  def add_arguments(self, parser):
    pass

  def handle_arguments(self, args):
    pass


class AllStarsJpClient:
  pass


__plugin__ = AllStarsJpPlugin
