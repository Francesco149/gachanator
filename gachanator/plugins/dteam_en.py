from gachanator import KlabHttpApi, Plugin, ApkPureDownloader
from gachanator import Il2CppMetadata
from gachanator import pubkey_xml_to_pem, zopen, apk_signatures
from gachanator import file_hashes, array_xor, iter2
from gachanator import gen_randomized_sequential_id
from gachanator import gen_google_play_service_id, gen_resemara
from gachanator import randsleep, millitime
from gachanator import db_exec, db_exec_wait, db_query
from urllib.parse import urlunparse
from base64 import b64decode
from gachanator import b64encode
from push_receiver import register
import random
import uuid
import io
import multiprocessing as mp
import time


def gen_pass_code():
  # I haven't checked the game's code but random passcode seems to work
  return "".join([random.choice("0123456789abcdef") for _ in range(19)])


PACKAGE_NAME = "com.klab.captain283.global"


class DreamTeamEnPlugin(Plugin):
  def on_db_ready(self):
    db_exec_wait("""
      create table if not exists {}_accounts (
        user_id int not null,
        last_login int not null,
        archived int not null default 0,
        auth_count int not null,
        service_id char[21] not null,
        pass_code char[19] not null,
        advertising_id char[36] not null,
        device_token char[154] not null,
        session_key char[44] not null,
        klab_id_mail text
      )
    """.format(self.tag()))
    db_exec_wait("""
      create table if not exists {}_items(
        user_id integer not null,
        master_id integer not null,
        amount integer not null,
        primary key (user_id, master_id)
      )
    """.format(self.tag()))

  def on_config_loaded(self, j):
    self.api_builder = KlabHttpApi.builder(
        **j, log=self.tag(),
        gen_id=gen_randomized_sequential_id,
        time_multiplier=1,
        language="En"
    )
    self.sender_id = j["sender_id"]
    self.log.debug("firebase sender id is %d" % self.sender_id)

  def downloader(self):
    return ApkPureDownloader(
        game_name="captain-tsubasa-dream-team",
        package_name=PACKAGE_NAME
    )

  def on_update(self, apk):
    md = "/assets/bin/Data/Managed/Metadata/global-metadata.dat"
    with Il2CppMetadata(apk + md) as il2cpp:
      strings = il2cpp.strings()
      for s in strings:
        if s.startswith("<RSAKeyValue><Modulus"):
          pubkey = pubkey_xml_to_pem(io.StringIO(s))
        elif s.startswith("ep"):
          path = s
        elif s.startswith("gl-game"):
          break
      host = s[:-1]  # has a trailing slash
      for _ in range(4):
        next(strings)
      startup_key = next(strings)
    endpoint = urlunparse(("https", host, path, "", "", ""))
    with zopen(apk + "/lib/armeabi-v7a/libil2cpp.so") as f:
      il2cpp_hashes = file_hashes(f)
    with zopen(apk + "/lib/armeabi-v7a/libjackpot-core.so") as f:
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
        "sender_id": 975355246282
    }

  def tasks(self):
    return {
        **{"create_{}".format(i): self.create
           for i in range(self.create_threads)},
        "gifts": self.gifts
    }

  def add_arguments(self, parser):
    tag = "[{}] ".format(self.tag())
    pre = "--dteam-en-"
    desc = tag + "parallel account creation threads"
    params = {"help": desc, "type": int, "default": 12, "metavar": "N"}
    parser.add_argument(pre + "create-threads", **params)
    desc = tag + "parallel gifts login threads"
    parser.add_argument(pre + "gifts-threads", **params)

  def handle_arguments(self, args):
    self.create_threads = args.dteam_en_create_threads
    self.gifts_threads = args.dteam_en_gifts_threads

  def create(self):
    DreamTeamEnClient(**vars(self)).create_account()
    randsleep(1000)

  def gifts(self):
    # to ensure we don't try to log in the same accounts twice, we query
    # a bunch of accounts in advance and then start 1 process per account
    # and wait on all of them to be done

    old = millitime() - 3600000 * 24
    rows = db_query("""
      select * from {}_accounts where last_login < :old and archived = 0
      order by last_login asc
      limit :threads
    """.format(self.tag()),
        old=old, threads=self.gifts_threads
    )

    self.log.info("starting %d gifts workers" % len(rows))

    q = mp.Queue()

    def gifts_worker(client_fields, row):
      try:
        client = DreamTeamEnClient(**client_fields)
        row["session_key"] = b64decode(row["session_key"])
        client.update(**row)
        client.login_and_get_rewards()
      except KeyboardInterrupt:
        pass
      except Exception as e:
        q.put(e)
        return
      q.put(None)

    processes = []

    for row in rows:
      p = mp.Process(target=gifts_worker, args=(self.client_fields(), row))
      p.start()
      processes.append(p)

    for process in processes:
      e = q.get()
      if e:
        self.log.error("error in gifts worker", exc_info=e)

    if len(rows) == 0:
      time.sleep(60)
    else:
      time.sleep(1)

  def client_fields(self):
    fields = ["log", "api_builder", "sender_id"]
    return {k: v for k, v in vars(self).items() if k in fields}


__plugin__ = DreamTeamEnPlugin


class DreamTeamEnClient:
  def __init__(self, log, api_builder, sender_id, **kwargs):
    self.log = log
    self.api = api_builder()
    self.auth_count = 0
    self.service_id = gen_google_play_service_id()
    self.pass_code = gen_pass_code()
    self.advertising_id = str(uuid.uuid4())
    self.update_info = None
    self.sender_id = sender_id
    self.device_token = None

  def update(self, **kwargs):
    d = self.__dict__
    d.update({k: v for k, v in kwargs.items() if k in d})
    d = self.api.__dict__
    d.update({k: v for k, v in kwargs.items() if k in d})

  def startup(self):
    resp = self.api.call(
        path="/login/startup",
        payload={
            "language_code": 2,
            "platform_type": 0,
            "mask": self.api.gen_mask(),
            "locale_identifer": "en_US"
        }
    )
    # yes, locale_identifer is supposed to be typed wrong
    # yes, I might or might have not spent 1+h debugging because of it
    mask_bytes = b64decode(resp["authorization_key"])
    self.api.user_id = resp["user_id"]
    self.api.session_key = array_xor(mask_bytes, self.api.mask_bytes())
    return resp

  def asset_state(self):
    digits = str(self.api.user_id)
    digits = digits[::-1]
    digits = digits[2:7].encode("ascii")
    return self.api.asset_state_v2(digits)

  def login(self):
    resp = self.api.call(
        path="/login/login",
        payload={
            "user_id": self.api.user_id,
            "auth_count": self.auth_count + 1,
            "mask": self.api.gen_mask(),
            "asset_state": self.asset_state(),
            "resemara_id": gen_resemara(
                package_name=PACKAGE_NAME,
                advertising_id=self.advertising_id
            )
        }
    )
    if "invalid_auth_count" in resp:
      # InvalidAuthCountResponse
      self.auth_count = resp["invalid_auth_count"]["authorization_count"]
      self.login()
      return
    self.auth_count += 1
    mask_bytes = b64decode(resp["session_key"])
    key = array_xor(mask_bytes, self.api.mask_bytes())
    self.api.temporary_session_key = key
    self.api.master_version = resp["master_version"]["version"]
    self.update_info = resp["update_info"]
    return resp

  def get_data_link_status_list(self):
    return self.api.call("/dataLink/getDataLinkStatusList")

  def link_with_google_play(self):
    return self.api.call(
        path="/dataLink/linkWithGooglePlay",
        payload={
            "service_id": self.service_id,
            "pass_code": self.pass_code,
        }
    )

  def update_gdpr_consents(self):
    consents = self.update_info["gdpr_consent_infos"]
    return self.api.call(
        path="/user/updateGdprConsents",
        payload={
            "consents": [{"consent_type": k, "has_consented": True}
                         for x in iter2(consents)]
        }
    )

  def tutorial_download(self):
    return self.api.call("/tutorial/download")

  def check_ad_identifier(self):
    return self.api.call(
        path="/user/checkAdIdentifier",
        payload={
            "identifier_type": 1,
            "identifier": self.advertising_id
        }
    )

  def tutorial_kickoff(self):
    return self.api.call("/tutorial/kickoff")

  def tutorial_match_result(self):
    return self.api.call("/tutorial/matchResult")

  def fetch_home_info(self):
    return self.api.call("/user/fetchHomeInfo")

  def update_notification_setting(self):
    credentials = register(sender_id=self.sender_id)
    self.device_token = credentials["fcm"]["token"]
    return self.api.call(
        path="/notification/updateNotificationSetting",
        payload={
            "device_token": self.device_token,
            "is_admin_notice": True,
            "is_ap_max": True,
            "is_league_result": True,
            "is_event_reservation": True,
            "is_coop_recruitment": True
        }
    )

  def gacha_fetch(self):
    return self.api.call("/gacha/fetch")

  def gacha_play(
      self, gacha_product_info_id, play_count,
      selected_category=1, mixer_materials=[]
  ):
    return self.api.call(
        path="/gacha/play",
        payload={
            "gacha_product_info_id": gacha_product_info_id,
            "play_count": play_count,
            "selected_category": selected_category,
            "mixer_materials": []
        }
    )

  def gacha_fix_retry(self):
    return self.api.call("/gacha/fixRetry")

  def fetch_home_info(self):
    return self.api.call("/user/fetchHomeInfo")

  def update_deck_list(self, deck_list):
    return self.api.call(
        path="/formation/updateDeckList",
        payload={"deck_list": deck_list}
    )

  def set_profile(self, name, team_name, comment):
    return self.api.call(
        path="/user/setProfile",
        payload={"name": name, "team_name": team_name, "comment": comment}
    )

  def tutorial_end(self):
    return self.api.call("/tutorial/end")

  def present_fetch(self):
    return self.api.call("/present/fetch")

  def present_receive_multiple(self, present_ids):
    return self.api.call(
        path="/present/receiveMultiple",
        payload={"present_ids": present_ids}
    )

  @staticmethod
  def gacha_by_name(gacha_fetch_response, name):
    for x in gacha_fetch_response["elements"]:
      if x["name"] == name:
        return x
    return None

  @staticmethod
  def gacha_product_by_description(gacha, description):
    for x in gacha["product_info_list"]:
      for y in x["product_info_list"]:
        if y["description"] == description:
          return y
    return None

  def perform_login(self):
    self.login()
    randsleep(15000)
    self.get_data_link_status_list()
    randsleep(4000)

  def create_account(self):
    self.startup()
    self.perform_login()
    self.link_with_google_play()
    randsleep(10000)
    self.update_gdpr_consents()
    randsleep(2000)
    self.tutorial_download()
    randsleep(4000)
    self.check_ad_identifier()
    randsleep(2000)
    self.tutorial_kickoff()
    randsleep(110000)
    self.tutorial_match_result()
    randsleep(3000)
    self.fetch_home_info()
    randsleep(3000)
    self.update_notification_setting()
    randsleep(6000)
    gachas = self.gacha_fetch()
    g = self.gacha_by_name(gachas, "GACHA_NAME_TUTORIAL")
    if not g:
      raise RuntimeError("couldn't find tutorial gacha")
    p = self.gacha_product_by_description(g, "GACHA_DESCRIPTION_TUTORIAL")
    if not p:
      raise RuntimeError("couldn't find tutorial gacha product")
    randsleep(6000)
    r = self.gacha_play(
        gacha_product_info_id=p["id"],
        play_count=p["play_count"]
    )
    master_id = r["gacha_result_info"]["prizes"][0]["prize"]["content_id"]
    randsleep(28000)
    r = self.gacha_fix_retry()
    cards = r["update_info"]["playable_card_by_id"]
    card_id = next(
        (x["id"] for _, x in iter2(cards) if x["master_id"] == master_id),
        None
    )
    if not card_id:
      raise RuntimeError("couldn't find card we got from gacha")
    randsleep(3000)
    self.gacha_fetch()
    randsleep(6000)
    self.fetch_home_info()
    deck = next(
        (v for k, v in iter2(self.update_info["deck_by_id"]) if k == 1),
        None
    )
    if not deck:
      raise RuntimeError("couldn't find deck 1")
    deck["expiration_date"] = 0
    # swap 7th player with the card we got from gacha, set it as captain
    deck["captain_card_id"] = card_id
    deck["card_ids"][7] = card_id
    randsleep(30000)
    self.update_deck_list([deck])
    randsleep(2000)
    self.fetch_home_info()
    user = self.update_info["user"]
    profile = {k: user[k] for k in ["name", "team_name", "comment"]}
    randsleep(6000)
    self.set_profile(**profile)
    randsleep(18000)
    self.tutorial_end()
    if not self.api.alive():
      return
    randsleep(5000)
    self.fetch_home_info()
    self.commit_account()

  def login_and_get_rewards(self):
    self.perform_login()
    self.check_ad_identifier()
    randsleep(2000)
    self.fetch_home_info()
    randsleep(10000)
    j = self.present_fetch()
    randsleep(5000)
    present_ids = [x["id"] for x in j["present_response"]["present_list"]]
    if len(present_ids) > 0:
      self.present_receive_multiple(present_ids)
    j = self.fetch_home_info()
    free_stone = j["update_info"]["user_billing_info"]["free_stone"]
    # TODO: other items
    db_exec("""
      insert or replace into {}_items(user_id, master_id, amount)
      values (:user_id, :master_id, :amount)
        """.format(self.log.name),
            user_id=self.api.user_id, master_id=0, amount=free_stone)
    self.commit_account()

  def commit_account(self):
    db_exec("""
      insert or replace into {}_accounts (
        user_id, last_login, auth_count, service_id, pass_code,
        advertising_id, device_token, session_key
      ) values (
        :user_id, :last_login, :auth_count, :service_id, :pass_code,
        :advertising_id, :device_token, :session_key
      )
    """.format(self.log.name),
            last_login=millitime(), **self.account_fields())

  def account_fields(self):
    # transforms the class fields into a dict to be used in sql queries
    everything = {**vars(self), **vars(self.api)}
    fields = [
        "user_id", "auth_count", "service_id", "pass_code",
        "advertising_id", "device_token", "session_key"
    ]
    res = {k: v for k, v in everything.items() if k in fields}
    res["session_key"] = b64encode(res["session_key"])
    return res
