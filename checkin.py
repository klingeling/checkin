# -*- coding: utf-8 -*-
# @Date    : 2021-04-24 16:31:25
# @Author  : gwentmaster(gwentmaster@vivaldi.net)
# I regret in my life


import json
import logging
import logging.config
import os
import re
import time
from hashlib import md5
from typing import List, Optional

import httpx
from bs4 import BeautifulSoup


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    + "(KHTML, like Gecko) Chrome/90.0.4430.95 Safari/537.36"
)


def chicken_checkin() -> None:
    """几鸡签到
    """

    logger = logging.getLogger("chicken")

    client = httpx.Client(timeout=50)
    email = os.environ["CHICKEN_MAIL"]
    passwd = os.environ["CHICKEN_PASSWORD"]

    login_resp = client.post(
        "https://j01.space/signin",
        headers={"Content-Type": "application/json;charset=UTF-8"},
        content=json.dumps(
            {"email": email, "passwd": passwd},
            separators=(",", ":")
        )
    )
    logger.info(login_resp.json())

    checkin_resp = client.post(
        "https://j01.space/user/checkin"
    )
    logger.info(checkin_resp.json())


def lovezhuoyou_checkin() -> None:
    """爱桌游签到
    """

    logger = logging.getLogger("lovezhuoyou")

    url = "https://www.zhuoyoux.com/wp-admin/admin-ajax.php"

    client = httpx.Client(timeout=50)
    username = os.environ["LOVEZHUOYOU_USER"]
    password = os.environ["LOVEZHUOYOU_PASSWORD"]

    login_resp = client.post(
        url,
        data={
            "action": "user_login",
            "username": username,
            "password": password
        }
    )
    logger.info(login_resp.json())

    checkin_resp = client.post(
        url,
        data={"action": "user_qiandao"}
    )
    logger.info(checkin_resp.json())


def vgtime_checkin() -> None:
    """游戏时光签到
    """

    logger = logging.getLogger("vgtime")

    client = httpx.Client(timeout=50)
    username = os.environ["VGTIME_USER"]
    password = os.environ["VGTIME_PASSWORD"]

    login_resp = client.post(
        "https://www.vgtime.com/handle/login.jhtml",
        headers={"User-Agent": USER_AGENT},
        data={
            "username": username,
            "password": password,
            "remember": "1"
        }
    )
    logger.info(login_resp.json()["message"])

    checkin_resp = client.post(
        "https://www.vgtime.com/uc/writesign.jhtml",
        headers={"User-Agent": USER_AGENT}
    )
    logger.info(checkin_resp.json()["message"])


def iyingdi_checkin() -> None:
    """旅法师营地签到
    """

    client = httpx.Client(timeout=50)

    username = os.environ["IYINGDI_USER"]
    password = os.environ["IYINGDI_PASSWORD"]
    timestamp = str(int(time.time()))
    key = "b8d5b38577b8bb382b0c783b474b95f9"

    sign_material = ""
    for k, v in {
        "password": password,
        "timestamp": timestamp,
        "type": "password",
        "username": username,
        "key": key
    }.items():
        sign_material += f"&{k}={v}"
    sign_material = sign_material.lstrip("&")
    sign = md5(sign_material.encode()).hexdigest()

    login_resp = client.post(
        "https://api.iyingdi.com/web/user/login",
        headers={
            "Login-Token": "nologin",
            "Platform": "pc"
        },
        data={
            "username": username,
            "password": password,
            "timestamp": timestamp,
            "type": "password",
            "sign": sign
        }
    )

    cookies = {
        "yd_token": login_resp.json()["login_token"],
        "yd_refresh_token": login_resp.json()["refresh_token"],
        "user_id": login_resp.json()["user_id"]
    }
    client.cookies.update({k: str(v) for k, v in cookies.items()})

    artical_resp = client.get("https://www.iyingdi.com/tz/tag/19")
    search = re.search(r"/tz/post/\d+", artical_resp.content.decode("utf-8"))
    if search:
        client.get(f"https://www.iyingdi.com{search.group(0)}")


def kkgal_checkin() -> None:
    """kkgal签到
    """

    logger = logging.getLogger("kkgal")

    url = "https://www.kkgal.com/wp-login.php"

    client = httpx.Client(timeout=200)
    username = os.environ["KKGAL_USER"]
    password = os.environ["KKGAL_PASSWORD"]

    login_resp = client.post(
        url,
        data={
            "log": username,
            "pwd": password,
            "rememberme": "forever",
            "wp-submit": "登录",
            "redirect_to": "https://www.kkgal.com/",
            "testcookie": "1"
        }
    )

    profile_points_resp = client.get("https://www.kkgal.com/wp-admin/profile.php?ref=site_visit&order=DESC&paged=1&s=&page=mycred_default_history&ref=site_visit&order=DESC&paged=1")
    points_change = BeautifulSoup(profile_points_resp.text, "html.parser").find("td", class_="column-time")
    if points_change is not None:
        points_change = points_change.string
    profile_resp = client.get("https://www.kkgal.com/wp-admin/profile.php")
    points = BeautifulSoup(profile_resp.text, "html.parser").find(
        "li",
        id="wp-admin-bar-mycred-account-balance-mycred-default1")
    if points is not None:
        points = points.contents[0].text
    logger.info("最近一次获取经验时间： " + str(points_change) + "\t总" + str(points))


def suying_checkin() -> None:
    """suying666签到
    """

    logger = logging.getLogger("suying666")

    url = "https://suying66.com/auth/login"

    client = httpx.Client(timeout=50)
    username = os.environ["SUYING_USER"]
    password = os.environ["SUYING_PASSWORD"]

    login_resp = client.post(
        url,
        data={
            "email": username,
            "passwd": password,
            "code": "",
            "rememberme_me": "on"
        }
    )

    logger.info(login_resp.json())

    checkin_resp = client.post(
        "https://suying66.com/user/checkin"
    )

    logger.info(checkin_resp.json())


def smzdm_checkin() -> None:
    """什么值得买签到
    """

    logger = logging.getLogger("smzdm")

    client = httpx.Client()
    sess_cookie = os.environ["SMZDM_SESS_COOKIE"]

    checkin_resp = client.get(
        url="https://zhiyou.smzdm.com/user/checkin/jsonp_checkin",
        cookies={"sess": sess_cookie},
        headers={
            "User-Agent": USER_AGENT,
            "Referer": "https://www.smzdm.com/"
        }
    )
    logger.info(
        "continue_checkin_days: "
        + str(checkin_resp.json()["data"]["continue_checkin_days"])
    )


if __name__ == "__main__":

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "logging.Formatter",
                "fmt": (
                    "[%(asctime)s]-[%(name)s]-[%(levelname)s]: %(message)s\n"
                ),
                "datefmt": "%m-%d %H:%M:%S"
            }
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            }
        },
        "loggers": {
            "": {"handlers": ["default"], "level": "INFO"},
        }
    })

    errors = []  # type: List[Optional[Exception]]
    for func in [
        chicken_checkin,
        lovezhuoyou_checkin,
        vgtime_checkin,
        iyingdi_checkin,
        kkgal_checkin,
        suying_checkin,
        smzdm_checkin
    ]:
        try:
            func()
        except Exception as e:
            errors.append(e)

    for er in errors:
        if isinstance(er, Exception):
            raise er
