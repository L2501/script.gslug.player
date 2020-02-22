# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import sys
from kodi_six import xbmc, xbmcgui, xbmcaddon, xbmcplugin
from routing import Plugin

import socket
import requests
from contextlib import closing
from hashlib import sha256
from future.moves.urllib.parse import urlencode

addon = xbmcaddon.Addon()
plugin = Plugin()
plugin.name = addon.getAddonInfo("name")

ADDON_DATA_DIR = xbmc.translatePath(addon.getAddonInfo("path"))
RESOURCES_DIR = os.path.join(ADDON_DATA_DIR, "resources")
XBMC_GSLUG_SCRIPT = os.path.join(RESOURCES_DIR, "service", "gslug.py")
user_agent = "Mozilla/5.0 (Linux; Android 7.1.2; AFTN Build/NS6212) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.109 Mobile Safari/537.36"


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


@plugin.route("/")
def root():
    gslug_url = plugin.args.get("url", [""])[-1]
    if gslug_url:
        gslug_referer = plugin.args.get("referer", [gslug_url])[-1]
        quality = plugin.args.get("quality", ["best"])[-1]
        _port = find_free_port()

        LIVE = False
        xbmc.executebuiltin(
            "RunScript({0},{1},{2},{3},{4},{5})".format(
                XBMC_GSLUG_SCRIPT, gslug_url, gslug_referer, user_agent, quality, _port
            )
        )

        playlist_path = "http://127.0.0.1:{0}/{1}/chunks.m3u8".format(
            _port, sha256(gslug_url.encode("utf-8")).hexdigest()
        )

        timeout = 0
        monitor = xbmc.Monitor()
        while not monitor.abortRequested() and (timeout < 10):
            try:
                _r = requests.get(playlist_path, stream=True, timeout=1)
                _r.raise_for_status()
                LIVE = True
                break
            except Exception:
                if monitor.waitForAbort(1):
                    break
                else:
                    timeout +=1

        if LIVE:
            headers = urlencode([("User-Agent", user_agent,)])
            li = xbmcgui.ListItem(path="{0}|{1}".format(playlist_path, headers))
            li.setMimeType("application/vnd.apple.mpegurl")
            li.setContentLookup(False)
            xbmcplugin.setResolvedUrl(plugin.handle, True, li)
        else:
            xbmcgui.Dialog().notification(plugin.name, "Stream offline", xbmcgui.NOTIFICATION_ERROR)
            xbmcplugin.setResolvedUrl(plugin.handle, False, xbmcgui.ListItem())


if __name__ == "__main__":
    plugin.run(sys.argv)
