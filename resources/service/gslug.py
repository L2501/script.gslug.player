# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import sys
import errno
import socket
import re
import requests
from future.moves.urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from base64 import b64decode
from hashlib import sha256
from xbmc import Monitor, Player
from functools import partial

try:
    from http.server import BaseHTTPRequestHandler
    from http.server import HTTPServer
except ImportError:
    # Python 2.7
    from BaseHTTPServer import BaseHTTPRequestHandler
    from BaseHTTPServer import HTTPServer

try:
    from socketserver import ThreadingMixIn
except ImportError:
    # Python 2.7
    from SocketServer import ThreadingMixIn

ACCEPTABLE_ERRNO = (
    errno.ECONNABORTED,
    errno.ECONNRESET,
    errno.EINVAL,
    errno.EPIPE,
)
try:
    ACCEPTABLE_ERRNO += (errno.WSAECONNABORTED,)
except AttributeError:
    pass  # Not windows


class Gslug(object):
    def __init__(self, url, referer, user_agent, host):
        self.user_agent = user_agent
        self.quality_pref = ("fullhd", "hd", "mhd", "sd", "origin")
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": self.user_agent})
        self.url = url
        self.referer = referer
        self.host = host
        self.slug = self.parse_slug_from_url(self.url)
        self.key = self.scrape_key_from_url(self.url)
        if self.key:
            self.playlist = self.get_playlist_vip()
        else:
            self.playlist = self.get_playlist_guest()
        self.segments = {}
        self.m3u8_path = "/{0}.m3u8".format(sha256(url.encode("utf-8")).hexdigest())
        self.m3u8_key = ""
        self.m3u8 = ""

    def parse_slug_from_url(self, url):
        _parsed = urlparse(url)
        if _parsed.fragment:
            for q in parse_qsl(_parsed.fragment):
                if "slug" in q:
                    return q[1]
        elif _parsed.query:
            for q in parse_qsl(_parsed.query):
                if "v" in q:
                    return q[1]
        raise ValueError

    def scrape_key_from_url(self, url):
        headers = {
            "Referer": self.referer,
        }
        r = self.s.get(url, headers=headers, timeout=5)
        r.raise_for_status()
        _key_re = re.search(r"key:\s*\W([0-9a-f]+)\W", r.text, re.I)
        if _key_re:
            return _key_re.group(1)
        else:
            return None

    def get_playlist_guest(self):
        guest_url = "https://multi.idocdn.com/guest"
        headers = {
            "Referer": self.url,
            "Origin": urlparse(self.url)
            ._replace(path="", params="", query="", fragment="")
            .geturl(),
        }
        data = {
            "slug": self.slug,
        }
        r = self.s.post(guest_url, headers=headers, data=data, timeout=5)
        r.raise_for_status()
        return r.json()

    def get_playlist_vip(self):
        vip_url = "https://multi.idocdn.com/vip"
        headers = {
            "Referer": self.url,
            "Origin": urlparse(self.url)
            ._replace(path="", params="", query="", fragment="")
            .geturl(),
        }
        data = {
            "key": self.key,
            "type": "slug",
            "value": self.slug,
        }
        r = self.s.post(vip_url, headers=headers, data=data, timeout=5)
        r.raise_for_status()
        return r.json()

    def get_ping(self, stream):
        ping_url = urljoin(self.playlist["ping"], self.playlist[stream]["id"] + "/ping")
        headers = {
            "Referer": self.url,
            "Origin": urlparse(self.url)
            ._replace(path="", params="", query="", fragment="")
            .geturl(),
        }
        r = self.s.get(ping_url, headers=headers, timeout=5)
        r.raise_for_status()

    def get_key(self, key_url):
        headers = {
            "Referer": self.url,
            "Origin": urlparse(self.url)
            ._replace(path="", params="", query="", fragment="")
            .geturl(),
        }
        r = self.s.get(key_url, headers=headers, timeout=5)
        r.raise_for_status()
        self.m3u8_key = r.content

    def resolve_segment_url(self, url):
        if url in self.segments:
            return self.segments[url]
        else:
            headers = {
                "Referer": self.url,
                "Origin": urlparse(self.url)
                ._replace(path="", params="", query="", fragment="")
                .geturl(),
            }
            r = self.s.get(url, headers=headers, timeout=5)
            r.raise_for_status()
            g_url = b64decode(r.json()["url"]).decode("utf-8")
            self.segments[url] = g_url
            return self.segments[url]

    def generate_stream(self, stream):
        if stream not in self.playlist:
            for q in self.quality_pref:
                if q in self.playlist:
                    stream = q
                    break

        self.get_ping(stream)
        _m3u8 = [
            "#EXTM3U\n",
            "#EXT-X-VERSION:4\n",
            "#EXT-X-PLAYLIST-TYPE:VOD\n",
            "#EXT-X-TARGETDURATION:{0}\n".format(self.playlist[stream]["duration"]),
            "#EXT-X-MEDIA-SEQUENCE:1\n",
        ]
        if "hash" in self.playlist:
            key_url = "https://{0}/hash/{1}?key={2}".format(
                self.playlist["servers"]["stream"],
                self.playlist[stream]["sig"],
                self.playlist[stream]["hash"],
            )
            self.get_key(key_url)
            # _m3u8.append("#EXT-X-HASH:{0}\n".format(self.playlist["hash"]))
            _m3u8.append(
                '#EXT-X-KEY:METHOD=AES-128,URI="http://{0}:{1}/key",IV={2}\n'.format(
                    self.host[0], self.host[1], self.playlist[stream]["iv"],
                )
            )

        def segment_id_generator(stream):
            next_ids = list(stream["ids"])
            next_ids.append(next_ids.pop(0))
            for seg_id in zip(stream["ranges"], stream["ids"], next_ids):
                for seg_range in seg_id[0]:
                    yield seg_range, seg_id[1], seg_id[2]

        def segment_generator(stream):
            for inf in zip(stream["extinfs"], segment_id_generator(stream)):
                yield inf[0], inf[1][0], inf[1][1], inf[1][2]

        for i, seg in enumerate(segment_generator(self.playlist[stream])):
            _m3u8.append("#EXTINF:{0}\n".format(seg[0]))
            _m3u8.append("#EXT-X-BYTERANGE:{0}\n".format(seg[1]))
            _seg_url = "https://{0}/html/{1}/{2}/{3}/{4}.html?domain={5}".format(
                self.playlist["servers"]["stream"],
                self.playlist[stream]["sig"],
                self.playlist[stream]["id"],
                seg[2],
                seg[3],
                urlparse(self.url).netloc,
            )

            _m3u8.append(
                "{0}\n".format(
                    urlparse("/gslug-{:08d}.ts".format(i))
                    ._replace(query=urlencode([("url", _seg_url)]))
                    .geturl()
                )
            )
        _m3u8.append("#EXT-X-ENDLIST\n")

        self.m3u8 = b"".join([f.encode("utf-8") for f in _m3u8])


class GslugHandler(BaseHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"

    def __init__(self, gslug, *args, **kwargs):
        self.gslug = gslug
        super(GslugHandler, self).__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def do_HEAD(self):
        if self.path.startswith(self.gslug.m3u8_path):
            self.send_response(204)
            self.send_header("Content-Type", "application/vnd.apple.mpegurl")
            self.send_header("Content-length", 0)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-length", 0)
            self.send_header("Connection", "keep-alive")
            self.end_headers()

    def do_GET(self):
        if self.path.startswith(self.gslug.m3u8_path):
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.apple.mpegurl")
            self.send_header("Content-Length", len(self.gslug.m3u8))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(self.gslug.m3u8)
        elif self.path.startswith("/key"):
            self.send_response(200)
            self.send_header("Content-Length", len(self.gslug.m3u8_key))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(self.gslug.m3u8_key)
        elif self.path.startswith("/gslug"):
            _gslug_url = ""
            for q in parse_qsl(urlparse(self.path).query):
                if "url" in q:
                    _gslug_url = q[1]
            if _gslug_url:
                _location = self.gslug.resolve_segment_url(_gslug_url)
                if _location:
                    self.send_response(301)
                    self.send_header("Location", _location)
                    self.send_header("Content-length", 0)
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
            else:
                self.send_response(404)
                self.send_header("Content-length", 0)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-length", 0)
            self.send_header("Connection", "keep-alive")
            self.end_headers()


class GslugPlayer(Player):
    def __init__(self):
        Player.__init__(self)
        self.ended = False
        self.started = False

    def onPlayBackStarted(self):
        self.started = True

    def onPlayBackError(self):
        self.ended = True

    def onPlayBackEnded(self):
        self.ended = True

    def onPlayBackStopped(self):
        self.ended = True


class GslugMonitor(Monitor):
    def __init__(self):
        Monitor.__init__(self)
        self.player = GslugPlayer()


class Server(HTTPServer):
    """HTTPServer class with timeout."""

    timeout = 5

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        try:
            self.RequestHandlerClass(request, client_address, self)
        except socket.error as err:
            if err.errno not in ACCEPTABLE_ERRNO:
                raise


class GslugServer(ThreadingMixIn, Server, object):
    def __init__(self, addr_port, handler_class):
        super(GslugServer, self).__init__(addr_port, handler_class)
        self.sessions = {}  # e.g. (addr, port) -> client socket

    def get_request(self):
        """Just call the super's method and cache the client socket"""
        client_socket, client_addr = super(GslugServer, self).get_request()
        self.sessions[client_addr] = client_socket
        return (client_socket, client_addr)

    def server_close(self):
        """Close any leftover connections."""
        super(GslugServer, self).server_close()
        for _, sock in self.sessions.items():
            try:
                sock.shutdown(socket.SHUT_WR)
            except socket.error:
                pass
            sock.close()


if __name__ == "__main__":
    gslug_url = sys.argv[1]
    gslug_referer = sys.argv[2]
    user_agent = sys.argv[3]
    quality = sys.argv[4]
    host = ("localhost", int(sys.argv[5]))

    my_gslug = Gslug(gslug_url, gslug_referer, user_agent, host)
    my_gslug.generate_stream(quality)

    handler = partial(GslugHandler, my_gslug)
    httpd = GslugServer(host, handler)

    monitor = GslugMonitor()
    while not monitor.abortRequested():
        if monitor.player.ended:
            break
        httpd.handle_request()
        if monitor.waitForAbort(0.1):
            break

    httpd.server_close()
