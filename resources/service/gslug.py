# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

import sys
import socket
import errno
import threading
import posixpath
import re
import requests
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError
from hashlib import sha256
from base64 import b64decode
from future.moves.urllib.parse import urlparse, parse_qsl, urljoin
from future.moves.http.server import BaseHTTPRequestHandler
from future.moves.socketserver import ThreadingMixIn, TCPServer
from queue import Queue, Empty
from xbmc import Monitor, Player
import warnings

warnings.simplefilter("ignore")
retries = Retry(total=5, method_whitelist=["GET", "POST"], backoff_factor=1,)
retryable_adapter = HTTPAdapter(max_retries=retries)


class SlugPlaylist(threading.Thread, object):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        super(SlugPlaylist, self).__init__(group=group, target=target, name=name)
        self.abort = kwargs.get("abort")
        """ (url, referer, user_agent, quality) """
        self.stream_info = kwargs.get("stream_info")
        """ (host, port) """
        self.host = kwargs.get("host")
        """ request session """
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": self.stream_info[2]})
        self.s.mount("https://", retryable_adapter)
        self.s.mount("http://", retryable_adapter)
        """ playlist info """
        self.path = sha256(self.stream_info[0].encode("utf-8")).hexdigest()
        self.playlist, self.key, self.segments = self.fetch_playlist()
        self.segment_urls = {}
        """ queues """
        self.notify_q = kwargs.get("notify_q")
        self.handler_q = kwargs.get("handler_q")

    def fetch_playlist(self):
        s_url, s_referer, user_agent, quality = self.stream_info
        s_origin = urlparse(s_url)._replace(path="", params="", query="", fragment="").geturl()
        s_domain = urlparse(s_url).netloc
        """ parse stream id "slug" """
        _slug = None
        _parsed = urlparse(s_url)
        if _parsed.fragment:
            for q in parse_qsl(_parsed.fragment):
                if "slug" in q:
                    _slug = q[1]
        elif _parsed.query:
            for q in parse_qsl(_parsed.query):
                if "v" in q:
                    _slug = q[1]
        if not _slug:
            raise ValueError
        """ scrape key for vip streams """
        _key = None
        r = self.s.get(s_url, headers={"Referer": s_referer}, timeout=5, verify=False)
        r.raise_for_status()
        _key_re = re.search(r"key:\s*\W([0-9a-f]+)\W", r.text, re.I)
        if _key_re:
            _key = _key_re.group(1)
        """ fetch stream infos from API """
        _api_url = "http://multi.idocdn.com/guest"
        _data = {"slug": _slug}
        if _key:
            _api_url = "http://multi.idocdn.com/vip"
            _data = {"key": _key, "type": "slug", "value": _slug}
        try:
            r = self.s.post(_api_url, headers={"Referer": s_url, "Origin": s_origin,}, data=_data, timeout=5, verify=False,)
            r.raise_for_status()
        except HTTPError:
            """ stream offline/blocked """
            print(repr(r.text))
            self.abort.set()
            return None, None, None
        s_json = r.json()
        """ compile playlist """
        s_stream = None
        s_key = None
        s_segments = []
        s_playlist = []
        if quality not in s_json:
            for q in ("fullhd", "hd", "mhd", "sd", "origin"):
                if q in s_json:
                    quality = q
                    s_stream = s_json[quality]
                    break
        else:
            s_stream = s_json[quality]
        if not s_stream:
            """ stream offline/blocked """
            print(repr(r.text))
            self.abort.set()
            return None, None, None
        s_playlist.append("#EXTM3U\n")
        s_playlist.append("#EXT-X-VERSION:4\n")
        s_playlist.append("#EXT-X-PLAYLIST-TYPE:VOD\n")
        s_playlist.append("#EXT-X-TARGETDURATION:{0}\n".format(s_stream["duration"]))
        s_playlist.append("#EXT-X-MEDIA-SEQUENCE:0\n")
        if "hash" in s_stream:
            s_key_url = "http://{0}/hash/{1}?key={2}".format(s_json["servers"][0], s_stream["sig"], s_stream["hash"],)
            s_playlist.append(
                '#EXT-X-KEY:METHOD=AES-128,URI="http://{0}:{1}/{2}/key.bin",IV={3}\n'.format(
                    self.host[0], self.host[1], self.path, s_stream["iv"]
                )
            )
            r = self.s.get(s_key_url, headers={"Referer": s_url, "Origin": s_origin,}, timeout=5, verify=False,)
            r.raise_for_status()
            s_key = r.content
        s_segment_urls = []
        for i, _id in enumerate(s_stream["ids"]):
            s_segment_urls.append(
                "http://{0}/html/{1}/{2}/{3}/{4}.html?domain={5}".format(
                    s_json["servers"][0],
                    s_stream["sig"],
                    s_stream["id"],
                    s_stream["ids"][i],
                    s_stream["ids"][(i + 1) % (len(s_stream["ids"]) - 1)],
                    s_domain,
                )
            )
        segment_index = 0
        for i, rs in enumerate(s_stream["ranges"]):
            for r in rs:
                s_playlist.append("#EXTINF:{0},\n".format(s_stream["extinfs"][segment_index]))
                s_playlist.append("#EXT-X-BYTERANGE:{0}\n".format(r))
                s_playlist.append("{0}-{1}.ts\n".format(quality, segment_index))
                s_segments.append((r, s_segment_urls[i]))
                segment_index += 1
        s_playlist.append("#EXT-X-ENDLIST\n")
        return "".join(s_playlist), s_key, s_segments

    def run(self):
        s_url, s_referer, user_agent, quality = self.stream_info
        s_origin = urlparse(s_url)._replace(path="", params="", query="", fragment="").geturl()
        while not self.abort.wait(0.1):
            try:
                hid = self.notify_q.get(block=True, timeout=1)
                sid = self.handler_q[hid][0].get(block=False)
                seg_url = self.segments[sid][1]
                if seg_url in self.segment_urls:
                    location = self.segment_urls[seg_url]
                else:
                    r = self.s.get(seg_url, headers={"Referer": s_url, "Origin": s_origin,}, timeout=5, verify=False,)
                    r.raise_for_status()
                    location = b64decode(r.json()["url"]).decode("utf-8")
                    self.segment_urls[seg_url] = location
                self.handler_q[hid][1].put(location)
            except Empty:
                pass


class GslugHandler(BaseHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_HEAD(self):
        stream_path = posixpath.join("/", self.server.slug.path)
        playlist_path = posixpath.join(stream_path, "chunks.m3u8")
        if self.server.slug.playlist:
            if self.path == playlist_path:
                self.close_connection = 0
                self.send_response(204)
                self.send_header("Content-Type", "application/vnd.apple.mpegurl")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
            else:
                self.send_error(404)
                self.end_headers()
        else:
            self.send_error(500)
            self.end_headers()

    def do_GET(self):
        handler_id = int(threading.current_thread().name)
        stream_path = posixpath.join("/", self.server.slug.path)
        playlist_path = posixpath.join(stream_path, "chunks.m3u8")
        key_path = posixpath.join(stream_path, "key.bin")
        if self.server.slug.playlist:
            if urlparse(self.path).path == playlist_path:
                self.close_connection = 0
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.apple.mpegurl")
                self.send_header("Content-Length", len(self.server.slug.playlist))
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(self.server.slug.playlist.encode("utf-8"))
            elif urlparse(self.path).path == key_path:
                self.close_connection = 0
                self.send_response(200)
                self.send_header("Content-Length", len(self.server.slug.key))
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(self.server.slug.key)
            elif self.path.startswith(stream_path):
                self.close_connection = 0
                segment_file = posixpath.split(urlparse(self.path).path)[1]
                segment_id = int(segment_file.split(".")[0].split("-")[-1])
                self.server.notify_q.put(handler_id)
                self.server.handler_q[handler_id][0].put(segment_id)
                location = self.server.handler_q[handler_id][1].get(timeout=30)
                self.send_response(301)
                self.send_header("Location", location)
                self.send_header("Content-length", 0)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
            else:
                self.send_error(404)
                self.end_headers()
        else:
            self.send_error(500)
            self.end_headers()

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except socket.timeout as e:
            self.close_connection = 1
            return
        except socket.error as e:
            if e[0] == errno.ECONNRESET:
                self.close_connection = 1
                return
            elif e[0] == errno.EPIPE:
                self.close_connection = 1
                return
            raise


class ThreadPoolMixIn(ThreadingMixIn):
    numThreads = 5
    allow_reuse_address = True

    def serve_forever(self, host, stream):
        self.abort = threading.Event()
        self.handler_q = [(Queue(), Queue()) for i in range(self.numThreads)]
        self.notify_q = Queue()

        self.slug = SlugPlaylist(
            kwargs={"stream_info": stream, "host": host, "notify_q": self.notify_q, "handler_q": self.handler_q, "abort": self.abort}
        )
        self.slug.setDaemon(1)
        self.slug.start()

        # set up the threadpool
        self.requests = Queue(self.numThreads)
        _handlers = [threading.Thread(target=self.process_request_thread, name=str(i)) for i in range(self.numThreads)]
        for t in _handlers:
            t.setDaemon(1)
            t.start()
            
        # server main loop
        while not self.abort.wait(0.1):
            self.handle_request()
        for t in _handlers:
            t.join(1)
        self.slug.abort.set()
        self.slug.join(5)
        self.server_close()

    def process_request_thread(self):
        """
        obtain request from queue instead of directly from server socket
        """
        while not self.abort.wait(0.1):
            try:
                request, client_address = self.requests.get(True, 1)
                try:
                    self.finish_request(request, client_address)
                    self.shutdown_request(request)
                except:
                    self.handle_error(request, client_address)
                    self.shutdown_request(request)
            except Empty:
                pass

    def handle_request(self):
        """
        simply collect requests and put them on the queue for the workers.
        """
        try:
            request, client_address = self.get_request()
        except socket.error:
            return
        if self.verify_request(request, client_address):
            self.requests.put((request, client_address))


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


class ThreadedServer(ThreadPoolMixIn, TCPServer):
    pass


if __name__ == "__main__":
    stream = (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    host = ("127.0.0.1", int(sys.argv[5]))

    server = ThreadedServer(host, GslugHandler)
    httpd = threading.Thread(target=server.serve_forever, args=(host, stream))
    httpd.setDaemon(1)
    httpd.start()

    monitor = GslugMonitor()
    while not monitor.abortRequested():
        if monitor.player.ended:
            break
        if monitor.waitForAbort(0.5):
            break
        if server.abort.wait(0.5):
            break
    server.abort.set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(host)
        s.close()
    except socket.error:
        pass
    httpd.join(5)
