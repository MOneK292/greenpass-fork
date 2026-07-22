class TgWsCore:
    def __init__(self):
        self.listener = None
        self.listener_thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.tracked = set()
        self.fail_until = {}
        self.fail_count = {}
        self.ws_blacklist = set()
        self.ws_blacklist_until = {}
        self.ws_domain_pref = {}
        self.cf_domain_pref = {}
        self.ws_pool = _TgWsWsPool()
        self.pool_size = int(TGWS_WS_POOL_SIZE)
        self.cfproxy_enabled = bool(TGWS_CFPROXY_ENABLED)
        self.cfproxy_priority = bool(TGWS_CFPROXY_PRIORITY)
        self.cfproxy_domains = list(TGWS_CFPROXY_DEFAULT_DOMAINS)
        self.cfproxy_worker_domain = str(TGWS_CFPROXY_WORKER_DOMAIN or "")
        self.cfproxy_refresh_thread = None
        self.cfproxy_refresh_stop = threading.Event()
        self.cf_429_until = {}
        self._heal_lock = threading.Lock()
        self.port = 0
        self.dc_ip = dict(TGWS_DEFAULT_DC_IP)

    def is_available(self):
        return JavaCipher is not None

    def _reset_cf_domain_pref(self):
        domains = list(self.cfproxy_domains or [])
        if not domains:
            self.cf_domain_pref = {}
            return
        try:
            self.cf_domain_pref = {dc: random.choice(domains) for dc in (1, 2, 3, 4, 5, 203)}
        except:
            self.cf_domain_pref = {}

    def _apply_cfproxy_domains(self, domains):
        pool = _tgws_normalize_domain_pool(domains)
        if len(pool) < int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
            return False
        try:
            if set(pool) == set(list(self.cfproxy_domains or [])):
                return False
        except:
            if pool == list(self.cfproxy_domains or []):
                return False
        self.cfproxy_domains = pool
        self._reset_cf_domain_pref()
        return True

    def _refresh_cfproxy_domains(self, stop_event=None):
        try:
            event = stop_event
            if event is not None and event.is_set():
                return False
            fetched = _tgws_fetch_cfproxy_domains()
            if event is not None and event.is_set():
                return False
            return self._apply_cfproxy_domains(fetched)
        except:
            return False

    def _cfproxy_refresh_loop(self, stop_event=None):
        event = stop_event or self.stop_event
        if not event.is_set():
            self._refresh_cfproxy_domains(event)
        try:
            while not event.wait(float(TGWS_CFPROXY_REFRESH_INTERVAL_SEC)):
                self._refresh_cfproxy_domains(event)
        except:
            pass

    def self_heal(self):
        if not self._heal_lock.acquire(blocking=False):
            return
        try:
            try:
                self.ws_blacklist.clear()
            except:
                pass
            try:
                self.ws_blacklist_until.clear()
            except:
                pass
            try:
                self.fail_until.clear()
            except:
                pass
            try:
                self.fail_count.clear()
            except:
                pass
            try:
                self.ws_domain_pref.clear()
            except:
                pass
            try:
                self.cf_429_until.clear()
            except:
                pass
            try:
                self.ws_pool.reset()
                self.ws_pool.warmup(self.dc_ip)
            except:
                pass
            try:
                self._refresh_cfproxy_domains()
            except:
                pass
        finally:
            self._heal_lock.release()

    def _track(self, closer):
        with self.lock:
            self.tracked.add(closer)

    def _untrack(self, closer):
        with self.lock:
            self.tracked.discard(closer)

    def _close_all_tracked(self):
        with self.lock:
            closers = list(self.tracked)
            self.tracked.clear()
        for closer in closers:
            try:
                closer.close()
            except:
                pass

    def _ws_fail_record(self, dc_key):
        try:
            count = int(self.fail_count.get(dc_key, 0) or 0) + 1
            self.fail_count[dc_key] = count
            backoff = float(TGWS_WS_FAIL_COOLDOWN_SEC) * (2 ** min(max(count - 1, 0), 4))
            self.fail_until[dc_key] = time.time() + min(backoff, float(TGWS_WS_FAIL_COOLDOWN_MAX_SEC))
        except:
            self.fail_until[dc_key] = time.time() + float(TGWS_WS_FAIL_COOLDOWN_SEC)

    def _ws_fail_clear(self, dc_key):
        try:
            self.fail_until.pop(dc_key, None)
            self.fail_count.pop(dc_key, None)
        except:
            pass

    def _ws_is_blacklisted(self, dc_key):
        try:
            until = float(self.ws_blacklist_until.get(dc_key, 0.0) or 0.0)
            if until and until > time.time():
                return True
            self.ws_blacklist_until.pop(dc_key, None)
            self.ws_blacklist.discard(dc_key)
        except:
            pass
        return False

    def _ws_blacklist_add(self, dc_key):
        try:
            self.ws_blacklist.add(dc_key)
            self.ws_blacklist_until[dc_key] = time.time() + float(TGWS_WS_BLACKLIST_TTL_SEC)
        except:
            pass

    def _parse_config(self, config_json):
        cfg = {
            "port": int(TGWS_LOCAL_PORT),
            "dc_ip": dict(TGWS_DEFAULT_DC_IP),
            "pool_size": int(TGWS_WS_POOL_SIZE),
            "cfproxy": bool(TGWS_CFPROXY_ENABLED),
            "cfproxy_priority": bool(TGWS_CFPROXY_PRIORITY),
            "cfproxy_domains": list(TGWS_CFPROXY_DEFAULT_DOMAINS),
            "cfproxy_worker_domain": str(TGWS_CFPROXY_WORKER_DOMAIN or ""),
        }
        raw = str(config_json or "").strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                if parsed.get("port"):
                    cfg["port"] = int(parsed.get("port") or TGWS_LOCAL_PORT)
                if "pool_size" in parsed:
                    try:
                        cfg["pool_size"] = max(0, int(parsed.get("pool_size") or 0))
                    except:
                        pass
                if "cfproxy" in parsed:
                    cfg["cfproxy"] = bool(parsed.get("cfproxy"))
                if "cfproxy_priority" in parsed:
                    cfg["cfproxy_priority"] = bool(parsed.get("cfproxy_priority"))
                if "cfproxy_worker_domain" in parsed:
                    cfg["cfproxy_worker_domain"] = str(parsed.get("cfproxy_worker_domain") or "")
                cf_domains = parsed.get("cfproxy_domains")
                if isinstance(cf_domains, list):
                    clean = _tgws_normalize_domain_pool(cf_domains)
                    if len(clean) >= int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
                        cfg["cfproxy_domains"] = clean
                dc_ip = parsed.get("dc_ip")
                if isinstance(dc_ip, dict):
                    cfg["dc_ip"] = _tgws_normalize_dc_ip_map(dc_ip, with_defaults=True)
        if cfg["port"] <= 0 or cfg["port"] > 65535:
            cfg["port"] = int(TGWS_LOCAL_PORT)
        return cfg

    def start(self, config_json):
        if not self.is_available():
            return "Java crypto недоступно"
        try:
            cfg = self._parse_config(config_json)
            self.stop()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _tgws_set_socket_options(listener)
            listener.bind((VLESS_LOCAL_HOST, int(cfg["port"])))
            listener.listen(32)
            listener.settimeout(1.0)
            self.listener = listener
            self.port = int(cfg["port"])
            self.dc_ip = _tgws_normalize_dc_ip_map(cfg.get("dc_ip") or {}, with_defaults=False)
            self.pool_size = max(0, int(cfg.get("pool_size", TGWS_WS_POOL_SIZE) or 0))
            self.cfproxy_enabled = bool(cfg.get("cfproxy", TGWS_CFPROXY_ENABLED))
            self.cfproxy_priority = bool(cfg.get("cfproxy_priority", TGWS_CFPROXY_PRIORITY))
            cf_domains = _tgws_normalize_domain_pool(cfg.get("cfproxy_domains") or TGWS_CFPROXY_DEFAULT_DOMAINS)
            if len(cf_domains) < int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
                cf_domains = list(TGWS_CFPROXY_DEFAULT_DOMAINS)
            self.cfproxy_domains = list(cf_domains)
            self.cfproxy_worker_domain = str(cfg.get("cfproxy_worker_domain", "") or "")
            self._reset_cf_domain_pref()
            self.ws_pool.reset()
            self.ws_pool.size = int(self.pool_size)
            self.ws_blacklist.clear()
            self.ws_blacklist_until.clear()
            self.fail_until.clear()
            self.fail_count.clear()
            self.ws_domain_pref.clear()
            self.cf_429_until.clear()
            self.stop_event.clear()
            self.cfproxy_refresh_stop = threading.Event()
            self.listener_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.listener_thread.start()
            self.ws_pool.warmup(self.dc_ip)
            refresh_stop = self.cfproxy_refresh_stop
            self.cfproxy_refresh_thread = threading.Thread(target=self._cfproxy_refresh_loop, args=(refresh_stop,), daemon=True)
            self.cfproxy_refresh_thread.start()
            return ""
        except Exception as exc:
            try:
                if self.listener is not None:
                    self.listener.close()
            except:
                pass
            self.listener = None
            return str(exc)

    def stop(self):
        self.stop_event.set()
        try:
            self.cfproxy_refresh_stop.set()
        except:
            pass
        try:
            if self.listener is not None:
                self.listener.close()
        except:
            pass
        self.listener = None
        try:
            self.ws_pool.reset()
        except:
            pass
        try:
            self.cf_429_until.clear()
        except:
            pass
        self._close_all_tracked()
        thread = self.listener_thread
        self.listener_thread = None
        if thread is not None and thread.is_alive():
            try:
                thread.join(1.5)
            except:
                pass
        refresh = self.cfproxy_refresh_thread
        self.cfproxy_refresh_thread = None
        if refresh is not None and refresh.is_alive():
            try:
                refresh.join(1.0)
            except:
                pass

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except:
                if self.stop_event.is_set():
                    break
                continue
            try:
                _tgws_set_socket_options(conn)
            except:
                pass
            self._track(conn)
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _close_write(self, conn):
        try:
            conn.shutdown(socket.SHUT_WR)
        except:
            pass

    def _bridge_tcp(self, left, right, streams=None):
        done = threading.Event()
        clt_dec = clt_enc = tg_enc = tg_dec = None
        if streams:
            try:
                clt_dec, clt_enc, tg_enc, tg_dec = streams
            except:
                clt_dec = clt_enc = tg_enc = tg_dec = None
        for conn in (left, right):
            try:
                conn.settimeout(None)
            except:
                pass

        def _forward(src, dst, transform=None):
            try:
                while not done.is_set():
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    if transform is not None:
                        chunk = transform(chunk)
                    dst.sendall(chunk)
            except:
                pass
            done.set()
            self._close_write(dst)

        up = (lambda chunk: tg_enc.xor(clt_dec.xor(chunk))) if clt_dec is not None and tg_enc is not None else None
        down = (lambda chunk: clt_enc.xor(tg_dec.xor(chunk))) if clt_enc is not None and tg_dec is not None else None
        t1 = threading.Thread(target=_forward, args=(left, right, up), daemon=True)
        t2 = threading.Thread(target=_forward, args=(right, left, down), daemon=True)
        t1.start()
        t2.start()
        while not done.is_set() and (t1.is_alive() or t2.is_alive()):
            time.sleep(0.1)
        done.set()
        for item in (left, right):
            try:
                item.close()
            except:
                pass
            self._untrack(item)

    def _bridge_ws_split(self, client, ws, splitter, streams=None):
        done = threading.Event()
        downstream_seen = threading.Event()
        clt_dec = clt_enc = tg_enc = tg_dec = None
        if streams:
            try:
                clt_dec, clt_enc, tg_enc, tg_dec = streams
            except:
                clt_dec = clt_enc = tg_enc = tg_dec = None
        try:
            client.settimeout(None)
        except:
            pass

        def _keepalive():
            interval = float(TGWS_WS_PING_INTERVAL_SEC)
            if interval <= 0:
                return
            interval = max(1.0, interval)
            while not done.wait(interval):
                try:
                    ws.ping()
                except:
                    done.set()
                    try:
                        ws.close()
                    except:
                        pass
                    try:
                        client.close()
                    except:
                        pass
                    break

        def _client_to_ws():
            try:
                while not done.is_set():
                    chunk = client.recv(65536)
                    if not chunk:
                        if splitter is not None:
                            try:
                                for tail in splitter.flush():
                                    ws.send(tail)
                            except:
                                pass
                        break
                    if clt_dec is not None and tg_enc is not None:
                        chunk = tg_enc.xor(clt_dec.xor(chunk))
                    if splitter is not None:
                        parts = splitter.split(chunk)
                        if not parts:
                            continue
                        if len(parts) > 1:
                            try:
                                ws.send_batch(parts)
                            except Exception:
                                for payload in parts:
                                    ws.send(payload)
                        else:
                            ws.send(parts[0])
                    else:
                        ws.send(chunk)
            except:
                pass
            done.set()

        def _ws_to_client():
            try:
                while not done.is_set():
                    payload = ws.recv()
                    if payload is None:
                        break
                    downstream_seen.set()
                    if tg_dec is not None and clt_enc is not None:
                        payload = clt_enc.xor(tg_dec.xor(payload))
                    client.sendall(payload)
            except:
                pass
            done.set()

        t1 = threading.Thread(target=_client_to_ws, daemon=True)
        t2 = threading.Thread(target=_ws_to_client, daemon=True)
        t3 = threading.Thread(target=_keepalive, daemon=True)
        t1.start()
        t2.start()
        t3.start()
        while not done.is_set() and (t1.is_alive() or t2.is_alive()):
            time.sleep(0.1)
        done.set()
        try:
            ws.close()
        except:
            pass
        self._untrack(ws)
        try:
            client.close()
        except:
            pass
        self._untrack(client)
        return downstream_seen.is_set()

    def _direct_passthrough(self, client, dst, port):
        remote = socket.create_connection((str(dst), int(port)), 10.0)
        _tgws_set_socket_options(remote)
        try:
            client.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
            remote.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
        except:
            pass
        self._track(remote)
        client.sendall(_tgws_socks_reply(0x00))
        self._bridge_tcp(client, remote)

    def _tcp_fallback(self, client, dst, port, init_packet, streams=None):
        remote = socket.create_connection((str(dst), int(port)), 10.0)
        _tgws_set_socket_options(remote)
        try:
            client.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
            remote.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
        except:
            pass
        self._track(remote)
        if init_packet:
            remote.sendall(bytes(init_packet))
        self._bridge_tcp(client, remote, streams=streams)

    def _cfproxy_worker_fallback(self, client, dc, is_media, init_packet, proto_int, streams=None):
        worker_domain = str(self.cfproxy_worker_domain or "").strip()
        if not worker_domain:
            return False
        try:
            fallback_dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or "").strip()
        except:
            fallback_dst = ""
        if not fallback_dst:
            return False
        try:
            query = urllib.parse.urlencode({
                "dst": fallback_dst,
                "dc": str(int(dc)),
                "media": "1" if bool(is_media) else "0",
            })
        except:
            return False
        path = "/apiws?" + query
        ws = None
        try:
            ws = _TgWsRawWebSocket.connect(worker_domain, worker_domain, timeout=TGWS_CFPROXY_CONNECT_TIMEOUT_SEC, path=path)
            self._track(ws)
            ws.send(init_packet)
            splitter = None
            try:
                splitter = _TgWsMsgSplitter(init_packet, proto_int)
            except:
                splitter = None
            self._bridge_ws_split(client, ws, splitter, streams=streams)
            return True
        except:
            try:
                if ws is not None:
                    ws.close()
            except:
                pass
            return False

    def _cfproxy_fallback(self, client, dc, is_media, init_packet, proto_int, streams=None):
        domains = list(self.cfproxy_domains or [])
        try:
            preferred = str(self.cf_domain_pref.get(int(dc)) or "").strip()
        except:
            preferred = ""
        if preferred:
            rest = [domain for domain in domains if domain != preferred]
            try:
                random.shuffle(rest)
            except:
                pass
            domains = [preferred] + rest
        else:
            try:
                random.shuffle(domains)
            except:
                pass
        for base_domain in domains:
            base = str(base_domain or "").strip()
            if not base:
                continue
            try:
                if float(self.cf_429_until.get(base, 0.0) or 0.0) > time.time():
                    continue
            except:
                pass
            domain = "kws%s.%s" % (int(dc), base)
            ws = None
            try:
                ws = _TgWsRawWebSocket.connect(domain, domain, timeout=TGWS_CFPROXY_CONNECT_TIMEOUT_SEC)
                try:
                    self.cf_429_until.pop(base, None)
                except:
                    pass
                self.cf_domain_pref[int(dc)] = base
                self._track(ws)
                ws.send(init_packet)
                splitter = None
                try:
                    splitter = _TgWsMsgSplitter(init_packet, proto_int)
                except:
                    splitter = None
                healthy = self._bridge_ws_split(client, ws, splitter, streams=streams)
                if not healthy:
                    self.cf_domain_pref.pop(int(dc), None)
                return True
            except Exception as exc:
                try:
                    if int(getattr(exc, "status_code", 0) or 0) == 429:
                        self.cf_429_until[base] = time.time() + float(TGWS_CFPROXY_429_COOLDOWN_SEC)
                except:
                    pass
                try:
                    if ws is not None:
                        ws.close()
                except:
                    pass
                continue
        return False

    def _fallback(self, client, dst, port, init_packet, dc=None, is_media=False, proto_int=None, allow_cf=True, streams=None):
        methods = ["tcp"]
        if bool(allow_cf) and bool(self.cfproxy_enabled) and dc is not None:
            methods.insert(0 if bool(self.cfproxy_priority) else 1, "cf")
        if dc is not None and str(self.cfproxy_worker_domain or "").strip():
            methods.insert(0, "cf_worker")
        for method in methods:
            try:
                if method == "cf_worker":
                    if self._cfproxy_worker_fallback(client, int(dc), bool(is_media), init_packet, proto_int, streams=streams):
                        return True
                elif method == "cf":
                    if self._cfproxy_fallback(client, int(dc), bool(is_media), init_packet, proto_int, streams=streams):
                        return True
                else:
                    fallback_dst = str(dst or "")
                    try:
                        if dc is not None:
                            fallback_dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or fallback_dst)
                    except:
                        pass
                    self._tcp_fallback(client, fallback_dst, port, init_packet, streams=streams)
                    return True
            except:
                continue
        return False

    def _handle_client(self, conn):
        try:
            conn.settimeout(10.0)
            header = _tgws_recv_exact(conn, 2)
            streams = None
            if header[0] == 0x05:
                _tgws_recv_exact(conn, header[1])
                conn.sendall(b"\x05\x00")
                req = _tgws_recv_exact(conn, 4)
                if req[1] != 0x01:
                    conn.sendall(_tgws_socks_reply(0x07))
                    return
                atyp = int(req[3])
                dst, port = _tgws_read_socks_address(conn, atyp)

                dst_ip = str(dst)
                if atyp == 0x03:
                    try:
                        resolved = _tgws_resolve_ipv4(dst)
                        if resolved:
                            dst_ip = resolved
                    except Exception:
                        pass

                if not _tgws_is_telegram_ip(dst_ip):
                    try:
                        self._direct_passthrough(conn, dst, port)
                    except:
                        try:
                            conn.sendall(_tgws_socks_reply(0x05))
                        except:
                            pass
                    return
                conn.sendall(_tgws_socks_reply(0x00))
                conn.settimeout(15.0)
                init_packet = _tgws_recv_exact(conn, 64)
                conn.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
                if _tgws_is_http_transport(init_packet):
                    return
                dc, is_media, proto_int = _tgws_init_info(init_packet)
                dst_entry = _tgws_dc_from_dst_ip(dst_ip)

                if dst_entry is not None:
                    try:
                        dc = int(dst_entry[0])
                        is_media = bool(dst_entry[1])
                        target_ip0 = _tgws_dc_target(self.dc_ip, dc, is_media)
                        if target_ip0:
                            init_packet = _tgws_patch_init_dc(init_packet, -dc if is_media else dc)
                    except Exception:
                        pass

                if dc is None:
                    try:
                        if _tgws_is_telegram_ip(dst_ip) and ":" in str(dst_ip):
                            default_dc = _tgws_default_dc(self.dc_ip)
                            if default_dc is not None:
                                dc = int(default_dc)
                                is_media = False
                    except Exception:
                        pass
            else:
                init_in = bytes(header) + _tgws_recv_exact(conn, 62)
                conn.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
                if _tgws_is_http_transport(init_in):
                    return
                session = _tgws_raw_proxy_session(init_in)
                if not session:
                    return
                dc, is_media, proto_int, init_packet, streams = session
                port = 443
                dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or "")
                dst_ip = str(_tgws_dc_target(self.dc_ip, dc, is_media) or dst)

            if dc is None:
                self._fallback(conn, dst, port, init_packet, None, False, proto_int, streams=streams)
                return
            target_ip = _tgws_dc_target(self.dc_ip, dc, is_media)
            dc_key = (int(dc), bool(is_media))
            priority_cf_tried = False
            if bool(self.cfproxy_enabled) and bool(self.cfproxy_priority):
                priority_cf_tried = True
                if self._cfproxy_fallback(conn, dc, is_media, init_packet, proto_int, streams=streams):
                    return
            if not target_ip:
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            try:
                if self._ws_is_blacklisted(dc_key):
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
            except Exception:
                pass
            fail_until = float(self.fail_until.get(dc_key, 0.0) or 0.0)
            if fail_until > time.time():
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            ws = None
            ws_failed_redirect = False
            all_redirects = True
            domains = _tgws_ws_domains(dc, is_media)
            try:
                preferred = str(self.ws_domain_pref.get(dc_key) or "").strip()
            except Exception:
                preferred = ""
            if preferred:
                domains = [preferred] + [domain for domain in domains if domain != preferred]

            try:
                ws = self.ws_pool.get(dc, is_media, target_ip, domains)
                if ws is not None:
                    all_redirects = False
            except:
                ws = None

            if ws is None:
                for domain in domains:
                    for candidate_ip in _tgws_unique_values(target_ip, dst_ip):
                        try:
                            ws = _TgWsRawWebSocket.connect(candidate_ip, domain, timeout=TGWS_WS_CONNECT_TIMEOUT_SEC)
                            self.ws_domain_pref[dc_key] = str(domain)
                            all_redirects = False
                            break
                        except Exception as exc:
                            if _tgws_is_redirect_error(exc):
                                ws_failed_redirect = True
                                continue
                            all_redirects = False
                            ws = None
                    if ws is not None:
                        break
            if ws is None:
                try:
                    if ws_failed_redirect and all_redirects:
                        self._ws_blacklist_add(dc_key)
                except Exception:
                    pass
                self._ws_fail_record(dc_key)
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            self._ws_fail_clear(dc_key)
            self._track(ws)
            try:
                ws.send(init_packet)
            except:
                try:
                    ws.close()
                except:
                    pass
                self._untrack(ws)
                ws = None
                for domain in domains:
                    for candidate_ip in _tgws_unique_values(target_ip, dst_ip):
                        try:
                            ws = _TgWsRawWebSocket.connect(candidate_ip, domain, timeout=TGWS_WS_CONNECT_TIMEOUT_SEC)
                            self.ws_domain_pref[dc_key] = str(domain)
                            break
                        except Exception:
                            ws = None
                    if ws is not None:
                        break
                if ws is None:
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
                self._track(ws)
                try:
                    ws.send(init_packet)
                except:
                    try:
                        ws.close()
                    except:
                        pass
                    self._untrack(ws)
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
            splitter = None
            try:
                splitter = _TgWsMsgSplitter(init_packet, proto_int)
            except Exception:
                splitter = None
            healthy = self._bridge_ws_split(conn, ws, splitter, streams=streams)
            if not healthy:
                self._ws_fail_record(dc_key)
                self.ws_domain_pref.pop(dc_key, None)
            return
        except:
            pass
        finally:
            try:
                conn.close()
            except:
                pass
            self._untrack(conn)


class _NativeLinker:
    def __init__(self):
        self.libdl = None
        self.open_ext = None
        self.Info = None
        try:
            self.libdl = ctypes.CDLL("libdl.so")
            self.open_ext = self.libdl.android_dlopen_ext

            class Info(ctypes.Structure):
                _fields_ = [
                    ("flags", ctypes.c_uint64),
                    ("reserved_addr", ctypes.c_void_p),
                    ("reserved_size", ctypes.c_size_t),
                    ("relro_fd", ctypes.c_int),
                    ("library_fd", ctypes.c_int),
                    ("library_fd_offset", ctypes.c_uint64),
                    ("library_namespace", ctypes.c_void_p),
                ]

            self.Info = Info
            self.open_ext.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(self.Info)]
            self.open_ext.restype = ctypes.c_void_p
        except:
            self.open_ext = None

    def load(self, path):
        try:
            p = str(path or "")
        except:
            p = ""
        if not p or not os.path.exists(p):
            return None

        try:
            from android.os import Build
            if int(Build.VERSION.SDK_INT) >= 29 and self.open_ext and self.Info:
                fd = os.open(p, os.O_RDONLY)
                try:
                    info = self.Info(flags=0x10, library_fd=fd)
                    handle = self.open_ext(p.encode("utf-8"), 2 | 0x100, ctypes.byref(info))
                    if handle:
                        return ctypes.CDLL(p, handle=handle)
                finally:
                    try:
                        os.close(fd)
                    except:
                        pass
        except:
            pass

        try:
            return ctypes.CDLL(p, mode=2 | 0x100)
        except:
            return None


class VlessCore:
    def __init__(self, so_path):
        self.lib = None
        self.libc = None
        self.free_c_string = None
        self.mode = None
        self._native_lock = threading.RLock()
        self._so_path = str(so_path or "")
        self._init_native()

    def _init_native(self):
        try:
            if not self._so_path or (not os.path.exists(self._so_path)) or os.path.getsize(self._so_path) < 1024:
                return
            linker = _NativeLinker()
            lib = linker.load(self._so_path)
            if not lib:
                return
            lib.StartCore.argtypes = [ctypes.c_char_p]
            lib.StartCore.restype = ctypes.c_void_p
            lib.StopCore.argtypes = []
            lib.StopCore.restype = None
            try:
                lib.FreeCString.argtypes = [ctypes.c_void_p]
                lib.FreeCString.restype = None
                self.free_c_string = lib.FreeCString
            except:
                self.free_c_string = None
            try:
                lib.LastLog.argtypes = []
                lib.LastLog.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.LastError.argtypes = []
                lib.LastError.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.GetStatusJSON.argtypes = []
                lib.GetStatusJSON.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.GetLogsJSON.argtypes = []
                lib.GetLogsJSON.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.Version.argtypes = []
                lib.Version.restype = ctypes.c_void_p
                self.mode = "singbox"
            except Exception as _e:
                pass
            try:
                lib.IsRunning.argtypes = []
                lib.IsRunning.restype = ctypes.c_int
            except:
                pass
            try:
                lib.CurrentEngine.argtypes = []
                lib.CurrentEngine.restype = ctypes.c_void_p
            except:
                pass
            try:
                lib.ValidateConfig.argtypes = [ctypes.c_char_p]
                lib.ValidateConfig.restype = ctypes.c_void_p
            except:
                pass
            self.lib = lib
            if not self.mode:
                self.mode = "standalone"
            try:
                self.libc = ctypes.CDLL("libc.so")
                self.libc.free.argtypes = [ctypes.c_void_p]
                self.libc.free.restype = None
            except:
                self.libc = None
        except Exception as _e:
            self.lib = None

    def _free_result_ptr(self, result_ptr):
        if not result_ptr:
            return
        try:
            if self.free_c_string:
                self.free_c_string(result_ptr)
                return
        except:
            pass
        try:
            if self.libc:
                self.libc.free(result_ptr)
        except:
            pass

    def is_available(self):
        return self.lib is not None

    def start(self, config_json):
        if not self.is_available():
            return "Native library not loaded"
        try:
            config_text = str(config_json or "")
            is_qwdtt = False
            try:
                is_qwdtt = str(json.loads(config_text).get("engine", "") or "").strip().lower() == QWDTT_KIND
            except:
                is_qwdtt = False
            if is_qwdtt:
                result_ptr = self.lib.StartCore(config_text.encode("utf-8"))
            else:
                with self._native_lock:
                    result_ptr = self.lib.StartCore(config_text.encode("utf-8"))
            if not result_ptr:
                return ""
            try:
                raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                out = raw.decode("utf-8", errors="ignore") if raw else ""
            except:
                out = ""
            self._free_result_ptr(result_ptr)
            return out
        except Exception as e:
            return str(e)

    def _read_c_string_func(self, name):
        if not self.is_available():
            return ""
        try:
            fn = getattr(self.lib, str(name or ""))
        except:
            return ""
        try:
            with self._native_lock:
                result_ptr = fn()
                if not result_ptr:
                    return ""
                try:
                    raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                    out = raw.decode("utf-8", errors="ignore") if raw else ""
                except:
                    out = ""
                self._free_result_ptr(result_ptr)
                return out
        except:
            return ""

    def last_log(self):
        return self._read_c_string_func("LastLog")

    def last_error(self):
        return self._read_c_string_func("LastError")

    def status_json(self):
        return self._read_c_string_func("GetStatusJSON")

    def logs_json(self):
        return self._read_c_string_func("GetLogsJSON")

    def current_engine(self):
        return self._read_c_string_func("CurrentEngine").strip().lower()

    def validate(self, config_json):
        if not self.is_available():
            return None
        try:
            fn = self.lib.ValidateConfig
        except:
            return None
        try:
            with self._native_lock:
                result_ptr = fn(str(config_json or "").encode("utf-8"))
                if not result_ptr:
                    return ""
                try:
                    raw = ctypes.cast(result_ptr, ctypes.c_char_p).value
                    out = raw.decode("utf-8", errors="ignore") if raw else ""
                except:
                    out = ""
                self._free_result_ptr(result_ptr)
                return out
        except Exception as exc:
            return str(exc)

    def is_running(self):
        if not self.is_available():
            return False
        try:
            return bool(int(self.lib.IsRunning()))
        except:
            return False

    def stop(self):
        if not self.is_available():
            return
        try:
            with self._native_lock:
                self.lib.StopCore()
        except Exception as _e:
            pass


class AWGUAPIParser:
    @staticmethod
    def parse(conf_text):
        uapi = []
        local_ip = "10.0.0.2"
        dns_ip = "8.8.8.8"
        section = None

        for raw in str(conf_text or "").splitlines():
            line = str(raw or "").strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if "=" not in line:
                continue

            key, val = (x.strip() for x in line.split("=", 1))
            k = key.lower()

            if section == "interface":
                if k == "privatekey":
                    try:
                        uapi.append("private_key=%s" % base64.b64decode(val).hex())
                    except:
                        pass
                elif k == "address":
                    local_ip = val.split("/")[0].strip()
                elif k == "dns":
                    dns_ip = val.split(",")[0].strip()
                elif k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
                    uapi.append("%s=%s" % (k, val))
                elif k == "listenport":
                    uapi.append("listen_port=%s" % val)

            elif section == "peer":
                if k == "publickey":
                    try:
                        uapi.append("public_key=%s" % base64.b64decode(val).hex())
                    except:
                        pass
                elif k == "endpoint":
                    uapi.append("endpoint=%s" % val)
                elif k == "allowedips":
                    for ip in val.split(","):
                        item = ip.strip()
                        if item:
                            uapi.append("allowed_ip=%s" % item)
                elif k == "presharedkey":
                    try:
                        uapi.append("preshared_key=%s" % base64.b64decode(val).hex())
                    except:
                        pass
                elif k == "persistentkeepalive":
                    uapi.append("persistent_keepalive_interval=%s" % val)

        return "\n".join(uapi) + "\n", local_ip, dns_ip


_GP_GO_CORE_BLOCKED = False
_GP_GO_CORE_LOCK = threading.Lock()


def _gp_claim_go_core(kind):
    """All modes share libgreenpass.so and its single Go runtime."""
    global _GP_GO_CORE_BLOCKED
    with _GP_GO_CORE_LOCK:
        if _GP_GO_CORE_BLOCKED:
            return False
        return True


class _LazySingboxCore:
    """Lazy view of the shared GreenPass core used by sing-box modes."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("vless"):
                return None
            self._real = VlessCore(self._so_path)
            if not self._real.is_available():
                self._real = None
        return self._real

    def is_available(self) -> bool:
        if self._real is not None:
            return self._real.is_available()
        return False

    def start(self, config_json):
        core = self._ensure()
        if core is None:
            return "Ядро GreenPass не загружено"
        return core.start(config_json)

    def stop(self):
        if self._real is not None:
            self._real.stop()

    def logs_json(self):
        core = self._ensure()
        return core.logs_json() if core is not None else ""

    def last_log(self):
        core = self._ensure()
        return core.last_log() if core is not None else ""

    def last_error(self):
        core = self._ensure()
        return core.last_error() if core is not None else ""

    def status_json(self):
        core = self._ensure()
        return core.status_json() if core is not None else ""

    def current_engine(self):
        core = self._ensure()
        return core.current_engine() if core is not None else ""

    def validate(self, config_json):
        core = self._ensure()
        return core.validate(config_json) if core is not None else None

    def is_running(self):
        core = self._ensure()
        return core.is_running() if core is not None else False

    @property
    def lib(self):
        core = self._ensure()
        return core.lib if core is not None else None

    @property
    def mode(self):
        if self._real is not None:
            return self._real.mode
        return None


class _LazyAWGCore:
    """Lazy AWG view of the shared GreenPass core."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None
        self.is_downloading = False
        self.started = False

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("awg"):
                return None
            self._real = AWGCore(self._so_path)
            if not self._real.is_available():
                self._real = None
        return self._real

    def init_native(self, on_success=None, on_error=None):
        core = self._ensure()
        if core is None:
            if on_error:
                on_error("Ядро GreenPass не загружено")
            return
        return core.init_native(on_success=on_success, on_error=on_error)

    def is_available(self) -> bool:
        if self._real is not None:
            return self._real.is_available()
        return False

    def start(self, conf_text: str) -> str:
        core = self._ensure()
        if core is None:
            self.started = False
            return "Ядро GreenPass не загружено"
        err = core.start(conf_text)
        self.started = bool(getattr(core, "started", False))
        return err

    def stop(self):
        if self._real is not None:
            self._real.stop()
            self.started = bool(getattr(self._real, "started", False))
        else:
            self.started = False


class _LazyVlessCore:
    """Lazy olcRTC view of the shared GreenPass core."""
    def __init__(self, so_path):
        self._so_path = str(so_path or "")
        self._real = None

    def _ensure(self):
        if self._real is None:
            if not _gp_claim_go_core("olcrtc"):
                return None
            self._real = VlessCore(self._so_path)
            if not self._real.is_available():
                self._real = None
        return self._real
    def start(self, config_json):
        core = self._ensure()
        if core is None:
            return "Ядро GreenPass не загружено"
        return core.start(config_json)

    def is_available(self) -> bool:
        return self._real is not None and self._real.is_available()
    def stop(self):
        if self._real is not None:
            self._real.stop()
    def status_json(self):
        core = self._ensure()
        return core.status_json() if core is not None else ""

    @property
    def lib(self):
        core = self._ensure()
        return core.lib if core is not None else None

    @property
    def mode(self):
        if self._real is not None:
            return self._real.mode
        return None

class AWGCore:
    def __init__(self, so_path):
        self.lib = None
        self.is_downloading = False
        self.started = False
        self._so_path = str(so_path or "")
        self._init_native()

    def _init_native(self):
        self._core = VlessCore(self._so_path)
        self.lib = self._core.lib

    def init_native(self, on_success=None, on_error=None):
        if self.is_available():
            if on_success: on_success()
            return
        if on_error:
            on_error("Ядро AWG не загружено")

    def is_available(self) -> bool:
        return self.lib is not None

    def start(self, conf_text: str) -> str:
        if not self.is_available(): return "Нативная библиотека еще не загружена"
        try:
            config = json.loads(_build_singbox_awg_config(conf_text, PROXY_PORT))
            experimental = config.get("experimental")
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            cache_file = experimental.get("cache_file")
            cache_file = dict(cache_file) if isinstance(cache_file, dict) else {}
            cache_file["path"] = os.path.join(os.path.dirname(self._so_path), "singbox-cache.db")
            experimental["cache_file"] = cache_file
            config["experimental"] = experimental
            config_json = json.dumps(config)
            err = self._core.start(config_json)
            if not err:
                self.started = True
            return err
        except Exception as e:
            return str(e)

    def stop(self):
        if self.is_available():
            if not bool(self.started):
                return
            try:
                self.started = False
                self._core.stop()
            except Exception:
                pass


def _check_vless_port(port, timeout=0.2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            return sock.connect_ex((VLESS_LOCAL_HOST, int(port))) == 0
    except:
        return False


def _wait_vless_port_closed(port, timeout_sec=1.5, poll_sec=0.1):
    try:
        target_port = int(port)
    except:
        return False

    deadline = time.time() + float(timeout_sec)
    while time.time() < deadline:
        if not _check_vless_port(target_port):
            return True
        time.sleep(float(poll_sec))
    return not _check_vless_port(target_port)


def _recv_socks_bytes(sock, size):
    data = b""
    while len(data) < int(size):
        chunk = sock.recv(int(size) - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def _check_vless_socks_auth(sock, username="", password=""):
    user = str(username or "")
    secret = str(password or "")
    method = b"\x02" if user and secret else b"\x00"
    sock.sendall(b"\x05\x01" + method)
    if _recv_socks_bytes(sock, 2) != b"\x05" + method:
        return False
    if method == b"\x02":
        user_bytes = user.encode("utf-8")[:255]
        pass_bytes = secret.encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
        auth = _recv_socks_bytes(sock, 2)
        if len(auth) != 2 or auth[1] != 0:
            return False
    return True


def _check_vless_socks_ready(port, timeout=0.5, username="", password=""):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            sock.connect((VLESS_LOCAL_HOST, int(port)))
            return _check_vless_socks_auth(sock, username, password)
    except:
        return False


def _check_vless_socks_connect(port, host, target_port, timeout=1.5, username="", password="", probe=b""):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            sock.connect((VLESS_LOCAL_HOST, int(port)))
            if not _check_vless_socks_auth(sock, username, password):
                return False

            try:
                host_bytes = socket.inet_aton(str(host or ""))
                req = b"\x05\x01\x00\x01" + host_bytes + int(target_port).to_bytes(2, "big")
            except:
                host_raw = str(host or "").encode("idna", errors="ignore")
                if not host_raw:
                    return False
                req = b"\x05\x01\x00\x03" + bytes([len(host_raw)]) + host_raw + int(target_port).to_bytes(2, "big")

            sock.sendall(req)
            head = _recv_socks_bytes(sock, 4)
            if len(head) < 4 or head[1] != 0x00:
                return False
            atyp = head[3]
            if atyp == 0x01:
                need = 4 + 2
            elif atyp == 0x03:
                size = _recv_socks_bytes(sock, 1)
                if len(size) != 1:
                    return False
                need = int(size[0]) + 2
            elif atyp == 0x04:
                need = 16 + 2
            else:
                return False
            remaining = b""
            while len(remaining) < need:
                chunk = _recv_socks_bytes(sock, need - len(remaining))
                if not chunk:
                    return False
                remaining += chunk
            if probe:
                sock.sendall(bytes(probe))
                return bool(sock.recv(1))
            return True
    except:
        return False


def _check_vless_tunnel_ready(port, timeout=1.5, username="", password=""):
    probe = b"HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"
    for host, target_port in list(VLESS_EGRESS_TEST_TARGETS or []):
        if _check_vless_socks_connect(port, host, target_port, timeout=timeout, username=username, password=password, probe=probe):
            return True
    return False


def _check_olcrtc_tunnel_ready(port, timeout=OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC):
    for host, target_port in list(OLCRTC_TEST_TARGETS or []):
        if _check_vless_socks_connect(port, host, target_port, timeout=timeout):
            return True
    return False


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _pick_tgws_port(preferred=None, excluded=None):
    used = set(int(x) for x in list(TGWS_RESERVED_PORTS or []))
    try:
        preferred_port = int(preferred or 0)
    except:
        preferred_port = 0
    if excluded:
        try:
            for value in excluded:
                try:
                    used.add(int(value))
                except:
                    pass
        except:
            pass
    if preferred_port > 0 and preferred_port not in used and _wait_vless_port_closed(preferred_port, timeout_sec=0.05, poll_sec=0.05):
        return preferred_port
    for _ in range(32):
        candidate = _get_free_port()
        if candidate in used:
            continue
        if _wait_vless_port_closed(candidate, timeout_sec=0.05, poll_sec=0.05):
            return int(candidate)
    return 0


_SUBSCRIPTION_HWID = ""


def _get_or_create_subscription_hwid():
    global _SUBSCRIPTION_HWID
    try:
        prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
        custom = str(prefs.getString("subscription_hwid_custom", "") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{16}", custom):
            return custom
        if _SUBSCRIPTION_HWID:
            return _SUBSCRIPTION_HWID
        value = str(prefs.getString("subscription_hwid", "") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            value = os.urandom(8).hex()
            prefs.edit().putString("subscription_hwid", value).commit()
        _SUBSCRIPTION_HWID = value
    except:
        _SUBSCRIPTION_HWID = os.urandom(8).hex()
    return _SUBSCRIPTION_HWID


def _set_subscription_hwid_custom(value):
    global _SUBSCRIPTION_HWID
    custom = str(value or "").strip().lower()
    if custom and not re.fullmatch(r"[0-9a-f]{16}", custom):
        return False
    try:
        prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
        prefs.edit().putString("subscription_hwid_custom", custom).commit()
        _SUBSCRIPTION_HWID = ""
        return True
    except:
        return False


def _vless_retry_delay(failures):
    try:
        count = max(1, int(failures))
    except:
        count = 1
    return min(float(VLESS_RETRY_MAX_SEC), float(VLESS_RETRY_BASE_SEC) * (2 ** min(count - 1, 4)))


def _subscription_request_headers(url):
    try:
        host = str(urllib.parse.urlparse(str(url or "")).netloc or "").strip()
    except:
        host = ""
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "close",
        "User-agent": "Happ/3.13.0",
        "X-Device-Locale": "en",
        "X-Device-model": "Pixel 9",
        "X-Device-OS": "Android",
        "X-HWID": _get_or_create_subscription_hwid(),
        "X-Ver-OS": "16",
    }
    if host:
        headers["Host"] = host
    return headers


def _subscription_candidate_urls(url):
    try:
        target = str(url or "").strip()
    except:
        target = ""
    if not target:
        return []

    urls = [target]
    try:
        parsed = urllib.parse.urlparse(target)
        host = str(parsed.netloc or "").strip().lower()
        parts = [part for part in str(parsed.path or "").split("/") if part]
        if host == "raw.githubusercontent.com" and len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            repo_owner = str(parts[0] or "").strip()
            repo_name = str(parts[1] or "").strip()
            branch_name = str(parts[4] or "").strip()
            tail_parts = list(parts[5:])
            canonical_path = "/" + "/".join([parts[0], parts[1], parts[4]] + parts[5:])
            canonical = urllib.parse.urlunparse((
                parsed.scheme or "https",
                parsed.netloc,
                canonical_path,
                "",
                parsed.query or "",
                "",
            ))
            if canonical and canonical not in urls:
                urls.append(canonical)
            if repo_owner and repo_name and branch_name:
                jsd_path = "/gh/" + "/".join([repo_owner, repo_name + "@" + branch_name] + tail_parts)
                for jsd_host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net", "fastly.jsdelivr.net"):
                    jsd = urllib.parse.urlunparse((
                        "https",
                        jsd_host,
                        jsd_path,
                        "",
                        parsed.query or "",
                        "",
                    ))
                    if jsd and jsd not in urls:
                        urls.append(jsd)
    except:
        pass
    return urls


def _decode_subscription_body(raw, encoding=""):
    data = bytes(raw or b"")
    enc = str(encoding or "").lower().strip()
    if data[:2] == b"\x1f\x8b" or "gzip" in enc:
        try:
            data = gzip.decompress(data)
        except:
            pass
    try:
        return data.decode("utf-8")
    except:
        return data.decode("utf-8", errors="ignore")


def _fetch_text_url(url, timeout_sec=15.0):
    try:
        base_timeout = max(float(timeout_sec), 15.0)
    except:
        base_timeout = 15.0
    timeouts = []
    for item in (base_timeout, max(base_timeout, 30.0), max(base_timeout, 45.0)):
        try:
            value = float(item)
        except:
            continue
        if value not in timeouts:
            timeouts.append(value)

    errors = []
    candidate_urls = _subscription_candidate_urls(url)

    for candidate_url in candidate_urls:
        headers = _subscription_request_headers(candidate_url)

        for current_timeout in list(timeouts or [15.0]):
            try:
                req = urllib.request.Request(str(candidate_url or ""), headers=headers)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=float(current_timeout), context=ctx) as resp:
                    raw = resp.read()
                    try:
                        encoding = str(resp.headers.get("Content-Encoding", "") or "")
                    except:
                        encoding = ""
                    text = _decode_subscription_body(raw, encoding=encoding)
                    if text:
                        _set_vless_fetch_diag(
                            url,
                            stage="fetched",
                            fetched_url=str(candidate_url or ""),
                            timeout=float(current_timeout),
                            tried=len(candidate_urls),
                            errors=" | ".join(list(errors or [])[:4]),
                        )
                        return text
            except Exception as e:
                try:
                    host = str(urllib.parse.urlparse(str(candidate_url or "")).netloc or "").strip()
                except:
                    host = ""
                err = "urllib@%s:%s" % (host or "?", str(type(e).__name__))
                if err not in errors:
                    errors.append(err)

            try:
                import requests
                r = requests.get(str(candidate_url or ""), timeout=float(current_timeout), verify=False, headers=headers)
                if int(getattr(r, "status_code", 0) or 0) == 200:
                    raw = getattr(r, "content", b"") or b""
                    encoding = str(getattr(getattr(r, "headers", {}), "get", lambda *a, **k: "")("Content-Encoding", "") or "")
                    text = _decode_subscription_body(raw, encoding=encoding)
                    if text:
                        _set_vless_fetch_diag(
                            url,
                            stage="fetched",
                            fetched_url=str(candidate_url or ""),
                            timeout=float(current_timeout),
                            tried=len(candidate_urls),
                            errors=" | ".join(list(errors or [])[:4]),
                        )
                        return text
            except Exception as e:
                try:
                    host = str(urllib.parse.urlparse(str(candidate_url or "")).netloc or "").strip()
                except:
                    host = ""
                err = "requests@%s:%s" % (host or "?", str(type(e).__name__))
                if err not in errors:
                    errors.append(err)
    _set_vless_fetch_diag(
        url,
        stage="fetch_failed",
        fetched_url="",
        timeout=float(timeouts[-1] if timeouts else 0.0),
        tried=len(candidate_urls),
        errors=" | ".join(list(errors or [])[:4]),
    )
    return ""


def _qwdtt_int(value, default=0):
    try:
        return int(value)
    except:
        return int(default)


def _qwdtt_profile_from_mapping(value, source_uri=""):
    if not isinstance(value, dict):
        return None
    peer = str(value.get("peer", "") or "").strip()
    if not peer:
        host = str(value.get("server", value.get("dtls_host", "")) or "").strip()
        port = _qwdtt_int(value.get("dtls_port", value.get("server_port", 56000)), 56000)
        if host:
            peer = "%s:%d" % (host, port)
    elif value.get("dtls_port", value.get("server_port", "")) not in (None, ""):
        port = _qwdtt_int(value.get("dtls_port", value.get("server_port", 56000)), 56000)
        if peer.startswith("["):
            if "]:" not in peer:
                peer = "%s:%d" % (peer, port)
        elif ":" not in peer:
            peer = "%s:%d" % (peer, port)
    raw_hashes = value.get("hashes", value.get("vkHashes", value.get("vk_hashes", value.get("vk_hash", ""))))
    if isinstance(raw_hashes, (list, tuple)):
        hashes = [str(item or "").strip() for item in raw_hashes if str(item or "").strip()]
    else:
        hashes = [item.strip() for item in str(raw_hashes or "").replace("\n", ",").split(",") if item.strip()]
    password = str(value.get("password", value.get("pass", "")) or "").strip()
    if not peer or not hashes or not password:
        return None
    workers = _qwdtt_int(value.get("workers", value.get("workersPerHash", 16)), 16)
    workers = max(9, min(108, workers))
    local_port = _qwdtt_int(value.get("local_port", value.get("port", value.get("listenPort", 9000))), 9000)
    if local_port < 0 or local_port > 65535:
        local_port = 9000
    name = str(value.get("name", value.get("label", "")) or "").strip() or (peer.split(":", 1)[0] if peer else "qWDTT")
    canonical = json.dumps({
        "peer": peer,
        "hashes": hashes,
        "password": password,
        "workers": workers,
        "local_port": local_port,
        "turn_host": str(value.get("turn_host", "") or "").strip(),
        "turn_port": str(value.get("turn_port", "") or "").strip(),
        "vk_anon_path": str(value.get("vk_anon_path", "") or "").strip(),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "id": hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()[:24],
        "name": name[:80],
        "peer": peer,
        "hashes": hashes,
        "password": password,
        "workers": workers,
        "local_port": local_port,
        "turn_host": str(value.get("turn_host", "") or "").strip(),
        "turn_port": str(value.get("turn_port", "") or "").strip(),
        "vk_anon_path": str(value.get("vk_anon_path", "") or "").strip(),
        "wait_ready_timeout_millis": max(15000, min(120000, _qwdtt_int(value.get("wait_ready_timeout_millis", 60000), 60000))),
        "source_uri": str(source_uri or "").strip(),
    }


def _parse_qwdtt_uri(value):
    text = str(value or "").strip().rstrip(".,!?)]}>")
    low = text.lower()
    if low.startswith("wdtt://"):
        parts = text[7:].split(":")
        if len(parts) < 6:
            return None
        return _qwdtt_profile_from_mapping({
            "name": parts[0],
            "peer": "%s:%s" % (parts[0], parts[1]),
            "wg_port": parts[2],
            "local_port": parts[3],
            "password": parts[4],
            "hashes": ":".join(parts[5:]),
            "workers": 16,
        }, source_uri=text)
    if low.startswith("qwdtt:config?"):
        text = "qwdtt://config?" + text.split("?", 1)[1]
        low = text.lower()
    if not low.startswith("qwdtt://"):
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
        values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        def first(*names):
            for name in names:
                items = values.get(name, [])
                if items:
                    return items[0]
            return ""
        return _qwdtt_profile_from_mapping({
            "name": first("name", "label"),
            "peer": first("peer", "server"),
            "dtls_port": first("dtls_port", "server_port"),
            "hashes": first("hashes", "vkHashes", "vk_hash"),
            "workers": first("workers", "workersPerHash"),
            "local_port": first("local_port", "port", "listenPort"),
            "password": first("password", "pass"),
            "turn_host": first("turn_host"),
            "turn_port": first("turn_port"),
            "vk_anon_path": first("vk_anon_path"),
            "wait_ready_timeout_millis": first("wait_ready_timeout_millis"),
        }, source_uri=text)
    except:
        return None


def _parse_qwdtt_payload(value):
    text = str(value or "").strip()
    result = {"name": "", "description": "", "profiles": []}
    if not text:
        return result
    direct = _parse_qwdtt_uri(text)
    if direct:
        result["name"] = str(direct.get("name", "") or "")
        result["profiles"] = [direct]
        return result
    raw = text
    if not raw.startswith(("{", "[")):
        try:
            blob = raw.replace("-", "+").replace("_", "/")
            blob += "=" * ((4 - len(blob) % 4) % 4)
            decoded = base64.b64decode(blob.encode("ascii", errors="ignore"), validate=False).decode("utf-8", errors="ignore").strip()
            if decoded.startswith(("{", "[", "wdtt://", "qwdtt:")):
                return _parse_qwdtt_payload(decoded)
        except:
            pass
        return result
    try:
        data = json.loads(raw)
    except:
        return result
    entries = []
    if isinstance(data, dict):
        result["name"] = str(data.get("subscriptionName", data.get("groupName", data.get("name", ""))) or "").strip()
        result["description"] = str(data.get("description", data.get("info", "")) or "").strip()
        nested = data.get("profiles", data.get("servers", None))
        entries = nested if isinstance(nested, list) else [data]
    elif isinstance(data, list):
        entries = data
    for item in entries:
        profile = _qwdtt_profile_from_mapping(item)
        if profile and not any(str(old.get("id", "")) == str(profile.get("id", "")) for old in result["profiles"]):
            result["profiles"].append(profile)
    return result


def _qwdtt_core_config(profile, socks_port):
    if not isinstance(profile, dict):
        return ""
    payload = {
        "engine": QWDTT_KIND,
        "peer": str(profile.get("peer", "") or ""),
        "hashes": list(profile.get("hashes", []) or []),
        "password": str(profile.get("password", "") or ""),
        "workers": _qwdtt_int(profile.get("workers", 16), 16),
        "local_port": _qwdtt_int(profile.get("local_port", 9000), 9000),
        "device_id": _get_or_create_subscription_hwid(),
        "socks_listen_host": VLESS_LOCAL_HOST,
        "socks_port": int(socks_port or 0),
        "wait_ready_timeout_millis": 60000,
    }
    for key in ("turn_host", "turn_port", "vk_anon_path"):
        value = str(profile.get(key, "") or "").strip()
        if value:
            payload[key] = value
    payload["wait_ready_timeout_millis"] = max(15000, min(120000, _qwdtt_int(profile.get("wait_ready_timeout_millis", 60000), 60000)))
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _olcrtc_carrier_alias(value):
    try:
        v = str(value or "").strip().lower()
    except:
        v = ""
    if v in ("wb", "wildberries", "wbstream", "wb-stream"):
        return "wbstream"
    if v in ("ya", "yandex", "yamost", "telemost", "yandex_telemost"):
        return "telemost"
    if v in ("meet", "jitsi", "jitsi-meet", "jitsi_meet"):
        return "jitsi"
    if v in OLCRTC_CARRIER_ITEMS:
        return v
    return ""


def _olcrtc_transport_alias(value):
    try:
        v = str(value or "").strip().lower().replace("_", "-")
    except:
        v = ""
    if v in ("data", "dc", "data-channel"):
        return "datachannel"
    if v in ("vp8", "vp8-channel"):
        return "vp8channel"
    if v in ("sei", "sei-channel"):
        return "seichannel"
    if v in ("video", "video-channel"):
        return "videochannel"
    if v in OLCRTC_TRANSPORT_ITEMS:
        return v
    return ""


def _olcrtc_default_transport_for_carrier(carrier):
    return "datachannel" if _olcrtc_carrier_alias(carrier) == "jitsi" else "vp8channel"


def _olcrtc_qs_get(qs, *names):
    for name in names:
        try:
            values = qs.get(name)
        except:
            values = None
        if values:
            value = str(values[0] or "").strip()
            if value:
                return urllib.parse.unquote(value)
    return ""


def _olcrtc_qs_int(qs, *names):
    try:
        value = int(_olcrtc_qs_get(qs, *names) or 0)
        return value if value > 0 else 0
    except:
        return 0


def _olcrtc_parse_kv_blob(value):
    try:
        blob = str(value or "").strip().strip("<>").replace(";", "&")
    except:
        blob = ""
    if not blob or "=" not in blob:
        return {}
    try:
        return urllib.parse.parse_qs(blob, keep_blank_values=False)
    except:
        return {}


def _olcrtc_room_from_http_url(raw, parsed=None):
    try:
        p = parsed or urllib.parse.urlparse(str(raw or "").strip())
        host = str(p.netloc or "").strip().lower()
        path = urllib.parse.unquote(str(p.path or "")).strip("/")
        full = str(raw or "").strip()
    except:
        return "", ""
    if not host:
        return "", ""
    if host == "telemost.yandex.ru" or host.endswith(".telemost.yandex.ru"):
        room = ""
        try:
            qs = urllib.parse.parse_qs(str(p.query or ""))
            room = _olcrtc_qs_get(qs, "room_id", "room", "roomId", "meeting_id", "meetingId")
        except:
            room = ""
        if not room and path:
            room = path.rstrip("/").split("/")[-1]
        return "telemost", room
    if host == "stream.wb.ru" or host.endswith(".stream.wb.ru"):
        room = ""
        try:
            qs = urllib.parse.parse_qs(str(p.query or ""))
            room = _olcrtc_qs_get(qs, "room_id", "room", "roomId")
        except:
            room = ""
        if not room and path:
            room = path.rstrip("/").split("/")[-1]
        return "wbstream", room
    if host.startswith("meet.") or "jitsi" in host:
        return "jitsi", full
    return "", ""


def _olcrtc_client_id_from_url(url):
    try:
        parsed = urllib.parse.urlparse(str(url or "").strip())
        qs = urllib.parse.parse_qs(str(parsed.query or ""))
        value = _olcrtc_qs_get(qs, "client_id", "client", "device_id", "id")
        if not value:
            parts = [urllib.parse.unquote(p) for p in str(parsed.path or "").split("/") if p]
            value = str(parts[-1] or "") if parts else ""
        return str(value or "").strip().strip("()")
    except:
        return ""


def _olcrtc_profile_from_json(value, default_client_id=""):
    if not isinstance(value, dict):
        return None
    try:
        endpoint = value.get("endpoint")
        endpoint = endpoint if isinstance(endpoint, dict) else {}
        metadata = value.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        transport_data = value.get("transport")
        transport_data = transport_data if isinstance(transport_data, dict) else {}
        vp8 = transport_data.get("vp8")
        vp8 = vp8 if isinstance(vp8, dict) else {}

        carrier = _olcrtc_carrier_alias(
            value.get("auth_provider")
            or value.get("carrier")
            or value.get("bypass_provider")
            or value.get("bypassProvider")
            or value.get("provider")
        ) or "telemost"
        transport = _olcrtc_transport_alias(
            transport_data.get("type") or value.get("transport")
        ) or _olcrtc_default_transport_for_carrier(carrier)
        room_id = str(
            endpoint.get("room_id")
            or value.get("room_id")
            or value.get("id")
            or value.get("server")
            or ""
        ).strip()
        client_id = str(
            endpoint.get("client_id")
            or value.get("client_id")
            or value.get("clientId")
            or value.get("device_id")
            or value.get("deviceId")
            or default_client_id
            or ""
        ).strip()
        key_hex = str(
            endpoint.get("key")
            or value.get("key_hex")
            or value.get("key")
            or value.get("password")
            or ""
        ).strip()
        if not room_id or not client_id or not key_hex:
            return None
        out = {
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
            "name": str(value.get("name") or metadata.get("name") or "").strip()[:64],
        }
        for target, raw in (("vp8_fps", vp8.get("fps") or value.get("vp8_fps") or value.get("vp8Fps")), ("vp8_batch_size", vp8.get("batch") or value.get("vp8_batch") or value.get("vp8Batch"))):
            try:
                parsed = int(raw or 0)
                if parsed > 0:
                    out[target] = parsed
            except:
                pass
        return out
    except:
        return None


def _extract_olcrtc_json_profiles(text, default_client_id=""):
    try:
        root = json.loads(str(text or "").strip())
    except:
        return []
    if isinstance(root, dict) and isinstance(root.get("olcrtc"), dict):
        root = root.get("olcrtc")
    if isinstance(root, dict):
        items = root.get("locations")
        items = items if isinstance(items, list) else [root]
    elif isinstance(root, list):
        items = root
    else:
        return []
    profiles = []
    for item in items:
        profile = _olcrtc_profile_from_json(item, default_client_id=default_client_id)
        if profile:
            profiles.append(profile)
    return profiles


def _parse_olcrtc_uri_to_data(raw, default_client_id=""):
    try:
        text = str(raw or "").strip()
    except:
        text = ""
    if not text:
        return None, "Буфер обмена пуст"

    try:
        parsed = urllib.parse.urlparse(text)
        scheme = str(parsed.scheme or "").lower()
        if scheme in ("http", "https"):
            carrier, room_id = _olcrtc_room_from_http_url(text, parsed)
            if carrier and room_id:
                return {
                    "carrier": carrier,
                    "transport": _olcrtc_default_transport_for_carrier(carrier),
                    "room_id": room_id,
                    "client_id": str(default_client_id or "").strip(),
                    "key_hex": "",
                }, ""
            return None, "В буфере нет olcRTC конфига"
        if scheme != OLCRTC_KIND:
            return None, "В буфере нет olcRTC конфига"

        qs = urllib.parse.parse_qs(parsed.query)
        carrier = _olcrtc_carrier_alias(_olcrtc_qs_get(qs, "carrier", "provider"))
        transport = _olcrtc_transport_alias(_olcrtc_qs_get(qs, "transport", "t"))
        room_id = _olcrtc_qs_get(qs, "room_id", "room")
        client_id = _olcrtc_qs_get(qs, "client_id", "device_id", "client", "id") or str(default_client_id or "").strip()
        key_hex = _olcrtc_qs_get(qs, "key_hex", "key")

        compact_query = urllib.parse.unquote(str(parsed.query or "")).strip()
        payload_qs = {}
        if "@" in compact_query:
            left, compact_room = compact_query.split("@", 1)
            payload = ""
            transport_part = left.strip()
            if "<" in transport_part and ">" in transport_part:
                transport_part, payload = transport_part.split("<", 1)
                payload = payload.rsplit(">", 1)[0]
                payload_qs = _olcrtc_parse_kv_blob(payload)
            compact_transport = _olcrtc_transport_alias(transport_part)
            if compact_transport:
                transport = transport or compact_transport
                room_id = room_id or compact_room.strip()
                client_id = client_id or _olcrtc_qs_get(payload_qs, "client_id", "device_id", "client", "id")
                key_hex = key_hex or _olcrtc_qs_get(payload_qs, "key_hex", "key")

        fragment = urllib.parse.unquote(str(parsed.fragment or "")).strip()
        if fragment:
            key_part = fragment
            meta_part = ""
            if "$" in fragment:
                key_part, meta_part = fragment.split("$", 1)
            if "%" in key_part:
                key_part, compact_client_id = key_part.split("%", 1)
                client_id = client_id or str(compact_client_id or "").strip()
            key_hex = key_hex or str(key_part or "").strip()
            meta_qs = _olcrtc_parse_kv_blob(meta_part)
            client_id = client_id or _olcrtc_qs_get(meta_qs, "client_id", "device_id", "client", "id")

        netloc = urllib.parse.unquote(str(parsed.netloc or "")).strip()
        path = urllib.parse.unquote(str(parsed.path or ""))
        if path.startswith("/"):
            path = path[1:]
        path = path.strip()
        if not carrier and _olcrtc_carrier_alias(netloc):
            carrier = _olcrtc_carrier_alias(netloc)
            room_id = room_id or path
        elif not room_id:
            room_id = (netloc + ("/" + path if path else "")).strip()

        carrier = carrier or "telemost"
        transport = transport or _olcrtc_default_transport_for_carrier(carrier)
        out = {
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
        }
        vp8_fps = _olcrtc_qs_int(payload_qs, "vp8-fps", "vp8_fps", "fps") or _olcrtc_qs_int(qs, "vp8-fps", "vp8_fps")
        vp8_batch = _olcrtc_qs_int(payload_qs, "vp8-batch", "vp8_batch", "vp8_batch_size", "batch") or _olcrtc_qs_int(qs, "vp8-batch", "vp8_batch", "vp8_batch_size")
        if vp8_fps > 0:
            out["vp8_fps"] = int(vp8_fps)
        if vp8_batch > 0:
            out["vp8_batch_size"] = int(vp8_batch)
        return out, ""
    except Exception as exc:
        return None, str(exc)


def _extract_olcrtc_subscription_profiles(text, default_client_id=""):
    profiles = []
    current = None
    try:
        lines = str(text or "").splitlines()
    except:
        lines = []
    for raw_line in lines:
        try:
            line = str(raw_line or "").strip()
        except:
            line = ""
        if not line:
            continue
        if line.lower().startswith("olcrtc://"):
            data, err = _parse_olcrtc_uri_to_data(line, default_client_id=default_client_id)
            if data and not err:
                profiles.append(data)
                current = data
            continue
        if current is not None and line.startswith("##") and ":" in line:
            key, value = line[2:].split(":", 1)
            if key.strip().lower() == "name":
                current["name"] = value.strip()[:64]
    return profiles or _extract_olcrtc_json_profiles(text, default_client_id=default_client_id)


def _extract_declared_plugin_version(text):
    try:
        match = re.search(r'(?m)^__version__\s*=\s*["\']([^"\']+)["\']', str(text or ""))
    except:
        match = None
    if not match:
        return ""
    try:
        return str(match.group(1) or "").strip()
    except:
        return ""


def _version_tuple(value):
    try:
        parts = re.findall(r"\d+", str(value or ""))
    except:
        parts = []
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts[:8])


def _is_version_newer(remote_version, local_version):
    remote = list(_version_tuple(remote_version))
    local = list(_version_tuple(local_version))
    size = max(len(remote), len(local))
    remote.extend([0] * (size - len(remote)))
    local.extend([0] * (size - len(local)))
    return tuple(remote) > tuple(local)


def _set_vless_fetch_diag(url, **kwargs):
    global _LAST_VLESS_FETCH_DIAG
    try:
        key = str(url or "").strip()
    except:
        key = ""
    if not key:
        return
    try:
        payload = dict(kwargs or {})
    except:
        payload = {}
    payload["url"] = key
    _LAST_VLESS_FETCH_DIAG[key] = payload


def _get_vless_fetch_diag(url):
    global _LAST_VLESS_FETCH_DIAG
    try:
        key = str(url or "").strip()
    except:
        key = ""
    if not key:
        return {}
    try:
        value = _LAST_VLESS_FETCH_DIAG.get(key, {})
        return dict(value or {}) if isinstance(value, dict) else {}
    except:
        return {}


def _vless_json_name(obj, server="", sni=""):
    try:
        name = str(
            obj.get("name")
            or obj.get("remark")
            or obj.get("ps")
            or obj.get("tag")
            or ""
        ).strip()
    except:
        name = ""

    low = str(name or "").strip().lower()
    if not name or low in ("proxy", "vless", "node", "out", "outbound", "default"):
        try:
            sni_text = str(sni or "").strip()
        except:
            sni_text = ""
        if sni_text:
            return sni_text
        try:
            server_text = str(server or "").strip()
        except:
            server_text = ""
        if server_text:
            return server_text
        return "sing-box узел"
    return name


def _collect_vless_json_params(obj, user_obj=None):
    params = {}

    try:
        network = obj.get("network") or obj.get("type")
    except:
        network = ""
    try:
        security = obj.get("security")
    except:
        security = ""
    try:
        sni = obj.get("sni") or obj.get("serverName")
    except:
        sni = ""
    try:
        flow = obj.get("flow")
    except:
        flow = ""
    try:
        path = obj.get("path")
    except:
        path = ""
    try:
        host = obj.get("host")
    except:
        host = ""
    try:
        fp = obj.get("fp") or obj.get("fingerprint")
    except:
        fp = ""
    try:
        pbk = obj.get("pbk") or obj.get("publicKey")
    except:
        pbk = ""
    try:
        sid = obj.get("sid") or obj.get("shortId")
    except:
        sid = ""
    try:
        spx = obj.get("spx") or obj.get("spiderX")
    except:
        spx = ""
    try:
        packet_encoding = obj.get("packetEncoding")
    except:
        packet_encoding = ""

    if isinstance(user_obj, dict):
        try:
            flow = flow or user_obj.get("flow")
        except:
            pass

    try:
        tls = obj.get("tls")
    except:
        tls = None
    if isinstance(tls, dict):
        try:
            enabled = tls.get("enabled")
            if enabled is True or str(enabled).lower() == "true":
                security = security or "tls"
        except:
            pass
        try:
            sni = sni or tls.get("server_name") or tls.get("serverName") or tls.get("sni")
        except:
            pass
        try:
            fp = fp or tls.get("fingerprint")
        except:
            pass

    try:
        transport = obj.get("transport")
    except:
        transport = None
    if isinstance(transport, dict):
        try:
            network = network or transport.get("type") or transport.get("network")
        except:
            pass
        try:
            path = path or transport.get("path")
        except:
            pass
        try:
            headers2 = transport.get("headers") or {}
        except:
            headers2 = {}
        if isinstance(headers2, dict):
            try:
                host = host or headers2.get("Host") or headers2.get("host")
            except:
                pass

    try:
        stream = obj.get("streamSettings")
    except:
        stream = None
    if isinstance(stream, dict):
        try:
            network = stream.get("network") or network
        except:
            pass
        try:
            security = stream.get("security") or security
        except:
            pass
        try:
            packet_encoding = packet_encoding or stream.get("packetEncoding")
        except:
            pass

        try:
            reality = stream.get("realitySettings")
        except:
            reality = None
        if isinstance(reality, dict):
            try:
                sni = reality.get("serverName") or reality.get("server_name") or reality.get("sni") or sni
            except:
                pass
            try:
                fp = reality.get("fingerprint") or fp
            except:
                pass
            try:
                pbk = reality.get("publicKey") or reality.get("public_key") or pbk
            except:
                pass
            try:
                sid = reality.get("shortId") or reality.get("short_id") or sid
            except:
                pass
            try:
                spx = reality.get("spiderX") or reality.get("spider_x") or spx
            except:
                pass

        try:
            tls_settings = stream.get("tlsSettings")
        except:
            tls_settings = None
        if isinstance(tls_settings, dict):
            try:
                sni = tls_settings.get("serverName") or tls_settings.get("server_name") or sni
            except:
                pass
            try:
                fp = tls_settings.get("fingerprint") or fp
            except:
                pass

        try:
            ws_settings = stream.get("wsSettings")
        except:
            ws_settings = None
        if isinstance(ws_settings, dict):
            try:
                path = ws_settings.get("path") or path
            except:
                pass
            try:
                headers2 = ws_settings.get("headers") or {}
            except:
                headers2 = {}
            if isinstance(headers2, dict):
                try:
                    host = headers2.get("Host") or headers2.get("host") or host
                except:
                    pass

        try:
            grpc_settings = stream.get("grpcSettings")
        except:
            grpc_settings = None
        if isinstance(grpc_settings, dict):
            try:
                service_name = grpc_settings.get("serviceName") or grpc_settings.get("service_name")
            except:
                service_name = ""
            try:
                multi_mode = grpc_settings.get("multiMode")
            except:
                multi_mode = None
            if service_name:
                params["serviceName"] = str(service_name)
            if multi_mode is not None:
                params["mode"] = "multi" if bool(multi_mode) else "gun"

        try:
            xhttp_settings = stream.get("xhttpSettings")
        except:
            xhttp_settings = None
        if isinstance(xhttp_settings, dict):
            try:
                path = xhttp_settings.get("path") or path
            except:
                pass
            try:
                host = xhttp_settings.get("host") or host
            except:
                pass
            try:
                mode = xhttp_settings.get("mode")
            except:
                mode = ""
            if mode:
                params["mode"] = str(mode)
            try:
                extra = xhttp_settings.get("extra")
            except:
                extra = None
            if isinstance(extra, (dict, list)):
                try:
                    params["extra"] = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
                except:
                    pass

        try:
            httpupgrade_settings = stream.get("httpupgradeSettings")
        except:
            httpupgrade_settings = None
        if isinstance(httpupgrade_settings, dict):
            try:
                host = httpupgrade_settings.get("host") or host
            except:
                pass
            try:
                path = httpupgrade_settings.get("path") or path
            except:
                pass

    if network:
        params["type"] = str(network)
    if security:
        params["security"] = str(security)
    if sni:
        params["sni"] = str(sni)
    if flow:
        params["flow"] = str(flow)
    if path:
        params["path"] = str(path)
    if host:
        params["host"] = str(host)
    if fp:
        params["fp"] = str(fp)
    if pbk:
        params["pbk"] = str(pbk)
    if sid:
        params["sid"] = str(sid)
    if spx:
        params["spx"] = str(spx)
    if packet_encoding:
        params["packetEncoding"] = str(packet_encoding)
    return params


def _build_vless_uri_from_json_obj(obj, uuid_str, server, port, user_obj=None):
    try:
        server_text = str(server or "").strip()
    except:
        server_text = ""
    try:
        uuid_text = str(uuid_str or "").strip()
    except:
        uuid_text = ""
    try:
        port_num = int(port)
    except:
        port_num = 0
    if not uuid_text or not server_text or port_num <= 0:
        return ""

    params = _collect_vless_json_params(obj, user_obj=user_obj)
    sni = str(params.get("sni", "") or "")
    name = _vless_json_name(obj, server=server_text, sni=sni)

    query_parts = []
    for key in ("type", "security", "sni", "flow", "path", "host", "serviceName", "mode", "fp", "pbk", "sid", "spx", "packetEncoding", "extra"):
        try:
            value = params.get(key)
        except:
            value = None
        if value in (None, ""):
            continue
        safe = "/" if key == "path" else ""
        query_parts.append(
            "%s=%s" % (
                urllib.parse.quote(str(key), safe=""),
                urllib.parse.quote(str(value), safe=safe),
            )
        )

    query = ("?" + "&".join(query_parts)) if query_parts else ""
    return "vless://%s@%s:%s%s#%s" % (
        urllib.parse.quote(uuid_text, safe=""),
        server_text,
        str(port_num),
        query,
        urllib.parse.quote(str(name or "sing-box узел"), safe=""),
    )


def _xray_vless_links(outbound, profile_name=""):
    if not isinstance(outbound, dict) or str(outbound.get("protocol", "") or "").lower() != "vless":
        return []
    settings = outbound.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    prefix = str(profile_name or "").strip()
    tag = str(outbound.get("tag", "") or "").strip()
    links = []

    def _build(uuid_str, server, port, user=None):
        named = dict(outbound)
        child_name = "" if _is_generic_proxy_name(tag) else tag
        named["name"] = (prefix + (" " + child_name if child_name else "")).strip() if prefix else (child_name or _proxy_address_name(server, port))
        link = _build_vless_uri_from_json_obj(named, uuid_str, server, port, user_obj=user)
        if link:
            links.append(link)

    vnext = settings.get("vnext")
    if isinstance(vnext, list):
        for target in vnext:
            if not isinstance(target, dict):
                continue
            users = target.get("users")
            users = users if isinstance(users, list) else []
            for user in users:
                if isinstance(user, dict):
                    _build(user.get("id") or user.get("uuid"), target.get("address") or target.get("server"), target.get("port"), user)
        return links

    users = settings.get("users")
    users = users if isinstance(users, list) else []
    user = users[0] if users and isinstance(users[0], dict) else None
    _build(
        settings.get("uuid") or settings.get("id") or settings.get("user") or ((user or {}).get("id") if user else ""),
        settings.get("address") or settings.get("server"),
        settings.get("port") or settings.get("server_port"),
        user,
    )
    return links


def _xray_config_vless_nodes(config):
    if not isinstance(config, dict):
        return []
    profile_name = str(config.get("remarks") or config.get("remark") or config.get("name") or "").strip()
    if str(config.get("protocol", "") or ""):
        outbounds = [config]
    else:
        outbounds = [item for item in list(config.get("outbounds", []) or []) if isinstance(item, dict)]

    routing = config.get("routing")
    routing = routing if isinstance(routing, dict) else {}
    balancers = [item for item in list(routing.get("balancers", []) or []) if isinstance(item, dict)]

    def _nodes_for(items):
        nodes = []
        for outbound in items:
            for link in _xray_vless_links(outbound, profile_name=profile_name):
                node = _proxy_node_from_uri(link)
                if node:
                    nodes.append(node)
        return nodes

    groups = []
    for balancer in balancers:
        balancer_tag = str(balancer.get("tag", "") or "").strip()
        selectors = [str(value or "") for value in list(balancer.get("selector", []) or []) if str(value or "")]
        selected = [
            outbound for outbound in outbounds
            if any(str(outbound.get("tag", "") or "").startswith(selector) for selector in selectors)
        ]
        children = _nodes_for(selected)
        if not children:
            continue
        group_name = profile_name or "VLESS Auto"
        if len(balancers) > 1 and balancer_tag:
            group_name += " • " + balancer_tag
        identity = group_name + "|" + balancer_tag + "|" + ",".join(selectors)
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        first = children[0]
        groups.append({
            "id": "greenpass-balancer://" + digest,
            "uri": "greenpass-balancer://" + digest,
            "kind": "vless",
            "name": group_name,
            "server": str(first.get("server", "") or ""),
            "port": int(first.get("port", 0) or 0),
            "network": "auto",
            "security": str(first.get("security", "") or ""),
            "balance_nodes": children,
        })
    return groups or _nodes_for(outbounds)


def _fetch_vless_nodes(url, text=None):
    if text is None:
        text = _fetch_text_url(url, timeout_sec=15.0)
    if not text:
        _set_vless_fetch_diag(url, stage="empty_text", text_len=0, vless_count=0, ss_count=0, proxy_count=0, link_count=0, node_count=0)
        return []

    body = str(text or "").strip()
    original_body = body
    low_body = body.lower()
    vless_count = int(low_body.count("vless://")) if low_body else 0
    ss_count = int(low_body.count("ss://")) if low_body else 0
    proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else 0
    hitvpn_count = (
        int(low_body.count(HITVPN_LINK_PREFIX))
        + int(low_body.count(HITRAY_LINK_PREFIX))
        + int(low_body.count("hitvpn://"))
    ) if low_body else 0
    raw_starts_json = bool(str(original_body or "").lstrip().startswith("{") or str(original_body or "").lstrip().startswith("["))
    if (not _contains_import_uri_text(low_body)) and (not raw_starts_json):
        try:
            b64 = body.replace("\n", "").replace("\r", "").replace("-", "+").replace("_", "/")
            b64 = "".join(ch for ch in b64 if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            missing = len(b64) % 4
            if missing:
                b64 += "=" * (4 - missing)
            decoded = base64.b64decode(b64.encode("ascii", errors="ignore"), validate=False)
            body = decoded.decode("utf-8", errors="ignore")
            low_body = body.lower()
            vless_count = int(low_body.count("vless://")) if low_body else 0
            ss_count = int(low_body.count("ss://")) if low_body else 0
            proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else 0
            hitvpn_count = (
                int(low_body.count(HITVPN_LINK_PREFIX))
                + int(low_body.count(HITRAY_LINK_PREFIX))
                + int(low_body.count("hitvpn://"))
            ) if low_body else hitvpn_count
        except:
            pass

    links = []
    prebuilt_nodes = []
    if ("\n" in body or "\r" in body) and (proxy_scheme_count > 0 or hitvpn_count > 0):
        try:
            for line in str(body or "").splitlines():
                line = str(line or "").strip()
                if not line:
                    continue
                low = line.lower()
                if (
                    _is_proxy_uri(low)
                    or low.startswith(HITVPN_LINK_PREFIX)
                    or low.startswith(HITRAY_LINK_PREFIX)
                    or low.startswith(HITVPN_SCHEME_PREFIX)
                ):
                    links.append(line.rstrip(".,!?;:)]}>"))
        except:
            links = []
    try:
        if not links:
            links = re.findall(
                r"(?:vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls|ssh|shadowtls|hysteria|naive|mieru)://[^\s\"'<>]+|https://(?:hvpn|hitray)\.io/[^\s\"'<>]+|hitvpn://[^\s\"'<>]+",
                str(body or ""),
                re.IGNORECASE,
            )
    except:
        links = []

    if not links:
        try:
            raw = str(body or "").lstrip()
            if raw.startswith("{") or raw.startswith("["):
                parsed = json.loads(raw)
            else:
                parsed = None
        except:
            parsed = None

        if parsed is None:
            try:
                raw = str(original_body or "").lstrip()
                if raw.startswith("{") or raw.startswith("["):
                    parsed = json.loads(raw)
                    body = original_body
                    low_body = body.lower()
                    vless_count = int(low_body.count("vless://")) if low_body else vless_count
                    ss_count = int(low_body.count("ss://")) if low_body else ss_count
                    proxy_scheme_count = sum(int(low_body.count(scheme + "://")) for scheme in PROXY_URI_SCHEMES) if low_body else proxy_scheme_count
                    hitvpn_count = (
                        int(low_body.count(HITVPN_LINK_PREFIX))
                        + int(low_body.count(HITRAY_LINK_PREFIX))
                        + int(low_body.count("hitvpn://"))
                    ) if low_body else hitvpn_count
            except:
                parsed = parsed

        if parsed is not None:
            configs = parsed if isinstance(parsed, list) else [parsed]
            for config in configs:
                prebuilt_nodes.extend(_xray_config_vless_nodes(config))

    if not links:
        try:
            for line in str(body or "").splitlines():
                line = str(line or "").strip()
                low = line.lower()
                if (
                    _is_proxy_uri(low)
                    or low.startswith(HITVPN_LINK_PREFIX)
                    or low.startswith(HITRAY_LINK_PREFIX)
                    or low.startswith(HITVPN_SCHEME_PREFIX)
                ):
                    links.append(line)
        except:
            pass

    expanded_links = []
    for link in list(links or []):
        try:
            low = str(link or "").strip().lower()
        except:
            low = ""
        if low.startswith(HITVPN_LINK_PREFIX) or low.startswith(HITRAY_LINK_PREFIX) or low.startswith(HITVPN_SCHEME_PREFIX):
            try:
                expanded_links.extend(_decode_hitvpn_link_to_vless_uris(link))
            except:
                pass
        else:
            expanded_links.append(link)

    nodes = []
    seen = set()
    for node in prebuilt_nodes:
        key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")
        if key and key not in seen:
            seen.add(key)
            nodes.append(node)
    for link in list(expanded_links or []):
        try:
            low = str(link or "").strip().lower()
        except:
            low = ""
        if not _is_proxy_uri(low):
            continue
        try:
            decoded = urllib.parse.unquote(str(link or ""))
            decoded_low = decoded.lower()
        except:
            decoded_low = low
        if "@0.0.0.0:1" in low:
            continue
        if "приложение" in decoded_low and "не поддерж" in decoded_low:
            continue
        node = _proxy_node_from_uri(link)
        if not node:
            continue
        key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        nodes.append(node)
    name_counts = {}
    for node in nodes:
        base_name = _clean_proxy_name(node.get("name", "Узел"))
        count = int(name_counts.get(base_name, 0)) + 1
        name_counts[base_name] = count
        if count > 1:
            node["name"] = "%s (%d)" % (base_name, count)
    _set_vless_fetch_diag(
        url,
        stage="done",
        text_len=len(body),
        vless_count=vless_count,
        ss_count=ss_count,
        proxy_count=proxy_scheme_count,
        link_count=len(expanded_links or links),
        node_count=len(nodes),
    )
    return nodes


def _force_show_dialogs_proxy_button(da):
    try:
        if da is None:
            return

        cls = None
        try:
            cls = da.getClass()
        except:
            cls = None

        proxy_item = None
        if cls is not None:
            try:
                f = cls.getDeclaredField("proxyItem")
                f.setAccessible(True)
                proxy_item = f.get(da)
            except:
                proxy_item = None

        if proxy_item is not None:
            try:
                from android.view import View
                proxy_item.setVisibility(View.VISIBLE)
            except:
                pass

        if cls is not None:
            try:
                vf = cls.getDeclaredField("proxyItemVisible")
                vf.setAccessible(True)
                try:
                    vf.setBoolean(da, True)
                except:
                    vf.set(da, True)
            except:
                pass

        proxy_drawable = None
        if cls is not None:
            try:
                df = cls.getDeclaredField("proxyDrawable")
                df.setAccessible(True)
                proxy_drawable = df.get(da)
            except:
                proxy_drawable = None

        if proxy_drawable is not None:
            state = None
            try:
                sf = cls.getDeclaredField("currentConnectionState")
                sf.setAccessible(True)
                state = sf.getInt(da)
            except:
                state = None

            enabled = _is_tg_proxy_enabled()
            connected = False
            try:
                connected = (
                    state == ConnectionsManager.ConnectionStateConnected
                    or state == ConnectionsManager.ConnectionStateUpdating
                )
            except:
                connected = False

            try:
                proxy_drawable.setConnected(bool(enabled), bool(connected), False)
            except:
                pass
    except:
        pass

