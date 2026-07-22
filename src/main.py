class SafeBypassPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self._active = False
        self._thread = None
        self._worker_stop = threading.Event()
        self._reload_ui_pending = False
        self._tgws_connecting = False
        self._tgws_ready = False
        self._tgws_generation = 0
        self._tgws_last_heal_ts = 0.0
        self._tgws_backgrounded = False
        self._tgws_connect_lock = threading.Lock()
        self._proxy_suspended_by_vpn = False
        self._proxy_suspended_by_wifi = False
        self._excluded_wifi_ssids = []
        self._wifi_mode_rules = {}
        self._wifi_default_mode = AWG_KIND
        self._wifi_rule_active_ssid = ""
        self._wifi_rule_switching = False
        self._current_wifi_ssid_cache = ""
        self._vpn_policy_lock = threading.Lock()
        self._chat_menu_item_id = "greenpass_settings_open"
        self._drawer_menu_item_id = "greenpass_settings_drawer"
        self._redirect_hook_installed = False
        self._proxy_button_hooks_installed = False
        self._sync_hooks_installed = False
        self._proxy_killswitch_hook_installed = False
        self._awg_activity_hook_installed = False
        self._browser_vless_hook_installed = False
        self._voip_relay_link_hook_installed = False
        self._text_vless_hook_installed = False
        self._cell_vless_hook_installed = False
        self._greenpass_file_hook_installed = False
        self._voip_relay_hook_installed = False
        self._webrtc_relay_hook_installed = False
        self._plugin_proxy_python_patch_installed = False
        self._plugin_proxy_originals = {}
        self._plugin_proxy_frida_registered = False
        self._plugin_proxy_frida_endpoint_key = ""
        self._plugin_proxy_last_error = ""

        self._last_proxy_sponsor_hide = 0
        self._last_provider_name = ""
        
        self._current_server = ""
        self._desired_use_proxy = False
        self._proxy_state = {}
        self._hot_proxy_cache = []
        self._last_working_proxy = None
        self._connection_mode = AWG_KIND
        self._tgws_port = 0
        self._tgws_running = False
        self._awg_port = 0
        self._awg_running = False
        self._awg_prepare_in_progress = False
        self._awg_conf_name = ""
        self._awg_conf_content = ""
        self._awg_config_downloading = False
        self._olcrtc_port = 0
        self._olcrtc_running = False
        self._olcrtc_connecting = False
        self._olcrtc_backgrounded = False
        self._olcrtc_health_stale = False
        self._olcrtc_resume_checking = False
        self._olcrtc_feedback_requested = False
        self._olcrtc_dead_checks = 0
        self._olcrtc_profiles = []
        self._olcrtc_active_profile_id = ""
        self._olcrtc_prepare_in_progress = False
        self._olcrtc_generation = 0
        self._olcrtc_start_in_progress = False
        self._olcrtc_connect_lock = threading.Lock()
        self._olcrtc_connect_worker_active = False
        self._olcrtc_connect_pending = False
        self._olcrtc_stop_lock = threading.Lock()
        self._olcrtc_stop_in_progress = False
        self._olcrtc_last_error = ""
        self._olcrtc_last_log = ""
        self._vless_port = 0
        self._vless_running = False
        self._vless_connecting = False
        self._vless_last_error = ""
        self._vless_generation = 0
        self._vless_transition_lock = threading.RLock()
        self._vless_connect_lock = threading.Lock()
        self._vless_connect_worker_active = False
        self._vless_connect_pending = False
        self._vless_socks_username = ""
        self._vless_socks_password = ""
        self._vless_local_owner = VLESS_KIND
        self._vless_active_config_key = ""
        self._vless_backgrounded = False
        self._vless_retry_failures = 0
        self._vless_retry_after = 0.0
        self._local_socks_lock = threading.RLock()
        self._local_socks_owner = ""
        self._local_socks_port = 0
        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}
        self._pending_vless_import = ""
        self._vless_prepare_in_progress = False
        self._vless_provider_sync_in_progress = False
        self._autoupdate_last_check_ts = 0
        self._autoupdate_last_seen_version = ""
        self._autoupdate_in_progress = False
        self._libsingbox_validation_cache = None
        self._core_restart_required_pid = 0
        self._core_restart_resume_mode = ""
        self._core_restart_resume_enabled = False
        self._core_restart_resumed = False
        self._config_needs_save = False
        self._proxy_transition_state_lock = threading.Lock()
        self._proxy_transition_next_lease = 1
        self._proxy_transition_active_leases = set()
        self._proxy_transition_param_leases = {}

        try:
            ctx = ApplicationLoader.applicationContext
            self._config_file = os.path.join(ctx.getFilesDir().getAbsolutePath(), "safebypass_v2_config.json")
            self._vless_dir = os.path.join(ctx.getFilesDir().getAbsolutePath(), "greenpass_modules")
        except:
            self._config_file = "safebypass_v2_config.json"
            self._vless_dir = "greenpass_modules"

        try:
            self._plugin_file_path = os.path.abspath(str(__file__ or ""))
        except:
            self._plugin_file_path = os.path.abspath("GreenPass.plugin")

        try:
            if not os.path.exists(self._vless_dir):
                os.makedirs(self._vless_dir)
        except:
            pass

        self._tgws_core = TgWsCore()
        self._vless_core = _LazySingboxCore(self._libvless_so_path())
        self._awg_core = _LazyAWGCore(self._libawg_so_path())
        self._olcrtc_core = _LazyVlessCore(self._libzvonki_so_path())
            
        self._load_config()
        if self._config_needs_save:
            self._save_config()
        if self._core_restart_resumed:
            self._cleanup_legacy_core_files()

    def _atomic_write_json(self, path, data):
        path = str(path)
        try:
            suffix = "%s.%s" % (int(threading.get_ident()), int(time.time() * 1000000))
        except:
            suffix = str(int(time.time() * 1000000))
        tmp = path + "." + suffix + ".tmp"
        try:
            payload = json.dumps(data)
            with open(tmp, 'w') as f:
                f.write(payload)
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except:
                    pass
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except:
                pass
            raise

    def _recover_config_from_backup(self):
        if getattr(self, "_config_recovering", False):
            return
        bak = self._config_file + ".bak"
        try:
            if not os.path.exists(bak):
                return
        except:
            return
        self._config_recovering = True
        try:
            with open(bak, 'r') as bf:
                good = bf.read()
            data = json.loads(good)
            self._atomic_write_json(self._config_file, data)
            self._load_config()
        except Exception:
            pass
        finally:
            self._config_recovering = False

    def _load_config(self):
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r') as f:
                    data = json.load(f)
                    _saved_schema = int(data.get("config_schema", 0) or 0)
                    _saved_version = str(data.get("last_loaded_version", "") or "")
                    _cur_major = str(__version__).split(".")[0]
                    _saved_major = _saved_version.split(".")[0] if _saved_version else ""
                    _stale = (_saved_schema < self._GREENPASS_CONFIG_SCHEMA) or (
                        bool(_saved_major) and _saved_major != _cur_major
                    )
                    self._current_server = data.get("server", "")
                    self._current_port = data.get("port", 0)
                    self._current_secret = data.get("secret", "")
                    self._last_provider_name = data.get("last_provider_name", "")
                    self._connection_mode = str(data.get("connection_mode", AWG_KIND) or AWG_KIND)
                    self._desired_use_proxy = bool(data.get("desired_use_proxy", data.get("use_proxy", False)))
                    saved_socks_password = str(data.get("vless_socks_password", "") or "").strip().lower()
                    self._vless_socks_password = saved_socks_password if re.fullmatch(r"[0-9a-f]{32}", saved_socks_password) else ""
                    _current_pid = int(os.getpid())
                    _restart_pid = int(data.get("core_restart_required_pid", 0) or 0)
                    self._core_restart_resume_mode = str(data.get("core_restart_resume_mode", "") or "")
                    self._core_restart_resume_enabled = bool(data.get("core_restart_resume_enabled", False))
                    if _restart_pid and _restart_pid != _current_pid:
                        self._core_restart_required_pid = 0
                        if self._core_restart_resume_mode:
                            self._connection_mode = self._core_restart_resume_mode
                        self._desired_use_proxy = self._core_restart_resume_enabled
                        self._core_restart_resumed = True
                        self._config_needs_save = True
                    elif _restart_pid:
                        self._core_restart_required_pid = _restart_pid
                        if self._core_restart_resume_mode:
                            self._connection_mode = self._core_restart_resume_mode
                        globals()["_GP_GO_CORE_BLOCKED"] = True
                    if _stale:
                        self._core_restart_resume_mode = self._connection_mode
                        self._core_restart_resume_enabled = self._desired_use_proxy
                        self._core_restart_required_pid = _current_pid
                        globals()["_GP_GO_CORE_BLOCKED"] = True
                        self._desired_use_proxy = False
                        self._config_needs_save = True
                    self._autoupdate_last_check_ts = int(data.get("autoupdate_last_check_ts", 0) or 0)
                    self._autoupdate_last_seen_version = str(data.get("autoupdate_last_seen_version", "") or "")
                    self._proxy_suspended_by_vpn = False
                    self._proxy_suspended_by_wifi = False
                    self._excluded_wifi_ssids = self._sanitize_excluded_wifi_ssids(data.get("excluded_wifi_ssids", []))
                    self._wifi_mode_rules = self._sanitize_wifi_mode_rules(data.get("wifi_mode_rules", {}))
                    for _ssid in self._excluded_wifi_ssids:
                        self._wifi_mode_rules.setdefault(_ssid, "off")
                    self._excluded_wifi_ssids = [
                        _ssid for _ssid, _mode in self._wifi_mode_rules.items() if _mode == "off"
                    ]
                    self._wifi_default_mode = self._normalize_proxy_mode(
                        data.get("wifi_default_mode", self._connection_mode), self._connection_mode
                    )
                    awg_data = data.get("awg_data", None)
                    if isinstance(awg_data, dict):
                        self._awg_conf_name = str(awg_data.get("conf_name", "") or "")
                        self._awg_conf_content = str(awg_data.get("conf_content", "") or "")
                    else:
                        self._awg_conf_name = ""
                        self._awg_conf_content = ""
                    hot_cache = data.get("hot_proxy_cache", [])
                    if isinstance(hot_cache, list):
                        self._hot_proxy_cache = hot_cache
                    else:
                        self._hot_proxy_cache = []
                    last_working = data.get("last_working_proxy", None)
                    if isinstance(last_working, dict):
                        self._last_working_proxy = last_working
                    else:
                        self._last_working_proxy = None

                    legacy_list = data.get("plugin_proxies", [])
                    state = data.get("plugin_proxy_state", None)
                    if isinstance(state, dict):
                        self._proxy_state = state
                    else:
                        self._proxy_state = {}
                    vless_data = data.get("vless_data", None)
                    if isinstance(vless_data, dict):
                        manual = vless_data.get("manual", [])
                        subs = vless_data.get("subs", [])
                        active_uri = vless_data.get("active_uri", "")
                        self._vless_data = {
                            "manual": manual if isinstance(manual, list) else [],
                            "subs": subs if isinstance(subs, list) else [],
                            "active_uri": str(active_uri or ""),
                        }
                    else:
                        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}

                    qwdtt_data = data.get("qwdtt_data", None)
                    if isinstance(qwdtt_data, dict):
                        self._qwdtt_data = {
                            "profiles": self._sanitize_qwdtt_profiles(qwdtt_data.get("profiles", [])),
                            "subs": self._sanitize_qwdtt_subscriptions(qwdtt_data.get("subs", [])),
                            "active_id": str(qwdtt_data.get("active_id", "") or ""),
                        }
                        if self._qwdtt_data["active_id"] and not self._find_qwdtt_profile(self._qwdtt_data["active_id"]):
                            self._qwdtt_data["active_id"] = ""
                    else:
                        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}

                    legacy_qwdtt_nodes = [self._qwdtt_node_from_profile(profile) for profile in self._iter_qwdtt_profiles()]
                    legacy_qwdtt_nodes = [node for node in legacy_qwdtt_nodes if node]
                    if legacy_qwdtt_nodes:
                        known = {str(node.get("uri", "") or "") for node in legacy_qwdtt_nodes}
                        self._vless_data["manual"] = (legacy_qwdtt_nodes + [node for node in list(self._vless_data.get("manual", []) or []) if str(node.get("uri", "") or "") not in known])[:64]
                        if self._connection_mode == QWDTT_KIND and not self._vless_data.get("active_uri"):
                            self._vless_data["active_uri"] = str(legacy_qwdtt_nodes[0].get("uri", "") or "")
                        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}
                        self._config_needs_save = True
                    if self._connection_mode == QWDTT_KIND:
                        self._connection_mode = VLESS_KIND
                        self._config_needs_save = True
                    if self._wifi_default_mode == QWDTT_KIND:
                        self._wifi_default_mode = VLESS_KIND
                    self._connection_mode = self._normalize_proxy_mode(
                        self._wifi_default_mode, self._connection_mode
                    )

                    olcrtc_data = data.get("olcrtc_data", None)
                    if isinstance(olcrtc_data, dict):
                        profiles = olcrtc_data.get("profiles", [])
                        self._olcrtc_profiles = self._sanitize_olcrtc_profiles(profiles if isinstance(profiles, list) else [])
                        self._olcrtc_active_profile_id = str(olcrtc_data.get("active_profile_id", "") or "")
                        if self._olcrtc_active_profile_id and not self._find_olcrtc_profile(self._olcrtc_active_profile_id):
                            self._olcrtc_active_profile_id = ""
                    else:
                        self._olcrtc_profiles = []
                        self._olcrtc_active_profile_id = ""
                    self._ensure_olcrtc_legacy_profile()
                    active_olcrtc_profile = self._active_olcrtc_profile()
                    if active_olcrtc_profile:
                        self._set_olcrtc_legacy_settings_from_profile(active_olcrtc_profile)

                    if isinstance(legacy_list, list):
                        for k in legacy_list:
                            if not isinstance(k, str):
                                continue
                            self._proxy_state.setdefault(k, {"owned": True, "last_used": 0, "failures": 0, "fail_ts": 0})

                    self._prune_proxy_state(now=int(time.time()))
                    self._hot_proxy_cache = self._sanitize_hot_proxy_cache(self._hot_proxy_cache)
                try:
                    self._atomic_write_json(self._config_file + ".bak", data)
                except:
                    pass
        except Exception:
            self._recover_config_from_backup()
        try:
            prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
            persisted_password = str(prefs.getString("vless_socks_password", "") or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", persisted_password):
                self._vless_socks_password = persisted_password
            else:
                if not re.fullmatch(r"[0-9a-f]{32}", str(self._vless_socks_password or "")):
                    self._vless_socks_password = os.urandom(16).hex()
                prefs.edit().putString("vless_socks_password", self._vless_socks_password).commit()
                self._config_needs_save = True
        except:
            if not re.fullmatch(r"[0-9a-f]{32}", str(self._vless_socks_password or "")):
                self._vless_socks_password = os.urandom(16).hex()
                self._config_needs_save = True

    _GREENPASS_CONFIG_SCHEMA = 3

    def _save_config(self):
        try:
            data = {
                "server": self._current_server,
                "port": self._current_port,
                "secret": self._current_secret,
                "last_provider_name": self._last_provider_name,
                "connection_mode": str(self._connection_mode or AWG_KIND),
                "desired_use_proxy": bool(self._desired_use_proxy),
                "vless_socks_password": str(self._vless_socks_password or ""),
                "config_schema": int(self._GREENPASS_CONFIG_SCHEMA),
                "last_loaded_version": str(__version__),
                "core_restart_required_pid": int(self._core_restart_required_pid or 0),
                "core_restart_resume_mode": str(self._core_restart_resume_mode or ""),
                "core_restart_resume_enabled": bool(self._core_restart_resume_enabled),
                "autoupdate_last_check_ts": int(self._autoupdate_last_check_ts or 0),
                "autoupdate_last_seen_version": str(self._autoupdate_last_seen_version or ""),
                "proxy_suspended_by_vpn": bool(self._proxy_suspended_by_vpn),
                "excluded_wifi_ssids": self._sanitize_excluded_wifi_ssids(self._excluded_wifi_ssids),
                "wifi_mode_rules": self._sanitize_wifi_mode_rules(self._wifi_mode_rules),
                "wifi_default_mode": self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode),
                "awg_data": {
                    "conf_name": str(self._awg_conf_name or ""),
                    "conf_content": str(self._awg_conf_content or ""),
                },
                "vless_data": self._vless_data,
                "olcrtc_data": {
                    "profiles": self._sanitize_olcrtc_profiles(self._olcrtc_profiles),
                    "active_profile_id": str(self._olcrtc_active_profile_id or ""),
                },
                "plugin_proxies": list(self._proxy_state.keys())[:MAX_TRACKED_PROXY_STATE],
                "plugin_proxy_state": self._proxy_state,
                "hot_proxy_cache": self._sanitize_hot_proxy_cache(self._hot_proxy_cache),
                "last_working_proxy": self._normalize_proxy_dict(self._last_working_proxy),
            }
            self._atomic_write_json(self._config_file, data)
            try:
                self._atomic_write_json(self._config_file + ".bak", data)
            except:
                pass
        except Exception:
            pass

    def _greenpass_settings_keys(self):
        return (
            "use_proxy",
            "proxy_calls_via_proxy",
            "tgws_voip_relay_enabled",
            "tgws_voip_relay_ip",
            "tgws_voip_relay_port",
            "tgws_voip_relay_hmac",
            "dont_use_with_vpn",
            "proxy_plugins_via_greenpass",
            "proxy_provider_auto",
            "proxy_provider",
            "vless_provider",
            "subscription_hwid_custom",
            "olcrtc_carrier",
            "olcrtc_transport",
            "olcrtc_room_id",
            "olcrtc_client_id",
            "olcrtc_key_hex",
            "hardcoded_proxies_text",
        )

    def _greenpass_legacy_settings_keys(self):
        return (
            "tgjiv_source_url",
            "tgjiv_cookie_header",
            "tgjiv_user_agent",
        )

    def _greenpass_repair_settings_keys(self):
        return self._greenpass_settings_keys() + self._greenpass_legacy_settings_keys()

    def _greenpass_setting_default(self, key):
        key = str(key or "")
        if key == "use_proxy":
            try:
                return bool(self._desired_use_proxy)
            except:
                return False
        defaults = {
            "proxy_calls_via_proxy": False,
            "tgws_voip_relay_enabled": True,
            "tgws_voip_relay_ip": TGWS_VOIP_RELAY_HOST,
            "tgws_voip_relay_port": str(TGWS_VOIP_RELAY_CONTROL_PORT),
            "tgws_voip_relay_hmac": TGWS_VOIP_RELAY_SECRET.decode("utf-8"),
            "dont_use_with_vpn": True,
            "proxy_plugins_via_greenpass": False,
            "proxy_provider_auto": True,
            "proxy_provider": 0,
            "vless_provider": 0,
            "subscription_hwid_custom": "",
            "tgjiv_source_url": "",
            "tgjiv_cookie_header": "",
            "tgjiv_user_agent": "",
            "olcrtc_carrier": 0,
            "olcrtc_transport": 0,
            "olcrtc_room_id": "",
            "olcrtc_client_id": "",
            "olcrtc_key_hex": "",
            "hardcoded_proxies_text": FALLBACK_PROXIES_TEXT,
        }
        return defaults.get(key, "")

    def _sanitize_greenpass_setting_value(self, key, value):
        key = str(key or "")
        if key not in self._greenpass_repair_settings_keys():
            return None
        if value is None:
            value = self._greenpass_setting_default(key)
        if key in ("use_proxy", "proxy_calls_via_proxy", "tgws_voip_relay_enabled", "dont_use_with_vpn", "proxy_plugins_via_greenpass", "proxy_provider_auto"):
            return bool(value)
        if key in ("proxy_provider", "vless_provider", "olcrtc_carrier", "olcrtc_transport"):
            try:
                return int(value)
            except:
                return int(self._greenpass_setting_default(key) or 0)
        return str(value or "")

    def _repair_greenpass_settings_nulls(self):
        sentinel = object()
        for key in self._greenpass_repair_settings_keys():
            try:
                raw = self.get_setting(str(key), sentinel)
            except:
                continue
            if raw is None:
                try:
                    value = self._sanitize_greenpass_setting_value(key, raw)
                    if value is not None:
                        self._set_setting_value(key, value, reload_settings=False)
                except:
                    pass

    def _greenpass_export_settings(self):
        settings = {}
        sentinel = object()
        for key in self._greenpass_settings_keys():
            try:
                raw = self.get_setting(str(key), sentinel)
                if raw is sentinel:
                    continue
                value = self._sanitize_greenpass_setting_value(key, raw)
                if value is not None:
                    settings[str(key)] = value
            except:
                pass
        try:
            settings["use_proxy"] = bool(self._desired_use_proxy)
        except:
            pass
        return settings

    def _greenpass_current_config_snapshot(self):
        try:
            self._save_config()
        except:
            pass
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
        except:
            pass
        return {
            "server": self._current_server,
            "port": self._current_port,
            "secret": self._current_secret,
            "last_provider_name": self._last_provider_name,
            "connection_mode": str(self._connection_mode or AWG_KIND),
            "desired_use_proxy": bool(self._desired_use_proxy),
            "vless_socks_password": str(self._vless_socks_password or ""),
            "proxy_suspended_by_vpn": bool(self._proxy_suspended_by_vpn),
            "excluded_wifi_ssids": self._sanitize_excluded_wifi_ssids(self._excluded_wifi_ssids),
            "wifi_mode_rules": self._sanitize_wifi_mode_rules(self._wifi_mode_rules),
            "wifi_default_mode": self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode),
            "awg_data": {
                "conf_name": str(self._awg_conf_name or ""),
                "conf_content": str(self._awg_conf_content or ""),
            },
            "vless_data": self._vless_data,
            "olcrtc_data": {
                "profiles": self._sanitize_olcrtc_profiles(self._olcrtc_profiles),
                "active_profile_id": str(self._olcrtc_active_profile_id or ""),
            },
            "plugin_proxy_state": self._proxy_state,
            "hot_proxy_cache": self._sanitize_hot_proxy_cache(self._hot_proxy_cache),
            "last_working_proxy": self._normalize_proxy_dict(self._last_working_proxy),
        }

    def _greenpass_export_payload(self):
        return {
            "format": GREENPASS_EXPORT_FORMAT,
            "plugin_id": str(__id__),
            "plugin_version": str(__version__),
            "exported_at": int(time.time()),
            "config": self._greenpass_current_config_snapshot(),
            "settings": self._greenpass_export_settings(),
        }

    def _greenpass_export_bytes(self):
        raw = json.dumps(self._greenpass_export_payload(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return gzip.compress(raw)

    def _greenpass_export_file_path(self):
        try:
            base_dir = os.path.dirname(os.path.abspath(str(self._config_file or "")))
        except:
            base_dir = ""
        if not base_dir:
            try:
                base_dir = os.path.abspath(str(self._vless_dir or ""))
            except:
                base_dir = ""
        if base_dir:
            try:
                if not os.path.exists(base_dir):
                    os.makedirs(base_dir)
            except:
                pass
            return os.path.join(base_dir, GREENPASS_EXPORT_FILE_NAME)
        return GREENPASS_EXPORT_FILE_NAME

    def _export_settings_to_favorites(self):
        def _worker():
            try:
                file_path = self._greenpass_export_file_path()
                payload = self._greenpass_export_bytes()
                with open(file_path, "wb") as f:
                    f.write(payload)
                account = UserConfig.selectedAccount
                user_id = UserConfig.getInstance(account).getClientUserId()

                def _send():
                    try:
                        send_document(user_id, file_path, caption=GREENPASS_EXPORT_FILE_NAME)
                        BulletinHelper.show_success("Экспорт отправлен")
                    except Exception as send_exc:
                        BulletinHelper.show_error("Ошибка отправки: %s" % str(send_exc))

                run_on_ui_thread(_send)
            except Exception as exc:
                err_text = str(exc)
                run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка экспорта: %s" % err_text))

        threading.Thread(target=_worker, daemon=True).start()

    def _current_activity(self):
        activity = None
        try:
            fragment = get_last_fragment()
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            try:
                AU = find_class("org.telegram.messenger.AndroidUtilities")
                activity = AU.getActivity()
            except:
                activity = None
        return activity

    def _open_greenpass_import_file_picker(self):
        try:
            Intent = jclass("android.content.Intent") if jclass is not None else find_class("android.content.Intent")
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            activity = self._current_activity()
            if activity is not None:
                activity.startActivityForResult(intent, int(GREENPASS_IMPORT_FILE_PICKER_REQ))
            else:
                BulletinHelper.show_error("Не удалось открыть файл")
        except Exception as exc:
            BulletinHelper.show_error("Ошибка выбора: %s" % str(exc))

    def _read_greenpass_import_uri_bytes(self, uri):
        activity = self._current_activity()
        if activity is None:
            raise Exception("activity is missing")
        resolver = activity.getContentResolver()
        stream = None
        out = None
        try:
            ByteArrayOutputStream = jclass("java.io.ByteArrayOutputStream") if jclass is not None else find_class("java.io.ByteArrayOutputStream")
            stream = resolver.openInputStream(uri)
            if stream is None:
                raise Exception("stream is missing")
            out = ByteArrayOutputStream()
            try:
                from java import jarray, jbyte
                buffer = jarray(jbyte)(8192)
            except:
                buffer = None
            if buffer is None:
                value = int(stream.read())
                while value != -1:
                    out.write(value)
                    value = int(stream.read())
            else:
                read_count = int(stream.read(buffer))
                while read_count != -1:
                    if read_count > 0:
                        out.write(buffer, 0, read_count)
                    read_count = int(stream.read(buffer))
            arr = out.toByteArray()
            return bytes([(int(arr[i]) + 256) % 256 for i in range(len(arr))])
        finally:
            try:
                if out is not None:
                    out.close()
            except:
                pass
            try:
                if stream is not None:
                    stream.close()
            except:
                pass

    def _decode_greenpass_export_bytes(self, raw_bytes):
        decoded = gzip.decompress(bytes(raw_bytes))
        payload = json.loads(decoded.decode("utf-8"))
        if not isinstance(payload, dict):
            raise Exception("bad export")
        if str(payload.get("format", "") or "") != GREENPASS_EXPORT_FORMAT:
            raise Exception("bad format")
        if not isinstance(payload.get("config", None), dict):
            raise Exception("missing config")
        settings = payload.get("settings", {})
        if settings is not None and not isinstance(settings, dict):
            raise Exception("bad settings")
        return payload

    def _process_greenpass_import_bytes(self, raw):
        payload = self._decode_greenpass_export_bytes(raw)
        self._apply_greenpass_import_payload(payload)

    def _process_greenpass_import_file_path(self, file_path):
        try:
            with open(str(file_path), "rb") as f:
                raw = f.read()
            self._process_greenpass_import_bytes(raw)
            run_on_ui_thread(lambda: BulletinHelper.show_success("Импорт выполнен"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _apply_greenpass_import_payload(self, payload):
        config = payload.get("config", {})
        settings = payload.get("settings", {}) or {}
        if not isinstance(config, dict):
            raise Exception("missing config")
        self._atomic_write_json(self._config_file, config)
        try:
            self._atomic_write_json(self._config_file + ".bak", config)
        except:
            pass
        self._load_config()
        for key in self._greenpass_settings_keys():
            if key in settings:
                try:
                    value = self._sanitize_greenpass_setting_value(key, settings.get(key))
                    if value is not None:
                        self._set_setting_value(key, value, reload_settings=False)
                except:
                    pass
        try:
            _set_subscription_hwid_custom(self.get_setting("subscription_hwid_custom", ""))
        except:
            pass
        try:
            desired = bool(settings.get("use_proxy", config.get("desired_use_proxy", False)))
        except:
            desired = bool(getattr(self, "_desired_use_proxy", False))
        self._on_use_proxy_changed(desired)
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        self._refresh_settings_without_reopen()

    def _process_greenpass_import_file_uri(self, uri):
        try:
            raw = self._read_greenpass_import_uri_bytes(uri)
            self._process_greenpass_import_bytes(raw)
            run_on_ui_thread(lambda: BulletinHelper.show_success("Импорт выполнен"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _greenpass_document_name(self, message_object):
        try:
            name = message_object.getDocumentName()
            if name:
                return str(name)
        except:
            pass
        try:
            doc = message_object.getDocument()
        except:
            doc = None
        try:
            attrs = getattr(doc, "attributes", None)
            if attrs is not None:
                for attr in list(attrs or []):
                    try:
                        file_name = str(getattr(attr, "file_name", "") or "")
                    except:
                        file_name = ""
                    if file_name:
                        return file_name
        except:
            pass
        return ""

    def _is_greenpass_export_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".greenpass")
        except:
            return False

    def _is_singconf_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".singconf")
        except:
            return False

    def _is_qwdtt_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".qwdtt")
        except:
            return False

    def _greenpass_message_file_path(self, message_object):
        try:
            ChatUtils = jclass("com.exteragram.messenger.utils.chats.ChatUtils") if jclass is not None else find_class("com.exteragram.messenger.utils.chats.ChatUtils")
            path = ChatUtils.getInstance().getPathToMessage(message_object)
            if path:
                return str(path)
        except:
            pass
        try:
            owner = getattr(message_object, "messageOwner", None)
            media = getattr(owner, "media", None) if owner is not None else None
            doc = getattr(media, "document", None) if media is not None else None
            local_path = str(getattr(doc, "localPath", "") or "")
            if local_path:
                return local_path
        except:
            pass
        try:
            doc = message_object.getDocument()
            if doc is not None and hasattr(doc, "getPathName"):
                path = doc.getPathName()
                if path:
                    return str(path)
        except:
            pass
        try:
            doc = message_object.getDocument()
            if doc is not None and hasattr(doc, "getLocalPath"):
                path = doc.getLocalPath()
                if path:
                    return str(path)
        except:
            pass
        try:
            FileLoader = jclass("org.telegram.messenger.FileLoader") if jclass is not None else find_class("org.telegram.messenger.FileLoader")
            doc = message_object.getDocument()
            if doc is not None:
                path_obj = FileLoader.getInstance(UserConfig.selectedAccount).getPathToAttach(doc, True)
                if path_obj:
                    return str(path_obj.getAbsolutePath() if hasattr(path_obj, "getAbsolutePath") else path_obj)
        except:
            pass
        return ""

    def _confirm_greenpass_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт")
            return
        try:
            name = str(display_name or GREENPASS_EXPORT_FILE_NAME)
        except:
            name = GREENPASS_EXPORT_FILE_NAME
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Импорт GreenPass")
            builder.set_message("Импортировать настройки из %s?\nТекущие настройки будут заменены." % name)

            def _on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._process_greenpass_import_file_path(file_path)

            def _on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Импортировать", _on_yes)
            builder.set_negative_button("Отмена", _on_no)
            builder.show()
        except Exception as exc:
            BulletinHelper.show_error("Ошибка импорта: %s" % str(exc))

    def _confirm_singconf_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт")
            return
        try:
            name = str(display_name or os.path.basename(str(file_path)) or "config.singconf")
        except:
            name = "config.singconf"
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Импорт sing-box")
            builder.set_message("Импортировать sing-box конфиг из %s?" % name)

            def _on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._process_singconf_import_file_path(file_path, name)

            def _on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Импортировать", _on_yes)
            builder.set_negative_button("Отмена", _on_no)
            builder.show()
        except Exception as exc:
            BulletinHelper.show_error("Ошибка импорта: %s" % str(exc))

    def _confirm_qwdtt_file_import(self, file_path, display_name=""):
        activity = self._current_activity()
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть qWDTT")
            return
        name = str(display_name or os.path.basename(str(file_path)) or "config.qwdtt")
        builder = AlertDialogBuilder(activity)
        builder.set_title("Импорт qWDTT")
        builder.set_message("Импортировать %s?" % name)

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._process_qwdtt_import_file_path(file_path)

        builder.set_positive_button("Импортировать", _on_yes)
        builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
        builder.set_cancelable(True)
        builder.show()

    def _process_singconf_import_file_path(self, file_path, display_name=""):
        try:
            with open(str(file_path), "r", encoding="utf-8") as f:
                text = f.read()
            node = _singbox_node_from_config_text(text, display_name or os.path.basename(str(file_path)))
            prepared = _prepare_singbox_file_config(text, VLESS_LOCAL_PORT)
            validation_error = self._validate_core_config_for_import(prepared, "sing-box config")
            if validation_error:
                raise Exception(validation_error)
            self._save_vless_manual_node(node)
            self._set_connection_mode(VLESS_KIND)
            if self._is_plugin_proxy_enabled():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            self._refresh_settings_without_reopen(reload_main=True)
            run_on_ui_thread(lambda: BulletinHelper.show_success("sing-box конфиг импортирован"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _process_qwdtt_import_file_path(self, file_path):
        try:
            with open(str(file_path), "r", encoding="utf-8") as f:
                text = f.read(1024 * 1024)
            count = self._import_qwdtt_payload(text, activate_first=True)
            if count <= 0:
                raise Exception("неверный формат qWDTT")
            run_on_ui_thread(lambda: BulletinHelper.show_success("qWDTT импортирован"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка qWDTT: %s" % err_text))

    def _handle_greenpass_file_open(self, message_object):
        name = self._greenpass_document_name(message_object)
        is_greenpass = self._is_greenpass_export_file_name(name)
        is_singconf = self._is_singconf_file_name(name)
        is_qwdtt = self._is_qwdtt_file_name(name)
        if not is_greenpass and not is_singconf and not is_qwdtt:
            return False
        file_path = self._greenpass_message_file_path(message_object)
        if not file_path:
            BulletinHelper.show_info("Сначала скачайте файл")
            return True
        try:
            if not os.path.exists(str(file_path)):
                BulletinHelper.show_info("Сначала скачайте файл")
                return True
        except:
            pass
        if is_qwdtt:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_qwdtt_file_import(file_path, name))
        elif is_singconf:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_singconf_file_import(file_path, name))
        else:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_greenpass_file_import(file_path, name))
        return True

    def _plugin_runtime_path(self):
        try:
            path = os.path.abspath(str(self._plugin_file_path or ""))
        except:
            path = ""
        if not path:
            return ""
        try:
            name = os.path.basename(path).lower()
        except:
            name = ""
        if not name:
            return ""
        if not (name.endswith(".plugin") or name.endswith(".py")):
            return ""
        return path

    def _write_updated_plugin_source(self, plugin_text):
        path = self._plugin_runtime_path()
        if not path:
            return False
        source = str(plugin_text or "")
        if len(source.encode("utf-8", errors="ignore")) < 1024 or len(source.encode("utf-8", errors="ignore")) > 2 * 1024 * 1024:
            return False
        try:
            compile(source, path, "exec")
        except:
            return False
        temp_path = path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(source)
            os.replace(temp_path, path)
            return True
        except:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
        return False

    def _fetch_plugin_update_text(self):
        try:
            req = urllib.request.Request(str(GREENPASS_UPDATE_URL), headers={"User-Agent": "GreenPass-Updater"})
            with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
                raw = resp.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                return ""
            return raw.decode("utf-8", errors="strict")
        except:
            return ""

    def _run_autoupdate_check(self, force=False):
        if self._autoupdate_in_progress:
            return False

        now_ts = int(time.time())
        if (not force) and (now_ts - int(self._autoupdate_last_check_ts or 0) < int(PLUGIN_AUTOUPDATE_CHECK_INTERVAL_SEC)):
            return False

        self._autoupdate_in_progress = True
        try:
            self._autoupdate_last_check_ts = now_ts
            self._save_config()

            remote_text = self._fetch_plugin_update_text()
            if (not self._active) and (not force):
                return False
            remote_version = _extract_declared_plugin_version(remote_text)
            self._autoupdate_last_seen_version = str(remote_version or "")
            self._save_config()

            if not remote_text or not remote_version:
                return False
            if not _is_version_newer(remote_version, __version__):
                return False
            if (not self._active) and (not force):
                return False
            if not self._write_updated_plugin_source(remote_text):
                return False

            if (not self._active) and (not force):
                return False
            run_on_ui_thread(lambda: BulletinHelper.show_info("GreenPass обновлён до %s. Перезапустите приложение." % str(remote_version)))
            return True
        except Exception:
            return False
        finally:
            self._autoupdate_in_progress = False




    def _libvless_so_path(self):
        return self._libsingbox_so_path()

    def _libawg_so_path(self):
        return self._libsingbox_so_path()

    def _libzvonki_so_path(self):
        return self._libsingbox_so_path()

    def _libsingbox_so_path(self):
        try:
            return os.path.join(self._vless_dir, SINGBOX_SO_FILE)
        except:
            return SINGBOX_SO_FILE

    def _core_restart_required(self):
        try:
            return int(self._core_restart_required_pid or 0) == int(os.getpid())
        except:
            return False

    def _mark_core_restart_required(self):
        self._core_restart_resume_mode = str(self._get_connection_mode() or AWG_KIND)
        self._core_restart_resume_enabled = bool(self._is_plugin_proxy_enabled())
        self._core_restart_required_pid = int(os.getpid())
        globals()["_GP_GO_CORE_BLOCKED"] = True
        self._save_config()

    def _cleanup_legacy_core_files(self):
        if not self._has_libsingbox_addon():
            return
        for name in ("libvless.so", "libawg_proxy.so", "libzvonki.so"):
            try:
                path = os.path.join(self._vless_dir, name)
                if os.path.exists(path):
                    os.remove(path)
            except:
                pass



    def _mask_olcrtc_key(self, key_hex=None):
        try:
            value = str(key_hex if key_hex is not None else self._get_olcrtc_key_hex() or "").strip()
        except:
            value = ""
        if not value:
            return ""
        return value[:6] + "..." + value[-6:] if len(value) > 12 else "***"



    def _sha256_file(self, path, max_bytes=0):
        try:
            hasher = hashlib.sha256()
            total = 0
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes and total > int(max_bytes):
                        return "", total
                    hasher.update(chunk)
            return hasher.hexdigest(), total
        except:
            return "", 0

    def _has_libzvonki_addon(self):
        return self._has_libsingbox_addon()

    def _libsingbox_addon_status(self):
        if not SINGBOX_BUNDLE_FILE:
            return "missing"
        try:
            path = self._libsingbox_so_path()
            if not path or not os.path.exists(path):
                return "missing"
            stat = os.stat(path)
            if int(stat.st_size) != int(SINGBOX_SO_SIZE):
                return "outdated"
            cache_key = (str(path), int(stat.st_size), int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000))))
            cached = self._libsingbox_validation_cache
            if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
                return "current" if cached[1] else "outdated"
            digest, size = self._sha256_file(path, max_bytes=int(SINGBOX_SO_SIZE))
            valid = bool(size == int(SINGBOX_SO_SIZE) and digest == SINGBOX_SO_SHA256)
            self._libsingbox_validation_cache = (cache_key, valid)
            return "current" if valid else "outdated"
        except:
            return "missing"

    def _has_libsingbox_addon(self):
        return self._libsingbox_addon_status() == "current"

    def _install_libzvonki_bundle(self, allow_network=True):
        return self._install_libsingbox_bundle(allow_network=allow_network)

    def _download_libsingbox_bundle_to_temp(self, dst_path, on_progress=None):
        for url in SINGBOX_BUNDLE_URLS:
            try:
                req = urllib.request.Request(str(url or ""), headers={"User-Agent": "GreenPass"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                hasher = hashlib.sha256()
                total = 0
                with urllib.request.urlopen(req, timeout=40, context=ctx) as resp, open(dst_path, "wb") as handle:
                    while True:
                        chunk = resp.read(128 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > int(SINGBOX_BUNDLE_SIZE) + 4096:
                            raise ValueError("singbox bundle too large")
                        hasher.update(chunk)
                        handle.write(chunk)
                        if on_progress:
                            try:
                                on_progress(min(1.0, float(total) / float(SINGBOX_BUNDLE_SIZE)))
                            except:
                                pass
                if total == int(SINGBOX_BUNDLE_SIZE) and hasher.hexdigest() == SINGBOX_BUNDLE_SHA256:
                    return True
            except:
                try:
                    if os.path.exists(dst_path):
                        os.remove(dst_path)
                except:
                    pass
                continue
        return False

    def _unpack_libsingbox_bundle(self, xz_path, target_path, on_progress=None):
        tmp_path = str(target_path) + ".tmp"
        try:
            hasher = hashlib.sha256()
            total = 0
            with lzma.open(xz_path, "rb", format=lzma.FORMAT_XZ) as src, open(tmp_path, "wb") as dst:
                while True:
                    chunk = src.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > int(SINGBOX_SO_SIZE) + 4096:
                        raise ValueError("singbox library too large")
                    hasher.update(chunk)
                    dst.write(chunk)
                    if on_progress:
                        try:
                            on_progress(min(1.0, float(total) / float(SINGBOX_SO_SIZE)))
                        except:
                            pass
            if total != int(SINGBOX_SO_SIZE) or hasher.hexdigest() != SINGBOX_SO_SHA256:
                raise ValueError("singbox checksum mismatch")
            os.replace(tmp_path, target_path)
            self._libsingbox_validation_cache = None
            return True
        except:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except:
                pass
            return False

    def _install_libsingbox_bundle(self, allow_network=True, on_progress=None):
        if not SINGBOX_BUNDLE_FILE:
            return False
        if self._has_libsingbox_addon():
            if on_progress:
                on_progress(1.0, "Готово")
            return True
        try:
            if not os.path.exists(self._vless_dir):
                os.makedirs(self._vless_dir)
        except:
            pass

        target = self._libsingbox_so_path()
        xz_tmp = str(target) + ".xz.tmp"
        try:
            if allow_network:
                ok = self._download_libsingbox_bundle_to_temp(
                    xz_tmp,
                    on_progress=(lambda value: on_progress(0.05 + 0.70 * value, "Скачивание")) if on_progress else None,
                )
            else:
                ok = False
            if not ok:
                return False
            digest, size = self._sha256_file(xz_tmp, max_bytes=int(SINGBOX_BUNDLE_SIZE))
            if size != int(SINGBOX_BUNDLE_SIZE) or digest != SINGBOX_BUNDLE_SHA256:
                return False
            installed = self._unpack_libsingbox_bundle(
                xz_tmp,
                target,
                on_progress=(lambda value: on_progress(0.75 + 0.24 * value, "Распаковка")) if on_progress else None,
            ) and self._has_libsingbox_addon()
            if installed:
                if on_progress:
                    on_progress(1.0, "Готово")
                self._mark_core_restart_required()
            return installed
        finally:
            try:
                if os.path.exists(xz_tmp):
                    os.remove(xz_tmp)
            except:
                pass








    def _vless_disconnect_with_reason(self, reason, silent=False):
        self._vless_disconnect(silent=bool(silent))

    def _reload_vless_core(self):
        try:
            self._vless_core = _LazySingboxCore(self._libvless_so_path())
        except:
            self._vless_core = _LazySingboxCore("")

    def _reload_awg_core(self):
        try:
            self._awg_core = _LazyAWGCore(self._libawg_so_path())
        except:
            self._awg_core = _LazyAWGCore("")

    def _reload_olcrtc_core(self):
        try:
            self._olcrtc_core = _LazyVlessCore(self._libzvonki_so_path())
        except:
            self._olcrtc_core = _LazyVlessCore("")

    def _has_libvless_addon(self):
        return self._has_libsingbox_addon()

    def _has_libawg_addon(self):
        return self._has_libsingbox_addon()

    def _has_olcrtc_core_addon(self):
        return self._has_libzvonki_addon()

    def _sanitize_qwdtt_profiles(self, profiles):
        result = []
        seen = set()
        for item in list(profiles or []):
            profile = _qwdtt_profile_from_mapping(item, source_uri=str((item or {}).get("source_uri", "") or "") if isinstance(item, dict) else "")
            if not profile:
                continue
            profile_id = str(profile.get("id", "") or "")
            if not profile_id or profile_id in seen:
                continue
            seen.add(profile_id)
            result.append(profile)
            if len(result) >= 64:
                break
        return result

    def _sanitize_qwdtt_subscriptions(self, subscriptions):
        result = []
        seen = set()
        for item in list(subscriptions or []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "") or "").strip()
            if not url or url in seen:
                continue
            profiles = self._sanitize_qwdtt_profiles(item.get("profiles", []))
            if not profiles:
                continue
            seen.add(url)
            result.append({
                "url": url,
                "name": str(item.get("name", "") or "").strip()[:80] or "qWDTT подписка",
                "description": str(item.get("description", "") or "").strip()[:160],
                "profiles": profiles,
                "updated_at": int(item.get("updated_at", 0) or 0),
            })
            if len(result) >= 16:
                break
        return result

    def _iter_qwdtt_profiles(self):
        seen = set()
        for profile in self._sanitize_qwdtt_profiles(self._qwdtt_data.get("profiles", [])):
            profile_id = str(profile.get("id", "") or "")
            if not profile_id or profile_id in seen:
                continue
            seen.add(profile_id)
            yield profile
        for sub in self._sanitize_qwdtt_subscriptions(self._qwdtt_data.get("subs", [])):
            for profile in list(sub.get("profiles", []) or []):
                profile_id = str(profile.get("id", "") or "")
                if not profile_id or profile_id in seen:
                    continue
                seen.add(profile_id)
                yield profile

    def _find_qwdtt_profile(self, profile_id):
        target = str(profile_id or "")
        if not target:
            return None
        for profile in self._iter_qwdtt_profiles():
            if str(profile.get("id", "") or "") == target:
                return profile
        return None

    def _active_qwdtt_profile(self):
        profile = self._find_qwdtt_profile(self._qwdtt_data.get("active_id", ""))
        if profile:
            return profile
        try:
            profile = next(self._iter_qwdtt_profiles())
        except:
            profile = None
        if profile:
            self._qwdtt_data["active_id"] = str(profile.get("id", "") or "")
        return profile

    def _save_qwdtt_profile(self, profile, activate=True):
        node = self._qwdtt_node_from_profile(profile)
        if not node:
            return None
        if activate:
            return self._save_vless_manual_node(node)
        return node

    def _qwdtt_profile_uri(self, profile):
        if not isinstance(profile, dict):
            return ""
        source = str(profile.get("source_uri", "") or "").strip()
        if source:
            return source
        query = urllib.parse.urlencode({
            "name": str(profile.get("name", "") or "qWDTT"),
            "peer": str(profile.get("peer", "") or ""),
            "hashes": ",".join(list(profile.get("hashes", []) or [])),
            "workers": int(profile.get("workers", 16) or 16),
            "port": int(profile.get("local_port", 9000) or 9000),
            "pass": str(profile.get("password", "") or ""),
        })
        return "qwdtt://config?" + query

    def _qwdtt_node_from_profile(self, profile):
        clean = _qwdtt_profile_from_mapping(profile, source_uri=str((profile or {}).get("source_uri", "") or "") if isinstance(profile, dict) else "")
        if not clean:
            return None
        profile_id = str(clean.get("id", "") or "")
        return {
            "id": "qwdtt://" + profile_id,
            "uri": "qwdtt://" + profile_id,
            "kind": QWDTT_KIND,
            "name": str(clean.get("name", "qWDTT") or "qWDTT"),
            "server": str(clean.get("peer", "") or ""),
            "port": int(clean.get("local_port", 9000) or 9000),
            "network": "turn",
            "security": "wireguard",
            "qwdtt": clean,
        }

    def _import_qwdtt_payload(self, text, activate_first=True, subscription_url=""):
        parsed = _parse_qwdtt_payload(text)
        profiles = self._sanitize_qwdtt_profiles(parsed.get("profiles", []))
        if not profiles:
            return 0
        nodes = [self._qwdtt_node_from_profile(profile) for profile in profiles]
        nodes = [node for node in nodes if node]
        if not nodes:
            return 0
        if subscription_url:
            target = str(subscription_url or "").strip()
            subs = [item for item in list(self._vless_data.get("subs", []) or []) if str(item.get("url", "") or "") != target]
            subs.append({
                "id": target,
                "url": target,
                "name": str(parsed.get("name", "") or "").strip()[:80] or str(urllib.parse.urlparse(target).netloc or "qWDTT подписка"),
                "nodes": nodes,
            })
            self._vless_data["subs"] = subs[-64:]
        else:
            known = {str(node.get("uri", "") or "") for node in nodes}
            current = [item for item in list(self._vless_data.get("manual", []) or []) if str(item.get("uri", "") or "") not in known]
            self._vless_data["manual"] = (nodes + current)[:64]
        if bool(activate_first) or not self._get_active_vless_uri():
            self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
            self._set_connection_mode(VLESS_KIND)
        self._save_config()
        if bool(activate_first):
            self._switch_to_vless_mode(False)
        self._refresh_settings_without_reopen(reload_main=bool(activate_first), reload_stack=True)
        return len(nodes)

    def _add_qwdtt_subscription(self, url, activate_first=False):
        target = str(url or "").strip()
        if not target.lower().startswith(("http://", "https://")):
            BulletinHelper.show_error("Нужна ссылка подписки")
            return False
        BulletinHelper.show_info("Загружаю qWDTT...")

        def _worker():
            text = _fetch_text_url(target, timeout_sec=20.0)
            count = self._import_qwdtt_payload(text, activate_first=bool(activate_first), subscription_url=target) if text else 0
            if count > 0:
                run_on_ui_thread(lambda: BulletinHelper.show_success("qWDTT профилей: %d" % int(count)))
            else:
                run_on_ui_thread(lambda: BulletinHelper.show_error("Нет qWDTT профилей"))

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _activate_qwdtt_profile(self, profile_id, connect=True):
        profile = self._find_qwdtt_profile(profile_id)
        if not profile:
            BulletinHelper.show_error("Профиль не найден")
            return False
        node = self._qwdtt_node_from_profile(profile)
        if not node:
            return False
        self._save_vless_manual_node(node)
        if connect:
            self._switch_to_vless_mode()
        else:
            self._set_connection_mode(VLESS_KIND)
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        return True

    def _import_qwdtt_from_clipboard(self):
        text = self._get_clipboard_text()
        if not text:
            BulletinHelper.show_error("Буфер обмена пуст")
            return False
        raw = str(text or "").strip()
        if raw.lower().startswith(("http://", "https://")):
            return self._add_qwdtt_subscription(raw, activate_first=self._active_qwdtt_profile() is None)
        count = self._import_qwdtt_payload(raw, activate_first=True)
        if count <= 0:
            BulletinHelper.show_error("Неверный qWDTT конфиг")
            return False
        BulletinHelper.show_success("qWDTT импортирован")
        return True

    def _restart_qwdtt_from_settings(self):
        self._switch_to_vless_mode()

    def _get_connection_mode(self):
        mode = str(self._connection_mode or AWG_KIND)
        if mode not in ("proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            mode = AWG_KIND
        return mode

    def _normalize_proxy_mode(self, mode, fallback="proxy"):
        try:
            target = str(mode or fallback)
        except:
            target = str(fallback or "proxy")
        if target not in ("proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = str(fallback or "proxy")
        if target not in ("proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = "proxy"
        return target

    def _set_connection_mode(self, mode):
        target = self._normalize_proxy_mode(mode)
        self._connection_mode = target
        if not bool(getattr(self, "_wifi_rule_switching", False)):
            self._wifi_default_mode = target
        self._save_config()

    def _get_active_vless_uri(self):
        try:
            return str(self._vless_data.get("active_uri", "") or "")
        except:
            return ""

    def _get_all_vless_nodes(self):
        nodes = []
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                if isinstance(node, dict):
                    nodes.append(node)
        except:
            pass
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if isinstance(node, dict):
                        nodes.append(node)
        except:
            pass
        return nodes

    def _find_vless_node(self, uri):
        target = str(uri or "")
        if not target:
            return None
        for node in self._get_all_vless_nodes():
            try:
                if str(node.get("uri", "") or "") == target:
                    return node
            except:
                continue
        return None

    def _current_vless_node(self):
        node = self._find_vless_node(self._get_active_vless_uri())
        if node is None and self._repair_active_vless_subscription_uri():
            self._vless_save_data()
            node = self._find_vless_node(self._get_active_vless_uri())
        return node

    def _vless_auto_subscription_nodes(self, uri=None):
        node = self._find_vless_node(uri if uri is not None else self._get_active_vless_uri())
        return [item for item in list((node or {}).get("balance_nodes", []) or []) if isinstance(item, dict)]

    def _repair_active_vless_subscription_uri(self):
        active_uri = self._get_active_vless_uri()
        active_key = _proxy_uri_dedup_key(active_uri) or active_uri
        if not active_key:
            return False

        manual_keys = set()
        candidates = []
        seen = set()
        preferred = ""
        try:
            current_server = str(self._current_server or "")
            current_port = int(self._current_port or 0)
        except:
            current_server = ""
            current_port = 0
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                value = str(node.get("uri", "") or "")
                key = _proxy_uri_dedup_key(value) or value
                if key:
                    manual_keys.add(key)
            if active_key in manual_keys:
                return False
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if not isinstance(node, dict):
                        continue
                    value = str(node.get("uri", "") or "")
                    key = _proxy_uri_dedup_key(value) or value
                    if not key:
                        continue
                    if key == active_key:
                        return False
                    if key not in seen:
                        seen.add(key)
                        candidates.append(value)
                        if not preferred and current_server and current_port > 0:
                            try:
                                if str(node.get("server", "") or "") == current_server and int(node.get("port", 0) or 0) == current_port:
                                    preferred = value
                            except:
                                pass
        except:
            return False
        if not candidates:
            return False
        self._vless_data["active_uri"] = preferred or candidates[0]
        return True

    def _iter_vless_nodes(self):
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                if isinstance(node, dict):
                    yield node
        except:
            pass
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if isinstance(node, dict):
                        yield node
        except:
            pass

    def _vless_ping_value(self, node):
        try:
            return int(node.get("ping", -1) or 0)
        except:
            return -1

    def _vless_ping_checked_at(self, node):
        try:
            return float(node.get("ping_checked_at", 0.0) or 0.0)
        except:
            return 0.0

    def _vless_ping_badge(self, node):
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC):
            return ""
        if ping <= 0 or ping >= 9999:
            return "нет"
        return f"{int(ping)} ms"

    def _append_green_tail(self, base_text, tail_text):
        text = str(base_text or "")
        tail = str(tail_text or "").strip()
        if not tail:
            return text
        try:
            from android.text import SpannableStringBuilder, Spanned
            from android.text.style import ForegroundColorSpan
            from org.telegram.ui.ActionBar import Theme

            builder = SpannableStringBuilder()
            builder.append(text)
            if text:
                builder.append("  ")
            start = int(builder.length())
            builder.append(tail)
            try:
                color = int(Theme.getColor(Theme.key_windowBackgroundWhiteGreenText))
            except:
                color = 0xFF26972C
            builder.setSpan(ForegroundColorSpan(color), start, int(builder.length()), int(Spanned.SPAN_EXCLUSIVE_EXCLUSIVE))
            return builder
        except:
            if text:
                return text + "  " + tail
            return tail

    def _probe_vless_node_latency(self, node, timeout_sec=None):
        try:
            payload = {
                "server": str(node.get("server", "") or ""),
                "port": int(node.get("port", 0) or 0),
            }
        except:
            payload = {"server": "", "port": 0}
        if timeout_sec is None:
            timeout_sec = float(VLESS_NODE_PING_TIMEOUT_SEC)
        return self._probe_proxy_latency(payload, timeout_sec=float(timeout_sec))

    def _vless_sort_key(self, node):
        checked_at = self._vless_ping_checked_at(node)
        ping = self._vless_ping_value(node)
        stale = checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC)
        if stale or ping < 0:
            rank = 2
            score = 999999
        elif ping <= 0 or ping >= 9999:
            rank = 1
            score = 999998
        else:
            rank = 0
            score = int(ping)
        try:
            name = str(node.get("name", "") or "").strip().lower()
        except:
            name = ""
        return (rank, score, name)

    def _sorted_vless_nodes(self, nodes):
        try:
            return sorted(list(nodes or []), key=self._vless_sort_key)
        except:
            return list(nodes or [])

    def _sort_all_vless_nodes_by_ping(self):
        changed = False
        try:
            manual = list(self._vless_data.get("manual", []) or [])
        except:
            manual = []
        manual_sorted = self._sorted_vless_nodes(manual)
        if manual_sorted != manual:
            self._vless_data["manual"] = manual_sorted
            changed = True
        return bool(changed)

    def _refresh_vless_node_pings(self, force=False, save=False, limit=None, nodes=None, refresh_each=False):
        nodes = list(self._iter_vless_nodes()) if nodes is None else list(nodes or [])
        nodes = [node for node in nodes if str((node or {}).get("kind", "") or "").strip().lower() != QWDTT_KIND]
        if not nodes:
            return {"changed": False, "checked": 0, "alive": 0}

        now = time.time()
        targets = []

        for node in nodes:
            checked_at = self._vless_ping_checked_at(node)
            if (not force) and checked_at and (now - checked_at) < float(VLESS_NODE_PING_REFRESH_SEC):
                continue
            targets.append(node)
            if limit is not None and len(targets) >= int(limit):
                break

        def _ping_one(node):
            changed = False
            dt = self._probe_vless_node_latency(node, timeout_sec=float(VLESS_NODE_PING_TIMEOUT_SEC))
            if dt is None:
                ping = 9999
                alive = 0
            else:
                ping = max(1, int(dt))
                alive = 1

            prev_ping = self._vless_ping_value(node)
            prev_checked = self._vless_ping_checked_at(node)
            node["ping"] = int(ping)
            node["ping_checked_at"] = float(time.time())
            if prev_ping != int(ping) or abs(float(node["ping_checked_at"]) - float(prev_checked)) > 0.001:
                changed = True
            return bool(changed), int(alive)

        checked = len(targets)
        alive = 0
        changed = False
        if targets:
            with ThreadPoolExecutor(max_workers=min(12, len(targets))) as ex:
                futures = [ex.submit(_ping_one, node) for node in targets]
                for future in as_completed(futures):
                    try:
                        item_changed, item_alive = future.result()
                    except:
                        item_changed, item_alive = False, 0
                    changed = bool(changed or item_changed)
                    alive += int(item_alive)
                    if refresh_each:
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))

        sorted_changed = self._sort_all_vless_nodes_by_ping()
        changed = bool(changed or sorted_changed)
        if save and changed:
            self._vless_save_data()
        return {"changed": bool(changed), "checked": int(checked), "alive": int(alive)}

    def _pick_fastest_vless_node(self, nodes=None):
        best = None
        best_ping = None
        source = self._iter_vless_nodes() if nodes is None else list(nodes or [])
        for node in source:
            if str((node or {}).get("kind", "") or "").strip().lower() == QWDTT_KIND:
                continue
            ping = self._vless_ping_value(node)
            checked_at = self._vless_ping_checked_at(node)
            if checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC):
                continue
            if ping <= 0 or ping >= 9999:
                continue
            if best is None or int(ping) < int(best_ping):
                best = node
                best_ping = ping
        return best

    def _run_vless_ping_test(self, nodes=None, refresh_each=False):
        nodes = list(self._iter_vless_nodes()) if nodes is None else list(nodes or [])
        nodes = [node for node in nodes if str((node or {}).get("kind", "") or "").strip().lower() != QWDTT_KIND]
        if not nodes:
            BulletinHelper.show_info("Нет узлов")
            return False
        BulletinHelper.show_info("Тестирую узлы...")

        def _worker():
            info = {"changed": False, "checked": 0, "alive": 0}
            try:
                info = self._refresh_vless_node_pings(force=True, save=True, nodes=nodes, refresh_each=refresh_each)
            finally:
                fastest = self._pick_fastest_vless_node(nodes)
                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
                if fastest is not None:
                    try:
                        name = str(fastest.get("name", "") or "").strip() or "Узел"
                    except:
                        name = "Узел"
                    ping = self._vless_ping_value(fastest)
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Самый быстрый: {name} ({int(ping)} ms)"))
                else:
                    checked = int(info.get("checked", 0) or 0)
                    alive = int(info.get("alive", 0) or 0)
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Пинг обновлен: {alive}/{checked}"))

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _is_vless_mode_selected(self):
        return self._get_connection_mode() == VLESS_KIND and bool(self._get_active_vless_uri())

    def _is_tgws_mode_selected(self):
        return self._get_connection_mode() == TGWS_KIND

    def _is_awg_mode_selected(self):
        return self._get_connection_mode() == AWG_KIND

    def _is_olcrtc_mode_selected(self):
        return self._get_connection_mode() == OLCRTC_KIND

    def _olcrtc_item_by_setting(self, key, items, default_index=0):
        try:
            idx = int(self.get_setting(key, int(default_index)))
        except:
            idx = int(default_index)
        try:
            if idx < 0 or idx >= len(items):
                idx = int(default_index)
        except:
            idx = int(default_index)
        try:
            return str(items[idx])
        except:
            return str(items[int(default_index)])

    def _olcrtc_carrier_index(self):
        try:
            idx = int(self.get_setting("olcrtc_carrier", 0))
            if 0 <= idx < len(OLCRTC_CARRIER_ITEMS):
                return idx
        except:
            pass
        return 0

    def _olcrtc_transport_index(self):
        try:
            idx = int(self.get_setting("olcrtc_transport", 0))
            if 0 <= idx < len(OLCRTC_TRANSPORT_ITEMS):
                return idx
        except:
            pass
        return 0

    def _get_olcrtc_carrier(self):
        return self._olcrtc_item_by_setting("olcrtc_carrier", OLCRTC_CARRIER_ITEMS, 0)

    def _get_olcrtc_transport(self):
        return self._olcrtc_item_by_setting("olcrtc_transport", OLCRTC_TRANSPORT_ITEMS, 0)

    def _olcrtc_carrier_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_CARRIER_ITEMS, OLCRTC_CARRIER_LABELS, 0)

    def _olcrtc_transport_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_TRANSPORT_ITEMS, OLCRTC_TRANSPORT_LABELS, 0)

    def _olcrtc_label_for_item(self, value, items, labels, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item or "").strip().lower() == target and idx < len(labels):
                    return str(labels[idx] or item)
        except:
            pass
        try:
            idx = int(default_index)
            if 0 <= idx < len(labels):
                return str(labels[idx] or items[idx])
        except:
            pass
        return str(value or "")

    def _olcrtc_current_labels(self):
        return self._olcrtc_carrier_label(self._get_olcrtc_carrier()), self._olcrtc_transport_label(self._get_olcrtc_transport())

    def _get_olcrtc_room_id(self):
        try:
            return str(self.get_setting("olcrtc_room_id", "") or "").strip()
        except:
            return ""

    def _get_olcrtc_client_id(self):
        try:
            return str(self.get_setting("olcrtc_client_id", "") or "").strip()
        except:
            return ""

    def _get_olcrtc_key_hex(self):
        try:
            return str(self.get_setting("olcrtc_key_hex", "") or "").strip()
        except:
            return ""

    def _olcrtc_config_error(self):
        if not self._get_olcrtc_room_id():
            return "Укажите room_id"
        if not self._get_olcrtc_client_id():
            return "Укажите client_id"
        key_hex = self._get_olcrtc_key_hex()
        if not key_hex:
            return "Укажите key_hex"
        if len(key_hex) != 64 or re.search(r"[^0-9a-fA-F]", key_hex):
            return "key_hex должен быть 64 hex"
        return ""

    def _is_olcrtc_config_ready(self):
        return not bool(self._olcrtc_config_error())

    def _olcrtc_profile_id_for(self, carrier, transport, room_id, client_id, key_hex):
        try:
            raw = "|".join([
                str(carrier or "").strip().lower(),
                str(transport or "").strip().lower(),
                str(room_id or "").strip(),
                str(client_id or "").strip(),
                str(key_hex or "").strip().lower(),
            ])
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        except:
            return str(int(time.time() * 1000))

    def _olcrtc_profile_name(self, profile):
        try:
            name = str(profile.get("name", "") or "").strip()
            if name:
                return name[:48]
            room_id = str(profile.get("room_id", "") or "").strip()
            client_id = str(profile.get("client_id", "") or "").strip()
            tail = room_id.rstrip("/").split("/")[-1] if room_id else ""
            base = tail or room_id or client_id or "olcRTC"
            if client_id and client_id not in base:
                base = "%s • %s" % (base, client_id)
            return base[:48] if base else "olcRTC"
        except:
            return "olcRTC"

    def _build_olcrtc_link_from_profile(self, profile):
        try:
            carrier = str(profile.get("carrier", "") or self._get_olcrtc_carrier()).strip().lower() or "jitsi"
            transport = str(profile.get("transport", "") or self._get_olcrtc_transport()).strip().lower()
            room_id = str(profile.get("room_id", "") or "").strip()
            client_id = str(profile.get("client_id", "") or "").strip()
            key_hex = str(profile.get("key_hex", "") or "").strip()
            query = {
                "transport": transport,
                "client_id": client_id,
                "key_hex": key_hex,
            }
            try:
                if int(profile.get("vp8_fps", 0) or 0) > 0:
                    query["vp8_fps"] = str(int(profile.get("vp8_fps", 0) or 0))
                if int(profile.get("vp8_batch_size", 0) or 0) > 0:
                    query["vp8_batch_size"] = str(int(profile.get("vp8_batch_size", 0) or 0))
            except:
                pass
            path = urllib.parse.quote(room_id, safe="")
            qs = urllib.parse.urlencode({k: v for k, v in query.items() if v})
            return "olcrtc://%s/%s%s" % (urllib.parse.quote(carrier, safe=""), path, ("?" + qs) if qs else "")
        except:
            return ""

    def _normalize_olcrtc_profile(self, profile):
        if not isinstance(profile, dict):
            return None
        carrier = str(profile.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
        transport = str(profile.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
        room_id = str(profile.get("room_id", "") or "").strip()
        client_id = str(profile.get("client_id", "") or "").strip()
        key_hex = str(profile.get("key_hex", "") or "").strip()
        if not room_id or not client_id or len(key_hex) != 64 or re.search(r"[^0-9a-fA-F]", key_hex):
            return None
        if carrier not in OLCRTC_CARRIER_ITEMS:
            carrier = self._get_olcrtc_carrier()
        if transport not in OLCRTC_TRANSPORT_ITEMS:
            transport = self._get_olcrtc_transport()
        out = {
            "id": str(profile.get("id", "") or "").strip(),
            "name": str(profile.get("name", "") or "").strip()[:64],
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
        }
        try:
            vp8_fps = int(profile.get("vp8_fps", 0) or 0)
            if vp8_fps > 0:
                out["vp8_fps"] = vp8_fps
        except:
            pass
        try:
            vp8_batch = int(profile.get("vp8_batch_size", profile.get("vp8_batch", 0)) or 0)
            if vp8_batch > 0:
                out["vp8_batch_size"] = vp8_batch
        except:
            pass
        if not out["id"]:
            out["id"] = self._olcrtc_profile_id_for(carrier, transport, room_id, client_id, key_hex)
        link = str(profile.get("link", "") or "").strip()
        out["link"] = link or self._build_olcrtc_link_from_profile(out)
        if not out["name"]:
            out["name"] = self._olcrtc_profile_name(out)
        return out

    def _sanitize_olcrtc_profiles(self, profiles):
        result = []
        seen = set()
        try:
            items = list(profiles or [])
        except:
            items = []
        for item in items:
            profile = self._normalize_olcrtc_profile(item)
            if not profile:
                continue
            pid = str(profile.get("id", "") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            result.append(profile)
            if len(result) >= 64:
                break
        return result

    def _find_olcrtc_profile(self, profile_id):
        target = str(profile_id or "").strip()
        if not target:
            return None
        for profile in list(self._olcrtc_profiles or []):
            try:
                if str(profile.get("id", "") or "") == target:
                    return profile
            except:
                pass
        return None

    def _active_olcrtc_profile(self):
        profile = self._find_olcrtc_profile(self._olcrtc_active_profile_id)
        if profile:
            return profile
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        if profiles:
            self._olcrtc_profiles = profiles
            self._olcrtc_active_profile_id = str(profiles[0].get("id", "") or "")
            return profiles[0]
        return None

    def _ensure_olcrtc_legacy_profile(self):
        if self._olcrtc_profiles:
            return
        try:
            profile = self._normalize_olcrtc_profile({
                "carrier": self._get_olcrtc_carrier(),
                "transport": self._get_olcrtc_transport(),
                "room_id": self._get_olcrtc_room_id(),
                "client_id": self._get_olcrtc_client_id(),
                "key_hex": self._get_olcrtc_key_hex(),
            })
        except:
            profile = None
        if profile:
            self._olcrtc_profiles = [profile]
            self._olcrtc_active_profile_id = str(profile.get("id", "") or "")

    def _set_olcrtc_legacy_settings_from_profile(self, profile):
        if not isinstance(profile, dict):
            return
        self._set_setting_value("olcrtc_carrier", self._olcrtc_index_for_item(profile.get("carrier"), OLCRTC_CARRIER_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(profile.get("transport"), OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_room_id", str(profile.get("room_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_client_id", str(profile.get("client_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_key_hex", str(profile.get("key_hex", "") or ""), reload_settings=False)

    def _upsert_olcrtc_profile(self, data, imported_link=""):
        if not isinstance(data, dict):
            return None
        link = str(imported_link or data.get("link", "") or "").strip()
        if not link.lower().startswith("olcrtc://"):
            link = ""
        profile = self._normalize_olcrtc_profile(dict(data, link=link))
        if not profile:
            return None
        profiles = [p for p in self._sanitize_olcrtc_profiles(self._olcrtc_profiles) if str(p.get("id", "") or "") != str(profile.get("id", "") or "")]
        profiles.insert(0, profile)
        self._olcrtc_profiles = profiles[:64]
        self._olcrtc_active_profile_id = str(profile.get("id", "") or "")
        self._set_olcrtc_legacy_settings_from_profile(profile)
        self._save_config()
        return profile

    def _activate_olcrtc_profile(self, profile_id, connect=True):
        profile = self._find_olcrtc_profile(profile_id)
        if not profile:
            BulletinHelper.show_error("Профиль не найден")
            return False
        self._olcrtc_active_profile_id = str(profile.get("id", "") or "")
        self._set_olcrtc_legacy_settings_from_profile(profile)
        self._set_connection_mode(OLCRTC_KIND)
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)
        if connect:
            self._restart_olcrtc_from_settings()
        return True

    def _delete_olcrtc_profile(self, profile_id):
        target = str(profile_id or "").strip()
        self._olcrtc_profiles = [p for p in self._sanitize_olcrtc_profiles(self._olcrtc_profiles) if str(p.get("id", "") or "") != target]
        if str(self._olcrtc_active_profile_id or "") == target:
            self._olcrtc_active_profile_id = str(self._olcrtc_profiles[0].get("id", "") or "") if self._olcrtc_profiles else ""
            if self._olcrtc_profiles:
                self._set_olcrtc_legacy_settings_from_profile(self._olcrtc_profiles[0])
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)

    def _active_olcrtc_link(self):
        legacy = self._normalize_olcrtc_profile({
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
        })
        profile = self._active_olcrtc_profile()
        if profile:
            try:
                profile_id = self._olcrtc_profile_id_for(profile.get("carrier"), profile.get("transport"), profile.get("room_id"), profile.get("client_id"), profile.get("key_hex"))
                legacy_id = self._olcrtc_profile_id_for(legacy.get("carrier"), legacy.get("transport"), legacy.get("room_id"), legacy.get("client_id"), legacy.get("key_hex")) if legacy else ""
                if legacy and profile_id != legacy_id:
                    return self._build_olcrtc_link_from_profile(legacy)
            except:
                pass
            return str(profile.get("link", "") or "") or self._build_olcrtc_link_from_profile(profile)
        return self._build_olcrtc_link_from_profile(legacy) if legacy else ""

    def _build_olcrtc_config_json(self):
        err = self._olcrtc_config_error()
        if err:
            return "", err
        payload = {
            "engine": "olcrtc",
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
            "socks_listen_host": VLESS_LOCAL_HOST,
            "socks_port": int(OLCRTC_LOCAL_PORT),
            "socks_user": "",
            "socks_pass": "",
            "dns_server": "1.1.1.1:53",
            "wait_ready_timeout_millis": int(float(OLCRTC_LOCAL_READY_TIMEOUT_SEC) * 1000),
        }
        try:
            profile = self._active_olcrtc_profile()
            current_id = self._olcrtc_profile_id_for(
                self._get_olcrtc_carrier(),
                self._get_olcrtc_transport(),
                self._get_olcrtc_room_id(),
                self._get_olcrtc_client_id(),
                self._get_olcrtc_key_hex(),
            )
            profile_id = self._olcrtc_profile_id_for(
                profile.get("carrier"),
                profile.get("transport"),
                profile.get("room_id"),
                profile.get("client_id"),
                profile.get("key_hex"),
            ) if profile else ""
            if profile and profile_id == current_id:
                vp8_fps = int(profile.get("vp8_fps", 0) or 0)
                vp8_batch = int(profile.get("vp8_batch_size", 0) or 0)
                if vp8_fps > 0:
                    payload["vp8_fps"] = vp8_fps
                if vp8_batch > 0:
                    payload["vp8_batch_size"] = vp8_batch
        except:
            pass
        try:
            return json.dumps(payload), ""
        except Exception as exc:
            return "", str(exc)

    def _olcrtc_status_label(self):
        room_id = self._get_olcrtc_room_id()
        client_id = self._get_olcrtc_client_id()
        if room_id and client_id:
            return "olcRTC: " + room_id[:32]
        if room_id:
            return "olcRTC: " + room_id[:32]
        return "olcRTC: не настроен"

    def _olcrtc_core_query_allowed(self, allow_connecting=False):
        if bool(getattr(self, "_olcrtc_prepare_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_start_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_stop_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        if (not bool(allow_connecting)) and bool(getattr(self, "_olcrtc_connecting", False)):
            return False
        try:
            return bool(self._olcrtc_core.is_available())
        except:
            return False

    def _safe_olcrtc_core_text(self, method_name, allow_connecting=False):
        if not self._olcrtc_core_query_allowed(allow_connecting=allow_connecting):
            return ""
        try:
            method = getattr(self._olcrtc_core, str(method_name or ""))
        except:
            return ""
        try:
            return str(method() or "").strip()
        except Exception as exc:
            try:
                self._olcrtc_last_log = "%s failed: %s" % (str(method_name or "native"), str(exc))
            except:
                pass
            return ""

    def _set_olcrtc_last_log(self, message, event="state", level="info", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_log = text

    def _set_olcrtc_last_error(self, message, event="error", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_error = text

    def _olcrtc_core_status_data(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            fallback_state = "background"
        elif bool(getattr(self, "_olcrtc_resume_checking", False)) or bool(getattr(self, "_olcrtc_health_stale", False)):
            fallback_state = "checking"
        elif bool(self._olcrtc_running):
            fallback_state = "ready"
        elif bool(getattr(self, "_olcrtc_connecting", False)):
            fallback_state = "handshake"
        else:
            fallback_state = "stopped"
        fallback = {
            "state": fallback_state,
            "message": str(getattr(self, "_olcrtc_last_error", "") or getattr(self, "_olcrtc_last_log", "") or "").strip(),
            "running": fallback_state == "ready",
        }
        if fallback_state in ("background", "checking"):
            return fallback
        try:
            raw = self._safe_olcrtc_core_text("status_json", allow_connecting=False)
            if not raw:
                return fallback
            data = json.loads(raw)
            if not isinstance(data, dict):
                return fallback
            state = str(data.get("state", "") or "").strip().lower()
            if not state:
                return fallback
            data["state"] = state
            return data
        except:
            return fallback

    def _olcrtc_status_presentation(self):
        data = self._olcrtc_core_status_data()
        state = str(data.get("state", "") or "stopped").strip().lower()
        labels = {
            "starting": "olcRTC: запуск",
            "handshake": "olcRTC: handshake",
            "ready": "olcRTC: подключен",
            "running": "olcRTC: подключен",
            "background": "olcRTC: в фоне",
            "checking": "olcRTC: проверка",
            "stopping": "olcRTC: остановка",
            "stopped": "olcRTC: выключен",
            "error": "olcRTC: ошибка",
        }
        text = labels.get(state, "olcRTC: " + state[:24])
        message = str(data.get("message", "") or "").strip()
        carrier_label, transport_label = self._olcrtc_current_labels()
        subtext = message[:120] if message else "%s / %s" % (carrier_label, transport_label)
        return text, subtext, state

    def _olcrtc_local_ready(self, port, check_tunnel=False, reason="health"):
        try:
            target_port = int(port or 0)
        except:
            target_port = 0
        if target_port <= 0:
            return False
        if not _check_vless_port(target_port):
            return False
        if not _check_vless_socks_ready(target_port, timeout=0.5):
            return False
        if not bool(check_tunnel):
            return True
        ok = _check_olcrtc_tunnel_ready(target_port, timeout=float(OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC))
        if not ok:
            pass
        return bool(ok)

    def _olcrtc_state_needs_restart(self, core_state):
        state = str(core_state or "").strip().lower()
        return state in ("error", "stopped") and (not bool(getattr(self, "_olcrtc_connecting", False)))

    def _olcrtc_try_next_profile(self, reason=""):
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        if len(profiles) < 2:
            return False
        active_id = str(self._olcrtc_active_profile_id or "")
        index = 0
        for idx, profile in enumerate(profiles):
            if str(profile.get("id", "") or "") == active_id:
                index = idx
                break
        next_profile = profiles[(index + 1) % len(profiles)]
        next_id = str(next_profile.get("id", "") or "")
        if not next_id or next_id == active_id:
            return False
        self._olcrtc_profiles = profiles
        self._olcrtc_active_profile_id = next_id
        self._set_olcrtc_legacy_settings_from_profile(next_profile)
        self._set_connection_mode(OLCRTC_KIND)
        self._save_config()
        self._set_olcrtc_last_log("next profile after " + str(reason or "failure"), event="profile_failover")
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        self._ensure_olcrtc_core_then(self._olcrtc_connect)
        return True

    def _should_run_vless(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == VLESS_KIND and bool(self._get_active_vless_uri())

    def _should_run_tgws(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == TGWS_KIND

    def _should_run_awg(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == AWG_KIND and bool(str(self._awg_conf_content or "").strip())

    def _should_run_olcrtc(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == OLCRTC_KIND and self._is_olcrtc_config_ready()


    def _normalize_local_socks_owner(self, owner):
        try:
            value = str(owner or "").strip().lower()
        except:
            value = ""
        if value in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            return value
        return ""

    def _current_mode_local_socks_owner(self):
        mode = self._get_connection_mode()
        return self._normalize_local_socks_owner(mode)

    def _local_socks_owner_can_apply(self, owner):
        target = self._normalize_local_socks_owner(owner)
        if target == VLESS_KIND:
            return self._should_run_vless()
        if target == TGWS_KIND:
            return self._should_run_tgws()
        if target == AWG_KIND:
            return self._should_run_awg()
        if target == OLCRTC_KIND:
            return self._should_run_olcrtc()
        return False

    def _local_socks_owner_snapshot(self):
        try:
            with self._local_socks_lock:
                return str(self._local_socks_owner or ""), int(self._local_socks_port or 0)
        except:
            return "", 0

    def _get_plugins_proxy_enabled(self):
        try:
            return bool(self.get_setting("proxy_plugins_via_greenpass", False))
        except:
            return False

    def _on_plugins_proxy_changed(self, enabled):
        val = bool(enabled)
        try:
            self.set_setting("proxy_plugins_via_greenpass", val, reload_settings=False)
        except:
            pass
        self._sync_plugin_proxy_bridge()
        self._refresh_settings_without_reopen()

    def _greenpass_socks_endpoint(self):
        if not bool(self._is_plugin_proxy_enabled()):
            self._plugin_proxy_last_error = "GreenPass proxy is off"
            return None
        if self._is_proxy_policy_suspended():
            self._plugin_proxy_last_error = "GreenPass proxy is suspended by network policy"
            return None

        mode = self._get_connection_mode()
        if mode == TGWS_KIND:
            self._plugin_proxy_last_error = "TGWS is Telegram-only"
            return None

        owner, local_port = self._local_socks_owner_snapshot()
        local_sources = {
            VLESS_KIND: (bool(self._vless_running), int(self._vless_port or 0)),
            AWG_KIND: (bool(self._awg_running), int(self._awg_port or 0)),
            OLCRTC_KIND: (bool(self._olcrtc_running), int(self._olcrtc_port or 0)),
        }
        if mode in local_sources:
            running, port = local_sources.get(mode)
            if owner == mode and int(local_port or 0) > 0:
                port = int(local_port)
            if running and port > 0:
                self._plugin_proxy_last_error = ""
                username = self._vless_socks_username if mode == VLESS_KIND else ""
                password = self._vless_socks_password if mode == VLESS_KIND else ""
                return {
                    "host": VLESS_LOCAL_HOST,
                    "port": int(port),
                    "username": str(username or ""),
                    "password": str(password or ""),
                    "source": str(mode),
                }
            self._plugin_proxy_last_error = "SOCKS is not ready"
            return None

        try:
            enabled = bool(SharedConfig.isProxyEnabled())
        except:
            try:
                enabled = bool(MessagesController.getGlobalMainSettings().getBoolean("proxy_enabled", False))
            except:
                enabled = False
        if not enabled:
            self._plugin_proxy_last_error = "Telegram proxy is off"
            return None

        try:
            proxy = SharedConfig.currentProxy
        except:
            proxy = None
        if proxy is None:
            self._plugin_proxy_last_error = "No active proxy"
            return None

        try:
            secret = str(getattr(proxy, "secret", "") or "")
            if secret:
                self._plugin_proxy_last_error = "MTProto is Telegram-only"
                return None
            host = str(getattr(proxy, "address", "") or "").strip()
            port = int(getattr(proxy, "port", 0) or 0)
            if not host or port <= 0:
                self._plugin_proxy_last_error = "No SOCKS endpoint"
                return None
            self._plugin_proxy_last_error = ""
            return {
                "host": host,
                "port": port,
                "username": str(getattr(proxy, "username", "") or ""),
                "password": str(getattr(proxy, "password", "") or ""),
                "source": "proxy",
            }
        except:
            self._plugin_proxy_last_error = "Bad SOCKS endpoint"
            return None

    def _plugin_proxy_endpoint(self):
        if not bool(self._get_plugins_proxy_enabled()):
            self._plugin_proxy_last_error = ""
            return None
        return self._greenpass_socks_endpoint()

    def _plugin_proxy_endpoint_key(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return ""
        try:
            return "%s:%s:%s:%s" % (
                str(ep.get("source", "") or ""),
                str(ep.get("host", "") or ""),
                int(ep.get("port", 0) or 0),
                "auth" if (ep.get("username") or ep.get("password")) else "noauth",
            )
        except:
            return ""

    def _plugin_proxy_url(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return ""
        try:
            host = str(ep.get("host", "") or "")
            port = int(ep.get("port", 0) or 0)
            user = str(ep.get("username", "") or "")
            password = str(ep.get("password", "") or "")
            auth = ""
            if user or password:
                auth = "%s:%s@" % (
                    urllib.parse.quote(user, safe=""),
                    urllib.parse.quote(password, safe=""),
                )
            return "socks5h://%s%s:%s" % (auth, host, port)
        except:
            return ""

    def _install_plugin_proxy_api(self):
        module = sys.modules.get(GREENPASS_PROXY_API_MODULE)
        if module is None:
            module = types.ModuleType(GREENPASS_PROXY_API_MODULE)
            sys.modules[GREENPASS_PROXY_API_MODULE] = module
        module._plugin = self

        def _current():
            plugin = getattr(module, "_plugin", None)
            if plugin is None:
                raise RuntimeError("GreenPass plugin is not loaded")
            return plugin

        def endpoint():
            ep = _current()._plugin_proxy_endpoint()
            return dict(ep or {})

        def is_available():
            return bool(_current()._plugin_proxy_endpoint())

        def requests_proxies():
            url = _current()._plugin_proxy_url()
            if not url:
                return {}
            return {"http": url, "https": url}

        def status():
            plugin = _current()
            ep = plugin._plugin_proxy_endpoint()
            return {
                "enabled": bool(plugin._get_plugins_proxy_enabled()),
                "available": bool(ep),
                "endpoint": dict(ep or {}),
                "proxy_url": plugin._plugin_proxy_url(ep),
                "error": str(plugin._plugin_proxy_last_error or ""),
            }

        module.endpoint = endpoint
        module.is_available = is_available
        module.requests_proxies = requests_proxies
        module.status = status
        module.API_VERSION = 1
        return module

    def _plugin_proxy_should_bypass_host(self, host, endpoint=None):
        try:
            h = str(host or "").strip().strip("[]").lower()
        except:
            h = ""
        if not h:
            return True
        if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        if h.startswith("127."):
            return True
        try:
            ep_host = str((endpoint or {}).get("host", "") or "").strip().strip("[]").lower()
            if ep_host and h == ep_host:
                return True
        except:
            pass
        return False

    def _plugin_proxy_is_greenpass_call(self):
        try:
            target = os.path.abspath(str(self._plugin_file_path or "")).replace("\\", "/").lower()
        except:
            target = ""
        try:
            target_name = os.path.basename(target)
        except:
            target_name = ""
        if not target and not target_name:
            return False

        ignored = {
            "_plugin_proxy_is_greenpass_call",
            "patched_socket_create_connection",
            "patched_urllib3_create_connection",
            "_plugin_proxy_socks_create_connection",
            "_plugin_proxy_recv_exact",
        }
        try:
            frame = sys._getframe(1)
        except:
            frame = None

        depth = 0
        while frame is not None and depth < 48:
            try:
                code = frame.f_code
                name = str(code.co_name or "")
                filename = os.path.abspath(str(code.co_filename or "")).replace("\\", "/").lower()
                filename_name = os.path.basename(filename)
                if name not in ignored and ((target and filename == target) or (target_name and filename_name == target_name)):
                    return True
            except:
                pass
            try:
                frame = frame.f_back
            except:
                frame = None
            depth += 1
        return False

    def _plugin_proxy_recv_exact(self, sock, size):
        chunks = []
        remain = int(size or 0)
        while remain > 0:
            chunk = sock.recv(remain)
            if not chunk:
                raise OSError("SOCKS proxy closed")
            chunks.append(chunk)
            remain -= len(chunk)
        return b"".join(chunks)

    def _plugin_proxy_socks_create_connection(self, endpoint, address, timeout=None, source_address=None):
        host, port = address
        proxy_host = str(endpoint.get("host", "") or "")
        proxy_port = int(endpoint.get("port", 0) or 0)
        if not proxy_host or proxy_port <= 0:
            raise OSError("GreenPass SOCKS endpoint is unavailable")

        original = self._plugin_proxy_originals.get("socket.create_connection") or socket.create_connection
        sock = original((proxy_host, proxy_port), timeout, source_address)
        try:
            user = str(endpoint.get("username", "") or "")
            password = str(endpoint.get("password", "") or "")
            if user or password:
                sock.sendall(b"\x05\x01\x02")
                reply = self._plugin_proxy_recv_exact(sock, 2)
                if reply != b"\x05\x02":
                    raise OSError("SOCKS auth method rejected")
                ub = user.encode("utf-8")[:255]
                pb = password.encode("utf-8")[:255]
                sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
                auth = self._plugin_proxy_recv_exact(sock, 2)
                if len(auth) != 2 or auth[1] != 0:
                    raise OSError("SOCKS auth rejected")
            else:
                sock.sendall(b"\x05\x01\x00")
                reply = self._plugin_proxy_recv_exact(sock, 2)
                if reply != b"\x05\x00":
                    raise OSError("SOCKS no-auth rejected")

            try:
                addr = socket.inet_pton(socket.AF_INET, str(host))
                atyp = b"\x01"
                host_part = addr
            except:
                try:
                    addr = socket.inet_pton(socket.AF_INET6, str(host))
                    atyp = b"\x04"
                    host_part = addr
                except:
                    hb = str(host).encode("idna")[:255]
                    atyp = b"\x03"
                    host_part = bytes([len(hb)]) + hb

            req = b"\x05\x01\x00" + atyp + host_part + struct.pack("!H", int(port) & 0xFFFF)
            sock.sendall(req)
            head = self._plugin_proxy_recv_exact(sock, 4)
            if len(head) != 4 or head[1] != 0:
                code = head[1] if len(head) > 1 else 0xFF
                raise OSError("SOCKS connect failed: 0x%02x" % code)
            atyp = head[3]
            if atyp == 1:
                self._plugin_proxy_recv_exact(sock, 4)
            elif atyp == 3:
                ln = self._plugin_proxy_recv_exact(sock, 1)[0]
                self._plugin_proxy_recv_exact(sock, ln)
            elif atyp == 4:
                self._plugin_proxy_recv_exact(sock, 16)
            else:
                raise OSError("SOCKS reply has invalid address type")
            self._plugin_proxy_recv_exact(sock, 2)
            return sock
        except:
            try:
                sock.close()
            except:
                pass
            raise

    def _install_python_http_proxy_patch(self):
        if self._plugin_proxy_python_patch_installed:
            return True
        endpoint = self._plugin_proxy_endpoint()
        if not endpoint:
            return False

        plugin = self
        originals = self._plugin_proxy_originals
        originals["socket.create_connection"] = socket.create_connection

        def patched_socket_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
            ep = plugin._plugin_proxy_endpoint()
            try:
                host = address[0]
            except:
                host = ""
            if ep and not plugin._plugin_proxy_is_greenpass_call() and not plugin._plugin_proxy_should_bypass_host(host, ep):
                try:
                    return plugin._plugin_proxy_socks_create_connection(ep, address, timeout, source_address)
                except OSError:
                    return originals["socket.create_connection"](address, timeout, source_address, *args, **kwargs)
            return originals["socket.create_connection"](address, timeout, source_address, *args, **kwargs)

        socket.create_connection = patched_socket_create_connection

        try:
            import urllib3.util.connection as urllib3_connection
            originals["urllib3.util.connection.create_connection"] = urllib3_connection.create_connection

            def patched_urllib3_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
                ep = plugin._plugin_proxy_endpoint()
                try:
                    host = address[0]
                except:
                    host = ""
                if ep and not plugin._plugin_proxy_is_greenpass_call() and not plugin._plugin_proxy_should_bypass_host(host, ep):
                    try:
                        conn = plugin._plugin_proxy_socks_create_connection(ep, address, timeout, source_address)
                    except OSError:
                        return originals["urllib3.util.connection.create_connection"](address, timeout, source_address, socket_options)
                    try:
                        for opt in list(socket_options or []):
                            conn.setsockopt(*opt)
                    except:
                        pass
                    return conn
                return originals["urllib3.util.connection.create_connection"](address, timeout, source_address, socket_options)

            urllib3_connection.create_connection = patched_urllib3_create_connection
        except:
            pass

        self._plugin_proxy_python_patch_installed = True
        return True

    def _remove_python_http_proxy_patch(self):
        if not self._plugin_proxy_python_patch_installed:
            return
        originals = self._plugin_proxy_originals
        try:
            original = originals.get("socket.create_connection")
            if original is not None:
                socket.create_connection = original
        except:
            pass
        try:
            original = originals.get("urllib3.util.connection.create_connection")
            if original is not None:
                import urllib3.util.connection as urllib3_connection
                urllib3_connection.create_connection = original
        except:
            pass
        self._plugin_proxy_python_patch_installed = False

    def _frida_plugin_proxy_script(self, endpoint):
        host = str(endpoint.get("host", "") or "")
        port = int(endpoint.get("port", 0) or 0)
        return """
Java.perform(function () {
  var HOST = %s;
  var PORT = %s;
  var URL = Java.use('java.net.URL');
  var Proxy = Java.use('java.net.Proxy');
  var ProxyType = Java.use('java.net.Proxy$Type');
  var InetSocketAddress = Java.use('java.net.InetSocketAddress');
  var System = Java.use('java.lang.System');
  var proxy = Proxy.$new(ProxyType.valueOf('SOCKS'), InetSocketAddress.$new(HOST, PORT));

  function bypass(host) {
    host = String(host || '').toLowerCase();
    return !host || host === 'localhost' || host === '127.0.0.1' || host === '::1' ||
      host.indexOf('127.') === 0 || host === String(HOST).toLowerCase();
  }

  System.setProperty('socksProxyHost', HOST);
  System.setProperty('socksProxyPort', String(PORT));

  var openNoProxy = URL.openConnection.overload();
  var openWithProxy = URL.openConnection.overload('java.net.Proxy');
  openNoProxy.implementation = function () {
    var host = '';
    try { host = String(this.getHost() || ''); } catch (_) {}
    if (bypass(host)) {
      return openNoProxy.call(this);
    }
    return openWithProxy.call(this, proxy);
  };

  fridaGadget.onDispose(function () {
    try {
      System.clearProperty('socksProxyHost');
      System.clearProperty('socksProxyPort');
    } catch (_) {}
  });
});
""" % (json.dumps(host), int(port))

    def _register_frida_plugin_proxy_hook(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return False
        key = self._plugin_proxy_endpoint_key(ep)
        try:
            import frida_gadget_api
        except Exception:
            self._plugin_proxy_frida_registered = False
            return False
        try:
            if self._plugin_proxy_frida_registered and self._plugin_proxy_frida_endpoint_key == key:
                if hasattr(frida_gadget_api, "set_plugin_active"):
                    frida_gadget_api.set_plugin_active(GREENPASS_PLUGIN_PROXY_FRIDA_ID, True, reason="greenpass_proxy", autoload=True)
                return True
            result = frida_gadget_api.register_script(
                GREENPASS_PLUGIN_PROXY_FRIDA_ID,
                self._frida_plugin_proxy_script(ep),
                name=GREENPASS_PLUGIN_PROXY_NAME,
                replace=True,
                autoload=True,
            )
            self._plugin_proxy_frida_registered = bool(result.get("ok", True))
            self._plugin_proxy_frida_endpoint_key = key
            return bool(self._plugin_proxy_frida_registered)
        except Exception as exc:
            self._plugin_proxy_frida_registered = False
            self._plugin_proxy_last_error = str(exc)[:180]
            return False

    def _deactivate_frida_plugin_proxy_hook(self):
        try:
            import frida_gadget_api
            if hasattr(frida_gadget_api, "set_plugin_active"):
                frida_gadget_api.set_plugin_active(GREENPASS_PLUGIN_PROXY_FRIDA_ID, False, reason="greenpass_proxy_off", autoload=True)
        except:
            pass
        self._plugin_proxy_frida_registered = False
        self._plugin_proxy_frida_endpoint_key = ""

    def _sync_plugin_proxy_bridge(self):
        try:
            self._install_plugin_proxy_api()
        except:
            pass
        endpoint = self._plugin_proxy_endpoint()
        if bool(endpoint):
            self._install_python_http_proxy_patch()
            self._register_frida_plugin_proxy_hook(endpoint)
        else:
            self._remove_python_http_proxy_patch()
            self._deactivate_frida_plugin_proxy_hook()
    def _proxy_key(self, server, port, secret, username="", password=""):
        try:
            srv = str(server or "")
        except:
            srv = ""
        try:
            prt = int(port or 0)
        except:
            prt = 0
        try:
            sec = str(secret or "")
        except:
            sec = ""
        try:
            usr = str(username or "")
        except:
            usr = ""
        try:
            pwd = str(password or "")
        except:
            pwd = ""
        if usr or pwd:
            return f"{srv}:{prt}:{sec}:{usr}:{pwd}"
        return f"{srv}:{prt}:{sec}"

    def _provider_count(self):
        try:
            return len(PROXY_PROVIDER_ITEMS)
        except:
            return 0

    def _get_selected_provider(self):
        default_idx = 0
        try:
            idx = int(self.get_setting("proxy_provider", default_idx))
        except:
            idx = default_idx
        if idx < 0 or idx >= self._provider_count():
            idx = default_idx
        return idx

    def _get_provider_auto(self):
        try:
            return bool(self.get_setting("proxy_provider_auto", True))
        except:
            return True

    def _set_selected_provider(self, idx):
        try:
            self._set_setting_value("proxy_provider", int(idx), reload_settings=True)
        except:
            pass

    def _set_provider_auto(self, enabled):
        try:
            self._set_setting_value("proxy_provider_auto", bool(enabled), reload_settings=True)
        except:
            pass

    def _is_plugin_proxy_enabled(self):
        try:
            raw = self.get_setting("use_proxy", None)
            if raw is not None:
                return bool(raw)
        except:
            pass
        try:
            return bool(self._desired_use_proxy)
        except:
            pass
        return bool(_is_tg_proxy_enabled())

    def _enable_plugin_proxy_flag(self):
        self._desired_use_proxy = True
        self._save_config()
        try:
            self._set_setting_value("use_proxy", True, reload_settings=False)
        except:
            pass


    def _is_dont_use_with_vpn_enabled(self):
        try:
            return bool(self.get_setting("dont_use_with_vpn", True))
        except:
            return True

    def _normalize_wifi_ssid(self, value):
        try:
            ssid = str(value or "").strip()
        except:
            return ""
        if len(ssid) >= 2 and ssid[0] == '"' and ssid[-1] == '"':
            ssid = ssid[1:-1]
        ssid = ssid.strip()
        if not ssid or ssid.lower() in ("<unknown ssid>", "unknown ssid", "0x"):
            return ""
        return ssid[:64]

    def _sanitize_excluded_wifi_ssids(self, values):
        if not isinstance(values, (list, tuple)):
            values = []
        result = []
        seen = set()
        for value in values:
            ssid = self._normalize_wifi_ssid(value)
            if not ssid or ssid in seen:
                continue
            seen.add(ssid)
            result.append(ssid)
            if len(result) >= 64:
                break
        return result

    def _sanitize_wifi_mode_rules(self, values):
        if not isinstance(values, dict):
            return {}
        result = {}
        for raw_ssid, raw_mode in values.items():
            ssid = self._normalize_wifi_ssid(raw_ssid)
            mode = str(raw_mode or "")
            if not ssid or mode not in ("off", "proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
                continue
            result[ssid] = mode
            if len(result) >= 64:
                break
        return result

    def _active_wifi_state(self):
        try:
            ctx = ApplicationLoader.applicationContext
            cm = ctx.getSystemService("connectivity")
            active = cm.getActiveNetwork() if cm is not None else None
            networks = [active] if active is not None else []
            try:
                for network in list(cm.getAllNetworks() or []):
                    if network not in networks:
                        networks.append(network)
            except:
                pass
            wifi_caps = []
            for network in networks:
                try:
                    caps = cm.getNetworkCapabilities(network)
                    if caps is not None and bool(caps.hasTransport(1)):
                        wifi_caps.append(caps)
                except:
                    pass
            if not wifi_caps:
                self._current_wifi_ssid_cache = ""
                return False, ""

            candidates = []
            for caps in wifi_caps:
                try:
                    candidates.append(caps.getTransportInfo())
                except:
                    pass
            try:
                wifi = ctx.getApplicationContext().getSystemService("wifi")
                candidates.append(wifi.getConnectionInfo() if wifi is not None else None)
            except:
                pass
            for info in candidates:
                if info is None:
                    continue
                try:
                    ssid = self._normalize_wifi_ssid(info.getSSID())
                except:
                    ssid = ""
                if ssid:
                    self._current_wifi_ssid_cache = ssid
                    return True, ssid
            self._current_wifi_ssid_cache = ""
            return True, ""
        except:
            self._current_wifi_ssid_cache = ""
            return False, ""

    def _is_proxy_policy_suspended(self):
        return bool(
            getattr(self, "_proxy_suspended_by_vpn", False)
            or getattr(self, "_proxy_suspended_by_wifi", False)
        )

    def _is_system_vpn_active(self):
        try:
            ctx = ApplicationLoader.applicationContext
            cm = ctx.getSystemService("connectivity")
            if cm is None:
                return False
            network = cm.getActiveNetwork()
            if network is None:
                return False
            caps = cm.getNetworkCapabilities(network)
            return bool(caps is not None and caps.hasTransport(4))
        except:
            pass
        return False

    def _apply_vpn_policy(self):
        try:
            if not self._vpn_policy_lock.acquire(blocking=False):
                return
        except:
            return
        try:
            was_suspended = self._is_proxy_policy_suspended()
            previous_vpn = bool(self._proxy_suspended_by_vpn)
            previous_wifi = bool(self._proxy_suspended_by_wifi)
            wants_proxy = bool(self._desired_use_proxy) or bool(self._is_plugin_proxy_enabled())
            wifi_active, ssid = self._active_wifi_state()
            rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
            self._wifi_mode_rules = rules
            self._excluded_wifi_ssids = [name for name, mode in rules.items() if mode == "off"]
            rule_mode = rules.get(ssid, "") if wifi_active and ssid else ""
            previous_rule_ssid = str(getattr(self, "_wifi_rule_active_ssid", "") or "")
            self._wifi_rule_active_ssid = ssid if rule_mode else ""
            target_mode = ""
            if rule_mode and rule_mode != "off":
                target_mode = rule_mode
            elif previous_rule_ssid and not rule_mode:
                target_mode = self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode)
            self._proxy_suspended_by_vpn = bool(
                wants_proxy and self._is_dont_use_with_vpn_enabled() and self._is_system_vpn_active()
            )
            self._proxy_suspended_by_wifi = bool(
                wants_proxy and rule_mode == "off"
            )
            is_suspended = self._is_proxy_policy_suspended()
            if target_mode and target_mode != self._get_connection_mode():
                self._switch_mode_for_wifi_rule(
                    target_mode,
                    connect=bool(
                        wants_proxy
                        and not is_suspended
                        and not was_suspended
                        and self._thread is not None
                    ),
                )
            changed = (
                previous_vpn != bool(self._proxy_suspended_by_vpn)
                or previous_wifi != bool(self._proxy_suspended_by_wifi)
            )
            if is_suspended and not was_suspended:
                message = (
                    "WIFI %s — прокси приостановлен" % ssid
                    if self._proxy_suspended_by_wifi
                    else "VPN активен — прокси приостановлен"
                )
                self._suspend_proxy_for_policy(message)
            elif was_suspended and not is_suspended:
                self._resume_proxy_after_policy()
            elif changed:
                run_on_ui_thread(self._refresh_settings_without_reopen)
        finally:
            try:
                self._vpn_policy_lock.release()
            except:
                pass

    def _switch_mode_for_wifi_rule(self, mode, connect=True):
        target = self._normalize_proxy_mode(mode, self._wifi_default_mode)
        self._wifi_rule_switching = True
        try:
            self._set_connection_mode(target)
        finally:
            self._wifi_rule_switching = False
        if not connect:
            self._refresh_mode_summary()
            run_on_ui_thread(self._refresh_settings_without_reopen)
            return
        switch = {
            "proxy": self._switch_to_proxy_mode,
            VLESS_KIND: self._switch_to_vless_mode,
            TGWS_KIND: self._switch_to_tgws_mode,
            AWG_KIND: self._switch_to_awg_mode,
            OLCRTC_KIND: self._switch_to_olcrtc_mode,
        }[target]
        try:
            threading.Thread(target=lambda: switch(False), daemon=True).start()
        except:
            switch(False)
        self._refresh_mode_summary()
        run_on_ui_thread(self._refresh_settings_without_reopen)

    def _suspend_proxy_for_policy(self, message):
        self._save_config()
        for disconnect in (self._vless_disconnect_with_reason, self._tgws_disconnect_with_reason, self._awg_disconnect_with_reason, self._olcrtc_disconnect_with_reason):
            try:
                disconnect("network_policy_suspend", silent=True)
            except:
                pass
        try:
            _set_tg_proxy_enabled(False)
        except:
            pass
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        run_on_ui_thread(self._refresh_settings_without_reopen)
        run_on_ui_thread(lambda message=message: BulletinHelper.show_info(message))

    def _resume_proxy_after_policy(self):
        self._save_config()
        if not bool(self._desired_use_proxy):
            run_on_ui_thread(self._refresh_settings_without_reopen)
            return
        try:
            if self._is_vless_mode_selected():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            elif self._is_tgws_mode_selected():
                self._tgws_connect()
            elif self._is_awg_mode_selected():
                self._ensure_awg_core_then(self._awg_connect)
            elif self._is_olcrtc_mode_selected():
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
            else:
                _set_tg_proxy_enabled(True)
                try:
                    if SharedConfig.currentProxy is None or (not self._is_proxy_connection_ready()):
                        self._force_update()
                except:
                    self._force_update()
        except:
            pass
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        run_on_ui_thread(self._refresh_settings_without_reopen)
        run_on_ui_thread(lambda: BulletinHelper.show_info("Прокси восстановлен"))

    def _on_dont_use_with_vpn_changed(self, enabled):
        try:
            self.set_setting("dont_use_with_vpn", bool(enabled), reload_settings=False)
        except:
            pass
        threading.Thread(target=self._apply_vpn_policy, daemon=True).start()

    def _excluded_wifi_menu_subtext(self):
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        _, current = self._active_wifi_state()
        if current and current in rules:
            return "%d сет. • %s" % (len(rules), self._wifi_rule_mode_title(rules[current]))
        return "%d сет." % len(rules) if rules else "Не настроено"

    def _after_excluded_wifi_change(self):
        self._wifi_mode_rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        self._excluded_wifi_ssids = [
            ssid for ssid, mode in self._wifi_mode_rules.items() if mode == "off"
        ]
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        threading.Thread(target=self._apply_vpn_policy, daemon=True).start()

    def _wifi_rule_mode_title(self, mode):
        return "Без прокси" if str(mode or "") == "off" else self._settings_mode_title(mode)

    def _set_wifi_rule(self, value, mode):
        ssid = self._normalize_wifi_ssid(value)
        if not ssid:
            BulletinHelper.show_error("Укажите SSID сети")
            return False
        target = str(mode or "")
        if target not in ("off", "proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            return False
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        rules[ssid] = target
        self._wifi_mode_rules = rules
        self._after_excluded_wifi_change()
        BulletinHelper.show_success("Правило WIFI сохранено")
        return True

    def _add_current_wifi_to_excluded(self):
        wifi_active, ssid = self._active_wifi_state()
        if not ssid:
            message = "SSID недоступен" if wifi_active else "WIFI не подключён"
            BulletinHelper.show_error(message)
            return False
        return self._open_wifi_rule_picker(ssid)

    def _create_themed_dialog_input(self, activity, hint=""):
        try:
            from org.telegram.ui.Components import EditTextBoldCursor
            field = EditTextBoldCursor(activity)
            field.setBackground(None)
        except:
            from android.widget import EditText as AndroidEditText
            field = AndroidEditText(activity)
        text_color = Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)
        hint_color = Theme.getColor(Theme.key_windowBackgroundWhiteHintText)
        accent_color = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)
        field.setTextColor(text_color)
        field.setHintTextColor(hint_color)
        field.setHint(str(hint or ""))
        field.setSingleLine(True)
        field.setPadding(
            0, AndroidUtilities.dp(8), 0, AndroidUtilities.dp(8),
        )
        try:
            field.setCursorColor(accent_color)
            field.setLineColors(
                Theme.getColor(Theme.key_dialogInputField),
                Theme.getColor(Theme.key_dialogInputFieldActivated),
                Theme.getColor(Theme.key_text_RedBold),
            )
        except:
            pass
        layout = LinearLayout(activity)
        layout.setOrientation(LinearLayout.VERTICAL)
        layout.setPadding(
            AndroidUtilities.dp(24), 0,
            AndroidUtilities.dp(24), AndroidUtilities.dp(8),
        )
        layout.addView(field, LinearLayout.LayoutParams(-1, -2))
        return field, layout

    def _prompt_add_excluded_wifi(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False
        try:
            from android.text import InputFilter
            field, field_view = self._create_themed_dialog_input(activity, "SSID")
            field.setFilters([InputFilter.LengthFilter(64)])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Добавить WIFI сеть")
            builder.set_view(field_view)

            def _save(dlg, which):
                ssid = self._normalize_wifi_ssid(field.getText())
                if not ssid:
                    BulletinHelper.show_error("Укажите SSID сети")
                    return
                try:
                    dlg.dismiss()
                except:
                    pass
                self._open_wifi_rule_picker(ssid)

            builder.set_positive_button("Добавить", _save)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.show()
            return True
        except:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False

    def _remove_excluded_wifi_ssid(self, value):
        ssid = self._normalize_wifi_ssid(value)
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        if ssid not in rules:
            return False
        rules.pop(ssid, None)
        self._wifi_mode_rules = rules
        self._after_excluded_wifi_change()
        return True

    def _open_wifi_rule_picker(self, value):
        ssid = self._normalize_wifi_ssid(value)
        if not ssid:
            return False
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            return False
        choices = [("off", "Без прокси")] + list(self._settings_mode_choices())
        if ssid in self._sanitize_wifi_mode_rules(self._wifi_mode_rules):
            choices.append(("delete", "Удалить правило"))
        modes = [mode for mode, label in choices]
        labels = [label for mode, label in choices]
        builder = AlertDialogBuilder(activity)
        builder.set_title(ssid)

        def _select(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            try:
                mode = modes[int(which)]
            except:
                return
            if mode == "delete":
                self._remove_excluded_wifi_ssid(ssid)
            else:
                self._set_wifi_rule(ssid, mode)

        builder.set_items(labels, _select)
        builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
        builder.show()
        return True

    def _create_excluded_wifi_subpage(self):
        wifi_active, current = self._active_wifi_state()
        current_text = current or ("SSID недоступен" if wifi_active else "WIFI не подключён")
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        items = [
            Header(text="Исключённые WIFI сети"),
            Text(
                text="Настроить текущую сеть",
                subtext=current_text,
                icon="msg_link",
                on_click=lambda *a: self._add_current_wifi_to_excluded(),
            ),
            Text(
                text="Добавить сеть",
                icon="msg_link",
                on_click=lambda *a: self._prompt_add_excluded_wifi(),
            ),
            Divider(),
            Header(text="Сети"),
        ]
        if not rules:
            items.append(Text(text="Список пуст", icon="msg_list"))
        else:
            for ssid, mode in rules.items():
                items.append(Text(
                    text=ssid,
                    subtext=self._wifi_rule_mode_title(mode),
                    icon="msg2_proxy_off" if mode == "off" else self._settings_mode_icon(mode),
                    on_click=lambda *a, ssid=ssid: self._open_wifi_rule_picker(ssid),
                ))
        return items

    def _regenerate_subscription_hwid(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return False
        try:
            from android.text import InputFilter
            from android.text.method import DigitsKeyListener
            field, field_view = self._create_themed_dialog_input(activity, "16 hex-символов")
            field.setText(_get_or_create_subscription_hwid())
            field.setSelection(field.length())
            field.setKeyListener(DigitsKeyListener.getInstance("0123456789abcdefABCDEF"))
            field.setFilters([InputFilter.LengthFilter(16)])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Изменить HWID")
            builder.set_view(field_view)

            def _save(dlg, which):
                value = str(field.getText() or "").strip().lower()
                if not _set_subscription_hwid_custom(value):
                    BulletinHelper.show_error("HWID должен содержать ровно 16 hex-символов")
                    return
                self._set_setting_value("subscription_hwid_custom", value, reload_settings=False)
                try:
                    dlg.dismiss()
                except:
                    pass
                BulletinHelper.show_success("HWID подписок обновлён")
                self._refresh_settings_without_reopen(reload_stack=True)

            builder.set_positive_button("Сохранить", _save)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("Не удалось изменить HWID: " + str(exc))
            return False

    def _get_calls_proxy_preference(self):
        try:
            raw = self.get_setting("proxy_calls_via_proxy", None)
            if raw is not None:
                return bool(raw)
        except:
            pass
        try:
            prefs = MessagesController.getGlobalMainSettings()
            return bool(prefs.getBoolean("proxy_enabled_calls", False))
        except:
            return False

    def _set_calls_proxy_preference(self, enabled, reload_settings=True):
        val = bool(enabled)
        try:
            self._set_setting_value("proxy_calls_via_proxy", val, reload_settings=bool(reload_settings))
        except:
            pass

    def _get_tgws_voip_relay_enabled(self):
        try:
            return bool(self.get_setting("tgws_voip_relay_enabled", True))
        except:
            return False

    def _set_tgws_voip_relay_enabled(self, enabled, reload_settings=True):
        self._set_setting_value("tgws_voip_relay_enabled", bool(enabled), reload_settings=bool(reload_settings))

    def _get_tgws_voip_relay_config(self):
        return _validate_tgws_voip_relay(
            self.get_setting("tgws_voip_relay_ip", TGWS_VOIP_RELAY_HOST),
            self.get_setting("tgws_voip_relay_port", str(TGWS_VOIP_RELAY_CONTROL_PORT)),
            self.get_setting("tgws_voip_relay_hmac", TGWS_VOIP_RELAY_SECRET.decode("utf-8")),
        )

    def _tgws_voip_relay_link(self):
        config, error = self._get_tgws_voip_relay_config()
        if config is None:
            return "", error
        relay_ip, relay_port, secret = config
        return "tg://relay?" + urllib.parse.urlencode({
            "ip": relay_ip,
            "port": relay_port,
            "h": secret,
        }), ""

    def _save_tgws_voip_relay_config(self, config):
        relay_ip, relay_port, secret = config
        self._tgws_voip_relay_retry_after = 0.0
        self.set_setting("tgws_voip_relay_ip", relay_ip, reload_settings=False)
        self.set_setting("tgws_voip_relay_port", str(relay_port), reload_settings=False)
        self.set_setting("tgws_voip_relay_hmac", secret, reload_settings=False)
        self._set_tgws_voip_relay_enabled(True, reload_settings=True)
        BulletinHelper.show_success("Voice Relay переключён")
        return True

    def _show_tgws_voip_relay_confirmation(self, config, ping_ms):
        if not self._active:
            return False
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        relay_ip, relay_port, _ = config
        ping_text = "%d мс" % ping_ms if ping_ms is not None else "нет ответа"
        builder = AlertDialogBuilder(activity)
        builder.set_title("Сменить Voice Relay?")
        builder.set_message("Сервер: %s:%d\nПинг: %s" % (relay_ip, relay_port, ping_text))

        def on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._save_tgws_voip_relay_config(config)

        def on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Сменить", on_yes)
        builder.set_negative_button("Отмена", on_no)
        builder.set_cancelable(True)
        builder.show()
        return True

    def _apply_tgws_voip_relay_link(self, uri):
        config, error = _parse_tgws_voip_relay_link(uri)
        if config is None:
            BulletinHelper.show_error(error)
            return False
        BulletinHelper.show_info("Проверяю Voice Relay...")

        def worker():
            ping_ms = _ping_tgws_voip_relay(config)
            run_on_ui_thread(lambda: self._show_tgws_voip_relay_confirmation(config, ping_ms))

        threading.Thread(target=worker, daemon=True).start()
        return True

    def _copy_tgws_voip_relay_link(self):
        link, error = self._tgws_voip_relay_link()
        if not link:
            BulletinHelper.show_error(error)
            return
        self._copy_link(link)

    def _tgws_allocate_voip_relay(self, target_ip, target_port, timeout_sec=None):
        if not self._get_tgws_voip_relay_enabled() or not _is_telegram_reflector_ip(target_ip):
            return None
        try:
            config, _ = self._get_tgws_voip_relay_config()
            if config is None:
                return None
            relay_ip, relay_control_port, relay_secret = config
            relay_secret = relay_secret.encode("utf-8")
            target_port = int(target_port)
            if target_port <= 0 or target_port > 65535:
                return None
            nonce = os.urandom(16)

            def build_request(operation, request_nonce):
                body = bytearray((2, int(operation)))
                body.extend(struct.pack(">Q", int(time.time())))
                body.extend(request_nonce)
                body.extend(struct.pack(">IHH", _ipv4_to_int(target_ip), target_port, 0))
                body.extend(hmac.new(relay_secret, bytes(body), hashlib.sha256).digest())
                return bytes(body)

            def valid_response(data):
                return (
                    len(data) == 48
                    and data[0] == 2
                    and hmac.compare_digest(
                        data[16:],
                        hmac.new(relay_secret, data[:16], hashlib.sha256).digest(),
                    )
                )

            deadline = None if timeout_sec is None else time.monotonic() + max(0.05, float(timeout_sec))

            def receive_timeout():
                if deadline is None:
                    return float(TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC)
                return max(0.05, deadline - time.monotonic())

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((relay_ip, relay_control_port))
                sock.send(build_request(1, nonce))
                sock.settimeout(receive_timeout())
                challenge = sock.recv(128)
                if not valid_response(challenge) or challenge[1] != 9:
                    return None
                allocation_nonce = nonce[:8] + challenge[8:16]
                sock.send(build_request(2, allocation_nonce))
                sock.settimeout(receive_timeout())
                data = sock.recv(128)
            if not valid_response(data) or data[8:16] != nonce[:8]:
                return None
            relay_port = struct.unpack(">H", data[2:4])[0]
            if data[1] != 0 or relay_port <= 0:
                return None
            return relay_ip, relay_port
        except:
            return None

    def _tgws_allocate_voip_relays(self, targets, timeout_sec=TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC):
        targets = list(targets or [])
        if not targets:
            return []
        if time.monotonic() < float(getattr(self, "_tgws_voip_relay_retry_after", 0.0) or 0.0):
            return [None] * len(targets)
        deadline = time.monotonic() + max(0.05, float(timeout_sec))

        def allocate(target):
            return self._tgws_allocate_voip_relay(
                target[0], target[1], timeout_sec=max(0.05, deadline - time.monotonic())
            )

        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as executor:
            relays = list(executor.map(allocate, targets))
        self._tgws_voip_relay_retry_after = 0.0 if any(relays) else time.monotonic() + 20.0
        return relays

    def _rewrite_webrtc_join_response(self, payload):
        if self._is_proxy_policy_suspended() or not self._get_tgws_voip_relay_enabled():
            return payload
        try:
            data = json.loads(str(payload))
            candidates = data.get("transport", {}).get("candidates", [])
            if not isinstance(candidates, list):
                return payload
            relay_candidates = []
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                target_ip = str(candidate.get("ip", "") or "")
                if not _is_telegram_reflector_ip(target_ip):
                    continue
                relay_candidates.append((candidate, target_ip, int(candidate.get("port", 0))))
            relays = self._tgws_allocate_voip_relays(
                [(target_ip, target_port) for _, target_ip, target_port in relay_candidates]
            )
            fallback = next((relay for relay in relays if relay), None)
            if fallback is None:
                return payload
            for (candidate, _, _), relay in zip(relay_candidates, relays):
                relay = relay or fallback
                candidate["ip"] = str(relay[0])
                candidate["port"] = str(int(relay[1]))
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        except:
            return payload

    def _rewrite_voip_endpoints(self, endpoints, endpoint_cls):
        if self._is_proxy_policy_suspended() or not self._get_tgws_voip_relay_enabled():
            return 0
        try:
            relay_endpoints = []
            for index in range(len(endpoints)):
                endpoint = endpoints[index]
                target_ip = str(getattr(endpoint, "ipv4", "") or "")
                if not _is_telegram_reflector_ip(target_ip) or bool(getattr(endpoint, "tcp", False)):
                    continue
                relay_endpoints.append((index, endpoint, target_ip, int(endpoint.port)))
            relays = self._tgws_allocate_voip_relays(
                [(target_ip, target_port) for _, _, target_ip, target_port in relay_endpoints]
            )
            fallback = next((relay for relay in relays if relay), None)
            if fallback is None:
                return 0
            replacements = []
            for (index, endpoint, _, _), relay in zip(relay_endpoints, relays):
                relay = relay or fallback
                replacement = endpoint_cls(
                    bool(endpoint.isRtc),
                    int(endpoint.id),
                    str(relay[0]),
                    "",
                    int(relay[1]),
                    int(endpoint.type),
                    endpoint.peerTag,
                    bool(endpoint.turn),
                    bool(endpoint.stun),
                    getattr(endpoint, "username", None),
                    getattr(endpoint, "password", None),
                    False,
                )
                try:
                    replacement.reflectorId = int(endpoint.reflectorId)
                except:
                    pass
                replacements.append((index, endpoint, replacement))
            applied = []
            try:
                for index, original, replacement in replacements:
                    endpoints[index] = replacement
                    applied.append((index, original))
            except:
                for index, original in applied:
                    try:
                        endpoints[index] = original
                    except:
                        pass
                return 0
            return len(replacements)
        except:
            return 0

    def _is_socks_proxy(self, pd):
        try:
            kind = str(pd.get("kind", "") or "").lower()
        except:
            kind = ""
        if kind == VLESS_KIND:
            return False
        if kind == "socks":
            return True
        try:
            sec = str(pd.get("secret", "") or "")
        except:
            sec = ""
        return not bool(sec)

    def _is_proxy_connection_ready(self, expected_port=None, owner=None, strict_connected=False):
        try:
            if expected_port is not None:
                if not self._is_local_proxy_applied(expected_port, owner=owner):
                    return False
            if not bool(_is_tg_proxy_enabled()):
                return False
            if SharedConfig.currentProxy is None:
                return False
            cm = ConnectionsManager.getInstance(UserConfig.selectedAccount)
            if cm is None:
                return False
            state = int(cm.getConnectionState())
            connected_state = int(getattr(ConnectionsManager, "ConnectionStateConnected", 3))
            if bool(strict_connected):
                return bool(state == connected_state)
            updating_state = int(getattr(ConnectionsManager, "ConnectionStateUpdating", connected_state))
            return bool(state == connected_state or state == updating_state or state == 3)
        except:
            return False

    def _plugins_controller_instance(self):
        try:
            PC = find_class("com.exteragram.messenger.plugins.PluginsController")
        except:
            PC = None
        if PC is None:
            return None
        try:
            return PC.getInstance()
        except:
            return None

    def _plugin_settings_id(self):
        candidates = []
        try:
            candidates.append(str(getattr(self, "id", "") or ""))
        except:
            pass
        for item in [__id__, __name__, "GreenPass", "greenpass"]:
            try:
                candidates.append(str(item or ""))
            except:
                pass

        inst = self._plugins_controller_instance()
        seen = set()
        if inst is not None:
            for candidate in candidates:
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    if hasattr(inst, "plugins") and inst.plugins.get(candidate) is not None:
                        return candidate
                except:
                    pass

        for candidate in candidates:
            if candidate:
                return candidate
        return str(__id__)

    def _set_setting_value(self, key, value, reload_settings=False):
        setting_key = str(key or "")
        if value is None:
            return False
        inst = self._plugins_controller_instance()
        pid = self._plugin_settings_id()
        if inst is not None and pid and setting_key:
            try:
                engine = inst.getPluginEngine(pid)
            except:
                engine = None
            if engine is not None:
                try:
                    engine.setPluginSetting(pid, setting_key, value)
                    if reload_settings:
                        try:
                            if setting_key == "__reload__":
                                inst.loadPluginSettings(pid)
                            else:
                                self._reload_settings_ui()
                        except:
                            pass
                    return True
                except:
                    pass
            try:
                inst.setPluginSetting(pid, setting_key, value)
                if reload_settings:
                    try:
                        if setting_key == "__reload__":
                            inst.loadPluginSettings(pid)
                        else:
                            self._reload_settings_ui()
                    except:
                        pass
                return True
            except:
                pass

        try:
            direct_reload = bool(reload_settings and setting_key == "__reload__")
            self.set_setting(setting_key, value, reload_settings=direct_reload)
            if reload_settings and setting_key != "__reload__":
                try:
                    self._reload_settings_ui()
                except:
                    pass
            return True
        except:
            return False

    def _reload_settings_ui(self, delay_ms=100):
        try:
            if bool(getattr(self, "_reload_ui_pending", False)):
                return
            self._reload_ui_pending = True
        except:
            pass

        def _run():
            try:
                self._reload_ui_pending = False
            except:
                pass
            try:
                frag = get_last_fragment()
            except:
                frag = None

            def _fallback_full_reload():
                try:
                    inst = self._plugins_controller_instance()
                    pid = self._plugin_settings_id()
                    if inst is not None and pid:
                        inst.loadPluginSettings(pid)
                        return
                except:
                    pass
                try:
                    self._set_setting_value("__reload__", time.time(), reload_settings=True)
                except:
                    pass

            if frag is None:
                return

            try:
                cls = frag.getClass()
                frag_name = str(cls.getName() or "")
            except:
                cls = None
                frag_name = ""
            if frag_name != "com.exteragram.messenger.plugins.ui.PluginSettingsActivity" or cls is None:
                return

            try:
                plugin_field = cls.getDeclaredField("plugin")
                plugin_field.setAccessible(True)
                plugin_obj = plugin_field.get(frag)
                frag_pid = str(plugin_obj.getId() or "") if plugin_obj is not None else ""
            except:
                frag_pid = ""
            if frag_pid != str(self._plugin_settings_id() or ""):
                return

            try:
                callback_field = cls.getDeclaredField("createSubFragmentCallback")
                callback_field.setAccessible(True)
                callback_obj = callback_field.get(frag)
            except:
                callback_obj = None

            if callback_obj is not None:
                try:
                    for method in list(cls.getDeclaredMethods() or []):
                        try:
                            method_name = str(method.getName() or "")
                        except:
                            method_name = ""
                        if method_name == "lambda$didReceivedNotification$1":
                            method.setAccessible(True)
                            method.invoke(frag)
                            return
                except:
                    pass

            try:
                list_field = cls.getDeclaredField("listView")
                list_field.setAccessible(True)
                list_view = list_field.get(frag)
            except:
                list_view = None
            if list_view is None:
                _fallback_full_reload()
                return

            try:
                adapter = getattr(list_view, "adapter", None)
            except:
                adapter = None
            if adapter is None:
                _fallback_full_reload()
                return

            try:
                adapter.update(True)
            except Exception as e:
                err = ""
                try:
                    err = str(e)
                except:
                    err = ""
                if "RecyclerView is computing a layout" in err:
                    try:
                        run_on_ui_thread(_run, 300)
                        return
                    except:
                        pass
                _fallback_full_reload()

        try:
            run_on_ui_thread(_run, int(delay_ms))
        except:
            try:
                self._reload_ui_pending = False
            except:
                pass
            _run()

    def _reload_settings_stack_ui(self, delay_ms=100):
        try:
            if bool(getattr(self, "_reload_stack_ui_pending", False)):
                return
            self._reload_stack_ui_pending = True
        except:
            pass

        def _run():
            try:
                self._reload_stack_ui_pending = False
            except:
                pass
            try:
                frag = get_last_fragment()
                stack = frag.getParentLayout().getFragmentStack()
            except:
                self._reload_settings_ui()
                return

            pid = str(self._plugin_settings_id() or "")

            def _reload_fragment(parent):
                cls = None
                try:
                    cls = parent.getClass()
                    if str(cls.getName() or "") != "com.exteragram.messenger.plugins.ui.PluginSettingsActivity":
                        return False

                    plugin_field = cls.getDeclaredField("plugin")
                    plugin_field.setAccessible(True)
                    plugin_obj = plugin_field.get(parent)
                    if str(plugin_obj.getId() or "") != pid:
                        return False

                    callback_field = cls.getDeclaredField("createSubFragmentCallback")
                    callback_field.setAccessible(True)
                    if callback_field.get(parent) is None:
                        return False
                except:
                    return False

                try:
                    for method in list(cls.getDeclaredMethods() or []):
                        try:
                            method_name = str(method.getName() or "")
                        except:
                            method_name = ""
                        if method_name == "lambda$didReceivedNotification$1":
                            method.setAccessible(True)
                            method.invoke(parent)
                            return True
                except:
                    pass

                try:
                    list_view = None
                    view_class = cls
                    while view_class is not None:
                        try:
                            list_field = view_class.getDeclaredField("listView")
                            list_field.setAccessible(True)
                            list_view = list_field.get(parent)
                            break
                        except:
                            view_class = view_class.getSuperclass()
                    adapter = getattr(list_view, "adapter", None) if list_view is not None else None
                    if adapter is None:
                        return False
                    adapter.update(True)
                    return True
                except Exception as e:
                    err = ""
                    try:
                        err = str(e)
                    except:
                        err = ""
                    if "RecyclerView is computing a layout" in err:
                        try:
                            run_on_ui_thread(_run, 300)
                            return True
                        except:
                            pass
                return False

            touched = False
            try:
                for index in range(int(stack.size()) - 1, -1, -1):
                    try:
                        if _reload_fragment(stack.get(index)):
                            touched = True
                    except:
                        continue
            except:
                pass

            if not touched:
                self._reload_settings_ui()

        try:
            run_on_ui_thread(_run, int(delay_ms))
        except:
            try:
                self._reload_stack_ui_pending = False
            except:
                pass
            _run()

    def _refresh_settings_without_reopen(self, reload_main=False, reload_stack=False):
        if reload_stack:
            self._reload_settings_stack_ui()
        else:
            self._reload_settings_ui()
        if reload_main:
            run_on_ui_thread(self._refresh_mode_summary)

    def _vless_save_data(self):
        try:
            self._vless_data["active_uri"] = str(self._vless_data.get("active_uri", "") or "")
        except:
            self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._save_config()

    def _get_selected_vless_provider(self):
        try:
            idx = int(self.get_setting("vless_provider", 0))
        except:
            idx = 0
        if idx < 0 or idx >= len(VLESS_PROVIDER_ITEMS):
            idx = 0
        return idx

    def _vless_provider_name(self, idx):
        try:
            provider_idx = int(idx or 0)
        except:
            provider_idx = 0
        if provider_idx == 0:
            return "Текущий"
        if provider_idx < 0 or provider_idx >= len(VLESS_PROVIDER_ITEMS):
            provider_idx = 0
        try:
            return str(VLESS_PROVIDER_ITEMS[provider_idx] or "")
        except:
            return ""

    def _selected_provider_vless_urls(self):
        provider_idx = self._get_selected_vless_provider()
        if provider_idx == 0:
            try:
                idx = int(self._get_selected_provider())
            except:
                idx = 0
        else:
            idx = int(provider_idx)
        urls = []
        try:
            for url in list(VLESS_PROVIDER_SUBS.get(idx, []) or []):
                value = str(url or "").strip()
                if value:
                    urls.append(value)
        except:
            urls = []
        return urls

    def _provider_vless_sub_name(self, provider_idx, url, total_urls=1):
        name = str(self._vless_provider_name(provider_idx) or "").strip()
        if provider_idx == 0:
            try:
                name = str(self._provider_name(self._get_selected_provider()) or "").strip()
            except:
                pass
        if name and int(total_urls) <= 1:
            return name
        try:
            host = str(urllib.parse.urlparse(str(url or "")).netloc or "").strip()
        except:
            host = ""
        if name and host:
            return f"{name} • {host}"
        if name:
            return name
        return host or "Серверы"

    def _sync_selected_provider_vless_nodes(self, force=False, activate_first=False, silent=False):
        urls = self._selected_provider_vless_urls()
        if not urls:
            if not silent:
                BulletinHelper.show_info("У выбранного провайдера нет узлов")
            return False

        if self._vless_provider_sync_in_progress:
            if not silent:
                BulletinHelper.show_info("Узлы уже загружаются")
            return True

        existing_urls = set()
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                existing_urls.add(str(sub.get("url", "") or ""))
        except:
            existing_urls = set()

        if not force and all(url in existing_urls for url in urls):
            return False

        try:
            provider_idx = int(self._get_selected_vless_provider())
        except:
            provider_idx = 0
        if provider_idx == 0:
            try:
                provider_idx = int(self._get_selected_provider())
            except:
                provider_idx = 0

        if not silent:
            BulletinHelper.show_info("Загружаю узлы...")

        self._vless_provider_sync_in_progress = True

        def _worker():
            imported_urls = []
            imported_nodes = 0
            try:
                merged = []
                try:
                    merged = [sub for sub in list(self._vless_data.get("subs", []) or []) if isinstance(sub, dict)]
                except:
                    merged = []

                merged_by_url = {}
                order = []
                for sub in merged:
                    url = str(sub.get("url", "") or "")
                    if not url or url in merged_by_url:
                        continue
                    merged_by_url[url] = sub
                    order.append(url)

                total_urls = len(urls)
                for url in urls:
                    nodes = _fetch_vless_nodes(url)
                    if not nodes:
                        continue
                    imported_urls.append(url)
                    imported_nodes += len(nodes)
                    merged_by_url[url] = {
                        "id": url,
                        "url": url,
                        "name": self._provider_vless_sub_name(provider_idx, url, total_urls=total_urls),
                        "nodes": nodes,
                    }
                    if url not in order:
                        order.append(url)

                if not imported_urls:
                    if not silent:
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить узлы"))
                    return

                subs = []
                seen = set()
                for url in order:
                    sub = merged_by_url.get(url)
                    if sub is None or url in seen:
                        continue
                    seen.add(url)
                    subs.append(sub)

                self._vless_data["subs"] = subs
                if activate_first and not str(self._vless_data.get("active_uri", "") or ""):
                    for url in imported_urls:
                        try:
                            nodes = list(merged_by_url.get(url, {}).get("nodes", []) or [])
                        except:
                            nodes = []
                        if not nodes:
                            continue
                        self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
                        break
                self._repair_active_vless_subscription_uri()
                self._vless_save_data()
                if self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                    self._ensure_vless_core_then(self._vless_connect)
                run_on_ui_thread(self._refresh_settings_without_reopen)
                if not silent:
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Импортировано узлов: {imported_nodes}"))
            finally:
                self._vless_provider_sync_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _apply_local_socks_proxy(self, port, enable, owner=None, expected_port=None, username="", password="", secret=""):
        try:
            target_port = int(port or 0)
        except:
            target_port = 0
        try:
            expected = int(expected_port or 0)
        except:
            expected = 0
        target_owner = self._normalize_local_socks_owner(owner)
        if bool(enable) and not target_owner:
            target_owner = self._current_mode_local_socks_owner()

        with self._local_socks_lock:
            current_owner = str(self._local_socks_owner or "")
            current_port = int(self._local_socks_port or 0)

            if bool(enable):
                if target_port <= 0 or not target_owner:
                    return False
                if not self._local_socks_owner_can_apply(target_owner):
                    return False
                self._local_socks_owner = target_owner
                self._local_socks_port = int(target_port)
            else:
                if target_owner and current_owner and current_owner != target_owner:
                    return False
                if expected > 0 and current_port > 0 and current_port != expected:
                    return False

            ok = self._apply_local_socks_proxy_unlocked(
                target_port,
                bool(enable),
                owner=target_owner,
                username=username,
                password=password,
                secret=secret,
            )
            if ok:
                if bool(enable):
                    self._local_socks_owner = target_owner
                    self._local_socks_port = int(target_port)
                elif (not target_owner) or (not current_owner) or current_owner == target_owner:
                    self._local_socks_owner = ""
                    self._local_socks_port = 0
            elif bool(enable):
                self._local_socks_owner = current_owner
                self._local_socks_port = current_port
            return bool(ok)

    def _apply_local_socks_proxy_unlocked(self, port, enable, owner=None, username="", password="", secret=""):
        try:
            ProxyInfoClass = find_class("org.telegram.messenger.SharedConfig$ProxyInfo")
        except:
            ProxyInfoClass = None

        try:
            self._load_proxy_list_safe()
        except:
            pass

        try:
            editor = MessagesController.getGlobalMainSettings().edit()
        except:
            editor = None

        proxy_user = str(username or "") if enable else ""
        proxy_pass = str(password or "") if enable else ""
        proxy_secret = str(secret or "") if enable else ""
        try:
            calls_proxy_enabled = bool(enable and (not proxy_secret) and self._get_calls_proxy_preference())
        except:
            calls_proxy_enabled = False

        existing_local_proxy = None
        try:
            proxy_list = getattr(SharedConfig, "proxyList", None)
            if proxy_list is not None and enable:
                stale_local = []
                for i in range(int(proxy_list.size())):
                    try:
                        item = proxy_list.get(i)
                        if str(getattr(item, "address", "") or "") != VLESS_LOCAL_HOST:
                            continue
                        same_proxy = (
                            int(getattr(item, "port", 0) or 0) == int(port)
                            and str(getattr(item, "username", "") or "") == proxy_user
                            and str(getattr(item, "password", "") or "") == proxy_pass
                            and str(getattr(item, "secret", "") or "") == proxy_secret
                        )
                        if same_proxy and existing_local_proxy is None:
                            existing_local_proxy = item
                        else:
                            stale_local.append(item)
                    except:
                        continue
                for item in stale_local:
                    try:
                        SharedConfig.deleteProxy(item)
                    except:
                        pass
        except:
            existing_local_proxy = None

        if enable:
            proxy_obj = existing_local_proxy
            try:
                if ProxyInfoClass is not None:
                    proxy_obj = ProxyInfoClass(VLESS_LOCAL_HOST, int(port), proxy_user, proxy_pass, proxy_secret)
            except:
                proxy_obj = None
            if proxy_obj is None:
                try:
                    proxy_obj = SharedConfig.ProxyInfo(VLESS_LOCAL_HOST, int(port), proxy_user, proxy_pass, proxy_secret)
                except:
                    proxy_obj = None
            if proxy_obj is None:
                return False

            if existing_local_proxy is None:
                try:
                    added_proxy = SharedConfig.addProxy(proxy_obj)
                    if added_proxy is not None:
                        proxy_obj = added_proxy
                except:
                    pass

            try:
                SharedConfig.currentProxy = proxy_obj
                SharedConfig.proxyEnabled = True
            except:
                pass

            if editor is not None:
                try:
                    editor.putString("proxy_ip", VLESS_LOCAL_HOST)
                    editor.putInt("proxy_port", int(port))
                    editor.putString("proxy_user", proxy_user)
                    editor.putString("proxy_pass", proxy_pass)
                    editor.putString("proxy_secret", proxy_secret)
                    editor.putBoolean("proxy_enabled", True)
                    editor.putBoolean("proxy_enabled_calls", bool(calls_proxy_enabled))
                    editor.putBoolean("proxy_calls_enabled", bool(calls_proxy_enabled))
                    editor.putBoolean("calls_use_proxy", bool(calls_proxy_enabled))
                except:
                    pass
        else:
            try:
                SharedConfig.proxyEnabled = False
            except:
                pass
            if editor is not None:
                try:
                    editor.putBoolean("proxy_enabled", False)
                    editor.putBoolean("proxy_enabled_calls", False)
                    editor.putBoolean("proxy_calls_enabled", False)
                    editor.putBoolean("calls_use_proxy", False)
                except:
                    pass

        try:
            if editor is not None:
                editor.commit()
        except:
            try:
                if editor is not None:
                    editor.apply()
            except:
                pass

        try:
            if hasattr(SharedConfig, "saveProxyList"):
                SharedConfig.saveProxyList()
        except:
            pass

        try:
            SharedConfig.saveConfig()
        except:
            pass

        try:
            if enable:
                ConnectionsManager.setProxySettings(True, VLESS_LOCAL_HOST, int(port), proxy_user, proxy_pass, proxy_secret)
            else:
                ConnectionsManager.setProxySettings(False, "", 0, "", "", "")
        except:
            pass

        def _notify():
            try:
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
            except:
                pass

        try:
            run_on_ui_thread(_notify, 300)
        except:
            _notify()
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        return True

    def _vless_apply_tg_proxy(self, port, enable, username="", password=""):
        result = self._apply_local_socks_proxy(
            port,
            enable,
            owner=str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND),
            username=username,
            password=password,
        )
        return result

    def _is_local_proxy_applied(self, port, owner=None):
        try:
            expected_port = int(port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False

        try:
            current = SharedConfig.currentProxy
        except:
            current = None
        if current is None:
            return False

        try:
            current_host = str(getattr(current, "address", "") or "")
        except:
            current_host = ""
        try:
            current_port = int(getattr(current, "port", 0) or 0)
        except:
            current_port = 0
        if current_host != VLESS_LOCAL_HOST or current_port != expected_port:
            return False

        try:
            prefs = MessagesController.getGlobalMainSettings()
            if not bool(prefs.getBoolean("proxy_enabled", False)):
                return False
            if str(prefs.getString("proxy_ip", "") or "") != VLESS_LOCAL_HOST:
                return False
            if int(prefs.getInt("proxy_port", 0) or 0) != expected_port:
                return False
        except:
            return False
        target_owner = self._normalize_local_socks_owner(owner)
        if target_owner:
            current_owner, current_owner_port = self._local_socks_owner_snapshot()
            if current_owner and current_owner != target_owner:
                return False
            if current_owner_port > 0 and current_owner_port != expected_port:
                return False
        return True

    def _is_local_vless_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND))

    def _vless_runtime_config_key(self, uri=None, node=None, auto_nodes=None):
        try:
            nodes = list(auto_nodes or [])
        except:
            nodes = []
        if len(nodes) > 1:
            values = []
            seen = set()
            for candidate in nodes:
                if not isinstance(candidate, dict):
                    continue
                try:
                    kind = str(candidate.get("kind", "") or "").strip().lower()
                    if kind == "singbox-config":
                        value = str(candidate.get("raw_config", "") or "")
                    else:
                        value = str(candidate.get("uri", "") or "")
                    key = _proxy_uri_dedup_key(value) or value
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    values.append(kind + ":" + value)
                except:
                    continue
            if len(values) > 1:
                try:
                    return "singbox-auto:" + hashlib.sha256("\n".join(values).encode("utf-8", errors="ignore")).hexdigest()
                except:
                    return "singbox-auto:" + "|".join(values)
        try:
            node = node if isinstance(node, dict) else None
            kind = str((node or {}).get("kind", "") or "").strip().lower()
            if kind == "singbox-config":
                raw = str((node or {}).get("raw_config", "") or "")
                if raw:
                    return "singbox-config:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        except:
            pass
        try:
            value = str(uri if uri is not None else self._get_active_vless_uri() or "")
        except:
            value = ""
        value = _proxy_uri_dedup_key(value) or value
        if not value:
            return ""
        try:
            return "uri:" + hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
        except:
            return value

    def _reuse_running_vless_if_ready(self, target_key):
        if not target_key or str(getattr(self, "_vless_active_config_key", "") or "") != str(target_key):
            return False
        try:
            port = int(self._vless_port or 0)
        except:
            port = 0
        if port <= 0 or not bool(self._vless_running):
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(port, timeout=0.35, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(port):
            if not self._vless_apply_tg_proxy(port, True, username=username, password=password):
                return False
        self._reset_vless_retry()
        self._set_vless_connection_state(False, "")
        run_on_ui_thread(self._refresh_settings_without_reopen)
        return True

    def _is_vless_connection_ready(self, port=None, check_tunnel=False):
        try:
            expected_port = int(port or self._vless_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0 or not bool(self._vless_running):
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(expected_port, timeout=0.5, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(expected_port):
            return False
        if bool(check_tunnel) and not _check_vless_tunnel_ready(expected_port, timeout=1.0, username=username, password=password):
            return False
        return True

    def _is_local_tgws_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=TGWS_KIND)

    def _is_tgws_connection_ready(self, port=None):
        try:
            expected_port = int(port or self._tgws_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False
        return bool(
            self._is_local_tgws_proxy_applied(expected_port)
            and _check_vless_port(expected_port)
        )

    def _tgws_heal_if_due(self):
        now = time.time()
        try:
            last = float(getattr(self, "_tgws_last_heal_ts", 0.0) or 0.0)
        except:
            last = 0.0
        if last and (now - last) < float(TGWS_HEAL_COOLDOWN_SEC):
            return False
        self._tgws_last_heal_ts = float(now)
        try:
            self._tgws_core.self_heal()
            return True
        except:
            return False

    def _tgws_local_alive(self):
        try:
            return bool(self._tgws_running and self._tgws_port and _check_vless_port(self._tgws_port))
        except:
            return False

    def _tgws_unapply_local_proxy_for_background(self):
        self._tgws_ready = False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0:
            try:
                owner, owner_port = self._local_socks_owner_snapshot()
                if owner == TGWS_KIND:
                    port = int(owner_port or 0)
            except:
                port = 0
        if port > 0:
            try:
                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
            except:
                pass
        return True

    def _tgws_ensure_local_proxy(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0 or not self._tgws_local_alive():
            self._tgws_ready = False
            if not bool(getattr(self, "_tgws_connecting", False)):
                self._tgws_connect()
            return False
        if not self._is_local_tgws_proxy_applied(port):
            if not self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram()):
                self._tgws_ready = False
                if not bool(getattr(self, "_tgws_connecting", False)):
                    self._tgws_disconnect_with_reason("tgws_local_proxy_reapply_failed", silent=True)
                    self._tgws_connect()
                return False
        self._tgws_running = True
        self._tgws_ready = bool(self._is_tgws_connection_ready(port))
        return bool(self._tgws_ready)

    def _is_local_awg_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=AWG_KIND)

    def _is_local_olcrtc_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=OLCRTC_KIND)

    def _clear_local_socks_proxy_if_port(self, port, owner=None):
        try:
            expected_port = int(port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False
        target_owner = self._normalize_local_socks_owner(owner)
        if target_owner:
            current_owner, current_owner_port = self._local_socks_owner_snapshot()
            if current_owner and current_owner != target_owner:
                return False
            if current_owner_port > 0 and current_owner_port != expected_port:
                return False
        try:
            if not self._is_local_proxy_applied(expected_port, owner=target_owner):
                return False
        except:
            return False
        return self._apply_local_socks_proxy(0, False, owner=target_owner, expected_port=expected_port)

    def _download_libvless_with_progress(self):
        return self._install_libsingbox_bundle(allow_network=True)

    def _download_libawg_with_progress(self):
        return self._install_libsingbox_bundle(allow_network=True)

    def _next_vless_generation(self):
        with self._vless_transition_lock:
            self._vless_generation = int(self._vless_generation or 0) + 1
            return int(self._vless_generation)

    def _same_vless_generation(self, generation):
        with self._vless_transition_lock:
            return int(self._vless_generation or 0) == int(generation)

    def _pick_vless_runtime_port(self):
        preferred = int(VLESS_LOCAL_PORT)
        if _wait_vless_port_closed(preferred, timeout_sec=1.5, poll_sec=0.1):
            return preferred
        reserved = set(int(value) for value in list(TGWS_RESERVED_PORTS or []))
        for _ in range(24):
            try:
                candidate = int(_get_free_port())
            except:
                continue
            if candidate in reserved:
                continue
            if _wait_vless_port_closed(candidate, timeout_sec=0.05, poll_sec=0.05):
                return candidate
        return 0

    def _vless_balancer_nodes(self):
        now = time.time()
        ranked = []
        seen = set()
        for node in self._iter_vless_nodes():
            try:
                uri = str(node.get("uri", "") or "")
                ping = self._vless_ping_value(node)
                checked_at = self._vless_ping_checked_at(node)
            except:
                continue
            key = _proxy_uri_dedup_key(uri) or uri
            if not key or key in seen or checked_at <= 0:
                continue
            if (now - checked_at) > float(VLESS_NODE_PING_STALE_SEC) or ping <= 0 or ping >= 9999:
                continue
            seen.add(key)
            ranked.append((int(ping), node))
        ranked.sort(key=lambda item: item[0])
        return [node for _, node in ranked[:VLESS_BALANCER_MAX_NODES]]

    def _reset_vless_retry(self):
        self._vless_retry_failures = 0
        self._vless_retry_after = 0.0

    def _set_vless_connection_state(self, connecting=False, error=""):
        connecting = bool(connecting)
        error = str(error or "").strip()
        changed = connecting != bool(getattr(self, "_vless_connecting", False)) or error != str(getattr(self, "_vless_last_error", "") or "")
        self._vless_connecting = connecting
        self._vless_last_error = error
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _delay_vless_retry(self):
        self._vless_retry_failures = int(self._vless_retry_failures or 0) + 1
        self._vless_retry_after = time.monotonic() + _vless_retry_delay(self._vless_retry_failures)

    def _auto_reconnect_vless(self):
        if bool(self._vless_backgrounded):
            return False
        if time.monotonic() < float(self._vless_retry_after or 0.0):
            return False
        if bool(getattr(self, "_vless_connect_worker_active", False)):
            return False
        if self._restore_running_vless_proxy():
            return True
        if int(self._vless_port or 0) > 0 and not bool(self._vless_running):
            self._vless_disconnect(silent=True, cancel_pending=False)
        self._ensure_vless_core_then(self._vless_connect)
        return True

    def _restore_running_vless_proxy(self):
        port = int(self._vless_port or 0)
        if not bool(self._vless_running) or port <= 0:
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(port, timeout=0.35, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(port):
            if not self._vless_apply_tg_proxy(port, True, username=username, password=password):
                return False
        self._reset_vless_retry()
        self._set_vless_connection_state(False, "")
        run_on_ui_thread(self._refresh_settings_without_reopen)
        return True

    def _resume_vless_after_background(self):
        if not self._should_run_vless():
            return False
        if self._restore_running_vless_proxy():
            return True
        time.sleep(0.25)
        if self._restore_running_vless_proxy():
            return True
        if time.monotonic() < float(self._vless_retry_after or 0.0):
            return False
        try:
            self._vless_disconnect(silent=True, cancel_pending=False)
        except:
            pass
        self._ensure_vless_core_then(self._vless_connect)
        return False

    def _abort_vless_generation(self, generation, port):
        with self._vless_transition_lock:
            if int(self._vless_generation or 0) != int(generation) or int(self._vless_port or 0) != int(port or 0):
                return False
            self._vless_generation = int(self._vless_generation or 0) + 1
            self._vless_running = False
            self._vless_port = 0
            self._vless_socks_username = ""
            self._vless_active_config_key = ""
            owner = str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)
            self._vless_local_owner = VLESS_KIND
            try:
                self._vless_core.stop()
            except:
                pass
            if int(port or 0) > 0:
                self._clear_local_socks_proxy_if_port(port, owner=owner)
            self._delay_vless_retry()
            return True

    def _ensure_vless_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_vless_mode = runner_name == "_vless_connect"
        if require_vless_mode and (not self._should_run_vless()):
            return
        if self._go_core_switch_blocked("vless"):
            if require_vless_mode:
                self._set_vless_connection_state(False, "Перезапустите приложение для смены ядра")
            return
        self._vless_core._ensure()
        if self._vless_core.is_available():
            if require_vless_mode and (not self._should_run_vless()):
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._vless_prepare_in_progress:
            return

        self._vless_prepare_in_progress = True
        BulletinHelper.show_info("Скачиваю ядро прокси...")

        def _worker():
            try:
                ok = self._download_libvless_with_progress()
                if ok and self._core_restart_required():
                    if require_vless_mode:
                        self._set_vless_connection_state(False, "Перезапустите приложение для нового ядра")
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    return
                self._reload_vless_core()
                self._vless_core._ensure()
                if ok and self._vless_core.is_available():
                    if require_vless_mode and (not self._should_run_vless()):
                        return
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро прокси готово"))
                    try:
                        runner()
                    except Exception as e:
                        if require_vless_mode:
                            self._set_vless_connection_state(False, f"Ошибка прокси: {e}")
                        else:
                            run_on_ui_thread(lambda: BulletinHelper.show_error(f"Ошибка прокси: {e}"))
                else:
                    if require_vless_mode:
                        self._set_vless_connection_state(False, "Не удалось загрузить ядро прокси")
                    else:
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро прокси"))
            finally:
                self._vless_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _save_vless_manual_node(self, node):
        if not isinstance(node, dict):
            return None
        node_key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")

        manual = []
        try:
            manual = list(self._vless_data.get("manual", []) or [])
        except:
            manual = []

        filtered = []
        for item in manual:
            try:
                item_key = _proxy_uri_dedup_key(item.get("uri", "")) or str(item.get("uri", "") or "")
                if item_key != node_key:
                    filtered.append(item)
            except:
                continue
        filtered.insert(0, node)
        self._vless_data["manual"] = filtered[:64]
        self._vless_data["active_uri"] = str(node.get("uri", "") or "")
        self._vless_save_data()
        return node

    def _validate_core_config_for_import(self, config_json, protocol_label):
        label = str(protocol_label or "Прокси")
        if not self._has_libvless_addon():
            return "Нужно ядро прокси"
        result = self._vless_core.validate(config_json)
        if result is None:
            return "Обновите ядро: проверка конфигурации недоступна"
        error = str(result or "").strip()
        if not error:
            return ""
        low = error.lower()
        if any(token in low for token in ("not included", "unknown outbound", "unsupported outbound", "not registered")):
            return "Протокол %s не поддерживается текущим ядром" % label
        return "Ошибка конфига %s: %s" % (label, error[:320])

    def _validate_proxy_uri_for_import(self, uri):
        scheme = _proxy_uri_scheme(uri)
        spec = PROXY_PROTOCOL_REGISTRY.get(scheme)
        label = str((spec or {}).get("label", scheme or "Прокси") or "Прокси")
        if not spec:
            return "Протокол %s не поддерживается плагином" % (scheme or "неизвестен")
        config_json, _ = _build_registered_proxy_config(uri, VLESS_LOCAL_PORT)
        if not config_json:
            return "Плагин не умеет собрать конфиг %s" % label
        return self._validate_core_config_for_import(config_json, label)

    def _add_vless_manual_node(self, uri):
        node = _proxy_node_from_uri(uri)
        if not node:
            return None
        return self._save_vless_manual_node(node)

    def _vless_connect(self):
        with self._vless_connect_lock:
            if bool(self._vless_connect_worker_active):
                self._vless_connect_pending = True
                return True
            self._vless_connect_worker_active = True
            self._vless_connect_pending = False

        def _worker():
            try:
                while True:
                    with self._vless_connect_lock:
                        self._vless_connect_pending = False
                    self._vless_connect_once()
                    with self._vless_connect_lock:
                        if bool(self._vless_connect_pending) and self._should_run_vless():
                            continue
                        self._vless_connect_worker_active = False
                        return
            except Exception as exc:
                with self._vless_connect_lock:
                    self._vless_connect_worker_active = False
                self._set_vless_connection_state(False, f"Ошибка подключения: {exc}")

        try:
            threading.Thread(target=_worker, daemon=True).start()
            return True
        except:
            with self._vless_connect_lock:
                self._vless_connect_worker_active = False
            self._set_vless_connection_state(False, "Не удалось запустить подключение")
            return False

    def _vless_connect_once(self):
        if not self._should_run_vless():
            return False
        if self._repair_active_vless_subscription_uri():
            self._vless_save_data()
        uri = self._get_active_vless_uri()
        scheme = _proxy_uri_scheme(uri)
        current_node = self._current_vless_node()
        mode_title = _proxy_protocol_label(current_node or scheme)
        qwdtt_mode = str((current_node or {}).get("kind", "") or "").strip().lower() == QWDTT_KIND
        if qwdtt_mode:
            mode_title = "qWDTT"
        if not uri or not current_node:
            self._set_vless_connection_state(False, "Нет выбранного узла")
            return False
        try:
            if str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config":
                mode_title = "sing-box config"
        except:
            pass
        try:
            is_file_config = str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config"
        except:
            is_file_config = False
        use_sb = _is_singbox_core(self._vless_core)
        auto_nodes = self._vless_auto_subscription_nodes(uri) if use_sb and not is_file_config and not qwdtt_mode else []
        target_config_key = self._vless_runtime_config_key(uri, current_node, auto_nodes=auto_nodes)
        if self._reuse_running_vless_if_ready(target_config_key):
            self._set_vless_connection_state(False, "")
            return True

        self._vless_disconnect(silent=True, cancel_pending=False)
        self._set_vless_connection_state(True, "")
        try:
            self._vless_core.lib
        except Exception as _le:
            pass
        if not self._vless_core.is_available():
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Ядро прокси не загружено")
            return False
        port = int(self._pick_vless_runtime_port() or 0)
        if port <= 0:
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Нет свободного локального порта")
            return False
        username = "" if qwdtt_mode else "gp" + os.urandom(6).hex()
        password = "" if qwdtt_mode else str(self._vless_socks_password or "")
        with self._vless_transition_lock:
            if not self._should_run_vless():
                return False
            generation = self._next_vless_generation()
            self._vless_port = int(port)
            self._vless_socks_username = username
            if not qwdtt_mode:
                self._vless_socks_password = password
            self._vless_local_owner = VLESS_KIND
        if qwdtt_mode:
            single_config = _qwdtt_core_config((current_node or {}).get("qwdtt", {}), port)
        elif is_file_config:
            if not use_sb:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, "Нужно ядро прокси")
                return False
            try:
                single_config = _prepare_singbox_file_config(
                    str((current_node or {}).get("raw_config", "") or ""),
                    port,
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
        elif use_sb:
            single_config = None
            if auto_nodes:
                if len(auto_nodes) > 1:
                    single_config = _build_singbox_balanced_config(
                        auto_nodes,
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                else:
                    single_config, _ = _build_registered_proxy_config(
                        str(auto_nodes[0].get("uri", "") or ""),
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                if single_config:
                    mode_title = "VLESS Auto"
            if not single_config:
                single_config, _ = _build_registered_proxy_config(
                    uri,
                    port,
                    socks_username=username,
                    socks_password=password,
                )
        else:
            single_config, _ = _build_vless_config(
                uri,
                port,
                socks_username=username,
                socks_password=password,
            )
        if not single_config:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, "Не удалось разобрать ссылку")
            return False
        if use_sb and not qwdtt_mode:
            try:
                runtime_config = json.loads(single_config)
                log_config = runtime_config.get("log")
                log_config = dict(log_config) if isinstance(log_config, dict) else {}
                log_config.update({"disabled": False, "level": "info"})
                runtime_config["log"] = log_config
                experimental = runtime_config.get("experimental")
                experimental = dict(experimental) if isinstance(experimental, dict) else {}
                cache_file = experimental.get("cache_file")
                cache_file = dict(cache_file) if isinstance(cache_file, dict) else {}
                cache_file["path"] = os.path.join(self._vless_dir, "singbox-cache.db")
                experimental["cache_file"] = cache_file
                runtime_config["experimental"] = experimental
                single_config = json.dumps(runtime_config)
            except Exception as exc:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, f"Ошибка конфига sing-box: {exc}")
                return False
            validation_error = self._validate_core_config_for_import(single_config, mode_title)
            if validation_error:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, validation_error)
                return False
        config_json = single_config

        if qwdtt_mode:
            with self._vless_transition_lock:
                if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                    return False
            err = self._vless_core.start(config_json)
            with self._vless_transition_lock:
                still_current = bool(self._same_vless_generation(generation) and self._should_run_vless() and int(self._vless_port or 0) == int(port))
            if not still_current:
                try:
                    if self._vless_core.current_engine() == QWDTT_KIND:
                        self._vless_core.stop()
                except:
                    pass
                return False
        else:
            with self._vless_transition_lock:
                if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                    return False
                err = self._vless_core.start(config_json)
        if err:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, f"Ошибка ядра прокси: {err}")
            return False

        def _watchdog():
            deadline = time.time() + float(VLESS_LOCAL_READY_TIMEOUT_SEC)
            while time.time() < deadline:
                if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                    return
                if _check_vless_port(port) and _check_vless_socks_ready(port, timeout=0.5, username=username, password=password):
                    if (not qwdtt_mode) and not _check_vless_tunnel_ready(port, timeout=1.5, username=username, password=password):
                        time.sleep(0.3)
                        continue
                    with self._vless_transition_lock:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                            return
                        applied = self._vless_apply_tg_proxy(port, True, username=username, password=password)
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        if self._is_local_vless_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_vless_proxy_applied(port)):
                        if not self._abort_vless_generation(generation, port):
                            return
                        self._set_vless_connection_state(False, "Локальный прокси не применился")
                        return
                    with self._vless_transition_lock:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        self._vless_running = True
                        self._vless_active_config_key = target_config_key
                        self._reset_vless_retry()
                        self._save_config()
                    self._set_vless_connection_state(False, "")
                    return
                time.sleep(0.3)
            if not self._abort_vless_generation(generation, port):
                return
            self._set_vless_connection_state(False, f"{mode_title} не запустился")

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _vless_disconnect(self, silent=False, cancel_pending=True):
        if cancel_pending:
            with self._vless_connect_lock:
                self._vless_connect_pending = False
        with self._vless_transition_lock:
            self._vless_generation = int(self._vless_generation or 0) + 1
            old_port = int(self._vless_port or 0)
            old_owner = str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)
            self._vless_running = False
            self._vless_connecting = False
            if cancel_pending:
                self._vless_last_error = ""
            self._vless_port = 0
            self._vless_socks_username = ""
            self._vless_active_config_key = ""
            self._vless_local_owner = VLESS_KIND
            try:
                self._vless_core.stop()
            except:
                pass
            if old_port > 0:
                self._clear_local_socks_proxy_if_port(old_port, owner=old_owner)
        if not silent:
            self._refresh_settings_without_reopen()

    def _tgws_proxy_link(self):
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0:
            port = int(TGWS_LOCAL_PORT)
        return f"tg://proxy?server={VLESS_LOCAL_HOST}&port={int(port)}&secret={_tgws_proxy_secret_for_telegram()}"

    def _tgws_connect(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        with self._tgws_connect_lock:
            if bool(getattr(self, "_tgws_connecting", False)):
                return False
            self._tgws_connecting = True
            try:
                self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
            except:
                self._tgws_generation = 1
            generation = int(self._tgws_generation or 0)
        handed_off = False
        try:
            try:
                self._vless_disconnect_with_reason("tgws_connect_preempt", silent=True)
            except:
                pass
            self._tgws_ready = False
            if not self._should_run_tgws():
                return False
            port = _pick_tgws_port(TGWS_LOCAL_PORT)
            if int(port or 0) <= 0:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False
            self._tgws_port = port
            config_json = json.dumps({"port": int(port), "verbose": False, "dc_ip": dict(TGWS_DEFAULT_DC_IP)})
            err = self._tgws_core.start(config_json)
            if err:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False

            def _watchdog():
                self._tgws_ready = False

                def _same_generation():
                    try:
                        return int(getattr(self, "_tgws_generation", 0) or 0) == int(generation)
                    except:
                        return False

                def _is_current():
                    try:
                        return bool(
                            _same_generation()
                            and self._should_run_tgws()
                            and int(self._tgws_port or 0) == int(port)
                        )
                    except:
                        return False

                deadline = time.time() + float(TGWS_LOCAL_READY_TIMEOUT_SEC)
                while time.time() < deadline:
                    if not _is_current():
                        if _same_generation():
                            self._tgws_running = False
                            self._tgws_ready = False
                            try:
                                self._tgws_core.stop()
                            except:
                                pass
                        return
                    if _check_vless_port(port):
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                            return
                        if self._is_local_tgws_proxy_applied(port):
                            applied = True
                        else:
                            applied = self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram())
                        apply_deadline = time.time() + 1.5
                        while applied and time.time() < apply_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                                return
                            if self._is_local_tgws_proxy_applied(port):
                                break
                            time.sleep(0.1)
                        if not applied or (not self._is_local_tgws_proxy_applied(port)):
                            if _same_generation():
                                self._tgws_running = False
                                self._tgws_ready = False
                                self._tgws_port = 0
                                try:
                                    self._tgws_core.stop()
                                except:
                                    pass
                            return
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                            return
                        self._tgws_running = True
                        self._tgws_ready = False
                        self._save_config()
                        run_on_ui_thread(self._refresh_settings_without_reopen)
                        confirm_deadline = time.time() + float(TGWS_CONNECT_CONFIRM_TIMEOUT_SEC)
                        connected = False
                        while time.time() < confirm_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    run_on_ui_thread(self._refresh_settings_without_reopen)
                                return
                            if self._is_tgws_connection_ready(port):
                                connected = True
                                break
                            time.sleep(0.5)
                        if connected:
                            self._tgws_ready = True
                            run_on_ui_thread(self._refresh_settings_without_reopen)
                            run_on_ui_thread(lambda: BulletinHelper.show_success("TG WS подключен"))
                        else:
                            self._tgws_ready = False
                            self._tgws_heal_if_due()
                            run_on_ui_thread(self._refresh_settings_without_reopen)
                            run_on_ui_thread(lambda: BulletinHelper.show_info("TG WS: соединяю..."))
                        return
                    time.sleep(0.3)
                if _same_generation():
                    self._tgws_running = False
                    self._tgws_ready = False
                    self._tgws_port = 0
                    try:
                        self._tgws_core.stop()
                    except:
                        pass
                    run_on_ui_thread(self._refresh_settings_without_reopen)

            def _watchdog_wrapped():
                try:
                    _watchdog()
                finally:
                    try:
                        if int(getattr(self, "_tgws_generation", 0) or 0) == int(generation):
                            self._tgws_connecting = False
                    except:
                        self._tgws_connecting = False

            threading.Thread(target=_watchdog_wrapped, daemon=True).start()
            handed_off = True
            return True
        except Exception:
            self._tgws_running = False
            self._tgws_ready = False
            self._tgws_port = 0
            try:
                self._tgws_core.stop()
            except:
                pass
            return False
        finally:
            if not handed_off:
                self._tgws_connecting = False

    def _tgws_disconnect_with_reason(self, reason, silent=False):
        self._tgws_disconnect(silent=bool(silent))

    def _tgws_disconnect(self, silent=False):
        old_port = int(self._tgws_port or 0)
        try:
            self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
        except:
            self._tgws_generation = 1
        try:
            self._tgws_core.stop()
        except:
            pass
        self._tgws_running = False
        self._tgws_ready = False
        self._tgws_port = 0
        self._tgws_connecting = False
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=TGWS_KIND)
        if not silent:
            self._refresh_settings_without_reopen()

    def _ensure_awg_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_awg_mode = runner_name == "_awg_connect"
        if require_awg_mode and (not self._should_run_awg()):
            return
        if self._go_core_switch_blocked("awg"):
            return
        self._awg_core._ensure()
        if self._awg_core.is_available():
            if require_awg_mode and (not self._should_run_awg()):
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._awg_prepare_in_progress:
            return

        self._awg_prepare_in_progress = True
        BulletinHelper.show_info("Скачиваю ядро AWG...")

        def _worker():
            try:
                ok = self._has_libawg_addon()
                if ok:
                    self._reload_awg_core()
                    self._awg_core._ensure()
                    if not self._awg_core.is_available():
                        try:
                            os.remove(self._libawg_so_path())
                            self._libsingbox_validation_cache = None
                        except:
                            pass
                        ok = False
                if not ok:
                    ok = self._download_libawg_with_progress()
                    if ok and self._core_restart_required():
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                        return
                    self._reload_awg_core()
                    self._awg_core._ensure()
                if not (ok and self._awg_core.is_available()):
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро AWG"))
                    return
                if require_awg_mode and (not self._should_run_awg()):
                    return
                try:
                    runner()
                except Exception as exc:
                    err_text = str(exc)
                    run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка AWG: %s" % err_text))
            finally:
                self._awg_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _awg_connect(self):
        if not self._should_run_awg():
            return False
        conf_content = str(self._awg_conf_content or "").strip()
        if not conf_content:
            self._awg_running = False
            self._awg_port = 0
            self._download_free_awg_config()
            return False

        if not self._awg_core.is_available():
            self._awg_running = False
            self._awg_port = 0
            self._ensure_awg_core_then(self._awg_connect)
            return False

        port = int(AWG_LOCAL_PORT)
        self._awg_port = port
        if not self._should_run_awg():
            self._awg_port = 0
            return False
        err = self._awg_core.start(conf_content)
        if err:
            self._awg_running = False
            self._awg_port = 0
            run_on_ui_thread(lambda: BulletinHelper.show_error("Ошибка AWG: %s" % str(err)))
            return False

        self._awg_running = True
        if not self._should_run_awg():
            self._awg_running = False
            self._awg_port = 0
            return False
        applied = self._apply_local_socks_proxy(port, True, owner=AWG_KIND)
        if not self._should_run_awg() or int(self._awg_port or 0) != int(port):
            self._clear_local_socks_proxy_if_port(port, owner=AWG_KIND)
            self._awg_running = False
            return False
        self._save_config()
        run_on_ui_thread(self._refresh_settings_without_reopen)
        run_on_ui_thread(lambda: BulletinHelper.show_success("AmneziaWG подключен"))
        return True

    def _awg_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "unknown")
        stop_core = reason_text in ("manual_stop", "restart_awg", "clear_awg_config", "start_failed", "apply_failed")
        self._awg_disconnect(silent=bool(silent), reason=reason_text, stop_core=bool(stop_core))

    def _awg_disconnect(self, silent=False, reason="unknown", stop_core=False):
        old_port = int(self._awg_port or 0)
        if bool(stop_core) and bool(getattr(self._awg_core, "started", False)):
            try:
                self._awg_core.stop()
            except Exception as exc:
                pass
        self._awg_running = False
        self._awg_port = 0
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=AWG_KIND)
        if not silent:
            self._refresh_settings_without_reopen()

    def _ensure_olcrtc_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_olcrtc_mode = runner_name == "_olcrtc_connect"
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if require_olcrtc_mode and (not self._should_run_olcrtc()):
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return
        if self._go_core_switch_blocked("olcrtc"):
            return
        self._olcrtc_core._ensure()
        if self._olcrtc_core.is_available():
            if require_olcrtc_mode and (not self._should_run_olcrtc()):
                if show_feedback and self._is_olcrtc_mode_selected():
                    run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._olcrtc_prepare_in_progress:
            if show_feedback:
                BulletinHelper.show_info("olcRTC уже готовится")
            return

        self._olcrtc_prepare_in_progress = True
        if show_feedback:
            BulletinHelper.show_info("Готовлю olcRTC...")

        def _worker():
            try:
                ok = self._install_libzvonki_bundle(allow_network=True)
                if ok and self._core_restart_required():
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    return
                self._reload_olcrtc_core()
                self._olcrtc_core._ensure()
                if ok and self._olcrtc_core.is_available():
                    if require_olcrtc_mode and (not self._should_run_olcrtc()):
                        return
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро olcRTC готово"))
                    try:
                        runner()
                    except Exception as exc:
                        err_text = str(exc)
                        self._set_olcrtc_last_error(err_text, event="ensure_runner_exception", runner=runner_name)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка olcRTC: %s" % err_text))
                else:
                    self._set_olcrtc_last_error("core prepare failed", event="ensure_prepare_failed", runner=runner_name, installed=ok)
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить olcRTC"))
            finally:
                self._olcrtc_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _next_olcrtc_generation(self):
        try:
            self._olcrtc_generation = int(getattr(self, "_olcrtc_generation", 0) or 0) + 1
        except:
            self._olcrtc_generation = 1
        return int(self._olcrtc_generation or 0)

    def _same_olcrtc_generation(self, generation):
        try:
            return int(getattr(self, "_olcrtc_generation", 0) or 0) == int(generation)
        except:
            return False

    def _stop_olcrtc_core_async(self):
        def _worker():
            try:
                with self._olcrtc_stop_lock:
                    if bool(getattr(self, "_olcrtc_stop_in_progress", False)):
                        return
                    self._olcrtc_stop_in_progress = True
                try:
                    self._olcrtc_core.stop()
                except Exception as exc:
                    pass
            finally:
                try:
                    with self._olcrtc_stop_lock:
                        self._olcrtc_stop_in_progress = False
                except:
                    pass

        try:
            threading.Thread(target=_worker, daemon=True).start()
        except:
            try:
                self._olcrtc_core.stop()
            except Exception as exc:
                pass

    def _olcrtc_connect(self):
        with self._olcrtc_connect_lock:
            if bool(getattr(self, "_olcrtc_connect_worker_active", False)):
                self._olcrtc_connect_pending = True
                should_queue = True
            else:
                self._olcrtc_connect_worker_active = True
                self._olcrtc_connect_pending = False
                should_queue = False
        if should_queue:
            self._set_olcrtc_last_log("restart queued", event="connect_queued")
            return True

        result = False
        try:
            while True:
                with self._olcrtc_connect_lock:
                    self._olcrtc_connect_pending = False
                result = self._olcrtc_connect_once()
                with self._olcrtc_connect_lock:
                    repeat = bool(self._olcrtc_connect_pending) and bool(self._should_run_olcrtc())
                    if not repeat:
                        self._olcrtc_connect_worker_active = False
                        return result
        finally:
            with self._olcrtc_connect_lock:
                self._olcrtc_connect_worker_active = False

    def _olcrtc_connect_once(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if not self._should_run_olcrtc():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_feedback_requested = False
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return False
        config_json, config_err = self._build_olcrtc_config_json()
        if config_err:
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._olcrtc_feedback_requested = False
            self._set_olcrtc_last_error(config_err, event="connect_config_error")
            if show_feedback:
                run_on_ui_thread(lambda config_err=config_err: BulletinHelper.show_error(config_err))
            return False
        if not self._olcrtc_core.is_available():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
            return False

        self._olcrtc_feedback_requested = False
        generation = self._next_olcrtc_generation()
        old_port = int(self._olcrtc_port or 0)
        self._olcrtc_running = False
        self._olcrtc_connecting = True
        self._olcrtc_dead_checks = 0
        self._olcrtc_last_error = ""
        self._set_olcrtc_last_log(
            "starting %s %s" % (self._get_olcrtc_carrier(), self._get_olcrtc_transport()),
            event="connect_start",
            generation=generation,
            old_port=old_port,
            carrier=self._get_olcrtc_carrier(),
            transport=self._get_olcrtc_transport(),
            room_id=self._get_olcrtc_room_id(),
            client_id=self._get_olcrtc_client_id(),
            key_hex=self._mask_olcrtc_key(),
        )
        run_on_ui_thread(self._refresh_settings_without_reopen)
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        port = int(OLCRTC_LOCAL_PORT)

        self._olcrtc_port = port
        self._olcrtc_start_in_progress = True
        self._set_olcrtc_last_log("handshake started", event="native_start_enter", generation=generation, port=port)
        try:
            err = self._olcrtc_core.start(config_json)
        finally:
            self._olcrtc_start_in_progress = False
        if err:
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return False
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            detail = str(err or "")
            self._set_olcrtc_last_error(detail, event="native_start_failed", generation=generation, port=port)
            self._set_olcrtc_last_log("start failed", event="connect_failed", generation=generation, port=port)
            if self._olcrtc_try_next_profile("start failed"):
                return False
            run_on_ui_thread(self._refresh_settings_without_reopen)
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda detail=detail: BulletinHelper.show_error("Ошибка olcRTC: %s" % str(detail)))
            return False

        def _watchdog():
            deadline = time.time() + float(OLCRTC_LOCAL_READY_TIMEOUT_SEC)
            while time.time() < deadline:
                if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                    self._olcrtc_running = False
                    self._olcrtc_connecting = False
                    self._set_olcrtc_last_log("watchdog cancelled", event="watchdog_cancelled", generation=generation, port=port)
                    return
                if self._olcrtc_local_ready(port, check_tunnel=True, reason="watchdog_ready"):
                    if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                        self._clear_local_socks_proxy_if_port(port, owner=OLCRTC_KIND)
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._set_olcrtc_last_log("cancelled before ready", event="watchdog_cancelled_before_apply", generation=generation, port=port)
                        return
                    applied = self._apply_local_socks_proxy(port, True, owner=OLCRTC_KIND)
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if self._is_local_olcrtc_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_olcrtc_proxy_applied(port)):
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._olcrtc_port = 0
                        self._set_olcrtc_last_error("telegram local proxy apply failed", event="telegram_proxy_apply_failed", generation=generation, port=port, applied=applied)
                        self._set_olcrtc_last_log("socks ready, telegram apply failed", event="connect_failed_after_socks_ready", generation=generation, port=port)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)) and self._same_olcrtc_generation(generation) and self._is_olcrtc_mode_selected():
                            run_on_ui_thread(lambda: BulletinHelper.show_error("Локальный прокси не применился"))
                        return
                    self._olcrtc_running = True
                    self._olcrtc_connecting = False
                    self._olcrtc_health_stale = False
                    self._olcrtc_resume_checking = False
                    self._olcrtc_dead_checks = 0
                    self._olcrtc_last_error = ""
                    self._set_olcrtc_last_log("connected on socks port %s" % int(port), event="connect_ready", generation=generation, port=port)
                    self._save_config()
                    run_on_ui_thread(self._refresh_settings_without_reopen)
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("olcRTC подключен"))
                    return
                time.sleep(0.3)
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._set_olcrtc_last_error("WebRTC timeout", event="watchdog_timeout", generation=generation, port=port)
            self._set_olcrtc_last_log("ready watchdog timeout", event="connect_timeout", generation=generation, port=port)
            if self._olcrtc_try_next_profile("timeout"):
                return
            run_on_ui_thread(self._refresh_settings_without_reopen)
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda: BulletinHelper.show_error("olcRTC: WebRTC timeout"))

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _olcrtc_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "")
        stop_core = reason_text in ("manual_stop", "start_failed", "ready_timeout", "apply_failed")
        self._olcrtc_disconnect(silent=bool(silent), stop_core=bool(stop_core))

    def _olcrtc_disconnect(self, silent=False, stop_core=False):
        self._next_olcrtc_generation()
        self._olcrtc_feedback_requested = False
        old_port = int(self._olcrtc_port or 0)
        with self._olcrtc_connect_lock:
            self._olcrtc_connect_pending = False
        if bool(stop_core):
            self._stop_olcrtc_core_async()
        self._olcrtc_running = False
        self._olcrtc_connecting = False
        self._olcrtc_dead_checks = 0
        self._olcrtc_port = 0
        self._set_olcrtc_last_log("stopped", event="disconnect_finish", old_port=old_port)
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        if not silent:
            self._refresh_settings_without_reopen()

    def _restart_olcrtc_from_settings(self):
        self._set_connection_mode(OLCRTC_KIND)
        if not self._is_olcrtc_config_ready():
            self._set_olcrtc_last_error(self._olcrtc_config_error(), event="restart_config_error")
            BulletinHelper.show_error(self._olcrtc_config_error())
            self._refresh_settings_without_reopen()
            return
        self._upsert_olcrtc_profile({
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
        })
        BulletinHelper.show_info("Запускаю olcRTC...")
        self._olcrtc_feedback_requested = True
        self._enable_plugin_proxy_flag()
        self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_main=True)

    def _download_olcrtc_addon(self):
        if self._has_olcrtc_core_addon():
            BulletinHelper.show_info("Ядро olcRTC уже установлено")
            self._refresh_settings_without_reopen(reload_main=True)
            return
        if self._olcrtc_prepare_in_progress:
            BulletinHelper.show_info("Ядро olcRTC уже готовится")
            return

        self._olcrtc_prepare_in_progress = True
        BulletinHelper.show_info("Готовлю olcRTC...")

        def _worker():
            try:
                ok = self._install_libzvonki_bundle(allow_network=True)
                if ok:
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
                else:
                    self._set_olcrtc_last_error("core download failed", event="download_core_failed", installed=ok)
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить olcRTC"))
            finally:
                self._olcrtc_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()



    def _copy_active_olcrtc_link(self):
        link = self._active_olcrtc_link()
        if not link:
            BulletinHelper.show_error("Нет olcRTC ссылки")
            return
        self._copy_link(link)

    def _on_olcrtc_status_tap(self):
        self._copy_active_olcrtc_link()

    def _confirm_remove_olcrtc_profile(self, profile_id):
        profile = self._find_olcrtc_profile(profile_id)
        if not profile:
            BulletinHelper.show_error("Профиль не найден")
            return
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if not activity:
            self._delete_olcrtc_profile(profile_id)
            return
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Удалить профиль?")
            builder.set_message(self._olcrtc_profile_name(profile))

            def on_yes(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass
                self._delete_olcrtc_profile(profile_id)

            def on_no(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass

            builder.set_positive_button("Удалить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            try:
                builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
            except:
                pass
            builder.show()
        except:
            self._delete_olcrtc_profile(profile_id)

    def _create_olcrtc_profiles_subpage(self):
        self._ensure_olcrtc_legacy_profile()
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        self._olcrtc_profiles = profiles
        active_id = str(self._olcrtc_active_profile_id or "")
        items = [
            Header(text="olcRTC профили"),
            Selector(
                key="olcrtc_carrier",
                text="Провайдер",
                default=self._olcrtc_carrier_index(),
                items=list(OLCRTC_CARRIER_LABELS),
                icon="msg_list",
                on_change=self._on_olcrtc_carrier_changed,
            ),
            Selector(
                key="olcrtc_transport",
                text="Транспорт",
                default=self._olcrtc_transport_index(),
                items=list(OLCRTC_TRANSPORT_LABELS),
                icon="msg_list",
                on_change=self._on_olcrtc_transport_changed,
            ),
            EditText(
                key="olcrtc_room_id",
                hint="room_id",
                default=self._get_olcrtc_room_id(),
                multiline=True,
                max_length=2000,
            ),
            EditText(
                key="olcrtc_client_id",
                hint="client_id",
                default=self._get_olcrtc_client_id(),
                multiline=False,
                max_length=256,
            ),
            EditText(
                key="olcrtc_key_hex",
                hint="key_hex",
                default=self._get_olcrtc_key_hex(),
                multiline=True,
                max_length=256,
            ),
            Text(text="Импорт из буфера", accent=True, icon="msg_link", on_click=lambda *a: self._import_olcrtc_from_clipboard()),
        ]
        active_link = self._active_olcrtc_link()
        if active_link:
            items.append(Text(text="Скопировать ссылку", icon="msg_link", on_click=lambda *a: self._copy_active_olcrtc_link()))
        if profiles:
            items.append(Divider())
            items.append(Header(text="Профили"))
        for profile in profiles:
            pid = str(profile.get("id", "") or "")
            label = self._olcrtc_profile_name(profile)
            subtext = "%s / %s" % (
                self._olcrtc_carrier_label(profile.get("carrier", "")),
                self._olcrtc_transport_label(profile.get("transport", "")),
            )
            items.append(Text(
                text=("🟢 " if pid == active_id else "") + label,
                subtext=subtext,
                icon="msg2_proxy_on" if pid == active_id else "msg2_proxy_off",
                accent=bool(pid == active_id),
                on_click=lambda *a, pid=pid: self._activate_olcrtc_profile(pid, connect=True),
                on_long_click=lambda view, pid=pid: self._confirm_remove_olcrtc_profile(pid),
            ))
        if not profiles:
            items.append(Divider())
            items.append(Text(text="Профилей нет"))
        return items

    def _open_awg_file_picker(self):
        try:
            Intent = jclass("android.content.Intent") if jclass is not None else find_class("android.content.Intent")
            intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.setType("*/*")
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            activity = None
            try:
                fragment = get_last_fragment()
                if fragment is not None:
                    activity = fragment.getParentActivity()
            except:
                activity = None
            if activity is None:
                try:
                    AU = find_class("org.telegram.messenger.AndroidUtilities")
                    activity = AU.getActivity()
                except:
                    activity = None
            if activity is not None:
                activity.startActivityForResult(intent, int(AWG_FILE_PICKER_REQ))
            else:
                BulletinHelper.show_error("Не удалось открыть выбор файла")
        except Exception as exc:
            BulletinHelper.show_error("Ошибка выбора файла: %s" % str(exc))

    def _process_awg_file_uri(self, uri):
        try:
            activity = None
            try:
                fragment = get_last_fragment()
                if fragment is not None:
                    activity = fragment.getParentActivity()
            except:
                activity = None
            if activity is None:
                try:
                    AU = find_class("org.telegram.messenger.AndroidUtilities")
                    activity = AU.getActivity()
                except:
                    activity = None
            if activity is None:
                raise Exception("activity is missing")

            resolver = activity.getContentResolver()
            file_name = "AWG.conf"
            try:
                raw_name = str(uri.getPath() or "").split("/")[-1]
                if ":" in raw_name:
                    raw_name = raw_name.split(":")[-1]
                if raw_name:
                    file_name = raw_name
            except:
                pass
            if not file_name.lower().endswith(".conf"):
                file_name += ".conf"

            BufferedReader = jclass("java.io.BufferedReader") if jclass is not None else find_class("java.io.BufferedReader")
            InputStreamReader = jclass("java.io.InputStreamReader") if jclass is not None else find_class("java.io.InputStreamReader")
            reader = BufferedReader(InputStreamReader(resolver.openInputStream(uri)))
            lines = []
            line = reader.readLine()
            while line is not None:
                lines.append(str(line))
                line = reader.readLine()
            reader.close()

            content = "\n".join(lines) + "\n"
            self._awg_conf_name = file_name
            self._awg_conf_content = content
            self._save_config()
            run_on_ui_thread(lambda: BulletinHelper.show_success("AWG конфиг загружен"))
            if self._is_awg_mode_selected():
                self._enable_plugin_proxy_flag()
                self._ensure_awg_core_then(self._awg_connect)
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка чтения AWG: %s" % err_text))

    def _download_free_awg_config(self):
        if bool(getattr(self, "_awg_config_downloading", False)):
            return
        self._awg_config_downloading = True
        BulletinHelper.show_info("Получаю AWG конфиг...")

        def _worker():
            try:
                device_seed = hashlib.sha1(("%s:%s" % (time.time(), random.random())).encode("utf-8")).hexdigest()[:16]
                req = urllib.request.Request(
                    "https://web-api.vpgram.click/client-api/v1/download-anonymous-key",
                    headers={"X-Device-Id": device_seed},
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
                    raw = resp.read(256 * 1024)
                    text = raw.decode("utf-8", errors="ignore")
                    filename = "VPgram_Free.conf"
                    try:
                        cd = str(resp.headers.get("content-disposition", "") or "")
                        if "filename=" in cd:
                            name = cd.split("filename=", 1)[1].strip("\"' ")
                            if name:
                                filename = name
                    except:
                        pass
                if "[Interface]" not in text or "[Peer]" not in text:
                    raise Exception("ответ не похож на .conf")
                self._awg_conf_name = filename
                self._awg_conf_content = text
                self._save_config()
                run_on_ui_thread(lambda: BulletinHelper.show_success("AWG конфиг получен"))
                if self._is_awg_mode_selected():
                    self._enable_plugin_proxy_flag()
                    self._ensure_awg_core_then(self._awg_connect)
                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
            except Exception as exc:
                err_text = str(exc)
                run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Не удалось получить AWG: %s" % err_text))
            finally:
                self._awg_config_downloading = False

        threading.Thread(target=_worker, daemon=True).start()

    def _ensure_awg_config_then_connect(self):
        if str(self._awg_conf_content or "").strip():
            self._ensure_awg_core_then(self._awg_connect)
            return
        self._download_free_awg_config()

    def _clear_awg_config(self):
        self._awg_disconnect_with_reason("clear_awg_config", silent=True)
        self._awg_conf_name = ""
        self._awg_conf_content = ""
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)

    def _restart_awg_from_settings(self):
        self._set_connection_mode(AWG_KIND)
        self._enable_plugin_proxy_flag()
        self._awg_disconnect_with_reason("restart_awg", silent=True)
        self._ensure_awg_config_then_connect()
        self._refresh_settings_without_reopen()

    def _activate_vless_uri(self, uri, enable_plugin=True, reload_settings=True):
        existing = self._find_vless_node(uri)
        existing_kind = str((existing or {}).get("kind", "") or "").strip().lower()
        existing_from_subscription = False
        if existing:
            try:
                target_uri = str(existing.get("uri", "") or "")
                existing_from_subscription = any(
                    str(item.get("uri", "") or "") == target_uri
                    for sub in list(self._vless_data.get("subs", []) or [])
                    if isinstance(sub, dict)
                    for item in list(sub.get("nodes", []) or [])
                    if isinstance(item, dict)
                )
            except:
                existing_from_subscription = False
        if existing_from_subscription:
            node = existing
            self._vless_data["active_uri"] = str(node.get("uri", "") or "")
            self._vless_save_data()
        elif list((existing or {}).get("balance_nodes", []) or []):
            node = existing
            self._vless_data["active_uri"] = str(node.get("uri", "") or "")
            self._vless_save_data()
        elif existing_kind == QWDTT_KIND:
            node = self._save_vless_manual_node(existing)
        elif existing_kind == "singbox-config":
            try:
                prepared = _prepare_singbox_file_config(str((existing or {}).get("raw_config", "") or ""), VLESS_LOCAL_PORT)
            except Exception as exc:
                BulletinHelper.show_error("Ошибка конфига sing-box: %s" % str(exc))
                return False
            validation_error = self._validate_core_config_for_import(prepared, "sing-box config")
            if validation_error:
                BulletinHelper.show_error(validation_error)
                return False
            node = self._save_vless_manual_node(existing)
        else:
            validation_error = self._validate_proxy_uri_for_import(uri)
            if validation_error:
                BulletinHelper.show_error(validation_error)
                return False
            node = self._add_vless_manual_node(uri)
        if not node:
            BulletinHelper.show_error("Неверная ссылка")
            return

        try:
            self._current_server = str(node.get("server", "") or "")
            self._current_port = int(node.get("port", 0) or 0)
            self._current_secret = ""
            self._last_provider_name = _proxy_protocol_label(node)
        except:
            pass
        self._set_connection_mode(VLESS_KIND)
        try:
            self._finding_proxy = False
        except:
            pass
        try:
            self._tgws_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass

        if enable_plugin:
            try:
                self._enable_plugin_proxy_flag()
            except:
                pass

        self._reset_vless_retry()
        self._set_vless_connection_state(True, "")
        self._ensure_vless_core_then(self._vless_connect)
        if bool(reload_settings):
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _add_vless_subscription(self, url, activate_first=False):
        target = str(url or "").strip()
        if not target.startswith("http"):
            BulletinHelper.show_error("Нужна ссылка на подписку")
            return

        BulletinHelper.show_info("Загружаю подписку...")

        def _worker():
            subscription_text = _fetch_text_url(target, timeout_sec=15.0)
            nodes = _fetch_vless_nodes(target, text=subscription_text)
            if not nodes:
                qwdtt_count = 0
                try:
                    qwdtt_count = self._import_qwdtt_payload(subscription_text, activate_first=bool(activate_first), subscription_url=target)
                except:
                    qwdtt_count = 0
                if qwdtt_count > 0:
                    run_on_ui_thread(lambda count=qwdtt_count: BulletinHelper.show_success(f"qWDTT профилей: {count}"))
                    return
                olcrtc_count = 0
                try:
                    olcrtc_count = self._try_import_olcrtc_subscription_text(target, subscription_text, activate_first=bool(activate_first))
                except:
                    olcrtc_count = 0
                if olcrtc_count > 0:
                    run_on_ui_thread(lambda count=olcrtc_count: BulletinHelper.show_success(f"olcRTC профилей: {count}"))
                    return
                diag = _get_vless_fetch_diag(target)
                if diag:
                    text_len = int(diag.get("text_len", 0) or 0)
                    vless_count = int(diag.get("vless_count", 0) or 0)
                    ss_count = int(diag.get("ss_count", 0) or 0)
                    proxy_count = int(diag.get("proxy_count", 0) or 0)
                    link_count = int(diag.get("link_count", 0) or 0)
                    stage = str(diag.get("stage", "") or "")
                    tried = int(diag.get("tried", 0) or 0)
                    fetched_host = ""
                    try:
                        fetched_host = str(urllib.parse.urlparse(str(diag.get("fetched_url", "") or "")).netloc or "").strip()
                    except:
                        fetched_host = ""
                    errors = str(diag.get("errors", "") or "").strip()
                    msg = f"Нет узлов: text={text_len} proxy={proxy_count} sing-box={vless_count} ss={ss_count} links={link_count} tried={tried}"
                    if stage:
                        msg += f" stage={stage}"
                    if fetched_host:
                        msg += f" host={fetched_host}"
                    if errors:
                        msg += f" err={errors[:120]}"
                    run_on_ui_thread(lambda: BulletinHelper.show_error(msg))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Подписка не содержит узлов"))
                return

            try:
                subs = list(self._vless_data.get("subs", []) or [])
            except:
                subs = []

            updated = False
            for sub in subs:
                try:
                    if str(sub.get("url", "") or "") == target:
                        sub["nodes"] = nodes
                        updated = True
                except:
                    continue
            if not updated:
                subs.append({
                    "id": target,
                    "url": target,
                    "name": str(urllib.parse.urlparse(target).netloc or target),
                    "nodes": nodes,
                })
            self._vless_data["subs"] = subs
            if activate_first and nodes:
                try:
                    self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
                    self._set_connection_mode(VLESS_KIND)
                except:
                    pass
            self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Импортировано узлов: {len(nodes)}"))

            if activate_first and nodes:
                try:
                    self._enable_plugin_proxy_flag()
                except:
                    pass
                try:
                    self._tgws_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                try:
                    self._awg_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                self._ensure_vless_core_then(self._vless_connect)
            elif updated and self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                self._ensure_vless_core_then(self._vless_connect)

        threading.Thread(target=_worker, daemon=True).start()

    def _clear_vless_nodes(self):
        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._vless_disconnect_with_reason("clear_vless_nodes", silent=True)
        self._save_config()
        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Узлы очищены")

    def _confirm_clear_vless_nodes(self):
        counts = self._vless_counts()
        if int(counts.get("nodes", 0) or 0) <= 0:
            BulletinHelper.show_info("Нет узлов")
            return True
        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        builder.set_title("Очистить узлы?")
        builder.set_message("Все узлы и подписки будут удалены. Действие необратимо.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._clear_vless_nodes()

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Очистить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _first_vless_uri(self):
        for node in self._get_all_vless_nodes():
            try:
                uri = str(node.get("uri", "") or "")
            except:
                uri = ""
            if uri:
                return uri
        return ""

    def _vless_counts(self):
        try:
            manual_count = len(list(self._vless_data.get("manual", []) or []))
        except:
            manual_count = 0
        try:
            subs = list(self._vless_data.get("subs", []) or [])
        except:
            subs = []
        sub_count = len(subs)
        node_count = int(manual_count)
        for sub in subs:
            try:
                node_count += len(list(sub.get("nodes", []) or []))
            except:
                pass
        return {"manual": int(manual_count), "subs": int(sub_count), "nodes": int(node_count)}

    def _connect_best_vless_node(self):
        if not list(self._iter_vless_nodes()):
            BulletinHelper.show_info("Нет узлов")
            return False
        BulletinHelper.show_info("Ищу лучший узел...")

        def _worker():
            try:
                self._refresh_vless_node_pings(force=True, save=True)
                node = self._pick_fastest_vless_node()
                if node is None:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Живых узлов нет"))
                    return
                try:
                    uri = str(node.get("uri", "") or "")
                    name = str(node.get("name", "") or "").strip() or "Узел"
                    ping = self._vless_ping_value(node)
                except:
                    uri = ""
                    name = "Узел"
                    ping = -1
                if not uri:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Узел без ссылки"))
                    return

                def _apply_best():
                    BulletinHelper.show_success(f"Лучший: {name} ({int(ping)} ms)")
                    self._activate_vless_uri(uri, enable_plugin=True)

                run_on_ui_thread(_apply_best)
            finally:
                run_on_ui_thread(self._refresh_settings_without_reopen)

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _remove_vless_uri(self, uri):
        target_uri = str(uri or "")
        if not target_uri:
            return False

        removed = False
        was_active = target_uri == self._get_active_vless_uri()

        manual = []
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                try:
                    if str(node.get("uri", "") or "") == target_uri:
                        removed = True
                        continue
                except:
                    pass
                manual.append(node)
        except:
            manual = []

        subs = []
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                nodes = []
                for node in list(sub.get("nodes", []) or []):
                    try:
                        if str(node.get("uri", "") or "") == target_uri:
                            removed = True
                            continue
                    except:
                        pass
                    nodes.append(node)
                if not nodes:
                    continue
                sub_copy = dict(sub)
                sub_copy["nodes"] = nodes
                subs.append(sub_copy)
        except:
            subs = []

        if not removed:
            return False

        self._vless_data["manual"] = manual
        self._vless_data["subs"] = subs
        if was_active:
            self._vless_data["active_uri"] = self._first_vless_uri()
        self._vless_save_data()

        if was_active:
            next_uri = self._get_active_vless_uri()
            if self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND:
                if next_uri:
                    self._ensure_vless_core_then(self._vless_connect)
                else:
                    self._vless_disconnect_with_reason("remove_vless_node", silent=True)
        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Узел удален")
        return True

    def _confirm_remove_vless_node(self, uri):
        target_uri = str(uri or "")
        if not target_uri:
            return True
        node = self._find_vless_node(target_uri)
        if node is None:
            return True

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        try:
            title = "Удалить %s?" % _proxy_protocol_label(node)
        except:
            title = "Удалить узел?"
        builder.set_title(title)
        builder.set_message(self._vless_node_label(node))

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._remove_vless_uri(target_uri)

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _refresh_vless_subscriptions(self):
        urls = []
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                url = str(sub.get("url", "") or "")
                if url and url not in urls:
                    urls.append(url)
        except:
            pass
        if not urls:
            BulletinHelper.show_info("Нет подписок")
            return

        BulletinHelper.show_info("Обновляю подписки...")

        def _worker():
            changed = 0
            for url in urls:
                nodes = _fetch_vless_nodes(url)
                if not nodes:
                    continue
                try:
                    for sub in list(self._vless_data.get("subs", []) or []):
                        if str(sub.get("url", "") or "") == url:
                            sub["nodes"] = nodes
                            changed += 1
                except:
                    continue
            if changed:
                self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            if changed and self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                self._ensure_vless_core_then(self._vless_connect)
            run_on_ui_thread(self._refresh_settings_without_reopen)
            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Подписок обновлено: {changed}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _install_singbox_as_vless_core(self, on_progress=None):
        return self._install_libsingbox_bundle(allow_network=True, on_progress=on_progress)

    def _open_core_download_progress(self):
        activity = self._current_activity()
        if activity is None:
            return None, lambda *_args: None
        try:
            container = LinearLayout(activity)
            container.setOrientation(LinearLayout.VERTICAL)
            padding = AndroidUtilities.dp(20)
            container.setPadding(padding, AndroidUtilities.dp(8), padding, AndroidUtilities.dp(12))

            label = TextView(activity)
            label.setText("%s • 0%%" % Z("Подготовка"))
            label.setTextSize(16)
            try:
                label.setTextColor(Theme.getColor(Theme.key_dialogTextBlack))
            except:
                pass

            progress = LineProgressView(activity)
            try:
                progress.setProgressColor(Theme.getColor(Theme.key_featuredStickers_addButton))
                progress.setBackColor(Theme.getColor(Theme.key_dialogLineProgressBackground))
            except:
                pass
            progress.setProgress(0.0, False)

            text_lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            bar_lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, AndroidUtilities.dp(6))
            bar_lp.setMargins(0, AndroidUtilities.dp(12), 0, AndroidUtilities.dp(8))
            container.addView(label, text_lp)
            container.addView(progress, bar_lp)

            dialog = AlertDialogBuilder(activity, _AlertDialogBuilder.ALERT_TYPE_MESSAGE)
            dialog.set_title("Ядро GreenPass")
            dialog.set_view(container)
            dialog.set_cancelable(False)
            dialog.show()

            def _update(value, stage="Скачивание"):
                value = max(0.0, min(1.0, float(value)))
                def _ui():
                    label.setText("%s • %d%%" % (Z(stage), int(value * 100)))
                    progress.setProgress(value, True)
                run_on_ui_thread(_ui)

            return dialog, _update
        except:
            return None, lambda *_args: None

    def _download_vless_addon(self):
        if self._vless_prepare_in_progress:
            BulletinHelper.show_info("Ядро прокси уже скачивается")
            return

        self._vless_prepare_in_progress = True
        dialog, update_progress = self._open_core_download_progress()
        if dialog is None:
            BulletinHelper.show_info("Скачиваю ядро прокси...")

        def _worker():
            try:
                ok = self._install_singbox_as_vless_core(on_progress=update_progress)
                if ok:
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    run_on_ui_thread(self._refresh_settings_without_reopen)
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро прокси"))
            finally:
                self._vless_prepare_in_progress = False
                if dialog is not None:
                    run_on_ui_thread(lambda: dialog.dismiss())

        threading.Thread(target=_worker, daemon=True).start()

    def _confirm_delete_vless_addon(self):
        if not self._has_libvless_addon():
            BulletinHelper.show_info("Ядро не установлено")
            return True
        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        builder = AlertDialogBuilder(activity)
        builder.set_title("Удалить ядро?")
        builder.set_message("Файл ядра прокси будет удалён. Его можно скачать снова.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._delete_vless_addon()

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _delete_vless_addon(self):
        try:
            self._vless_disconnect_with_reason("delete_vless_addon", silent=True)
        except:
            pass

        ok = False
        try:
            path = self._libvless_so_path()
            if os.path.exists(path):
                os.remove(path)
            self._libsingbox_validation_cache = None
            ok = True
        except:
            ok = False

        self._reload_vless_core()
        self._refresh_settings_without_reopen()
        if ok:
            BulletinHelper.show_success("Ядро прокси удалено")
        else:
            BulletinHelper.show_error("Не удалось удалить ядро прокси")

    def _provider_name(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= self._provider_count():
            i = 0
        try:
            return str(PROXY_PROVIDER_ITEMS[i])
        except:
            return ""

    def _normalize_proxy_dict(self, proxy):
        if not isinstance(proxy, dict):
            return None
        try:
            server = str(proxy.get("server", "") or "")
        except:
            server = ""
        try:
            port = int(proxy.get("port", 0) or 0)
        except:
            port = 0
        try:
            secret = str(proxy.get("secret", "") or "")
        except:
            secret = ""
        try:
            username = str(proxy.get("username", "") or "")
        except:
            username = ""
        try:
            password = str(proxy.get("password", "") or "")
        except:
            password = ""
        try:
            kind = str(proxy.get("kind", "mtproto") or "mtproto")
        except:
            kind = "mtproto"
        try:
            provider_idx = int(proxy.get("provider_idx", -1))
        except:
            provider_idx = -1
        try:
            provider_name = str(proxy.get("provider_name", "") or "")
        except:
            provider_name = ""
        try:
            latency = float(proxy.get("latency", 0.0) or 0.0)
        except:
            latency = 0.0
        try:
            checked_at = int(proxy.get("checked_at", int(time.time())) or int(time.time()))
        except:
            checked_at = int(time.time())

        if not server or port <= 0:
            return None
        if kind != "socks" and not secret:
            return None

        return {
            "server": server,
            "port": int(port),
            "secret": secret,
            "username": username,
            "password": password,
            "kind": kind,
            "provider_idx": int(provider_idx),
            "provider_name": provider_name,
            "latency": float(latency),
            "checked_at": int(checked_at),
        }

    def _merge_unique_proxies(self, proxy_lists):
        merged = {}
        for items in proxy_lists:
            for proxy in list(items or []):
                p = self._normalize_proxy_dict(proxy)
                if not p:
                    continue
                key = self._proxy_key(
                    p.get("server"),
                    p.get("port"),
                    p.get("secret"),
                    p.get("username"),
                    p.get("password"),
                )
                if key not in merged:
                    merged[key] = p
        return list(merged.values())

    def _sanitize_hot_proxy_cache(self, items):
        now = int(time.time())
        dedup = {}
        for proxy in list(items or []):
            p = self._normalize_proxy_dict(proxy)
            if not p:
                continue
            checked_at = int(p.get("checked_at", now) or now)
            if (now - checked_at) > int(HOT_CACHE_TTL_SEC):
                continue
            key = self._proxy_key(
                p.get("server"),
                p.get("port"),
                p.get("secret"),
                p.get("username"),
                p.get("password"),
            )
            prev = dedup.get(key)
            if prev is None or float(p.get("latency", 999999.0)) < float(prev.get("latency", 999999.0)):
                dedup[key] = p

        out = list(dedup.values())
        out.sort(key=lambda x: float(x.get("latency", 999999.0)))
        return out[: int(HOT_CACHE_MAX_ITEMS)]

    def _build_safe_fallback_chain(self, selected_provider_proxies, merged_provider_proxies):
        selected_list = self._merge_unique_proxies([selected_provider_proxies])
        merged_list = self._merge_unique_proxies([merged_provider_proxies])
        hot_list = self._sanitize_hot_proxy_cache(self._hot_proxy_cache)
        last_list = self._merge_unique_proxies([[self._last_working_proxy] if self._last_working_proxy else []])

        return [
            ("selected_provider", selected_list),
            ("all_providers", merged_list),
            ("hot_cache", hot_list),
            ("last_working", last_list),
        ]

    def _refresh_hot_proxy_cache(self, candidates):
        now = int(time.time())
        sample = self._build_probe_subset(list(candidates or []), limit=int(PRECHECK_SAMPLE_LIMIT))
        if not sample:
            self._hot_proxy_cache = self._sanitize_hot_proxy_cache(self._hot_proxy_cache)
            return

        checked = []
        for p in sample:
            dt = self._probe_proxy_latency(p, timeout_sec=float(PRECHECK_PING_TIMEOUT_SEC))
            if dt is None:
                continue
            item = self._normalize_proxy_dict(p)
            if not item:
                continue
            item["latency"] = float(dt)
            item["checked_at"] = int(now)
            checked.append(item)

        merged = self._merge_unique_proxies([checked, self._hot_proxy_cache])
        for p in merged:
            if "checked_at" not in p:
                p["checked_at"] = int(now)
        self._hot_proxy_cache = self._sanitize_hot_proxy_cache(merged)

    def _background_precheck(self):
        if not self._active:
            return
        if not self._is_plugin_proxy_enabled():
            return
        if self._finding_proxy:
            return

        try:
            provider_auto = self._get_provider_auto()
            selected_provider = self._get_selected_provider()

            if provider_auto:
                provider_proxy_map = self._collect_provider_proxy_map_sync(timeout_sec=2.0)
                selected = list(provider_proxy_map.get(selected_provider, []) or [])
                merged = self._merge_unique_proxies([provider_proxy_map.get(i, []) or [] for i in range(self._provider_count())])
                candidates = self._merge_unique_proxies([selected, merged])
            else:
                selected = self._collect_proxies_for_provider(selected_provider, timeout_sec=3.5)
                candidates = self._merge_unique_proxies([selected])

            self._refresh_hot_proxy_cache(candidates)
            self._save_config()
        except Exception:
            pass

    def _get_hardcoded_proxies_text(self):
        try:
            value = self.get_setting("hardcoded_proxies_text", FALLBACK_PROXIES_TEXT)
        except:
            value = FALLBACK_PROXIES_TEXT
        try:
            return str(value or "")
        except:
            return str(FALLBACK_PROXIES_TEXT)

    def _create_hardcoded_proxies_subpage(self):
        return [
            Header(text="Редактор встроенных прокси"),
            Text(text="Одна ссылка в строке (tg://proxy или https://t.me/proxy...)"),
            EditText(
                key="hardcoded_proxies_text",
                hint="Вставьте список прокси",
                default=self._get_hardcoded_proxies_text(),
                multiline=True,
                max_length=30000,
            ),
            Divider(),
            Text(
                text="Сбросить к стандартным",
                red=True,
                on_click=lambda *a: self._reset_hardcoded_proxies_to_default(),
            ),
            Text(
                text="Применить и найти прокси",
                accent=True,
                on_click=lambda *a: self._force_update(),
            ),
        ]

    def _reset_hardcoded_proxies_to_default(self):
        try:
            self._set_setting_value("hardcoded_proxies_text", str(FALLBACK_PROXIES_TEXT), reload_settings=True)
        except:
            pass
        BulletinHelper.show_success("Стандартные прокси восстановлены")

    def _collect_provider_proxy_map_sync(self, timeout_sec=2.5):
        out = {}
        for i in range(self._provider_count()):
            try:
                out[int(i)] = self._collect_proxies_for_provider(i, timeout_sec=timeout_sec)
            except:
                out[int(i)] = []
        return out

    def _choose_best_provider_auto_sync(self, provider_proxy_map, preferred_idx):
        best_idx = None
        best_score = None
        provider_scores = {}
        lock = threading.Lock()
        threads = []
        prefer_calls_proxy = bool(self._get_calls_proxy_preference())

        def _worker(provider_idx):
            proxies = list(provider_proxy_map.get(provider_idx, []) or [])
            if prefer_calls_proxy:
                proxies = [p for p in proxies if self._is_socks_proxy(p)]
            if not proxies:
                try:
                    lock.acquire()
                    provider_scores[int(provider_idx)] = None
                finally:
                    try:
                        lock.release()
                    except:
                        pass
                return

            score_values = []
            random.shuffle(proxies)
            sample_cap = min(int(AUTO_PROVIDER_MAX_SAMPLES_PER_PROVIDER), len(proxies))
            for proxy in proxies[:sample_cap]:
                dt = self._probe_proxy_latency(proxy, timeout_sec=float(AUTO_PROVIDER_PING_TIMEOUT_SEC))
                if dt is not None:
                    score_values.append(float(dt))

            score = self._provider_latency_score(score_values)
            if score is None:
                score = 999999.0

            try:
                lock.acquire()
                provider_scores[int(provider_idx)] = float(score)
            finally:
                try:
                    lock.release()
                except:
                    pass

        for idx in range(self._provider_count()):
            try:
                t = threading.Thread(target=_worker, args=(int(idx),), daemon=True)
                t.start()
                threads.append(t)
            except:
                try:
                    provider_scores[int(idx)] = None
                except:
                    pass

        deadline = time.time() + float(AUTO_PROVIDER_SELECT_DEADLINE_SEC)
        for t in threads:
            try:
                remain = float(deadline - time.time())
                if remain <= 0:
                    break
                t.join(timeout=remain)
            except:
                pass

        for idx in range(self._provider_count()):
            try:
                score = provider_scores.get(int(idx), None)
            except:
                score = None
            if score is None:
                continue
            if best_score is None or float(score) < float(best_score):
                best_score = float(score)
                best_idx = int(idx)

        if best_idx is not None:
            return int(best_idx)

        if prefer_calls_proxy:
            if provider_proxy_map.get(preferred_idx):
                try:
                    for p in list(provider_proxy_map.get(preferred_idx, []) or []):
                        if self._is_socks_proxy(p):
                            return int(preferred_idx)
                except:
                    pass
            for idx in range(self._provider_count()):
                try:
                    for p in list(provider_proxy_map.get(idx, []) or []):
                        if self._is_socks_proxy(p):
                            return int(idx)
                except:
                    pass

        if provider_proxy_map.get(preferred_idx):
            return int(preferred_idx)
        for idx in range(self._provider_count()):
            if provider_proxy_map.get(idx):
                return int(idx)
        return int(preferred_idx)

    def _build_probe_subset(self, proxies, limit=12):
        try:
            max_items = int(limit)
        except:
            max_items = 12
        if max_items <= 0:
            return []

        items = list(proxies or [])
        if not items:
            return []

        random.shuffle(items)

        grouped = {}
        for p in items:
            try:
                idx = int(p.get("provider_idx"))
            except:
                idx = None
            if idx is None:
                continue
            if idx not in grouped:
                grouped[idx] = []
            grouped[idx].append(p)

        if len(grouped) <= 1:
            return items[:max_items]

        provider_order = list(grouped.keys())
        random.shuffle(provider_order)
        subset = []

        for idx in provider_order:
            if len(subset) >= max_items:
                break
            arr = grouped.get(idx, [])
            if not arr:
                continue
            random.shuffle(arr)
            subset.append(arr.pop())

        leftovers = []
        for idx in provider_order:
            leftovers.extend(grouped.get(idx, []))
        random.shuffle(leftovers)

        used = set(id(x) for x in subset)
        for p in leftovers:
            if len(subset) >= max_items:
                break
            if id(p) in used:
                continue
            subset.append(p)
            used.add(id(p))

        if len(subset) < max_items:
            for p in items:
                if len(subset) >= max_items:
                    break
                if id(p) in used:
                    continue
                subset.append(p)
                used.add(id(p))

        return subset

    def _collect_proxies_for_provider(self, provider_idx, timeout_sec=5.0):
        try:
            idx = int(provider_idx)
        except:
            idx = 0

        urls = list(PROXY_PROVIDER_URLS.get(idx, []) or [])
        custom_headers = {}
        provider_name = self._provider_name(idx)
        proxies = []

        for url in urls:
            if not str(url or "").strip():
                continue
            fetched = self._fetch_proxies_from_url(url, timeout_sec=timeout_sec, headers=custom_headers)
            if fetched:
                for proxy in fetched:
                    try:
                        item = {
                            "server": str(proxy.get("server", "")),
                            "port": int(proxy.get("port", 0)),
                            "username": str(proxy.get("username", "")),
                            "password": str(proxy.get("password", "")),
                            "secret": str(proxy.get("secret", "")),
                            "kind": str(proxy.get("kind", "mtproto")),
                            "provider_idx": idx,
                            "provider_name": provider_name,
                        }
                        if item["server"] and item["port"] > 0 and (item["secret"] or item["kind"] == "socks"):
                            proxies.append(item)
                    except:
                        pass

        try:
            provider_fallback = str(PROXY_PROVIDER_FALLBACK_TEXT.get(idx, "") or "")
        except:
            provider_fallback = ""

        if provider_fallback:
            fallback_from_provider = self._parse_proxies(provider_fallback)
            for proxy in fallback_from_provider:
                try:
                    item = {
                        "server": str(proxy.get("server", "")),
                        "port": int(proxy.get("port", 0)),
                        "username": str(proxy.get("username", "")),
                        "password": str(proxy.get("password", "")),
                        "secret": str(proxy.get("secret", "")),
                        "kind": str(proxy.get("kind", "mtproto")),
                        "provider_idx": idx,
                        "provider_name": provider_name,
                    }
                    if item["server"] and item["port"] > 0 and (item["secret"] or item["kind"] == "socks"):
                        proxies.append(item)
                except:
                    pass

        if idx == 0:
            fallback_proxies = self._parse_proxies(self._get_hardcoded_proxies_text())
            if fallback_proxies:
                for proxy in fallback_proxies:
                    try:
                        item = {
                            "server": str(proxy.get("server", "")),
                            "port": int(proxy.get("port", 0)),
                            "username": str(proxy.get("username", "")),
                            "password": str(proxy.get("password", "")),
                            "secret": str(proxy.get("secret", "")),
                            "kind": str(proxy.get("kind", "mtproto")),
                            "provider_idx": idx,
                            "provider_name": provider_name,
                        }
                        if item["server"] and item["port"] > 0 and (item["secret"] or item["kind"] == "socks"):
                            proxies.append(item)
                    except:
                        pass

        dedup = {}
        for proxy in proxies:
            key = self._proxy_key(
                proxy.get("server"),
                proxy.get("port"),
                proxy.get("secret"),
                proxy.get("username"),
                proxy.get("password"),
            )
            if key not in dedup:
                dedup[key] = proxy

        return list(dedup.values())

    def _probe_proxy_latency(self, proxy, timeout_sec=2.0):
        sock = None
        try:
            host = str(proxy.get("server", ""))
            port = int(proxy.get("port", 0))
            if not host or port <= 0:
                return None

            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout_sec))
            res = sock.connect_ex((host, port))
            if res != 0:
                return None
            return (time.time() - start) * 1000.0
        except:
            return None
        finally:
            try:
                if sock is not None:
                    sock.close()
            except:
                pass

    def _provider_latency_score(self, samples):
        if not samples:
            return None
        try:
            ordered = sorted(float(x) for x in samples)
        except:
            return None
        if not ordered:
            return None

        take = min(7, len(ordered))
        if take <= 0:
            return None
        best_chunk = ordered[:take]
        avg = sum(best_chunk) / float(len(best_chunk))
        reliability_bonus = min(12, len(ordered))
        return avg - (0.5 * float(reliability_bonus))

    def _prune_proxy_state(self, now=None, valid_keys=None):
        if now is None:
            now = int(time.time())
        try:
            keys = list(self._proxy_state.keys())
        except:
            keys = []

        for k in keys:
            v = self._proxy_state.get(k, {})
            if not isinstance(v, dict):
                self._proxy_state.pop(k, None)
                continue
            last_used = int(v.get("last_used", 0) or 0)
            if last_used and (now - last_used) > PROXY_STATE_TTL_SEC:
                self._proxy_state.pop(k, None)
                continue
            if valid_keys is not None and k not in valid_keys:
                owned = False
                try:
                    owned = bool(v.get("owned", True))
                except:
                    owned = True
                if not owned:
                    if last_used == 0 or (now - last_used) > 24 * 60 * 60:
                        self._proxy_state.pop(k, None)

        try:
            if len(self._proxy_state) > MAX_TRACKED_PROXY_STATE:
                ordered = sorted(self._proxy_state.items(), key=lambda kv: int((kv[1] or {}).get("last_used", 0) or 0))
                for k, _ in ordered[: max(0, len(self._proxy_state) - MAX_TRACKED_PROXY_STATE)]:
                    self._proxy_state.pop(k, None)
        except:
            pass

    def _should_skip_proxy_due_to_failures(self, key, now=None):
        if now is None:
            now = int(time.time())
        v = self._proxy_state.get(key)
        if not isinstance(v, dict):
            return False
        failures = int(v.get("failures", 0) or 0)
        fail_ts = int(v.get("fail_ts", 0) or 0)
        if failures >= PROXY_FAIL_THRESHOLD and fail_ts and (now - fail_ts) < PROXY_FAIL_TTL_SEC:
            return True
        return False

    def _mark_proxy_failed(self, key, now=None):
        if now is None:
            now = int(time.time())
        v = self._proxy_state.get(key)
        if not isinstance(v, dict):
            v = {"owned": True, "last_used": 0, "failures": 0, "fail_ts": 0}
            self._proxy_state[key] = v
        try:
            v["failures"] = int(v.get("failures", 0) or 0) + 1
        except:
            v["failures"] = 1
        v["fail_ts"] = now

    def _mark_proxy_success(self, key, owned, now=None):
        if now is None:
            now = int(time.time())
        v = self._proxy_state.get(key)
        if not isinstance(v, dict):
            v = {}
            self._proxy_state[key] = v
        v["owned"] = bool(owned)
        v["last_used"] = now
        v["failures"] = 0
        v["fail_ts"] = 0

    def _load_proxy_list_safe(self):
        try:
            if hasattr(SharedConfig, "loadProxyList"):
                SharedConfig.loadProxyList()
        except:
            pass

    def _shared_proxy_list_snapshot(self):
        try:
            self._load_proxy_list_safe()
        except:
            pass

        try:
            pl = SharedConfig.proxyList
        except:
            return []

        out = []

        try:
            size = pl.size()
        except:
            size = None

        if size is not None:
            for i in range(int(size)):
                try:
                    out.append(pl.get(i))
                except:
                    pass
            return out

        try:
            for p in pl:
                out.append(p)
        except:
            pass

        return out

    def _find_proxy_in_shared_list(self, key):
        for p in self._shared_proxy_list_snapshot():
            try:
                k = self._proxy_key(
                    p.address,
                    p.port,
                    p.secret,
                    getattr(p, "username", ""),
                    getattr(p, "password", ""),
                )
                if k == key:
                    return p
            except:
                continue
        return None

    def _cleanup_plugin_proxies_from_shared_list(self, keep_current=True):
        try:
            self._load_proxy_list_safe()

            current = None
            try:
                current = SharedConfig.currentProxy
            except:
                current = None

            removed_any = False
            for p in self._shared_proxy_list_snapshot():
                try:
                    if keep_current and current is not None and p == current:
                        continue
                    key = self._proxy_key(
                        p.address,
                        p.port,
                        p.secret,
                        getattr(p, "username", ""),
                        getattr(p, "password", ""),
                    )
                    v = self._proxy_state.get(key)
                    if not isinstance(v, dict):
                        continue
                    if not bool(v.get("owned", True)):
                        continue
                    try:
                        if hasattr(SharedConfig, "deleteProxy"):
                            SharedConfig.deleteProxy(p)
                        else:
                            SharedConfig.proxyList.remove(p)
                            if hasattr(SharedConfig, "saveProxyList"):
                                SharedConfig.saveProxyList()
                    except:
                        continue
                    removed_any = True
                except:
                    continue

            if removed_any:
                try:
                    existing = set()
                    for p in self._shared_proxy_list_snapshot():
                        try:
                            existing.add(
                                self._proxy_key(
                                    p.address,
                                    p.port,
                                    p.secret,
                                    getattr(p, "username", ""),
                                    getattr(p, "password", ""),
                                )
                            )
                        except:
                            pass
                    if keep_current and current is not None:
                        try:
                            existing.add(
                                self._proxy_key(
                                    current.address,
                                    current.port,
                                    current.secret,
                                    getattr(current, "username", ""),
                                    getattr(current, "password", ""),
                                )
                            )
                        except:
                            pass
                    for k in list(self._proxy_state.keys()):
                        if k not in existing:
                            v = self._proxy_state.get(k)
                            if isinstance(v, dict) and bool(v.get("owned", True)):
                                self._proxy_state.pop(k, None)
                except:
                    pass

            try:
                if removed_any:
                    self._save_config()
            except:
                pass
        except:
            pass

    def _should_arm_proxy_transition_killswitch(self, enabled, address, port, username, password, secret):
        return True

    def _set_proxy_transition_network_paused(self, paused):
        try:
            account = int(UserConfig.selectedAccount)
        except:
            account = 0
        try:
            cm = ConnectionsManager.getInstance(account)
            if cm is not None:
                cm.setAppPaused(bool(paused), False)
        except:
            pass

    def _acquire_proxy_transition_killswitch(self, reason=""):
        with self._proxy_transition_state_lock:
            lease = int(self._proxy_transition_next_lease)
            self._proxy_transition_next_lease += 1
            should_pause = not bool(self._proxy_transition_active_leases)
            self._proxy_transition_active_leases.add(lease)

        if should_pause:
            try:
                self._set_proxy_transition_network_paused(True)
            except:
                pass

        def _failsafe_release():
            try:
                time.sleep(float(PROXY_TRANSITION_KILLSWITCH_FAILSAFE_SEC))
            except:
                pass
            self._release_proxy_transition_killswitch(lease)

        try:
            threading.Thread(target=_failsafe_release, daemon=True).start()
        except:
            pass
        return lease

    def _release_proxy_transition_killswitch(self, lease, delay_sec=0.0):
        if lease is None:
            return

        def _release():
            try:
                wait_sec = float(delay_sec or 0.0)
            except:
                wait_sec = 0.0
            if wait_sec > 0:
                try:
                    time.sleep(wait_sec)
                except:
                    pass

            with self._proxy_transition_state_lock:
                if lease not in self._proxy_transition_active_leases:
                    return
                self._proxy_transition_active_leases.discard(lease)
                should_resume = not bool(self._proxy_transition_active_leases)

            if should_resume:
                try:
                    self._set_proxy_transition_network_paused(False)
                except:
                    pass

        if float(delay_sec or 0.0) > 0:
            try:
                threading.Thread(target=_release, daemon=True).start()
                return
            except:
                pass
        _release()

    def _release_all_proxy_transition_killswitches(self):
        should_resume = False
        with self._proxy_transition_state_lock:
            if self._proxy_transition_active_leases:
                should_resume = True
            self._proxy_transition_active_leases.clear()
            self._proxy_transition_param_leases = {}
        if should_resume:
            try:
                self._set_proxy_transition_network_paused(False)
            except:
                pass

    def _remember_proxy_transition_param_lease(self, param, lease):
        if lease is None:
            return
        with self._proxy_transition_state_lock:
            self._proxy_transition_param_leases[id(param)] = lease

    def _pop_proxy_transition_param_lease(self, param):
        with self._proxy_transition_state_lock:
            return self._proxy_transition_param_leases.pop(id(param), None)

    def _maybe_acquire_proxy_transition_killswitch_from_args(self, args):
        if not args or len(args) < 6:
            return None
        try:
            enabled = bool(args[0])
        except:
            enabled = False
        address = args[1] if len(args) > 1 else ""
        port = args[2] if len(args) > 2 else 0
        username = args[3] if len(args) > 3 else ""
        password = args[4] if len(args) > 4 else ""
        secret = args[5] if len(args) > 5 else ""
        if not self._should_arm_proxy_transition_killswitch(enabled, address, port, username, password, secret):
            return None
        return self._acquire_proxy_transition_killswitch("setProxySettings")

    def on_plugin_load(self):
        self._active = True
        self._repair_greenpass_settings_nulls()
        try:
            _set_subscription_hwid_custom(self.get_setting("subscription_hwid_custom", ""))
        except:
            pass
        if self._core_restart_required():
            try:
                self._set_setting_value("use_proxy", False, reload_settings=False)
                _set_tg_proxy_enabled(False)
            except:
                pass
            run_on_ui_thread(lambda: BulletinHelper.show_info("Обновление готово — перезапустите приложение. Настройки сохранены"))
        elif self._core_restart_resumed:
            try:
                self._set_setting_value("use_proxy", bool(self._desired_use_proxy), reload_settings=False)
            except:
                pass
        self._install_plugin_proxy_api()

        try:
            self.add_menu_item(
                MenuItemData(
                    menu_type=MenuItemType.CHAT_ACTION_MENU,
                    item_id=self._chat_menu_item_id,
                    text=Z("Настройки GreenPass"),
                    icon="msg_settings",
                    priority=1000,
                    on_click=self._open_plugin_settings,
                )
            )
        except:
            pass

        try:
            self.add_menu_item(
                MenuItemData(
                    menu_type=MenuItemType.DRAWER_MENU,
                    item_id=self._drawer_menu_item_id,
                    text=Z("Настройки GreenPass"),
                    icon="msg_settings",
                    priority=1000,
                    on_click=self._open_plugin_settings,
                )
            )
        except:
            pass

        self._install_proxy_button_hooks()
        self._install_sync_hooks()
        self._install_proxy_killswitch_hook()
        self._install_awg_activity_result_hook()
        self._install_browser_vless_hook()
        self._install_voip_relay_link_hook()
        self._install_text_vless_hook()
        self._install_cell_vless_hook()
        self._install_greenpass_file_open_hook()
        self._install_voip_relay_hook()
        try:
            self._apply_vpn_policy()
        except:
            pass
        self._refresh_current_dialogs_proxy_button()
        self._start_thread()
        self._sync_plugin_proxy_bridge()

        if (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_vless_mode_selected():
            self._ensure_vless_core_then(self._vless_connect)
        elif (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_tgws_mode_selected():
            self._tgws_connect()
        elif self._is_awg_mode_selected():
            if (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled():
                self._ensure_awg_config_then_connect()
            elif not str(self._awg_conf_content or "").strip():
                self._download_free_awg_config()
        elif (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected():
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        
        try:
            mc_class = find_class("org.telegram.messenger.MessagesController")
            if mc_class:
                self.hook_all_methods(mc_class, "sortDialogs", HideProxySponsorDialogHook())

            for i in range(UserConfig.MAX_ACCOUNT_COUNT):
                run_on_ui_thread(lambda i=i: NotificationCenter.getInstance(i).postNotificationName(NotificationCenter.dialogsNeedReload))

            self._maybe_hide_proxy_sponsor_dialog()
        except Exception:
            pass

    def _install_sync_hooks(self):
        if self._sync_hooks_installed:
            return
        try:
            NC = find_class("org.telegram.messenger.NotificationCenter")
            if NC:
                try:
                    self.hook_all_methods(NC, "postNotificationName", _ProxySettingsChangedNotifyHook(self))
                except:
                    pass
            self._sync_hooks_installed = True
        except:
            pass

    def _install_voip_relay_hook(self):
        if self._voip_relay_hook_installed and self._webrtc_relay_hook_installed:
            return
        try:
            if not self._voip_relay_hook_installed:
                instance_cls = find_class("org.telegram.messenger.voip.Instance")
                endpoint_cls = jclass("org.telegram.messenger.voip.Instance$Endpoint") if jclass is not None else find_class("org.telegram.messenger.voip.Instance$Endpoint")
                if instance_cls is not None and endpoint_cls is not None:
                    self.hook_all_methods(instance_cls, "makeInstance", _VoipEndpointRewriteHook(self, endpoint_cls))
                    self._voip_relay_hook_installed = True
            if not self._webrtc_relay_hook_installed:
                native_instance_cls = find_class("org.telegram.messenger.voip.NativeInstance")
                if native_instance_cls is not None:
                    self.hook_all_methods(native_instance_cls, "setJoinResponsePayload", _WebRtcJoinResponseRewriteHook(self))
                    self._webrtc_relay_hook_installed = True
        except:
            pass

    def _install_proxy_button_hooks(self):
        if self._proxy_button_hooks_installed:
            return
        try:
            DA = find_class("org.telegram.ui.DialogsActivity")
            if not DA:
                return
            try:
                self.hook_all_methods(DA, "updateProxyButton", _ForceDialogsProxyButtonHook(self))
            except:
                pass
            try:
                self.hook_all_methods(DA, "showSearch", _DialogsShowSearchForceProxyHook(self))
            except:
                pass
            try:
                self.hook_all_methods(DA, "showDoneItem", _DialogsShowDoneItemForceProxyHook(self))
            except:
                pass
            self._proxy_button_hooks_installed = True
        except:
            pass

    def _install_browser_vless_hook(self):
        if self._browser_vless_hook_installed:
            return
        try:
            browser_cls = Browser if Browser is not None else find_class("org.telegram.messenger.browser.Browser")
        except:
            browser_cls = None
        if browser_cls is None:
            return
        try:
            self.hook_all_methods(browser_cls, "openUrl", _BrowserOpenUrlHook(self))
            self._browser_vless_hook_installed = True
        except:
            pass

    def _install_voip_relay_link_hook(self):
        if self._voip_relay_link_hook_installed:
            return
        try:
            launch_cls = find_class("org.telegram.ui.LaunchActivity")
            if launch_cls is not None:
                self.hook_all_methods(launch_cls, "handleIntent", _VoipRelayLinkIntentHook(self))
                self._voip_relay_link_hook_installed = True
        except:
            pass

    def _install_text_vless_hook(self):
        if self._text_vless_hook_installed:
            return
        try:
            AU = find_class("org.telegram.messenger.AndroidUtilities")
        except:
            AU = None
        if AU is None:
            return

        installed = False
        try:
            self.hook_all_methods(AU, "addLinksSafe", _AddVlessTextLinksHook(self))
            installed = True
        except:
            pass
        try:
            self.hook_all_methods(AU, "addLinks", _AddVlessTextLinksHook(self))
            installed = True
        except:
            pass
        self._text_vless_hook_installed = bool(installed)

    def _install_cell_vless_hook(self):
        if self._cell_vless_hook_installed:
            return

        installed = False
        try:
            CMC = find_class("org.telegram.ui.Cells.ChatMessageCell")
        except:
            CMC = None
        if CMC is not None:
            try:
                self.hook_all_methods(CMC, "setMessageObject", _BindVlessTextLinksHook(self))
                installed = True
            except:
                pass

        try:
            CAC = find_class("org.telegram.ui.Cells.ChatActionCell")
        except:
            CAC = None
        if CAC is not None:
            try:
                self.hook_all_methods(CAC, "setMessageObject", _BindVlessTextLinksHook(self))
                installed = True
            except:
                pass

        self._cell_vless_hook_installed = bool(installed)

    def _install_greenpass_file_open_hook(self):
        if self._greenpass_file_hook_installed:
            return
        try:
            AU = find_class("org.telegram.messenger.AndroidUtilities")
        except:
            AU = None
        if AU is None:
            return
        try:
            self.hook_all_methods(AU, "openForView", _GreenPassOpenForViewHook(self))
            self._greenpass_file_hook_installed = True
        except Exception:
            pass

    def _apply_vless_clickable_spans(self, target):
        if target is None:
            return 0
        try:
            raw = str(target or "")
        except:
            raw = ""
        if not _contains_import_uri_text(raw):
            return 0
        try:
            return int(_ensure_vless_url_spans(target, raw_text=raw))
        except:
            return 0

    def _open_plugin_settings(self, context):
        def _run():
            try:
                PC = find_class("com.exteragram.messenger.plugins.PluginsController")
            except:
                PC = None
            try:
                PSA = find_class("com.exteragram.messenger.plugins.ui.PluginSettingsActivity")
            except:
                PSA = None

            try:
                if PC:
                    inst = None
                    try:
                        inst = PC.getInstance()
                    except:
                        inst = None
                    if inst is not None and hasattr(inst, "plugins") and PSA:
                        plugin_obj = None
                        for pid in [self.id, "greenpass", "GreenPass", str(__id__), str(__name__)]:
                            try:
                                plugin_obj = inst.plugins.get(pid)
                            except:
                                plugin_obj = None
                            if plugin_obj is not None:
                                break
                        if plugin_obj is not None:
                            frag = get_last_fragment()
                            if frag is not None:
                                frag.presentFragment(PSA(plugin_obj))
                                return

                    seen = set()
                    for pid in [self.id, "greenpass", "GreenPass", str(__id__), str(__name__)]:
                        try:
                            x = str(pid or "")
                        except:
                            x = ""
                        if not x or x in seen:
                            continue
                        seen.add(x)
                        try:
                            r = PC.openPluginSettings(x)
                            if bool(r):
                                return
                        except:
                            pass
            except:
                pass

            try:
                frag = get_last_fragment()
                if frag and PC:
                    PC.getInstance().openPluginSettings(self.id, frag)
                    return
            except:
                pass

        try:
            run_on_ui_thread(_run)
        except:
            _run()

    def _open_tg_proxy_settings(self):
        try:
            fragment = get_last_fragment()
            if fragment:
                from org.telegram.ui import ProxyListActivity
                fragment.presentFragment(ProxyListActivity())
                return
        except:
            pass

        try:
            from android.content import Intent
            from android.net import Uri
            ctx = ApplicationLoader.applicationContext
            intent = Intent(Intent.ACTION_VIEW, Uri.parse("tg://settings/proxy"))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(intent)
        except:
            BulletinHelper.show_error("Не удалось открыть настройки Telegram")

    def _get_active_proxy_snapshot(self):
        try:
            if SharedConfig.currentProxy is not None and bool(_is_tg_proxy_enabled()):
                if self._get_connection_mode() in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND) and str(getattr(SharedConfig.currentProxy, "address", "") or "") == VLESS_LOCAL_HOST:
                    return None
                return self._normalize_proxy_dict({
                    "server": str(SharedConfig.currentProxy.address),
                    "port": int(SharedConfig.currentProxy.port),
                    "username": str(getattr(SharedConfig.currentProxy, "username", "") or ""),
                    "password": str(getattr(SharedConfig.currentProxy, "password", "") or ""),
                    "secret": str(getattr(SharedConfig.currentProxy, "secret", "") or ""),
                    "kind": "socks" if (str(getattr(SharedConfig.currentProxy, "secret", "") or "") == "") else "mtproto",
                    "provider_name": str(self._last_provider_name or ""),
                })
        except:
            pass

        try:
            prefs = MessagesController.getGlobalMainSettings()
            server = str(prefs.getString("proxy_ip", "") or "")
            port = int(prefs.getInt("proxy_port", 0) or 0)
            username = str(prefs.getString("proxy_user", "") or "")
            password = str(prefs.getString("proxy_pass", "") or "")
            secret = str(prefs.getString("proxy_secret", "") or "")
            if server and port > 0 and bool(prefs.getBoolean("proxy_enabled", False)):
                if self._get_connection_mode() in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND) and server == VLESS_LOCAL_HOST:
                    return None
                return self._normalize_proxy_dict({
                    "server": server,
                    "port": port,
                    "username": username,
                    "password": password,
                    "secret": secret,
                    "kind": "socks" if (not secret) else "mtproto",
                    "provider_name": str(self._last_provider_name or ""),
                })
        except:
            pass
        return None

    def _proxy_kind_label(self, proxy):
        try:
            if str(proxy.get("kind", "") or "").lower() == VLESS_KIND:
                return "sing-box"
        except:
            pass
        try:
            if self._is_socks_proxy(proxy):
                return "SOCKS"
        except:
            pass
        return "MTProto"

    def _proxy_label(self, proxy, active_key=None):
        try:
            p = self._normalize_proxy_dict(proxy)
        except:
            p = None
        if not p:
            return "Неизвестный прокси"

        key = self._proxy_key(
            p.get("server"),
            p.get("port"),
            p.get("secret"),
            p.get("username"),
            p.get("password"),
        )
        prefix = "🟢 " if (active_key and key == active_key) else ""
        provider_name = str(p.get("provider_name", "") or "").strip()
        parts = [f"{p.get('server')}:{p.get('port')}"]
        if provider_name:
            parts.append(provider_name)
        parts.append(self._proxy_kind_label(p))
        try:
            latency = float(p.get("latency", 0.0) or 0.0)
        except:
            latency = 0.0
        if latency > 0:
            parts.append(f"{int(latency)} ms")
        return prefix + " • ".join(parts)

    def _get_manual_proxy_candidates(self):
        active = self._get_active_proxy_snapshot()
        merged = self._merge_unique_proxies([
            [active] if active else [],
            [self._last_working_proxy] if self._last_working_proxy else [],
            list(self._hot_proxy_cache or []),
        ])
        return merged[:12]

    def _refresh_manual_candidates(self):
        if self._finding_proxy:
            BulletinHelper.show_info("Поиск уже выполняется")
            return

        BulletinHelper.show_info("Обновляю список кандидатов...")

        def _worker():
            try:
                provider_auto = self._get_provider_auto()
                selected_provider = self._get_selected_provider()
                if provider_auto:
                    provider_proxy_map = self._collect_provider_proxy_map_sync(timeout_sec=2.0)
                    selected = list(provider_proxy_map.get(selected_provider, []) or [])
                    merged = self._merge_unique_proxies([provider_proxy_map.get(i, []) or [] for i in range(self._provider_count())])
                    candidates = self._merge_unique_proxies([selected, merged])
                else:
                    candidates = self._collect_proxies_for_provider(selected_provider, timeout_sec=3.5)

                self._refresh_hot_proxy_cache(candidates)
                self._save_config()
                self._refresh_settings_without_reopen()
                run_on_ui_thread(lambda: BulletinHelper.show_success(f"Кандидаты обновлены: {len(self._get_manual_proxy_candidates())}"))
            except Exception as e:
                run_on_ui_thread(lambda: BulletinHelper.show_error(f"Не удалось обновить кандидатов: {e}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_manual_proxy_candidate(self, proxy):
        if self._finding_proxy:
            BulletinHelper.show_info("Сначала дождитесь окончания поиска")
            return

        candidate = self._normalize_proxy_dict(proxy)
        if not candidate:
            BulletinHelper.show_error("Не удалось прочитать выбранный узел")
            return

        BulletinHelper.show_info("Подключаю выбранный узел...")

        def _worker():
            try:
                if not self._is_plugin_proxy_enabled():
                    try:
                        self._set_setting_value("use_proxy", True, reload_settings=False)
                    except:
                        pass
                ok = self._apply_and_verify(candidate)
                if ok:
                    self._current_server = str(candidate.get("server", "") or "")
                    self._current_port = int(candidate.get("port", 0) or 0)
                    self._current_secret = str(candidate.get("secret", "") or "")
                    self._last_provider_name = str(candidate.get("provider_name", "") or self._last_provider_name or "")
                    self._last_working_proxy = self._normalize_proxy_dict(candidate)
                    self._refresh_hot_proxy_cache([candidate])
                    self._save_config()
                    self._refresh_settings_without_reopen()
                    self._refresh_current_dialogs_proxy_button()
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Подключено: {self._proxy_label(candidate)}"))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Этот узел не прошел проверку"))
            except Exception as e:
                run_on_ui_thread(lambda: BulletinHelper.show_error(f"Ошибка подключения: {e}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _create_manual_proxy_subpage(self):
        items = [
            Header(text="Выбор узла"),
            Text(text="Последние рабочие узлы."),
            Text(
                text="Обновить список",
                accent=True,
                on_click=lambda *a: self._refresh_manual_candidates(),
            ),
        ]

        active = self._get_active_proxy_snapshot()
        active_key = None
        if active:
            active_key = self._proxy_key(
                active.get("server"),
                active.get("port"),
                active.get("secret"),
                active.get("username"),
                active.get("password"),
            )
            items.append(Divider())
            items.append(Text(text=f"Сейчас: {self._proxy_label(active)}", icon="msg2_proxy_on"))

        candidates = self._get_manual_proxy_candidates()
        items.append(Divider())
        if not candidates:
            items.append(Text(text="Список пуст."))
            return items

        for proxy in candidates:
            candidate_key = self._proxy_key(
                proxy.get("server"),
                proxy.get("port"),
                proxy.get("secret"),
                proxy.get("username"),
                proxy.get("password"),
            )
            items.append(Text(
                text=self._proxy_label(proxy, active_key=active_key),
                accent=bool(active_key and candidate_key == active_key),
                on_click=lambda *a, proxy=proxy: self._apply_manual_proxy_candidate(proxy),
            ))
        return items

    def _get_clipboard_text(self):
        try:
            from android.content import Context
            ctx = ApplicationLoader.applicationContext
            clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
            if clipboard is None:
                return ""
            clip = clipboard.getPrimaryClip()
            if clip is None or clip.getItemCount() <= 0:
                return ""
            return str(clip.getItemAt(0).coerceToText(ctx) or "")[:VLESS_IMPORT_CLIPBOARD_MAX]
        except:
            return ""

    def _import_vless_from_clipboard(self):
        blob = self._get_clipboard_text()
        if not blob:
            BulletinHelper.show_error("Буфер обмена пуст")
            return

        uri = _extract_import_uri(blob)
        if uri:
            self._handle_import_uri(uri)
            return

        text = str(blob or "").strip()
        if text.startswith("http://") or text.startswith("https://"):
            self._add_vless_subscription(text, activate_first=(not self._get_active_vless_uri()))
            return

        BulletinHelper.show_error("В буфере нет ссылки на сервер")

    def _olcrtc_index_for_item(self, value, items, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item).lower() == target:
                    return int(idx)
        except:
            pass
        return int(default_index)

    def _parse_olcrtc_import_text(self, text):
        raw = str(text or "").strip()
        if not raw:
            return None, "Буфер обмена пуст"

        data = None
        try:
            data = json.loads(raw)
        except:
            data = None

        if data is None and "{" in raw and "}" in raw:
            try:
                data = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            except:
                data = None

        if isinstance(data, dict):
            if isinstance(data.get("olcrtc"), dict):
                data = data.get("olcrtc")
            carrier = _olcrtc_carrier_alias(data.get("carrier", data.get("provider", ""))) or str(data.get("carrier", data.get("provider", "")) or "").strip()
            transport = _olcrtc_transport_alias(data.get("transport", "")) or str(data.get("transport", "") or "").strip()
            out = {
                "carrier": carrier,
                "transport": transport,
                "room_id": str(data.get("room_id", data.get("room", "")) or "").strip(),
                "client_id": str(data.get("client_id", data.get("device_id", "")) or "").strip(),
                "key_hex": str(data.get("key_hex", data.get("key", "")) or "").strip(),
            }
            return out, ""

        return _parse_olcrtc_uri_to_data(raw)

    def _import_olcrtc_profiles(self, profiles, imported_link="", activate_first=False, connect_first=False):
        items = []
        try:
            items = [p for p in list(profiles or []) if isinstance(p, dict)]
        except:
            items = []
        first_profile = None
        imported = 0
        for data in reversed(items):
            profile = self._upsert_olcrtc_profile(data, imported_link=imported_link)
            if not profile:
                continue
            first_profile = profile
            imported += 1
        if imported <= 0:
            return 0
        if bool(activate_first) and first_profile:
            self._olcrtc_active_profile_id = str(first_profile.get("id", "") or "")
            self._set_olcrtc_legacy_settings_from_profile(first_profile)
            self._set_connection_mode(OLCRTC_KIND)
            self._save_config()
            if bool(connect_first):
                self._enable_plugin_proxy_flag()
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_stack=True, reload_main=bool(activate_first))
        return int(imported)

    def _try_import_olcrtc_subscription_text(self, url, text, activate_first=False):
        profiles = _extract_olcrtc_subscription_profiles(text, default_client_id=_olcrtc_client_id_from_url(url))
        if not profiles:
            return 0
        return self._import_olcrtc_profiles(profiles, imported_link=str(url or "").strip(), activate_first=bool(activate_first), connect_first=bool(activate_first))

    def _apply_olcrtc_import_data(self, data, connect=True, imported_link=""):
        if not isinstance(data, dict):
            BulletinHelper.show_error("Неверный olcRTC конфиг")
            return False
        carrier = str(data.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
        transport = str(data.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
        room_id = str(data.get("room_id", "") or "").strip()
        client_id = str(data.get("client_id", "") or "").strip()
        key_hex = str(data.get("key_hex", "") or "").strip()

        self._set_setting_value("olcrtc_carrier", self._olcrtc_index_for_item(carrier, OLCRTC_CARRIER_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(transport, OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_room_id", room_id, reload_settings=False)
        self._set_setting_value("olcrtc_client_id", client_id, reload_settings=False)
        self._set_setting_value("olcrtc_key_hex", key_hex, reload_settings=False)
        profile = self._upsert_olcrtc_profile({
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
        }, imported_link=imported_link)
        if not profile:
            BulletinHelper.show_error("Неверный olcRTC конфиг")
            self._refresh_settings_without_reopen()
            return False
        self._set_connection_mode(OLCRTC_KIND)
        if connect:
            if not self._is_olcrtc_config_ready():
                BulletinHelper.show_error(self._olcrtc_config_error())
                self._refresh_settings_without_reopen()
                return False
            try:
                self._vless_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            try:
                self._tgws_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            try:
                self._awg_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            self._enable_plugin_proxy_flag()
            self._olcrtc_feedback_requested = True
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen()
        room_short = room_id[:32] if room_id else "конфиг"
        BulletinHelper.show_success("olcRTC: " + room_short)
        return True

    def _import_olcrtc_from_clipboard(self):
        blob = self._get_clipboard_text()
        data, err = self._parse_olcrtc_import_text(blob)
        if err:
            BulletinHelper.show_error(err)
            return False
        return self._apply_olcrtc_import_data(data, connect=True, imported_link=str(blob or "").strip())

    def _confirm_olcrtc_link(self, data, uri):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        try:
            carrier = str(data.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
            transport = str(data.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
            room_id = str(data.get("room_id", "") or "").strip()
            client_id = str(data.get("client_id", "") or "").strip()
            key_hex = str(data.get("key_hex", "") or "").strip()
            key_mask = key_hex[:6] + "..." + key_hex[-6:] if len(key_hex) > 12 else "***"
            message = "\n".join([
                "Подключиться к olcRTC?",
                "",
                "Провайдер: %s" % self._olcrtc_carrier_label(carrier),
                "Транспорт: %s" % self._olcrtc_transport_label(transport),
                "Комната: %s" % (room_id[:120] if room_id else "—"),
                "Клиент: %s" % (client_id[:80] if client_id else "—"),
                "Ключ: %s" % key_mask,
            ])
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение olcRTC")
            builder.set_message(message)

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._apply_olcrtc_import_data(data, connect=True, imported_link=str(uri or ""))

            def on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("olcRTC: %s" % str(exc))
            return False

    def _confirm_tgws_link(self, uri="tg://ws"):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение TG WS")
            builder.set_message("Включить режим TG WS и применить локальный прокси Telegram?")

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                self._handle_tgws_link(uri, confirm=False)

            def on_no(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("TG WS: %s" % str(exc))
            return False

    def _confirm_qwdtt_link(self, profile, uri):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None or not isinstance(profile, dict):
            BulletinHelper.show_error("Не удалось открыть qWDTT")
            return False
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Подключение qWDTT")
            builder.set_message("\n".join([
                "Профиль: %s" % str(profile.get("name", "qWDTT") or "qWDTT")[:80],
                "Сервер: %s" % str(profile.get("peer", "") or "")[:120],
                "VK-хешей: %d" % len(list(profile.get("hashes", []) or [])),
            ]))

            def on_yes(dlg, which):
                try:
                    dlg.dismiss()
                except:
                    pass
                saved = self._save_qwdtt_profile(profile, activate=True)
                if saved:
                    self._switch_to_vless_mode()

            builder.set_positive_button("Подключить", on_yes)
            builder.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
            builder.set_cancelable(True)
            builder.show()
            return True
        except Exception as exc:
            BulletinHelper.show_error("qWDTT: %s" % str(exc))
            return False

    def _handle_tgws_link(self, uri="tg://ws", confirm=False):
        if bool(confirm):
            return self._confirm_tgws_link(uri)
        try:
            self._switch_to_tgws_mode()
            BulletinHelper.show_success("TG WS включен")
            return True
        except Exception as exc:
            BulletinHelper.show_error("TG WS: %s" % str(exc))
            return False

    def _handle_import_uri(self, uri, confirm=False):
        text = str(uri or "").strip()
        low = text.lower()
        if low.startswith(("wdtt://", "qwdtt://", "qwdtt:config?")):
            profile = _parse_qwdtt_uri(text)
            if not profile:
                BulletinHelper.show_error("Неверная qWDTT ссылка")
                return False
            if bool(confirm):
                return self._confirm_qwdtt_link(profile, text)
            saved = self._save_qwdtt_profile(profile, activate=True)
            if not saved:
                return False
            self._switch_to_vless_mode()
            return True
        if low.startswith("olcrtc://"):
            data, err = self._parse_olcrtc_import_text(text)
            if err:
                BulletinHelper.show_error(err)
                return False
            if bool(confirm):
                return self._confirm_olcrtc_link(data, text)
            return self._apply_olcrtc_import_data(data, connect=True, imported_link=text)
        if low.startswith("tg://relay?"):
            return self._apply_tgws_voip_relay_link(text)
        if low.startswith("tg://ws"):
            return self._handle_tgws_link(text, confirm=confirm)
        return self._show_vless_import_sheet(text)

    def _show_vless_import_sheet(self, uri):
        details = _parse_proxy_uri_details(uri)
        if not details:
            try:
                match = re.match(r"^([a-z][a-z0-9+.-]*)://", str(uri or "").strip(), re.IGNORECASE)
                scheme = str(match.group(1) or "").lower() if match else ""
            except:
                scheme = ""
            if scheme and scheme not in PROXY_PROTOCOL_REGISTRY:
                BulletinHelper.show_error("Протокол %s не поддерживается плагином" % scheme)
            else:
                BulletinHelper.show_error("Неверная ссылка")
            return

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт ссылки")
            return

        import_error_text = "Ошибка импорта"
        try:
            kind = str(details.get("kind", "vless") or "vless")
            params = dict(details.get("params", {}) or {})
            protocol_label = _proxy_protocol_label(details)
            rows = [
                ("Узел", str(details.get("name", protocol_label + " узел") or (protocol_label + " узел"))),
                ("Протокол", protocol_label),
                ("Адрес", str(details.get("server", "") or "")),
                ("Порт", str(details.get("port", "") or "")),
            ]
            if kind in ("vless", "vmess"):
                rows.append(("UUID", str(details.get("uuid", "") or "")))
            if kind == "vmess":
                rows.append(("AlterID", str(details.get("alter_id", "") or "")))
                rows.append(("Cipher", str(details.get("cipher", "") or "")))
            if kind == "ss":
                rows.append(("Метод", str(details.get("method", "") or "")))
                rows.append(("Plugin", str(params.get("plugin", "") or "")))
            rows.extend([
                ("Транспорт", str(details.get("network", "tcp") or "tcp")),
                ("Безопасность", str(details.get("security", "none") or "none")),
                ("SNI", str(params.get("sni", "") or "")),
                ("Host", str(params.get("host", "") or "")),
                ("Path", str(params.get("path", "") or "")),
                ("Service", str(params.get("serviceName", "") or "")),
                ("Flow", str(params.get("flow", "") or "")),
                ("ALPN", str(params.get("alpn", "") or "")),
            ])
            dialog_title = str(details.get("name", protocol_label) or protocol_label)
            need_core_text = "Нужно ядро прокси"
            check_text = "Проверяю %s..." % protocol_label
            import_error_text = "Ошибка импорта %s" % protocol_label

            def _build_message(status_text):
                lines = []
                for label, value in rows:
                    if not value:
                        continue
                    lines.append(f"{label}: {value}")
                if status_text:
                    lines.append("")
                    lines.append(f"Статус: {status_text}")
                return "\n".join(lines)

            def _show_dialog(status_text):
                dialog = AlertDialogBuilder(activity)
                dialog.set_title(dialog_title)
                dialog.set_message(_build_message(status_text))

                def _on_yes(dlg, which):
                    try:
                        dlg.dismiss()
                    except:
                        pass
                    self._activate_vless_uri(uri, enable_plugin=True)

                def _on_no(dlg, which):
                    try:
                        dlg.dismiss()
                    except:
                        pass

                dialog.set_positive_button("Подключить", _on_yes)
                dialog.set_negative_button("Отмена", _on_no)
                dialog.show()

            if not self._has_libvless_addon():
                _show_dialog(need_core_text)
                return

            BulletinHelper.show_info(check_text)

            def _check_status():
                validation_error = self._validate_proxy_uri_for_import(uri)
                if validation_error:
                    run_on_ui_thread(lambda validation_error=validation_error: BulletinHelper.show_error(validation_error))
                    return
                try:
                    ping = self._probe_proxy_latency({
                        "server": str(details.get("server", "") or ""),
                        "port": int(details.get("port", 0) or 0),
                    }, timeout_sec=float(VLESS_REMOTE_CHECK_TIMEOUT_SEC))
                except:
                    ping = None

                if ping is None:
                    status_text = "Недоступен"
                else:
                    status_text = f"Доступен, {int(ping)} ms"
                run_on_ui_thread(lambda: _show_dialog(status_text))

            threading.Thread(target=_check_status, daemon=True).start()
        except Exception as e:
            BulletinHelper.show_error(f"{import_error_text}: {e}")

    def _vless_node_label(self, node):
        base = self._vless_node_plain_label(node)
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at > 0 and (time.time() - checked_at) <= float(VLESS_NODE_PING_STALE_SEC):
            if ping > 0 and ping < 9999:
                return f"🟢 {int(ping)} ms: {base}"
            return f"🔴 {base}"
        return base

    def _custom_proxy_label(self, node=None):
        target = node
        if target is None:
            try:
                target = self._current_vless_node()
            except:
                target = None
        try:
            kind = str((target or {}).get("kind", "") or "").strip().lower()
        except:
            kind = ""
        if not kind and target is not None:
            try:
                kind = _proxy_uri_scheme((target or {}).get("uri", ""))
            except:
                kind = ""
        return _proxy_protocol_label(kind)

    def _vless_node_plain_label(self, node):
        try:
            target_uri = str(node.get("uri", "") or "")
        except:
            target_uri = ""
        is_active = bool(
            target_uri
            and target_uri == self._get_active_vless_uri()
            and self._is_vless_mode_selected()
            and self._is_plugin_proxy_enabled()
        )
        try:
            raw_name = str(node.get("name", "") or "").strip()
            name = _clean_proxy_name(raw_name, "") if raw_name else ""
            name = re.sub(r"\s+proxy(?:[-_ ]*\d+)?$", "", name, flags=re.I).strip()
        except:
            name = ""
        try:
            kind = str(node.get("kind", "") or "").strip().lower()
        except:
            kind = ""
        if not kind:
            kind = _proxy_uri_scheme(target_uri)
        protocol_label = _proxy_protocol_label(kind)

        parts = []
        if name:
            parts.append(name)
        if protocol_label and protocol_label.lower() != name.lower():
            parts.append(protocol_label)
        prefix = "🟢 " if is_active else ""
        return prefix + (" • ".join(parts) if parts else "Узел")

    def _switch_to_proxy_mode(self, persist_mode=True):
        if persist_mode:
            self._set_connection_mode("proxy")
        self._vless_disconnect_with_reason("switch_to_proxy_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_proxy_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_proxy_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_proxy_mode", silent=True)
        self._refresh_settings_without_reopen()
        if self._is_plugin_proxy_enabled():
            run_on_ui_thread(self._force_update)

    def _switch_to_tgws_mode(self, persist_mode=True):
        if persist_mode:
            self._set_connection_mode(TGWS_KIND)
        self._vless_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        if self._is_plugin_proxy_enabled():
            self._tgws_connect()
        self._refresh_settings_without_reopen()

    def _go_core_switch_blocked(self, target_kind):
        """Unified libgreenpass.so supports in-process engine switching."""
        if not self._core_restart_required():
            return False
        BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
        return True

    def _switch_to_awg_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("awg"):
            return
        if persist_mode:
            self._set_connection_mode(AWG_KIND)
        self._vless_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_awg_mode", silent=True)
        if not str(self._awg_conf_content or "").strip():
            self._enable_plugin_proxy_flag()
            self._ensure_awg_config_then_connect()
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_awg_core_then(self._awg_connect)
        self._refresh_settings_without_reopen()

    def _switch_to_olcrtc_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("olcrtc"):
            return
        if persist_mode:
            self._set_connection_mode(OLCRTC_KIND)
        self._vless_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        if not self._is_olcrtc_config_ready():
            run_on_ui_thread(lambda: BulletinHelper.show_info("Заполните olcRTC"))
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen()

    def _switch_to_vless_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("vless"):
            return
        if persist_mode:
            self._set_connection_mode(VLESS_KIND)
        try:
            self._tgws_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        if self._get_active_vless_uri():
            self._enable_plugin_proxy_flag()
            self._reset_vless_retry()
            self._ensure_vless_core_then(self._vless_connect)
        else:
            run_on_ui_thread(lambda: BulletinHelper.show_info("Импортируйте сервер"))
        self._refresh_settings_without_reopen()

    def _select_mode_from_settings(self, mode):
        target = str(mode or "proxy")
        if target not in ("proxy", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = "proxy"
        if target == self._get_connection_mode():
            self._refresh_mode_summary()
            self._refresh_settings_without_reopen()
            return True
        _switch = {
            "proxy": self._switch_to_proxy_mode,
            VLESS_KIND: self._switch_to_vless_mode,
            TGWS_KIND: self._switch_to_tgws_mode,
            AWG_KIND: self._switch_to_awg_mode,
            OLCRTC_KIND: self._switch_to_olcrtc_mode,
        }[target]
        self._set_connection_mode(target)
        self._refresh_mode_summary()
        self._refresh_settings_without_reopen()
        try:
            threading.Thread(target=lambda: _switch(False), daemon=True).start()
        except:
            _switch(False)
        return True

    def _install_awg_activity_result_hook(self):
        if self._awg_activity_hook_installed:
            return
        if Integer is None:
            return
        try:
            launch_cls = find_class("org.telegram.ui.LaunchActivity")
            intent_cls = find_class("android.content.Intent")
            method = launch_cls.getClass().getDeclaredMethod("onActivityResult", Integer.TYPE, Integer.TYPE, intent_cls)
            self.hook_method(method, _AwgActivityResultHook(self))
            self._awg_activity_hook_installed = True
        except Exception:
            pass

    def _install_proxy_killswitch_hook(self):
        if self._proxy_killswitch_hook_installed:
            return
        try:
            cm_class = find_class("org.telegram.tgnet.ConnectionsManager")
        except:
            cm_class = None
        if cm_class is None:
            return
        try:
            self.hook_all_methods(cm_class, "setProxySettings", _ProxyTransitionKillSwitchHook(self))
            self._proxy_killswitch_hook_installed = True
        except:
            pass

    def _find_vless_subscription(self, sub_url):
        target = str(sub_url or "").strip()
        if not target:
            return None
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                if str(sub.get("url", "") or "").strip() == target:
                    return sub
        except:
            pass
        return None

    def _update_vless_subscription(self, url, silent=False):
        target = str(url or "").strip()
        if not target:
            return False
        sub = self._find_vless_subscription(target)
        if sub is None:
            if not silent:
                BulletinHelper.show_error("Подписка не найдена")
            return False
        if not silent:
            BulletinHelper.show_info("Обновляю подписку...")

        def _worker():
            nodes = _fetch_vless_nodes(target)
            if not nodes:
                if not silent:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось обновить подписку"))
                return
            try:
                sub["nodes"] = nodes
            except:
                return
            self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            if self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                self._ensure_vless_core_then(self._vless_connect)
            run_on_ui_thread(self._refresh_settings_without_reopen)
            if not silent:
                run_on_ui_thread(lambda: BulletinHelper.show_success(f"Узлов обновлено: {len(nodes)}"))

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _delete_vless_subscription(self, url):
        target = str(url or "").strip()
        if not target:
            return False

        removed = False
        active_uri = self._get_active_vless_uri()
        removed_active = False
        subs = []
        for sub in list(self._vless_data.get("subs", []) or []):
            if not isinstance(sub, dict):
                continue
            sub_url = str(sub.get("url", "") or "").strip()
            if sub_url != target:
                subs.append(sub)
                continue
            removed = True
            for node in list(sub.get("nodes", []) or []):
                try:
                    if str(node.get("uri", "") or "") == active_uri:
                        removed_active = True
                        break
                except:
                    continue

        if not removed:
            return False

        self._vless_data["subs"] = subs
        if removed_active:
            self._vless_data["active_uri"] = self._first_vless_uri()
        self._vless_save_data()

        if removed_active and self._get_connection_mode() == VLESS_KIND:
            next_uri = self._get_active_vless_uri()
            if self._is_plugin_proxy_enabled() and next_uri:
                self._ensure_vless_core_then(self._vless_connect)
            else:
                self._vless_disconnect_with_reason("remove_vless_subscription", silent=True)

        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Подписка удалена")
        return True

    def _confirm_remove_vless_subscription(self, url):
        target = str(url or "").strip()
        sub = self._find_vless_subscription(target)
        if sub is None:
            return True

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None

        if activity is None:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return True

        try:
            title = str(sub.get("name", "Подписка") or "Подписка")
        except:
            title = "Подписка"
        count = len(list(sub.get("nodes", []) or []))

        builder = AlertDialogBuilder(activity)
        builder.set_title("Удалить подписку?")
        builder.set_message(f"{title}\n{count} узл.")

        def _on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._delete_vless_subscription(target)

        def _on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Удалить", _on_yes)
        builder.set_negative_button("Отмена", _on_no)
        try:
            builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
        except:
            pass
        builder.show()
        return True

    def _vless_subscription_label(self, sub):
        try:
            name = str(sub.get("name", "Подписка") or "Подписка").strip()
        except:
            name = "Подписка"
        count = len(list(sub.get("nodes", []) or []))
        active = self._vless_subscription_has_active(sub)
        prefix = "🟢 " if active and self._is_vless_mode_selected() and self._is_plugin_proxy_enabled() else ""
        return prefix + f"{name} • {count} узл."

    def _vless_subscription_has_active(self, sub):
        active_uri = self._get_active_vless_uri()
        if not active_uri:
            return False
        for node in list(sub.get("nodes", []) or []):
            try:
                if str(node.get("uri", "") or "") == active_uri:
                    return True
            except:
                pass
        return False

    def _create_vless_subscription_subpage(self, sub_url):
        sub = self._find_vless_subscription(sub_url)
        if sub is None:
            return [Header(text="Подписка"), Text(text="Подписка не найдена")]

        try:
            title = str(sub.get("name", "Подписка") or "Подписка").strip()
        except:
            title = "Подписка"
        title = title[:24] if title else "Подписка"
        nodes = list(sub.get("nodes", []) or [])

        items = [
            Header(text=title),
            Text(text="Обновить", icon="msg_retry", on_click=lambda *a, url=str(sub.get("url", "") or ""): self._update_vless_subscription(url)),
            Text(text="Тест пинга", icon="msg_retry", on_click=lambda *a, nodes=nodes: self._run_vless_ping_test(nodes=nodes, refresh_each=True)),
            Text(text="Удалить", red=True, icon="msg_delete", on_click=lambda *a, url=str(sub.get("url", "") or ""): self._confirm_remove_vless_subscription(url)),
        ]

        active_uri = self._get_active_vless_uri()
        if nodes:
            items.append(Divider())
        for node in nodes:
            items.append(Text(
                text=self._vless_node_label(node),
                accent=str(node.get("uri", "") or "") == active_uri,
                on_click=lambda *a, uri=str(node.get("uri", "") or ""): self._activate_vless_uri(uri, enable_plugin=True),
                on_long_click=lambda view, uri=str(node.get("uri", "") or ""): self._confirm_remove_vless_node(uri),
            ))

        if not nodes:
            items.append(Divider())
            items.append(Text(text="Подписка пуста"))
        return items


    def _create_vless_nodes_subpage(self):
        items = [
            Header(text="Серверы"),
            Text(text="Импорт из буфера", accent=True, icon="msg_link", on_click=lambda *a: self._import_vless_from_clipboard()),
            Text(text="Встроенные подписки", icon="msg_channel", create_sub_fragment=self._create_builtin_vless_subs_subpage),
            Text(text="Тест пинга", icon="msg_retry", on_click=lambda *a: self._run_vless_ping_test()),
            Text(text="Обновить подписки", icon="msg_retry", on_click=lambda *a: self._refresh_vless_subscriptions()),
            Text(text="Очистить узлы", icon="msg_delete", red=True, on_click=lambda *a: self._confirm_clear_vless_nodes()),
        ]

        current = self._current_vless_node()
        if current:
            items.append(Divider())
            items.append(Text(
                text=self._append_green_tail("Сейчас: " + self._vless_node_plain_label(current), self._vless_ping_badge(current)),
                icon="msg2_proxy_on",
            ))

        manual = list(self._vless_data.get("manual", []) or [])
        subs = list(self._vless_data.get("subs", []) or [])

        if manual:
            items.append(Divider())
            items.append(Header(text="Свои узлы"))
            for node in self._sorted_vless_nodes(manual):
                items.append(Text(
                    text=self._vless_node_label(node),
                    accent=str(node.get("uri", "") or "") == self._get_active_vless_uri(),
                    on_click=lambda *a, uri=str(node.get("uri", "") or ""): self._activate_vless_uri(uri, enable_plugin=True),
                    on_long_click=lambda view, uri=str(node.get("uri", "") or ""): self._confirm_remove_vless_node(uri),
                ))

        if subs:
            items.append(Divider())
            items.append(Header(text="Подписки"))
        for sub in subs:
            nodes = list(sub.get("nodes", []) or [])
            if not nodes:
                continue
            items.append(Text(
                text=self._vless_subscription_label(sub),
                icon="msg_list",
                accent=bool(self._vless_subscription_has_active(sub)),
                create_sub_fragment=lambda sub_url=str(sub.get("url", "") or ""): self._create_vless_subscription_subpage(sub_url),
                on_long_click=lambda view, url=str(sub.get("url", "") or ""): self._confirm_remove_vless_subscription(url),
            ))

        if len(items) <= 5:
            items.append(Divider())
            items.append(Text(text="Пока нет узлов"))

        return items

    def _refresh_current_dialogs_proxy_button(self):
        try:
            frag = get_last_fragment()
            if frag is None:
                return
            try:
                n = str(frag.getClass().getName() or "")
            except:
                n = ""
            if n == "org.telegram.ui.DialogsActivity":
                if self._is_plugin_proxy_enabled():
                    _force_show_dialogs_proxy_button(frag)
                else:
                    try:
                        if hasattr(frag, "updateProxyButton"):
                            frag.updateProxyButton(False, False)
                    except:
                        try:
                            if hasattr(frag, "updateProxyButton"):
                                frag.updateProxyButton()
                        except:
                            pass
        except:
            pass

    def _on_vless_provider_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= len(VLESS_PROVIDER_ITEMS):
            i = 0

        try:
            self._set_setting_value("vless_provider", i, reload_settings=True)
        except:
            pass

        manual_uris = set()
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                uri = str(node.get("uri", "") or "")
                if uri:
                    manual_uris.add(uri)
        except:
            manual_uris = set()

        active_uri = self._get_active_vless_uri()
        self._vless_data["subs"] = []
        if active_uri and active_uri not in manual_uris:
            self._vless_data["active_uri"] = ""
            if self._get_connection_mode() == VLESS_KIND:
                self._vless_disconnect_with_reason("vless_provider_changed", silent=True)
        self._vless_save_data()
        self._refresh_settings_without_reopen()
        self._sync_selected_provider_vless_nodes(force=True, activate_first=(not self._get_active_vless_uri()), silent=False)

    def _on_provider_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= self._provider_count():
            i = 0
        self._set_selected_provider(i)
        self._set_provider_auto(False)
        self._last_provider_name = self._provider_name(i)
        self._refresh_settings_without_reopen()
        self._force_update()

    def _on_provider_auto_changed(self, enabled):
        self._set_provider_auto(bool(enabled))
        self._refresh_settings_without_reopen()
        self._force_update()

    def _on_use_proxy_changed(self, enabled):
        val = bool(enabled)
        self._desired_use_proxy = bool(val)
        self._save_config()
        try:
            self._set_setting_value("use_proxy", val, reload_settings=True)
        except:
            pass

        if val:
            try:
                self._apply_vpn_policy()
            except:
                pass
            if self._is_proxy_policy_suspended():
                try:
                    self._sync_plugin_proxy_bridge()
                except:
                    pass
                self._refresh_settings_without_reopen()
                self._refresh_current_dialogs_proxy_button()
                return
            if self._is_vless_mode_selected():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            elif self._is_tgws_mode_selected():
                self._tgws_connect()
            elif self._is_awg_mode_selected():
                self._ensure_awg_config_then_connect()
            elif self._is_olcrtc_mode_selected():
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
            else:
                _set_tg_proxy_enabled(True)
                try:
                    if SharedConfig.currentProxy is None or (not self._is_proxy_connection_ready()):
                        self._force_update()
                except:
                    self._force_update()
        else:
            self._proxy_suspended_by_vpn = False
            self._proxy_suspended_by_wifi = False
            _set_tg_proxy_enabled(False)
            try:
                self._finding_proxy = False
            except:
                pass
            try:
                self._vless_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._tgws_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._awg_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._olcrtc_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                prefs = MessagesController.getGlobalMainSettings()
                ed = prefs.edit()
                ed.putBoolean("proxy_enabled_calls", False)
                ed.commit()
            except:
                pass

        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        self._refresh_settings_without_reopen()
        self._refresh_current_dialogs_proxy_button()

    def _on_use_proxy_calls_changed(self, enabled):
        val = bool(enabled)
        self._set_calls_proxy_preference(val, reload_settings=True)

        current_is_socks = False
        try:
            current = SharedConfig.currentProxy
        except:
            current = None
        if current is not None:
            try:
                host = str(getattr(current, "address", "") or "")
            except:
                host = ""
            try:
                sec = str(getattr(current, "secret", "") or "")
            except:
                sec = ""
            current_is_socks = bool(host == VLESS_LOCAL_HOST or (not sec))

        applied_calls_flag = bool(val and current_is_socks)
        try:
            prefs = MessagesController.getGlobalMainSettings()
            ed = prefs.edit()
            ed.putBoolean("proxy_enabled_calls", bool(applied_calls_flag))
            ed.putBoolean("proxy_calls_enabled", bool(applied_calls_flag))
            ed.putBoolean("calls_use_proxy", bool(applied_calls_flag))
            ed.commit()
        except:
            pass

        if val and _is_tg_proxy_enabled() and not current_is_socks:
            BulletinHelper.show_info("Для звонков нужен SOCKS-прокси, ищу подходящий...")
            self._force_update()

        self._refresh_settings_without_reopen()

    def on_plugin_unload(self):
        self._active = False
        try:
            self._worker_stop.set()
        except:
            pass
        try:
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(2.0)
        except:
            pass
        try:
            self._release_all_proxy_transition_killswitches()
        except:
            pass
        try:
            self._remove_python_http_proxy_patch()
        except:
            pass
        try:
            self._deactivate_frida_plugin_proxy_hook()
        except:
            pass
        try:
            self._vless_disconnect_with_reason("plugin_unload", silent=True)
        except:
            pass
        try:
            self._tgws_disconnect_with_reason("plugin_unload", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("plugin_unload", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("plugin_unload", silent=True)
        except:
            pass
        try:
            self.remove_menu_item(self._chat_menu_item_id)
        except:
            pass
        try:
            self.remove_menu_item(self._drawer_menu_item_id)
        except:
            pass
        try:
            self._cleanup_plugin_proxies_from_shared_list(keep_current=True)
        except:
            pass
        run_on_ui_thread(lambda: BulletinHelper.show_info("GreenPass остановлен"))

    def on_app_event(self, event):
        if event == AppEvent.PAUSE or event == AppEvent.STOP:
            self._vless_backgrounded = True
            self._tgws_backgrounded = True
            self._olcrtc_backgrounded = True
            self._olcrtc_feedback_requested = False
            if self._is_tgws_mode_selected() and self._is_plugin_proxy_enabled():
                self._tgws_unapply_local_proxy_for_background()
            return
        if event == AppEvent.RESUME or event == AppEvent.START:
            self._install_proxy_button_hooks()
            self._install_sync_hooks()
            self._install_proxy_killswitch_hook()
            self._install_awg_activity_result_hook()
            self._install_browser_vless_hook()
            self._install_text_vless_hook()
            self._install_cell_vless_hook()
            self._install_greenpass_file_open_hook()
            self._install_voip_relay_hook()
            self._refresh_current_dialogs_proxy_button()

            was_vless_backgrounded = bool(getattr(self, "_vless_backgrounded", False))
            was_backgrounded = bool(getattr(self, "_tgws_backgrounded", False))
            self._vless_backgrounded = False
            self._tgws_backgrounded = False
            self._olcrtc_backgrounded = False
            def _resume_bg():
                try:
                    self._apply_vpn_policy()
                except:
                    pass
                if self._is_proxy_policy_suspended():
                    self._olcrtc_resume_checking = False
                    self._olcrtc_health_stale = False
                    return
                if not self._is_plugin_proxy_enabled():
                    self._olcrtc_resume_checking = False
                    self._olcrtc_health_stale = False
                    return
                if self._is_vless_mode_selected():
                    if was_vless_backgrounded:
                        self._resume_vless_after_background()
                    elif not self._is_vless_connection_ready(self._vless_port, check_tunnel=False):
                        self._auto_reconnect_vless()
                elif self._is_tgws_mode_selected():
                    old_ready = bool(getattr(self, "_tgws_ready", False))
                    ready_now = bool(self._tgws_ensure_local_proxy())
                    if was_backgrounded or old_ready != ready_now:
                        run_on_ui_thread(self._refresh_settings_without_reopen)
                    elif not ready_now and not bool(getattr(self, "_tgws_connecting", False)):
                        self._tgws_heal_if_due()
                        run_on_ui_thread(self._refresh_settings_without_reopen)
                elif self._should_run_awg() and ((not self._awg_running) or (self._awg_port and not _check_vless_port(self._awg_port))):
                    self._ensure_awg_core_then(self._awg_connect)
                elif self._should_run_olcrtc():
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="resume")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_connecting = False
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                        run_on_ui_thread(self._refresh_settings_without_reopen)
                    else:
                        self._olcrtc_running = False
                        self._olcrtc_resume_checking = False
                        self._olcrtc_health_stale = False
                        self._set_olcrtc_last_log("resume health check failed", event="resume_health_failed", port=port)
                        core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                        if core_state not in ("starting", "handshake", "stopping") and not bool(getattr(self, "_olcrtc_connecting", False)):
                            self._ensure_olcrtc_core_then(self._olcrtc_connect)
            try:
                threading.Thread(target=_resume_bg, daemon=True).start()
            except:
                pass

            self._maybe_hide_proxy_sponsor_dialog()

    def _maybe_hide_proxy_sponsor_dialog(self):
        try:
            now = int(time.time())
            if now - int(self._last_proxy_sponsor_hide or 0) < 30:
                return

            prefs = MessagesController.getGlobalMainSettings()
            promo_id = int(prefs.getLong("proxy_dialog", 0))
            promo_type = int(prefs.getInt("promo_dialog_type", -1))
            proxy_type = int(getattr(MessagesController, "PROMO_TYPE_PROXY", 0))
            if promo_id == 0 or promo_type != proxy_type:
                return

            self._last_proxy_sponsor_hide = now

            def _hide_all():
                for i in range(UserConfig.MAX_ACCOUNT_COUNT):
                    try:
                        mc = MessagesController.getInstance(i)
                        if not mc:
                            continue

                        try:
                            from hook_utils import get_private_field, set_private_field
                            promo_dialog = None
                            try:
                                promo_dialog = get_private_field(mc, "promoDialog")
                            except:
                                promo_dialog = None
                            if promo_dialog is None:
                                try:
                                    promo_dialog = mc.dialogs_dict.get(promo_id)
                                except:
                                    promo_dialog = None
                                if promo_dialog is not None:
                                    try:
                                        set_private_field(mc, "promoDialog", promo_dialog)
                                    except:
                                        pass
                        except:
                            pass

                        try:
                            if hasattr(mc, "hidePromoDialog"):
                                mc.hidePromoDialog()
                        except:
                            pass
                    except:
                        pass

            run_on_ui_thread(_hide_all)
        except:
            pass

    def _start_thread(self):
        if self._thread and self._thread.is_alive():
            return
        try:
            self._worker_stop.clear()
        except:
            pass
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        self._worker_stop.wait(2)
        if self._worker_stop.is_set() or (not self._active):
            return
        try:
            self._run_autoupdate_check(force=False)
        except:
            pass
        try:
            self._apply_vpn_policy()
        except:
            pass
        if self._is_plugin_proxy_enabled() and not self._is_proxy_policy_suspended():
            if self._is_vless_mode_selected():
                if not self._vless_running or (self._vless_port and not _check_vless_port(self._vless_port)):
                    self._auto_reconnect_vless()
            elif self._is_tgws_mode_selected():
                self._tgws_ensure_local_proxy()
            elif self._should_run_awg():
                if not self._awg_running or (self._awg_port and not _check_vless_port(self._awg_port)):
                    self._ensure_awg_core_then(self._awg_connect)
            elif self._should_run_olcrtc():
                if (not bool(getattr(self, "_olcrtc_backgrounded", False))) and (not bool(getattr(self, "_olcrtc_connecting", False))):
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="worker_start")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                    else:
                        self._olcrtc_running = False
                        self._ensure_olcrtc_core_then(self._olcrtc_connect)
            elif not self._is_proxy_connection_ready():
                self._update_proxy_logic()

        last_refresh = time.time()
        last_health_check = time.time()
        last_precheck = 0

        while self._active:
            try:
                self._worker_stop.wait(30)
                if self._worker_stop.is_set() or (not self._active):
                    break

                try:
                    self._apply_vpn_policy()
                except:
                    pass
                if self._is_proxy_policy_suspended():
                    continue

                try:
                    self._run_autoupdate_check(force=False)
                except:
                    pass

                if not self._is_plugin_proxy_enabled():
                    continue

                if self._is_vless_mode_selected():
                    if not self._vless_running or (self._vless_port and not _check_vless_port(self._vless_port)):
                        self._auto_reconnect_vless()
                    continue

                if self._is_tgws_mode_selected():
                    backgrounded = bool(getattr(self, "_tgws_backgrounded", False))
                    if not backgrounded:
                        old_ready = bool(getattr(self, "_tgws_ready", False))
                        ready_now = self._tgws_ensure_local_proxy()
                        if old_ready != bool(ready_now):
                            run_on_ui_thread(self._refresh_settings_without_reopen)
                        if (not ready_now) and (not backgrounded) and (not bool(getattr(self, "_tgws_connecting", False))):
                            self._tgws_heal_if_due()
                    continue

                if self._should_run_awg():
                    if not self._awg_running or (self._awg_port and not _check_vless_port(self._awg_port)):
                        self._ensure_awg_core_then(self._awg_connect)
                    continue

                if self._should_run_olcrtc():
                    if bool(getattr(self, "_olcrtc_backgrounded", False)):
                        continue
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="worker")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_connecting = False
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                    elif bool(getattr(self, "_olcrtc_connecting", False)) or core_state in ("starting", "handshake", "stopping"):
                        self._olcrtc_dead_checks = 0
                    else:
                        self._olcrtc_running = False
                        self._olcrtc_resume_checking = False
                        self._olcrtc_dead_checks = int(getattr(self, "_olcrtc_dead_checks", 0) or 0) + 1
                        if self._olcrtc_dead_checks >= 2:
                            self._olcrtc_dead_checks = 0
                            self._ensure_olcrtc_core_then(self._olcrtc_connect)
                    continue

                now = time.time()

                if now - last_health_check >= 180:
                    last_health_check = now
                    try:
                        preferences = MessagesController.getGlobalMainSettings()
                        enabled = preferences.getBoolean("proxy_enabled", False)
                        if not enabled:
                            continue
                        if not self._is_proxy_connection_ready():
                            self._update_proxy_logic(force=True)
                    except Exception:
                        pass

                if now - last_refresh >= 1800:
                    last_refresh = now
                    self._update_proxy_logic()

                if now - last_precheck >= float(PRECHECK_INTERVAL_SEC):
                    last_precheck = now
                    self._background_precheck()

            except Exception:
                self._worker_stop.wait(60)
                if self._worker_stop.is_set() or (not self._active):
                    break

    def _update_proxy_logic(self, force=False):
        if not self._active:
            return
        if not self._is_plugin_proxy_enabled():
            self._finding_proxy = False
            return
        if self._is_vless_mode_selected():
            self._finding_proxy = False
            if (not self._vless_running) or (self._vless_port and not _check_vless_port(self._vless_port)):
                if force:
                    self._reset_vless_retry()
                    self._ensure_vless_core_then(self._vless_connect)
                else:
                    self._auto_reconnect_vless()
            return
        if self._is_tgws_mode_selected():
            self._finding_proxy = False
            old_ready = bool(getattr(self, "_tgws_ready", False))
            ready_now = bool(self._tgws_ensure_local_proxy())
            if old_ready != ready_now:
                run_on_ui_thread(self._refresh_settings_without_reopen)
            if (not ready_now) and (not bool(getattr(self, "_tgws_connecting", False))):
                self._tgws_heal_if_due()
            return
        if self._is_awg_mode_selected():
            self._finding_proxy = False
            if self._should_run_awg() and ((not self._awg_running) or (self._awg_port and not _check_vless_port(self._awg_port))):
                self._ensure_awg_core_then(self._awg_connect)
            return
        if self._is_olcrtc_mode_selected():
            self._finding_proxy = False
            if self._should_run_olcrtc() and (not bool(getattr(self, "_olcrtc_backgrounded", False))) and (not bool(getattr(self, "_olcrtc_connecting", False))):
                port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="update_proxy")
                core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                if local_alive and self._olcrtc_state_needs_restart(core_state):
                    local_alive = False
                if local_alive:
                    self._olcrtc_dead_checks = 0
                    self._olcrtc_port = port
                    self._olcrtc_running = True
                    self._olcrtc_health_stale = False
                    self._olcrtc_resume_checking = False
                else:
                    self._olcrtc_running = False
                    self._olcrtc_resume_checking = False
                    self._ensure_olcrtc_core_then(self._olcrtc_connect)
            return

        if self._finding_proxy:
            if not force:
                return
            wait_left = 2.0
            while self._finding_proxy and wait_left > 0 and self._active:
                time.sleep(0.2)
                wait_left -= 0.2
            if self._finding_proxy:
                return
        self._finding_proxy = True
        
        try:
            provider_auto = self._get_provider_auto()
            selected_provider = self._get_selected_provider()

            provider_proxy_map = {}
            merged_provider_proxies = []
            selected_provider_proxies = []

            if provider_auto:
                provider_proxy_map = self._collect_provider_proxy_map_sync(timeout_sec=2.5)
                chosen_provider = self._choose_best_provider_auto_sync(provider_proxy_map, selected_provider)
                selected_provider = chosen_provider
                self._set_selected_provider(chosen_provider)
                selected_provider_proxies = list(provider_proxy_map.get(chosen_provider, []) or [])
                merged_provider_proxies = self._merge_unique_proxies([provider_proxy_map.get(idx, []) or [] for idx in range(self._provider_count())])
            else:
                selected_provider_proxies = self._collect_proxies_for_provider(selected_provider, timeout_sec=5.0)
                merged_provider_proxies = self._merge_unique_proxies([selected_provider_proxies])

            fallback_chain = self._build_safe_fallback_chain(selected_provider_proxies, merged_provider_proxies)
            chain_for_prune = self._merge_unique_proxies([items for _, items in fallback_chain])

            try:
                now_ts = int(time.time())
                valid_keys = set()
                for p in chain_for_prune:
                    try:
                        valid_keys.add(
                            self._proxy_key(
                                p.get("server"),
                                p.get("port"),
                                p.get("secret"),
                                p.get("username"),
                                p.get("password"),
                            )
                        )
                    except:
                        pass
                self._prune_proxy_state(now=now_ts, valid_keys=valid_keys)
                self._save_config()
            except:
                pass

            if not chain_for_prune:
                self._refresh_settings_without_reopen()
                run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось найти прокси"))
                return

            working_proxy = None
            for _, candidate_list in fallback_chain:
                if not candidate_list:
                    continue
                working_proxy = self._find_fastest_proxy(candidate_list)
                if working_proxy:
                    break

            if working_proxy:
                self._current_server = working_proxy['server']
                self._current_port = working_proxy['port']
                self._current_secret = working_proxy['secret']
                try:
                    selected_provider = int(working_proxy.get("provider_idx", selected_provider))
                except:
                    pass
                self._set_selected_provider(selected_provider)
                self._last_provider_name = str(working_proxy.get("provider_name", self._provider_name(selected_provider)))
                self._last_working_proxy = self._normalize_proxy_dict(working_proxy)
                try:
                    self._refresh_hot_proxy_cache([working_proxy])
                except:
                    pass
                self._save_config()

                provider_name = self._last_provider_name or self._provider_name(selected_provider)
                self._refresh_settings_without_reopen()
                run_on_ui_thread(lambda: BulletinHelper.show_success(f"Прокси установлен: {self._current_server} ({provider_name}, Ping: {int(working_proxy.get('latency', 0))}ms)"))
            else:
                self._refresh_settings_without_reopen()
                run_on_ui_thread(lambda: BulletinHelper.show_error("Нет доступных рабочих прокси"))
                
        finally:
            self._finding_proxy = False

    def _fetch_proxies_from_url(self, url, timeout_sec=5.0, headers=None):
        req_headers = {}
        try:
            for k, v in dict(headers or {}).items():
                kk = str(k or "").strip()
                vv = str(v or "").strip()
                if kk and vv:
                    req_headers[kk] = vv
        except:
            req_headers = {}

        try:
            req = urllib.request.Request(url)
            for hk, hv in req_headers.items():
                try:
                    req.add_header(str(hk), str(hv))
                except:
                    pass
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=float(timeout_sec), context=ctx) as resp:
                content = resp.read().decode('utf-8')
                return self._parse_proxies(content)
        except Exception:
            pass

        try:
            import requests
            r = requests.get(url, timeout=float(timeout_sec), verify=False, headers=req_headers)
            if int(getattr(r, "status_code", 0)) == 200:
                return self._parse_proxies(getattr(r, "text", "") or "")
        except Exception:
            pass

        return []

    def _parse_proxies(self, text):
        results = []

        try:
            from urllib.parse import urlparse, parse_qs
        except:
            return results

        if not text:
            return results

        tokens = []
        try:
            blob = str(text)
        except:
            blob = ""

        try:
            blob = blob.replace("\\/", "/").replace("\\u0026", "&").replace("&amp;", "&")
        except:
            pass

        if not blob:
            return results

        try:
            tokens.extend(re.findall(r"(?:tg://(?:proxy|socks)\?[^\s]+|https?://t\.me/(?:proxy|socks)\?[^\s]+)", blob))
        except:
            pass

        try:
            raw_queries = re.findall(r"(server=[^\s\"']+?&port=\d+[^\s\"']*)", blob)
        except:
            raw_queries = []
        for q in raw_queries:
            try:
                qq = str(q or "").strip().strip("\"'`")
                if not qq:
                    continue
                if "secret=" in qq:
                    tokens.append("tg://proxy?" + qq.lstrip("?"))
                else:
                    tokens.append("tg://socks?" + qq.lstrip("?"))
            except:
                pass

        for raw in blob.splitlines():
            try:
                s = str(raw or "").strip()
                if not s:
                    continue

                if "server=" in s and "port=" in s and ("secret=" in s or "user=" in s or "pass=" in s):
                    if "://" not in s:
                        if "secret=" in s:
                            s = "tg://proxy?" + s.lstrip("?")
                        else:
                            s = "tg://socks?" + s.lstrip("?")
                    tokens.append(s)
            except:
                pass

        try:
            obj_chunks = re.findall(r"\{[^{}]{10,}\}", blob)
        except:
            obj_chunks = []

        for ch in obj_chunks:
            try:
                chunk = str(ch or "")
                if "server" not in chunk or "port" not in chunk:
                    continue

                def _pick(name):
                    m = re.search(r"(?:\"|')?" + re.escape(name) + r"(?:\"|')?\s*:\s*(?:\"([^\"]*)\"|'([^']*)'|([A-Za-z0-9_\-\.]+))", chunk)
                    if not m:
                        return ""
                    return str(m.group(1) or m.group(2) or m.group(3) or "").strip()

                server = _pick("server")
                port_s = _pick("port")
                secret = _pick("secret")
                user = _pick("user") or _pick("username")
                password = _pick("pass") or _pick("password")
                kind = (_pick("type") or "").lower()
                if kind not in ["mtproto", "socks"]:
                    kind = "socks" if (user or password) else "mtproto"

                if not server or not port_s:
                    continue
                try:
                    port = int(str(port_s))
                except:
                    continue

                if kind == "mtproto" and not secret:
                    continue

                if kind == "mtproto":
                    tokens.append(f"tg://proxy?server={server}&port={port}&secret={secret}")
                else:
                    if user or password:
                        tokens.append(f"tg://socks?server={server}&port={port}&user={user}&pass={password}")
                    else:
                        tokens.append(f"tg://socks?server={server}&port={port}")
            except:
                pass

        dedup = set()
        for token in tokens:
            t = str(token or "").strip().rstrip('.,;)]')
            if not t or t in dedup:
                continue
            dedup.add(t)

            try:
                parsed = urlparse(t)
                target = ""
                if str(parsed.scheme).lower() == "tg":
                    target = str(parsed.netloc or parsed.path or "").strip("/").lower()
                else:
                    target = str(parsed.path or "").strip("/").lower()

                q = parse_qs(parsed.query)
                server = str((q.get("server") or [""])[0] or "")
                port_s = str((q.get("port") or [""])[0] or "")
                secret = str((q.get("secret") or [""])[0] or "")
                user = str((q.get("user") or [""])[0] or "")
                password = str((q.get("pass") or q.get("password") or [""])[0] or "")

                if not server or not port_s:
                    continue

                try:
                    port = int(port_s)
                except:
                    continue

                kind = "socks" if "socks" in target else "mtproto"
                if kind == "mtproto" and not secret:
                    continue

                results.append({
                    "server": server,
                    "port": int(port),
                    "secret": secret,
                    "username": user,
                    "password": password,
                    "kind": kind,
                })
            except:
                pass

        return results

    def _find_fastest_proxy(self, proxies):
        working_proxies = []

        prefer_calls_proxy = bool(self._get_calls_proxy_preference())
        source = list(proxies or [])
        if prefer_calls_proxy:
            socks_only = [p for p in source if self._is_socks_proxy(p)]
            if not socks_only:
                return None
            source = socks_only

        subset = self._build_probe_subset(source, limit=12)
        if prefer_calls_proxy:
            socks_all = []
            for p in source:
                if self._is_socks_proxy(p):
                    socks_all.append(p)
            random.shuffle(socks_all)

            ordered = []
            used = set()
            for p in socks_all:
                if len(ordered) >= 12:
                    break
                pid = id(p)
                if pid in used:
                    continue
                ordered.append(p)
                used.add(pid)
            for p in subset:
                if len(ordered) >= 12:
                    break
                pid = id(p)
                if pid in used:
                    continue
                ordered.append(p)
                used.add(pid)
            subset = ordered

        for proxy in subset:
            if (not self._active) or (not self._is_plugin_proxy_enabled()):
                break
            dt = self._probe_proxy_latency(proxy, timeout_sec=0.8)
            if dt is None:
                continue
            try:
                proxy["latency"] = float(dt)
            except:
                proxy["latency"] = 999999.0
            working_proxies.append(proxy)

        if prefer_calls_proxy:
            working_proxies.sort(key=lambda x: (0 if self._is_socks_proxy(x) else 1, float(x.get('latency', 999999.0))))
        else:
            working_proxies.sort(key=lambda x: float(x.get('latency', 999999.0)))

        now_ts = int(time.time())
        max_verify = min(6, len(working_proxies))
        for proxy in working_proxies[:max_verify]:
            key = self._proxy_key(
                proxy.get("server"),
                proxy.get("port"),
                proxy.get("secret"),
                proxy.get("username"),
                proxy.get("password"),
            )
            if self._should_skip_proxy_due_to_failures(key, now=now_ts):
                continue
            if self._apply_and_verify(proxy, key=key):
                return proxy
                 
        return None

    def _apply_and_verify(self, proxy, key=None):
        if key is None:
            key = self._proxy_key(
                proxy.get("server"),
                proxy.get("port"),
                proxy.get("secret"),
                proxy.get("username"),
                proxy.get("password"),
            )

        ok = self._apply_proxy_settings(proxy, key=key)
        if ok:
            connected_state = 3
            try:
                connected_state = int(getattr(ConnectionsManager, "ConnectionStateConnected", 3))
            except:
                connected_state = 3

            updating_state = connected_state
            try:
                updating_state = int(getattr(ConnectionsManager, "ConnectionStateUpdating", connected_state))
            except:
                updating_state = connected_state

            deadline = time.time() + float(PROXY_CONNECT_VERIFY_WAIT_SEC)
            poll_sec = float(PROXY_CONNECT_VERIFY_POLL_SEC)
            if poll_sec <= 0:
                poll_sec = 0.25

            while True:
                if (not self._active) or (not self._is_plugin_proxy_enabled()):
                    break
                state = None
                try:
                    cm = ConnectionsManager.getInstance(UserConfig.selectedAccount)
                    if cm is not None:
                        state = int(cm.getConnectionState())
                except:
                    state = None

                if state == connected_state or state == updating_state or state == 3:
                    hold_sec = 0.0
                    try:
                        hold_sec = float(PROXY_CONNECT_STABILITY_HOLD_SEC)
                    except:
                        hold_sec = 0.0

                    if hold_sec <= 0:
                        return True

                    try:
                        now = time.time()
                        remain = max(0.01, deadline - now)
                        time.sleep(min(hold_sec, remain))
                    except:
                        pass

                    state2 = None
                    try:
                        cm2 = ConnectionsManager.getInstance(UserConfig.selectedAccount)
                        if cm2 is not None:
                            state2 = int(cm2.getConnectionState())
                    except:
                        state2 = None

                    if state2 == connected_state or state2 == updating_state or state2 == 3:
                        return True

                now = time.time()
                if now >= deadline:
                    break

                try:
                    time.sleep(min(poll_sec, max(0.01, deadline - now)))
                except:
                    break

        try:
            self._mark_proxy_failed(key, now=int(time.time()))
            self._save_config()
        except:
            pass
        return False

    def _apply_proxy_settings(self, pd, key=None):
        srv = pd.get("server")
        prt = int(pd.get("port", 0))
        usr = str(pd.get("username", "") or "")
        pwd = str(pd.get("password", "") or "")
        sec = pd.get("secret", "")

        if key is None:
            key = self._proxy_key(srv, prt, sec, usr, pwd)
        
        try:
            current_mode = self._get_connection_mode()
            if current_mode == VLESS_KIND:
                try:
                    self._vless_disconnect_with_reason("apply_proxy_settings_switch_to_proxy", silent=True)
                except:
                    pass
            elif current_mode == TGWS_KIND:
                try:
                    self._tgws_disconnect_with_reason("apply_proxy_settings_switch_to_proxy", silent=True)
                except:
                    pass
            elif current_mode == AWG_KIND:
                try:
                    self._awg_disconnect_with_reason("apply_proxy_settings_switch_to_proxy", silent=True)
                except:
                    pass
            elif current_mode == OLCRTC_KIND:
                try:
                    self._olcrtc_disconnect_with_reason("apply_proxy_settings_switch_to_proxy", silent=True)
                except:
                    pass
            self._set_connection_mode("proxy")
            pi = None

            try:
                self._cleanup_plugin_proxies_from_shared_list(keep_current=False)
            except:
                pass

            existed_before = False
            try:
                existed_before = self._find_proxy_in_shared_list(key) is not None
            except:
                existed_before = False
            try:
                from hook_utils import find_class
                PC = find_class("org.telegram.messenger.SharedConfig$ProxyInfo")
                if PC:
                    ctor_getter = getattr(PC, "getConstructor", None) or getattr(PC, "getDeclaredConstructor", None)
                    if ctor_getter:
                        ct = ctor_getter(str, int, str, str, str)
                        pi_candidate = ct.newInstance(srv, prt, usr, pwd, sec)
                        try:
                            pi = SharedConfig.addProxy(pi_candidate)
                        except:
                            pi = pi_candidate
            except:
                pi = None

            if not pi:
                try:
                    pi_candidate = SharedConfig.ProxyInfo(srv, prt, usr, pwd, sec)
                    pi = SharedConfig.addProxy(pi_candidate)
                except:
                    pi = None

            if not pi:
                return False

            if pi:
                SharedConfig.currentProxy = pi
                try:
                    if hasattr(SharedConfig, "saveProxyList"):
                        SharedConfig.saveProxyList()
                except:
                    pass

                try:
                    owned = not bool(existed_before)
                    self._mark_proxy_success(key, owned=owned, now=int(time.time()))
                    self._prune_proxy_state(now=int(time.time()))
                    self._save_config()
                except:
                    pass
            
            SharedConfig.proxyEnabled = True

            try:
                call_pref = bool(self._get_calls_proxy_preference())
            except:
                call_pref = False
            is_socks = bool(self._is_socks_proxy(pd))
            calls_proxy_enabled = bool(call_pref and is_socks)

            try:
                pr = MessagesController.getGlobalMainSettings()
                ed = pr.edit()
                ed.putBoolean("proxy_enabled", True)
                ed.putBoolean("proxy_enabled_calls", bool(calls_proxy_enabled))
                ed.putString("proxy_ip", srv)
                ed.putString("proxy_user", usr)
                ed.putString("proxy_pass", pwd)
                ed.putInt("proxy_port", prt)
                ed.putString("proxy_secret", sec)
                ed.commit()
            except: pass

            try:
                ConnectionsManager.setProxySettings(True, srv, prt, usr, pwd, sec)
            except: pass

            try: NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
            except: pass

            try:
                self._sync_plugin_proxy_bridge()
            except:
                pass
            return True
            
        except Exception:
            return False

    def _client_version_string(self):
        try:
            value = str(BuildVars.BUILD_VERSION_STRING or "").strip()
            if value:
                return value
        except:
            pass
        try:
            ctx = ApplicationLoader.applicationContext
            package_info = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0)
            value = str(getattr(package_info, "versionName", "") or "").strip()
            if value:
                return value
        except:
            pass
        return ""

    def _should_hide_proxy_mode_ui(self):
        version = self._client_version_string()
        try:
            if not re.search(r"\d+", str(version or "")):
                return False
            current = list(_version_tuple(version))
            limit = list(_version_tuple(PROXY_MODE_HIDE_CLIENT_MAX_VERSION))
            size = max(len(current), len(limit))
            current.extend([0] * (size - len(current)))
            limit.extend([0] * (size - len(limit)))
            return tuple(current) <= tuple(limit)
        except:
            return False

    def _settings_mode_choices(self):
        choices = [
            ("proxy", "Прокси"),
            (VLESS_KIND, "sing-box"),
            (TGWS_KIND, "TG WS"),
            (AWG_KIND, "AmneziaWG"),
            (OLCRTC_KIND, "olcRTC"),
        ]
        if self._should_hide_proxy_mode_ui():
            return [choice for choice in choices if choice[0] != "proxy"]
        return choices

    def _settings_mode_title(self, mode):
        target = str(mode or "proxy")
        if target == VLESS_KIND:
            return "sing-box"
        if target == TGWS_KIND:
            return "TG WS"
        if target == AWG_KIND:
            return "AmneziaWG"
        if target == OLCRTC_KIND:
            return "olcRTC"
        return "Прокси"

    def _settings_mode_icon(self, mode):
        target = str(mode or "proxy")
        if target == VLESS_KIND:
            return "msg_list"
        if target == TGWS_KIND:
            return "msg2_proxy_on"
        if target == AWG_KIND:
            return "msg_secret"
        if target == OLCRTC_KIND:
            return "msg_link"
        return "msg_settings"

    def _refresh_mode_summary(self):
        try:
            controller = self._plugins_controller_instance()
            plugin_id = self._plugin_settings_id()
            if controller is not None and plugin_id:
                controller.loadPluginSettings(plugin_id)
        except:
            pass

    def _safe_settings_items(self, title, builder):
        try:
            return list(builder() or [])
        except:
            return [Text(text=f"{str(title or 'Раздел')[:18]}: ошибка", icon="msg_settings")]

    def _open_mode_picker(self):
        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            return False

        builder = AlertDialogBuilder(activity)
        choices = self._settings_mode_choices()
        labels = [label for mode, label in choices]
        modes = [mode for mode, label in choices]

        def _on_item(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            try:
                idx = int(which)
            except:
                idx = -1
            if 0 <= idx < len(modes):
                self._select_mode_from_settings(modes[idx])

        builder.set_title("Режим")
        builder.set_items(labels, _on_item)
        builder.set_negative_button("Отмена", lambda d, w: d.dismiss())
        builder.show()
        return True

    def _refresh_proxy_from_settings(self):
        if self._is_plugin_proxy_enabled():
            self._force_update()
        else:
            self._on_use_proxy_changed(True)

    def _restart_tgws_from_settings(self):
        self._set_connection_mode(TGWS_KIND)
        if self._is_plugin_proxy_enabled():
            try:
                self._tgws_disconnect_with_reason("restart", silent=True)
            except:
                pass
            self._tgws_connect()
        else:
            self._on_use_proxy_changed(True)
        self._refresh_settings_without_reopen()

    def _on_olcrtc_carrier_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= len(OLCRTC_CARRIER_ITEMS):
            i = 0
        self._set_setting_value("olcrtc_carrier", i, reload_settings=True)
        if self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected() and (bool(self._olcrtc_running) or bool(self._olcrtc_connecting)):
            self._restart_olcrtc_from_settings()

    def _on_olcrtc_transport_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= len(OLCRTC_TRANSPORT_ITEMS):
            i = 0
        self._set_setting_value("olcrtc_transport", i, reload_settings=True)
        if self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected() and (bool(self._olcrtc_running) or bool(self._olcrtc_connecting)):
            self._restart_olcrtc_from_settings()

    def _settings_active_proxy_info(self):
        enabled = False
        active_server = ""
        active_port = 0
        active_user = ""
        active_pass = ""
        active_secret = ""

        try:
            try:
                enabled = bool(SharedConfig.isProxyEnabled())
            except:
                prefs = MessagesController.getGlobalMainSettings()
                enabled = prefs.getBoolean("proxy_enabled", False) and SharedConfig.currentProxy is not None

            if enabled and SharedConfig.currentProxy is not None:
                active_server = str(SharedConfig.currentProxy.address)
                active_port = int(SharedConfig.currentProxy.port)
                active_user = str(getattr(SharedConfig.currentProxy, "username", "") or "")
                active_pass = str(getattr(SharedConfig.currentProxy, "password", "") or "")
                active_secret = str(SharedConfig.currentProxy.secret)
            else:
                prefs = MessagesController.getGlobalMainSettings()
                active_server = prefs.getString("proxy_ip", "")
                active_port = prefs.getInt("proxy_port", 0)
                active_user = prefs.getString("proxy_user", "")
                active_pass = prefs.getString("proxy_pass", "")
                active_secret = prefs.getString("proxy_secret", "")
        except:
            enabled = False

        active_link = None
        if enabled and active_server:
            if active_secret:
                active_link = f"https://t.me/proxy?server={active_server}&port={active_port}&secret={active_secret}"
            else:
                try:
                    from urllib.parse import quote
                    q_user = quote(str(active_user or ""), safe="")
                    q_pass = quote(str(active_pass or ""), safe="")
                except:
                    q_user = str(active_user or "")
                    q_pass = str(active_pass or "")
                active_link = f"tg://socks?server={active_server}&port={active_port}&user={q_user}&pass={q_pass}"

        return {
            "enabled": bool(enabled),
            "server": active_server,
            "port": int(active_port or 0),
            "active_link": active_link,
        }

    def _build_status_settings_items(self):
        items = []
        if bool(getattr(self, "_proxy_suspended_by_wifi", False)):
            ssid = str(getattr(self, "_current_wifi_ssid_cache", "") or "")
            items.append(Text(text="Приостановлено: WIFI " + (ssid or "сеть"), icon="msg_list"))
        elif bool(getattr(self, "_proxy_suspended_by_vpn", False)):
            items.append(Text(text="Приостановлено: активен VPN", icon="msg_secret"))
        mode = self._get_connection_mode()
        info = self._settings_active_proxy_info()
        current_vless = self._current_vless_node()
        try:
            vless_applied = bool(self._vless_port and self._is_local_vless_proxy_applied(self._vless_port))
        except:
            vless_applied = False

        if mode == VLESS_KIND or vless_applied:
            vless_connecting = bool(getattr(self, "_vless_connecting", False))
            vless_error = str(getattr(self, "_vless_last_error", "") or "").strip()
            node_label = self._vless_node_plain_label(current_vless) if current_vless else "узел не выбран"
            if vless_connecting:
                status_text = "🟠 Подключение: " + node_label
            elif vless_error and not (vless_applied or bool(self._vless_running)):
                status_text = "🔴 Не подключено: " + node_label
            else:
                status_text = self._custom_proxy_label(current_vless) + ": " + node_label if current_vless else "VLESS: подключен" if vless_applied else "VLESS: узел не выбран"
            status_kwargs = {
                "text": self._append_green_tail(
                    status_text,
                    self._vless_ping_badge(current_vless) if current_vless else "",
                ),
                "icon": self._settings_mode_icon(VLESS_KIND),
                "create_sub_fragment": self._create_active_mode_subpage,
            }
            if vless_error and not vless_connecting and not (vless_applied or bool(self._vless_running)):
                status_kwargs["subtext"] = vless_error[:160]
                status_kwargs["red"] = True
            items.append(Text(**status_kwargs))
        elif mode == TGWS_KIND:
            tgws_ready = bool(getattr(self, "_tgws_ready", False))
            tgws_running = bool(getattr(self, "_tgws_running", False))
            if tgws_ready:
                tgws_text = "TG WS: подключен"
            elif tgws_running:
                tgws_text = "TG WS: соединяю"
            else:
                tgws_text = "TG WS: выключен"
            items.append(Text(
                text=tgws_text,
                icon=self._settings_mode_icon(TGWS_KIND),
                create_sub_fragment=self._create_active_mode_subpage,
            ))
        elif mode == AWG_KIND:
            name = str(self._awg_conf_name or "").strip() or "конфиг не выбран"
            items.append(Text(
                text="AWG: " + name,
                icon=self._settings_mode_icon(AWG_KIND),
                create_sub_fragment=self._create_active_mode_subpage,
            ))
        elif mode == OLCRTC_KIND:
            olcrtc_connecting = bool(getattr(self, "_olcrtc_connecting", False))
            status_text, status_subtext, core_state = self._olcrtc_status_presentation()
            items.append(Text(
                text=status_text,
                subtext=status_subtext,
                icon=self._settings_mode_icon(OLCRTC_KIND),
                create_sub_fragment=self._create_active_mode_subpage,
            ))
        elif info.get("enabled") and info.get("server"):
            items.append(Text(
                text=f"Прокси: {info.get('server')}:{int(info.get('port', 0) or 0)}",
                icon=self._settings_mode_icon("proxy"),
                create_sub_fragment=self._create_active_mode_subpage,
            ))
        else:
            items.append(Text(
                text="Прокси не установлен",
                icon="msg2_proxy_off",
                create_sub_fragment=self._create_active_mode_subpage,
            ))

        if mode == "proxy" and self._last_provider_name:
            items.append(Text(text=f"Источник: {self._last_provider_name}", icon="msg_link"))
        hot_count = len(self._sanitize_hot_proxy_cache(self._hot_proxy_cache))
        if mode == "proxy" and hot_count > 0:
            items.append(Text(text=f"Кэш: {hot_count}", icon="msg_list"))
        return items

    def _builtin_vless_sub_sources(self):
        items = []
        for provider_idx in sorted(VLESS_PROVIDER_SUBS.keys()):
            try:
                urls = list(VLESS_PROVIDER_SUBS.get(provider_idx, []) or [])
            except:
                urls = []
            total_urls = len(urls)
            for url in urls:
                value = str(url or "").strip()
                if not value:
                    continue
                items.append({
                    "name": self._provider_vless_sub_name(provider_idx, value, total_urls=total_urls) or "Подписка",
                    "url": value,
                })
        return items

    def _create_builtin_vless_subs_subpage(self):
        items = [Header(text="Встроенные подписки")]
        sources = self._builtin_vless_sub_sources()
        if not sources:
            items.append(Text(text="Подписок нет"))
            return items

        for source in sources:
            url = str(source.get("url", "") or "")
            imported = self._find_vless_subscription(url) is not None
            label = str(source.get("name", "Подписка") or "Подписка")
            if imported:
                label = "Импортировано: " + label
            items.append(Text(
                text=label,
                accent=bool(imported),
                icon="msg_link",
                on_click=lambda *a, url=url: self._add_vless_subscription(url, activate_first=(not self._get_active_vless_uri())),
            ))
        return items

    def _build_proxy_mode_items(self):
        selected_provider = self._get_selected_provider()
        items = [
            Switch(
                key="proxy_provider_auto",
                text="Автовыбор",
                default=bool(self._get_provider_auto()),
                icon="media_flip",
                on_change=self._on_provider_auto_changed,
            ),
            Selector(
                key="proxy_provider",
                text="Провайдер",
                default=int(selected_provider),
                items=list(PROXY_PROVIDER_ITEMS),
                icon="msg_list",
                on_change=self._on_provider_changed,
            ),
        ]
        items.extend([
            Text(text="Быстрый выбор", icon="msg_list", create_sub_fragment=self._create_manual_proxy_subpage),
            Text(text="Встроенные прокси", icon="msg_settings", create_sub_fragment=self._create_hardcoded_proxies_subpage),
            Text(text="Найти новый прокси", icon="msg_retry", on_click=lambda *a: self._refresh_proxy_from_settings()),
            Text(text="Очистить все прокси", icon="msg_delete", red=True, on_click=lambda *a: self._confirm_clear_all_proxies()),
        ])
        info = self._settings_active_proxy_info()
        if info.get("active_link"):
            items.append(Text(text="Скопировать текущий", icon="msg_link", on_click=lambda *a, link=info.get("active_link"): self._copy_link(link)))
        return items

    def _build_vless_mode_items(self):
        current_vless = self._current_vless_node()
        counts = self._vless_counts()
        nodes_count = int(counts.get("nodes", 0) or 0)
        subs_count = int(counts.get("subs", 0) or 0)
        vless_connecting = bool(getattr(self, "_vless_connecting", False))
        vless_error = str(getattr(self, "_vless_last_error", "") or "").strip()

        if current_vless:
            if vless_connecting:
                status_text = "🟠 Подключение: " + self._vless_node_plain_label(current_vless)
            elif vless_error and not bool(self._vless_running):
                status_text = "🔴 Не подключено: " + self._vless_node_plain_label(current_vless)
            else:
                status_text = ("Работает: " if bool(self._vless_running) else "Выбран: ") + self._vless_node_plain_label(current_vless)
            status_tail = self._vless_ping_badge(current_vless)
            active_link = str(current_vless.get("uri", "") or "")
        else:
            status_text = "Узел не выбран"
            status_tail = ""
            active_link = ""

        status_item_kwargs = {
            "text": self._append_green_tail(status_text, status_tail),
            "subtext": vless_error[:160] if current_vless and vless_error and not vless_connecting and not bool(self._vless_running) else f"Узлов: {nodes_count} • подписок: {subs_count}",
            "icon": "msg_retry" if current_vless and vless_connecting else "msg2_proxy_on" if bool(self._vless_running) else "msg2_proxy_off",
        }
        if current_vless and vless_error and not vless_connecting and not bool(self._vless_running):
            status_item_kwargs["red"] = True
        if _is_proxy_uri(active_link):
            status_item_kwargs["on_click"] = lambda *a, link=active_link: self._copy_link(link)

        items = [
            Text(**status_item_kwargs),
            Text(text="Импорт из буфера", accent=True, icon="msg_link", on_click=lambda *a: self._import_vless_from_clipboard()),
            Text(text="Узлы и подписки", icon="msg_list", create_sub_fragment=self._create_vless_nodes_subpage),
        ]
        if nodes_count > 0:
            items.append(Text(text="Подключить лучший", icon="msg_retry", on_click=lambda *a: self._connect_best_vless_node()))
            items.append(Text(text="Проверить пинг", icon="msg_retry", on_click=lambda *a: self._run_vless_ping_test()))
        if subs_count > 0:
            items.append(Text(text="Обновить подписки", icon="msg_retry", on_click=lambda *a: self._refresh_vless_subscriptions()))
        else:
            items.append(Text(text="Встроенные подписки", icon="msg_channel", create_sub_fragment=self._create_builtin_vless_subs_subpage))

        core_status = self._libsingbox_addon_status()
        if core_status == "current":
            is_sb = _is_singbox_core(self._vless_core)
            core_label = "sing-box" if is_sb else "xray"
            items.append(Text(text="Ядро: %s" % core_label, subtext="Нажмите, чтобы удалить", icon="msg_delete", red=True, on_click=lambda *a: self._confirm_delete_vless_addon()))
            if not is_sb:
                items.append(Text(text="Перескачать на sing-box", icon="msg_retry", on_click=lambda *a: self._download_vless_addon()))
        else:
            core_action = "Обновить ядро" if core_status == "outdated" and SINGBOX_BUNDLE_URLS else "Скачать ядро прокси"
            items.append(Text(text=core_action, icon="msg_retry", on_click=lambda *a: self._download_vless_addon()))
        return items

    def _build_tgws_mode_items(self):
        running = bool(self._tgws_running)
        ready = bool(getattr(self, "_tgws_ready", False))
        if ready:
            status_text = "TG WS работает"
        elif running:
            status_text = "TG WS соединяется"
        else:
            status_text = "TG WS выключен"
        return [
            Text(
                text=status_text,
                icon="msg2_proxy_on" if ready else "msg2_proxy_off",
            ),
            Text(
                text="Перезапустить TG WS" if running else "Запустить TG WS",
                icon="msg_retry",
                on_click=lambda *a: self._restart_tgws_from_settings(),
            ),
            Text(
                text="Скопировать tg://proxy",
                icon="msg_link",
                on_click=lambda *a: self._copy_link("tg://ws"),
            ),
        ]

    def _build_awg_mode_items(self):
        running = bool(self._awg_running)
        conf_name = str(self._awg_conf_name or "").strip() or "Не выбран"
        items = [
            Text(
                text="AWG работает" if running else "AWG выключен",
                icon="msg2_proxy_on" if running else "msg2_proxy_off",
            ),
            Text(
                text="Получить AWG конфиг",
                icon="msg_download",
                on_click=lambda *a: self._download_free_awg_config(),
            ),
            Text(
                text="Выбрать .conf",
                subtext=conf_name,
                icon="msg_folder",
                on_click=lambda *a: self._open_awg_file_picker(),
            ),
            Text(
                text="Перезапустить AWG" if running else "Запустить AWG",
                icon="msg_retry",
                on_click=lambda *a: self._restart_awg_from_settings(),
            ),
            Text(
                text="Очистить AWG",
                icon="msg_delete",
                red=True,
                on_click=lambda *a: self._confirm_clear_awg(),
            ),
        ]
        return items

    def _build_olcrtc_mode_items(self):
        running = bool(self._olcrtc_running)
        connecting = bool(getattr(self, "_olcrtc_connecting", False))
        config_err = self._olcrtc_config_error()
        status_text, status_subtext, core_state = self._olcrtc_status_presentation()
        profiles_count = len(self._sanitize_olcrtc_profiles(self._olcrtc_profiles))
        if config_err:
            status_subtext = config_err
        elif profiles_count > 0:
            status_subtext = "%s • профилей: %d" % (status_subtext, profiles_count)
        active_or_busy = bool(running or connecting or core_state in ("starting", "handshake", "ready", "running", "checking", "background"))
        items = [
            Text(
                text=status_text,
                subtext=status_subtext,
                icon="msg2_proxy_on" if running or core_state in ("ready", "running") else "msg_retry" if connecting or core_state in ("starting", "handshake", "stopping", "checking", "background") else "msg2_proxy_off",
                on_click=lambda *a: self._on_olcrtc_status_tap(),
            ),
            Text(
                text="Перезапустить olcRTC" if active_or_busy else "Запустить olcRTC",
                icon="msg_retry",
                on_click=lambda *a: self._restart_olcrtc_from_settings(),
            ),
        ]
        items.insert(1, Text(
            text="Профили и настройки",
            icon="msg_list",
            create_sub_fragment=self._create_olcrtc_profiles_subpage,
        ))
        core_status = self._libsingbox_addon_status()
        if core_status == "current":
            items.append(Text(text="Ядро установлено", icon="msg_settings"))
        else:
            core_action = "Обновить ядро" if core_status == "outdated" and SINGBOX_BUNDLE_URLS else "Скачать ядро"
            items.append(Text(text=core_action, icon="msg_retry", on_click=lambda *a: self._download_olcrtc_addon()))
        return items

    def _build_active_mode_items(self):
        mode = self._get_connection_mode()
        if mode == VLESS_KIND:
            return self._build_vless_mode_items()
        if mode == TGWS_KIND:
            return self._build_tgws_mode_items()
        if mode == AWG_KIND:
            return self._build_awg_mode_items()
        if mode == OLCRTC_KIND:
            return self._build_olcrtc_mode_items()
        return self._build_proxy_mode_items()

    def _build_other_mode_switch_items(self):
        active = self._get_connection_mode()
        items = []
        for mode, label in self._settings_mode_choices():
            if mode == active:
                continue
            items.append(Text(
                text=label if mode != VLESS_KIND else self._settings_mode_title(mode),
                icon=self._settings_mode_icon(mode),
                on_click=lambda *a, mode=mode: self._select_mode_from_settings(mode),
            ))
        return items

    def _create_active_mode_subpage(self):
        mode = self._get_connection_mode()
        title = self._settings_mode_title(mode)
        items = [Header(text=title)]
        items.extend(self._safe_settings_items(title, self._build_active_mode_items))
        items.extend([
            Divider(),
            Text(text="Скопировать логи ядра", icon="msg_link", on_click=lambda *a: self._copy_active_core_logs()),
        ])
        return items

    def _create_greenpass_extra_subpage(self):
        items = [
            Header(text="Дополнительно"),
            Text(
                text="Изменить HWID",
                subtext="Текущий: " + _get_or_create_subscription_hwid(),
                icon="msg_edit",
                on_click=lambda *a: self._regenerate_subscription_hwid(),
            ),
            Switch(
                key="proxy_plugins_via_greenpass",
                text="Проксировать плагины",
                default=bool(self._get_plugins_proxy_enabled()),
                subtext="Направляет запросы плагинов через GreenPass",
                icon="msg_link",
                on_change=self._on_plugins_proxy_changed,
            ),
            Switch(
                key="dont_use_with_vpn",
                text="Не использовать с VPN",
                default=bool(self.get_setting("dont_use_with_vpn", True)),
                subtext="Отключать при VPN",
                icon="msg_secret",
                on_change=self._on_dont_use_with_vpn_changed,
            ),
            Text(
                text="Исключённые WIFI сети",
                subtext=self._excluded_wifi_menu_subtext(),
                icon="msg_list",
                create_sub_fragment=self._create_excluded_wifi_subpage,
            ),
            Switch(
                key="tgws_voip_relay_enabled",
                text="Звонки через Relay",
                default=bool(self._get_tgws_voip_relay_enabled()),
                icon="msg_calls",
                on_change=self._set_tgws_voip_relay_enabled,
            ),
            Text(
                text="Voice Relay",
                icon="msg_settings",
                create_sub_fragment=self._create_voice_relay_subpage,
            ),
            Divider(),
            Text(
                text="Настройки Telegram",
                icon="msg_settings",
                on_click=lambda *a: self._open_tg_proxy_settings(),
            ),
            Text(
                text="Экспорт настроек",
                icon="msg_link",
                on_click=lambda *a: self._export_settings_to_favorites(),
            ),
            Text(
                text="Импорт настроек",
                icon="msg_download",
                on_click=lambda *a: self._open_greenpass_import_file_picker(),
            ),
        ]
        return items

    def _create_voice_relay_subpage(self):
        return [
            Header(text="Voice Relay"),
            EditText(
                key="tgws_voip_relay_ip",
                hint="IPv4 Relay",
                default=str(self.get_setting("tgws_voip_relay_ip", TGWS_VOIP_RELAY_HOST)),
                max_length=15,
            ),
            EditText(
                key="tgws_voip_relay_port",
                hint="UDP-порт Relay",
                default=str(self.get_setting("tgws_voip_relay_port", str(TGWS_VOIP_RELAY_CONTROL_PORT))),
                max_length=5,
            ),
            EditText(
                key="tgws_voip_relay_hmac",
                hint="HMAC-ключ Relay",
                default=str(self.get_setting("tgws_voip_relay_hmac", TGWS_VOIP_RELAY_SECRET.decode("utf-8"))),
                max_length=512,
            ),
            Text(
                text="Скопировать tg://relay",
                icon="msg_link",
                on_click=lambda *a: self._copy_tgws_voip_relay_link(),
            ),
        ]

    def create_settings(self):
        try:
            settings = [Header(text="GreenPass")]
            tg_proxy_enabled = bool(self._is_plugin_proxy_enabled())
            settings.append(Switch(
                key="use_proxy",
                text="Использовать прокси",
                default=bool(tg_proxy_enabled),
                icon="msg2_proxy_on" if bool(tg_proxy_enabled) else "msg2_proxy_off",
                on_change=self._on_use_proxy_changed,
            ))

            settings.append(Divider())
            settings.append(Header(text="Статус"))
            settings.extend(self._safe_settings_items("Статус", self._build_status_settings_items))

            active_mode = self._get_connection_mode()
            settings.append(Divider())
            settings.append(Text(
                text="Режим",
                subtext=self._settings_mode_title(active_mode),
                icon=self._settings_mode_icon(active_mode),
                on_click=lambda *a: self._open_mode_picker(),
            ))
            settings.append(Text(
                text="Дополнительно",
                icon="msg_settings",
                create_sub_fragment=self._create_greenpass_extra_subpage,
            ))

            return settings
        except Exception as e:
            return [Header(text="Ошибка"), Text(text=str(e))]

    def _force_update(self):
        if not self._is_plugin_proxy_enabled():
            return
        if self._is_vless_mode_selected():
            BulletinHelper.show_info("Переподключаю сервер...")
        elif self._is_tgws_mode_selected():
            BulletinHelper.show_info("Переподключаю TG WS...")
        elif self._is_awg_mode_selected():
            BulletinHelper.show_info("Переподключаю AWG...")
            self._restart_awg_from_settings()
            return
        elif self._is_olcrtc_mode_selected():
            self._restart_olcrtc_from_settings()
            return
        else:
            BulletinHelper.show_info("Поиск прокси...")
        threading.Thread(target=lambda: self._update_proxy_logic(force=True), daemon=True).start()

    def _confirm_clear_all_proxies(self):
        try:
            fragment = get_last_fragment()
            if not fragment:
                BulletinHelper.show_error("Не удалось открыть диалог")
                return

            activity = fragment.getParentActivity()
            if not activity:
                BulletinHelper.show_error("Не удалось открыть диалог")
                return

            builder = AlertDialogBuilder(activity)
            builder.set_title("Очистить все прокси?")
            builder.set_message("Будут удалены все сохраненные прокси в Telegram (включая добавленные вручную). Прокси будет выключен. Действие необратимо.")

            def on_yes(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass
                BulletinHelper.show_info("Очистка прокси...")
                threading.Thread(target=self._clear_all_proxies, daemon=True).start()

            def on_no(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass

            builder.set_positive_button("Очистить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            try:
                builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
            except:
                pass
            builder.show()
        except Exception as e:
            BulletinHelper.show_error(f"Ошибка: {e}")

    def _confirm_clear_awg(self):
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except Exception:
            activity = None
        if not activity:
            BulletinHelper.show_error("Не удалось открыть диалог")
            return
        try:
            builder = AlertDialogBuilder(activity)
            builder.set_title("Очистить AWG?")
            builder.set_message("Конфиг AWG будет удалён, туннель отключён. Действие необратимо.")

            def on_yes(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass
                self._clear_awg_config()

            def on_no(bld, which):
                try:
                    bld.dismiss()
                except:
                    pass

            builder.set_positive_button("Очистить", on_yes)
            builder.set_negative_button("Отмена", on_no)
            builder.set_cancelable(True)
            try:
                builder.make_button_red(AlertDialogBuilder.BUTTON_POSITIVE)
            except:
                pass
            builder.show()
        except Exception:
            self._clear_awg_config()

    def _clear_all_proxies(self):
        deleted = 0
        try:
            try:
                self._vless_disconnect_with_reason("clear_all_proxies", silent=True)
            except:
                pass
            try:
                self._tgws_disconnect_with_reason("clear_all_proxies", silent=True)
            except:
                pass
            try:
                self._awg_disconnect_with_reason("clear_all_proxies", silent=True)
            except:
                pass

            try:
                self._desired_use_proxy = False
                self._proxy_suspended_by_vpn = False
                self._proxy_suspended_by_wifi = False
                self._save_config()
                self._set_setting_value("use_proxy", False, reload_settings=False)
            except:
                pass
            self._load_proxy_list_safe()

            proxies = self._shared_proxy_list_snapshot()
            for p in proxies:
                try:
                    if hasattr(SharedConfig, "deleteProxy"):
                        SharedConfig.deleteProxy(p)
                        deleted += 1
                except:
                    pass

            try:
                if hasattr(SharedConfig, "proxyList"):
                    try:
                        SharedConfig.proxyList.clear()
                    except:
                        pass
                try:
                    SharedConfig.currentProxy = None
                except:
                    pass
                try:
                    if hasattr(SharedConfig, "saveProxyList"):
                        SharedConfig.saveProxyList()
                except:
                    pass
            except:
                pass

            try:
                pr = MessagesController.getGlobalMainSettings()
                ed = pr.edit()
                try:
                    ed.remove("proxy_list")
                except:
                    pass
                ed.putString("proxy_ip", "")
                ed.putString("proxy_pass", "")
                ed.putString("proxy_user", "")
                ed.putString("proxy_secret", "")
                ed.putInt("proxy_port", 1080)
                ed.putBoolean("proxy_enabled", False)
                ed.putBoolean("proxy_enabled_calls", False)
                ed.commit()
            except:
                pass
            try:
                SharedConfig.proxyEnabled = False
            except:
                pass

            try:
                ConnectionsManager.setProxySettings(False, "", 0, "", "", "")
            except:
                pass

            try:
                self._proxy_state = {}
                self._save_config()
            except:
                pass

            try:
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
            except:
                pass

            self._refresh_settings_without_reopen()

            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Прокси очищены: {deleted}"))
        except Exception as e:
            run_on_ui_thread(lambda: BulletinHelper.show_error(f"Ошибка очистки: {e}"))

    def _copy_text(self, label, text, success_text="Скопировано"):
        label_text = str(label or "Text")
        copy_text = str(text or "")
        if len(copy_text) > 240000:
            copy_text = copy_text[:240000] + "\n...truncated..."
        ok_text = str(success_text or "Скопировано")

        def _run():
            try:
                from android.content import ClipData, Context
                ctx = ApplicationLoader.applicationContext
                clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                clip = ClipData.newPlainText(label_text, copy_text)
                clipboard.setPrimaryClip(clip)
                BulletinHelper.show_success(ok_text)
            except:
                try:
                    BulletinHelper.show_error("Не удалось скопировать")
                except:
                    pass

        try:
            run_on_ui_thread(_run)
        except:
            _run()

    def _copy_active_core_logs(self):
        mode = self._get_connection_mode()
        if mode == TGWS_KIND:
            return self._copy_tgws_logs()
        if mode == AWG_KIND:
            core = getattr(getattr(self._awg_core, "_real", None), "_core", None)
        elif mode == OLCRTC_KIND:
            core = getattr(self._olcrtc_core, "_real", None)
        elif mode == VLESS_KIND:
            core = getattr(self._vless_core, "_real", None)
        else:
            self._copy_text("GreenPass core logs", "mode: proxy\ncore: Telegram native proxy", "Логи скопированы")
            return
        self._copy_singbox_logs(core)

    def _copy_singbox_logs(self, core=None):
        parts = ["state:\nmode=%s\nvless_running=%s\nvless_port=%s\nconnect_worker=%s\nconnect_pending=%s" % (
            self._get_connection_mode(),
            bool(getattr(self, "_vless_running", False)),
            int(getattr(self, "_vless_port", 0) or 0),
            bool(getattr(self, "_vless_connect_worker_active", False)),
            bool(getattr(self, "_vless_connect_pending", False)),
        )]
        if core is not None:
            for name in ("logs_json", "last_error", "last_log"):
                try:
                    value = getattr(core, name)()
                except:
                    value = ""
                value = str(value or "").strip()
                if value:
                    parts.append("%s:\n%s" % (name, value))
        self._copy_text("GreenPass core logs", "\n\n".join(parts), "Логи скопированы")

    def _copy_tgws_logs(self):
        try:
            port = int(getattr(self, "_tgws_port", 0) or 0)
        except:
            port = 0

        def _safe_len(value):
            try:
                return len(value)
            except:
                return 0

        def _safe_bool(fn):
            try:
                return bool(fn())
            except:
                return False

        local_port_alive = _safe_bool(lambda: port > 0 and _check_vless_port(port))
        local_mtproto_ready = local_port_alive
        local_proxy_applied = _safe_bool(lambda: port > 0 and self._is_local_tgws_proxy_applied(port))

        rows = [
            ("mode", self._get_connection_mode()),
            ("running", bool(getattr(self, "_tgws_running", False))),
            ("ready", bool(getattr(self, "_tgws_ready", False))),
            ("connecting", bool(getattr(self, "_tgws_connecting", False))),
            ("backgrounded", bool(getattr(self, "_tgws_backgrounded", False))),
            ("generation", int(getattr(self, "_tgws_generation", 0) or 0)),
            ("port", port),
            ("local_port_alive", local_port_alive),
            ("local_mtproto_ready", local_mtproto_ready),
            ("local_proxy_applied", local_proxy_applied),
        ]

        try:
            last_heal = float(getattr(self, "_tgws_last_heal_ts", 0.0) or 0.0)
            rows.append(("last_heal_age_sec", int(time.time() - last_heal) if last_heal > 0 else 0))
        except:
            pass

        core = getattr(self, "_tgws_core", None)
        if core is not None:
            rows.append(("core_available", _safe_bool(lambda: core.is_available())))
            rows.append(("listener", getattr(core, "listener", None) is not None))
            try:
                thread = getattr(core, "listener_thread", None)
                rows.append(("listener_thread_alive", bool(thread is not None and thread.is_alive())))
            except:
                pass
            try:
                with core.lock:
                    rows.append(("tracked", _safe_len(getattr(core, "tracked", []))))
            except:
                rows.append(("tracked", _safe_len(getattr(core, "tracked", []))))
            rows.extend([
                ("core_port", int(getattr(core, "port", 0) or 0)),
                ("fail_until", _safe_len(getattr(core, "fail_until", {}))),
                ("fail_count", _safe_len(getattr(core, "fail_count", {}))),
                ("ws_blacklist", _safe_len(getattr(core, "ws_blacklist", set()))),
                ("ws_domain_pref", _safe_len(getattr(core, "ws_domain_pref", {}))),
                ("cf_domain_pref", _safe_len(getattr(core, "cf_domain_pref", {}))),
                ("cf_429_until", _safe_len(getattr(core, "cf_429_until", {}))),
                ("cfproxy_enabled", bool(getattr(core, "cfproxy_enabled", False))),
                ("cfproxy_priority", bool(getattr(core, "cfproxy_priority", False))),
                ("cfproxy_domains", _safe_len(getattr(core, "cfproxy_domains", []))),
                ("cfproxy_worker", bool(str(getattr(core, "cfproxy_worker_domain", "") or "").strip())),
            ])
            try:
                pool = getattr(core, "ws_pool", None)
                idle_count = 0
                idle_keys = 0
                refilling = 0
                if pool is not None:
                    with pool.lock:
                        idle = getattr(pool, "idle", {}) or {}
                        idle_keys = len(idle)
                        idle_count = sum(len(value) for value in idle.values())
                        refilling = _safe_len(getattr(pool, "refilling", set()))
                rows.extend([
                    ("ws_pool_size", int(getattr(pool, "size", 0) or 0) if pool is not None else 0),
                    ("ws_pool_idle_keys", idle_keys),
                    ("ws_pool_idle", idle_count),
                    ("ws_pool_refilling", refilling),
                ])
            except:
                pass

        text = "\n".join("%s: %s" % (key, value) for key, value in rows)
        self._copy_text("GreenPass TG WS logs", text, "Логи скопированы")

    def _copy_link(self, link):
        self._copy_text("Proxy Link", link, "Ссылка скопирована")
