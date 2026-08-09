import json
import os
import sys
import logging

DEFAULT_SETTINGS = {"config_path": ""}


def _get_settings_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(__file__))


def _get_settings_path() -> str:
    return os.path.join(_get_settings_dir(), "settings.json")


def load() -> dict:
    path = _get_settings_path()
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                return {**DEFAULT_SETTINGS, **json.load(f)}
        except Exception as e:
            logging.getLogger(__name__).warning(f"读取设置失败: {e}")
    return dict(DEFAULT_SETTINGS)


def save(settings: dict) -> None:
    path = _get_settings_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.getLogger(__name__).error(f"保存设置失败: {e}")


def get_custom_config_path() -> str:
    s = load()
    p = s.get('config_path', '')
    if p and os.path.exists(p):
        return p
    return ""


def set_custom_config_path(path: str) -> None:
    s = load()
    s['config_path'] = path
    save(s)
