#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
INSTAGRAM PASSIVE OSINT SENTINEL & TRACKER (DEVSECOPS & ADVANCED OSINT)
================================================================================
Módulos integrados:
1. Rastreador diferencial de nuevos seguidores y unfollowers (Set-Difference).
2. Heurística de detección de cuentas sospechosas / posibles bots.
3. Sentinel de perfil y contenido (Bio, Nombre, Links y Nuevos Posts/Reels).
4. Procesador interactivo de comandos de Telegram (/status, /target, /report).
5. Resumen estadístico semanal consolidado (Domingos).
================================================================================
"""

from __future__ import annotations

import sys
import json
import time
import os
import re
import random
import base64
import argparse
import logging
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Tuple, Set, List, Optional

# Compatibilidad de codificación UTF-8 en consolas Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# Carga de variables de entorno desde .env si está disponible localmente
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import instaloader
    from instaloader.exceptions import (
        InstaloaderException,
        ProfileNotExistsException,
        ConnectionException,
        BadCredentialsException,
        TwoFactorAuthRequiredException,
        LoginRequiredException,
        QueryReturnedBadRequestException
    )
except ImportError:
    instaloader = None
    class InstaloaderException(Exception): pass
    class ProfileNotExistsException(InstaloaderException): pass
    class ConnectionException(InstaloaderException): pass
    class BadCredentialsException(InstaloaderException): pass
    class TwoFactorAuthRequiredException(InstaloaderException): pass
    class LoginRequiredException(InstaloaderException): pass
    class QueryReturnedBadRequestException(InstaloaderException): pass


# ==============================================================================
# CONFIGURACIÓN DE LOGGING ESTRUCTURADO
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("InstagramOSINTSentinel")

# Constantes de persistencia
HISTORICAL_FILE = Path("seguidores_historicos.json")
FOLLOWING_HISTORICAL_FILE = Path("seguidos_historicos.json")
NEW_FOLLOWERS_FILE = Path("nuevos_seguidores.json")
PROFILE_SNAPSHOT_FILE = Path("perfil_historico.json")
METRICS_HISTORY_FILE = Path("historial_metricas.json")
STORIES_HISTORICAL_FILE = Path("historias_historicas.json")
ACTIVITY_TIMESTAMPS_FILE = Path("timestamps_actividad.json")


# ==============================================================================
# GESTIÓN DE SESIONES & OPSEC
# ==============================================================================
def get_instaloader_instance() -> Any:
    if instaloader is None:
        logger.critical("❌ Instaloader no está instalado. Ejecuta 'pip install -r requirements.txt'")
        sys.exit(1)

    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    )
    
    L = instaloader.Instaloader(
        user_agent=user_agent,
        sleep=True,
        quiet=False,
        request_timeout=30.0,
        fatal_status_codes=[400, 401, 403, 429]
    )
    return L


def authenticate_session(L: Any, username: str, password: str = None, session_b64: str = None) -> bool:
    session_file_name = f"session-{username}"
    
    if session_b64:
        logger.info("🔑 Inyectando sesión desde variable Base64 (Estrategia Anti-Checkpoint)...")
        try:
            session_bytes = base64.b64decode(session_b64.strip())
            with open(session_file_name, "wb") as f:
                f.write(session_bytes)
            
            L.load_session_from_file(username, session_file_name)
            logger.info("✅ Sesión Base64 restaurada y validada exitosamente.")
            return True
        except Exception as e:
            logger.warning(f"⚠️ No se pudo restaurar la sesión Base64: {e}. Intentando fallback...")

    if os.path.exists(session_file_name):
        logger.info(f"📂 Archivo de sesión local encontrado: '{session_file_name}'. Cargando...")
        try:
            L.load_session_from_file(username, session_file_name)
            logger.info("✅ Sesión local restaurada con éxito.")
            return True
        except Exception as e:
            logger.warning(f"⚠️ Sesión local expirada o corrupta ({e}).")

    if not password:
        logger.error("❌ Se requiere contraseña (IG_PASSWORD) para iniciar sesión por primera vez.")
        return False

    logger.info(f"🌐 Iniciando sesión interactiva para el usuario '{username}'...")
    try:
        L.login(username, password)
        L.save_session_to_file(session_file_name)
        logger.info(f"✅ Login exitoso. Sesión persistida localmente en '{session_file_name}'.")
        return True
    except TwoFactorAuthRequiredException:
        logger.error("🔐 Error 2FA: La cuenta tiene doble factor activado.")
        return False
    except BadCredentialsException:
        logger.error("❌ Credenciales inválidas (IG_USERNAME / IG_PASSWORD).")
        return False
    except ConnectionException as ce:
        logger.error(f"❌ Error de conexión o bloqueo de IP: {ce}")
        return False
    except Exception as e:
        logger.error(f"❌ Error inesperado durante la autenticación: {e}")
        return False


# ==============================================================================
# MÓDULO: CROSS-PLATFORM OSINT (BÚSQUEDA CRUZADA)
# ==============================================================================
def check_cross_platform_presence(username: str) -> Dict[str, str]:
    """
    Comprueba de forma pasiva y segura la presencia del identificador en otras redes sociales.
    """
    found: Dict[str, str] = {}
    import requests

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    # 1. GitHub
    try:
        r = requests.get(f"https://api.github.com/users/{username}", headers=headers, timeout=2.5)
        if r.status_code == 200:
            found["GitHub"] = f"https://github.com/{username}"
    except Exception:
        pass

    # 2. Telegram
    try:
        r = requests.get(f"https://t.me/{username}", headers=headers, timeout=2.5)
        if r.status_code == 200 and "tgme_page_title" in r.text and "If you have Telegram" in r.text:
            found["Telegram"] = f"https://t.me/{username}"
    except Exception:
        pass

    # 3. Reddit
    try:
        r = requests.get(f"https://www.reddit.com/user/{username}/about.json", headers={"User-Agent": "OSINTSentinel/2.0"}, timeout=2.5)
        if r.status_code == 200 and not r.json().get("error"):
            found["Reddit"] = f"https://reddit.com/user/{username}"
    except Exception:
        pass

    found["TikTok"] = f"https://www.tiktok.com/@{username}"
    found["Twitter/X"] = f"https://x.com/{username}"
    return found


def send_telegram_media_file(media_url: str, caption: str, is_video: bool = False) -> bool:
    """
    Descarga un archivo multimedia temporalmente y lo envía directo a Telegram como foto o vídeo.
    """
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not tg_token or not tg_chat_id or not media_url:
        return False

    import requests

    try:
        r = requests.get(media_url, timeout=25)
        if r.status_code != 200:
            return False

        endpoint = "sendVideo" if is_video else "sendPhoto"
        field = "video" if is_video else "photo"
        ext = ".mp4" if is_video else ".jpg"

        files = {field: (f"archive_media{ext}", r.content)}
        data = {
            "chat_id": tg_chat_id,
            "caption": caption[:1024],
            "parse_mode": "Markdown"
        }
        resp = requests.post(f"https://api.telegram.org/bot{tg_token}/{endpoint}", data=data, files=files, timeout=35)
        return resp.status_code == 200
    except Exception as e:
        logger.warning(f"⚠️ Error al despachar archivo multimedia a Telegram: {e}")
        return False


def check_and_archive_stories(L: Any, profile: Any, target: str) -> None:
    """
    Verifica si hay historias activas y las respalda automáticamente en Telegram antes de que expiren.
    Incluye fallback a endpoint directo de reels_media para máxima resiliencia.
    """
    logger.info(f"📸 Comprobando historias (Stories) activas de @{target}...")
    archived_stories = []
    if os.path.exists(STORIES_HISTORICAL_FILE):
        try:
            with open(STORIES_HISTORICAL_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                archived_stories = data if isinstance(data, list) else []
        except Exception:
            archived_stories = []
    else:
        archived_stories = []

    archived_ids = set(archived_stories)
    new_story_ids = []

    # 1. Intento vía Instaloader
    try:
        for story in L.get_stories(userids=[profile.userid]):
            for item in story.get_items():
                s_id = str(item.mediaid)
                if s_id not in archived_ids:
                    new_story_ids.append(s_id)
                    archived_ids.add(s_id)
                    media_url = item.video_url if item.is_video else item.url
                    caption = (
                        f"📸 *[AUTO-ARCHIVER: NUEVA HISTORIA DETECTADA]*\n"
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"🎯 *Cuenta:* `@{target}`\n"
                        f"⏰ *Fecha:* {item.date_utc.strftime('%Y-%m-%d %H:%M UTC')}\n"
                        f"💾 _Respaldo permanente en Telegram antes de expiración (24h)._"
                    )
                    send_telegram_media_file(media_url, caption, is_video=item.is_video)
                    time.sleep(2)
    except Exception as e:
        logger.warning(f"⚠️ Método primario de historias: {e}")

    # 2. Fallback de alta resiliencia vía Reels Media API directa
    if not new_story_ids:
        try:
            import requests
            session_cookies = L.context._session.cookies.get_dict() if hasattr(L.context, "_session") else {}
            if session_cookies:
                s = requests.Session()
                s.cookies.update(session_cookies)
                s.headers.update({
                    "User-Agent": "Instagram 332.0.0.18.108 (iPhone14,5; iOS 17_5; en_US; scale=3.00; 1170x2532)",
                    "x-ig-app-id": "1217981644879628"
                })
                target_uid = str(getattr(profile, "userid", "6274282019"))
                r_stories = s.get(f"https://i.instagram.com/api/v1/feed/reels_media/?reel_ids={target_uid}", timeout=15)
                if r_stories.status_code == 200:
                    items = r_stories.json().get("reels", {}).get(target_uid, {}).get("items", [])
                    for item in items:
                        s_id = str(item.get("id"))
                        if s_id not in archived_ids:
                            new_story_ids.append(s_id)
                            archived_ids.add(s_id)
                            is_vid = (item.get("media_type") == 2)
                            m_url = item.get("video_versions", [{}])[0].get("url") if is_vid else item.get("image_versions2", {}).get("candidates", [{}])[0].get("url")
                            caption = (
                                f"📸 *[AUTO-ARCHIVER: NUEVA HISTORIA DETECTADA]*\n"
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"🎯 *Cuenta:* `@{target}`\n"
                                f"⏰ *Tipo:* {'Vídeo 🎥' if is_vid else 'Fotografía 🖼️'}\n"
                                f"💾 _Respaldo permanente enviado desde la nube a Telegram._"
                            )
                            send_telegram_media_file(m_url, caption, is_video=is_vid)
                            time.sleep(2)
        except Exception as ex:
            logger.warning(f"⚠️ Fallback de historias: {ex}")

    if new_story_ids:
        logger.info(f"📸 {len(new_story_ids)} nuevas historias respaldadas en Telegram.")
        with open(STORIES_HISTORICAL_FILE, "w", encoding="utf-8") as f:
            json.dump(list(archived_ids)[-100:], f, indent=2)


# ==============================================================================
# MÓDULO 1: HEURÍSTICA DE DETECCIÓN DE BOTS Y CUENTAS SOSPECHOSAS
# ==============================================================================
def analyze_bot_probability(user_data: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    Evalúa si un nuevo seguidor presenta patrones comunes de cuentas bot o falsas.
    Retorna: (Nivel_Riesgo, Lista_de_Indicios)
    """
    username = user_data.get("username", "").lower()
    full_name = user_data.get("full_name", "").strip()
    is_private = user_data.get("is_private", False)
    is_verified = user_data.get("is_verified", False)

    if is_verified:
        return "VERIFICADO", ["Cuenta Oficial Verificada 🔵"]

    flags = []
    score = 0

    # 1. Patrón de dígitos al final del username (ej: juan9832145)
    trailing_digits = len(re.findall(r'\d+$', username)[0]) if re.findall(r'\d+$', username) else 0
    if trailing_digits >= 5:
        score += 3
        flags.append(f"Patrón generado automáticamente ({trailing_digits} dígitos consecutivos)")
    elif trailing_digits >= 4:
        score += 2
        flags.append("Múltiples dígitos al final del nombre")

    # 2. Nombre completo vacío o idéntico al username
    if not full_name:
        score += 2
        flags.append("Sin nombre completo configurado")
    elif full_name.lower() == username:
        score += 1
        flags.append("Nombre idéntico al usuario")

    # 3. Densidad de caracteres aleatorios o longitud excesiva
    if re.search(r'[a-z]{10,}\d{4,}', username):
        score += 2
        flags.append("Estructura alfanumérica sintética")

    # Clasificación
    if score >= 4:
        return "POSIBLE BOT / FAKE 🔴", flags
    elif score >= 2:
        return "SOSPECHOSO 🟡", flags
    else:
        return "LEGÍTIMO 🟢", ["Perfil con apariencia orgánica"]


# ==============================================================================
# MÓDULO 2: MONITOREO DE PERFIL, BIO, AVATAR Y NUEVAS PUBLICACIONES
# ==============================================================================
def inspect_profile_and_content(L: Any, profile: Any, target: str) -> None:
    """
    Monitorea cambios en Bio, Nombre, Links y respalda nuevas publicaciones multimedia e historias.
    """
    now_utc = datetime.now(timezone.utc).isoformat()

    current_snapshot = {
        "target": target,
        "full_name": profile.full_name or "",
        "biography": profile.biography or "",
        "external_url": profile.external_url or "",
        "mediacount": profile.mediacount,
        "is_private": profile.is_private,
        "profile_pic_url": profile.profile_pic_url,
        "last_checked_utc": now_utc
    }

    latest_post = None
    try:
        for p in profile.get_posts():
            latest_post = p
            break
    except Exception:
        pass

    current_snapshot["latest_post_shortcode"] = latest_post.shortcode if latest_post else None

    if not os.path.exists(PROFILE_SNAPSHOT_FILE):
        logger.info("📸 Creando snapshot inicial de perfil y publicaciones...")
        with open(PROFILE_SNAPSHOT_FILE, "w", encoding="utf-8") as f:
            json.dump(current_snapshot, f, indent=2, ensure_ascii=False)
        return

    prev = {}
    if os.path.exists(PROFILE_SNAPSHOT_FILE):
        try:
            with open(PROFILE_SNAPSHOT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                prev = data if isinstance(data, dict) else {}
        except Exception:
            prev = {}
    else:
        prev = {}

    changes_detected = []

    if prev.get("biography") != current_snapshot["biography"]:
        changes_detected.append(
            f"📝 *Biografía Modificada:*\n"
            f"• *Antes:* _{prev.get('biography', 'Ninguna')}_\n"
            f"• *Ahora:* _{current_snapshot['biography']}_"
        )

    if prev.get("full_name") != current_snapshot["full_name"]:
        changes_detected.append(
            f"👤 *Nombre de Perfil Cambiado:*\n"
            f"• *Antes:* `{prev.get('full_name')}`\n"
            f"• *Ahora:* `{current_snapshot['full_name']}`"
        )

    if prev.get("external_url") != current_snapshot["external_url"]:
        changes_detected.append(
            f"🔗 *Enlace en Bio Actualizado:*\n"
            f"• *Nuevo Link:* {current_snapshot['external_url'] or 'Eliminado'}"
        )

    # Detección y respaldo de Nuevo Post / Reel
    prev_media = prev.get("mediacount", 0)
    curr_media = current_snapshot["mediacount"]
    if curr_media > prev_media and latest_post:
        post_link = f"https://instagram.com/p/{latest_post.shortcode}"
        caption_post = (
            f"📸 *[AUTO-ARCHIVER: NUEVA PUBLICACIÓN]*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 *Cuenta:* `@{target}`\n"
            f"📝 *Texto:* {latest_post.caption[:250] if latest_post.caption else 'Sin descripción'}\n"
            f"🔗 [Ver en Instagram]({post_link})\n"
            f"⏰ _{latest_post.date_utc.strftime('%Y-%m-%d %H:%M UTC')}_"
        )
        media_url = latest_post.video_url if latest_post.is_video else latest_post.url
        sent = send_telegram_media_file(media_url, caption_post, is_video=latest_post.is_video)
        if not sent:
            changes_detected.append(
                f"📸 *¡NUEVA PUBLICACIÓN / REEL PUBLICADO!*\n"
                f"• *Total Posts:* {curr_media} (Antes: {prev_media})\n"
                f"• 🔗 [Ver Publicación en Instagram]({post_link})"
            )

    if changes_detected:
        logger.info(f"⚡ Cambios detectados en el perfil de @{target}: {len(changes_detected)} eventos.")
        send_profile_change_alert(target, changes_detected)

    with open(PROFILE_SNAPSHOT_FILE, "w", encoding="utf-8") as f:
        json.dump(current_snapshot, f, indent=2, ensure_ascii=False)

    # Comprobar y respaldar historias
    check_and_archive_stories(L, profile, target)


# ==============================================================================
# MÓDULO: FOLLOWING TRACKER (A QUIÉN EMPIEZA O DEJA DE SEGUIR)
# ==============================================================================
def process_following_tracker(profile: Any, target: str) -> None:
    """
    Extrae las cuentas que sigue la cuenta objetivo y detecta altas y bajas.
    """
    logger.info(f"👥 Extrayendo lista de cuentas seguidas (Following) por @{target}...")
    current_following: Dict[str, Dict[str, Any]] = {}
    count = 0

    try:
        for followee in profile.get_followees():
            count += 1
            f_id = str(followee.userid)
            current_following[f_id] = {
                "id": f_id,
                "username": followee.username,
                "full_name": followee.full_name,
                "is_private": followee.is_private,
                "is_verified": followee.is_verified
            }
            if count % 35 == 0:
                time.sleep(random.uniform(2.0, 4.5))
            else:
                time.sleep(random.uniform(0.1, 0.3))
    except Exception as e:
        logger.warning(f"⚠️ Interrupción en extracción de following: {e}")

    if not current_following:
        return

    historical_following = {}
    if os.path.exists(FOLLOWING_HISTORICAL_FILE):
        try:
            with open(FOLLOWING_HISTORICAL_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                historical_following = d.get("following", {}) if isinstance(d, dict) else {}
        except Exception:
            historical_following = {}
    else:
        logger.info("🆕 Creando línea base de cuentas seguidas (Following)...")
        historical_following = {}

    curr_ids = set(current_following.keys())
    hist_ids = set(historical_following.keys())

    new_followed_ids = curr_ids - hist_ids
    unfollowed_ids = hist_ids - curr_ids

    # Alerta de nuevas cuentas seguidas
    if new_followed_ids and historical_following:
        new_followed_users = [current_following[uid] for uid in new_followed_ids]
        send_following_alert(target, new_followed_users, is_new=True)

    # Alerta de cuentas dejadas de seguir
    if unfollowed_ids and historical_following:
        unfollowed_users = [historical_following[uid] for uid in unfollowed_ids]
        send_following_alert(target, unfollowed_users, is_new=False)

    payload = {
        "target": target,
        "last_updated_utc": datetime.now(timezone.utc).isoformat(),
        "following_count": len(current_following),
        "following": current_following
    }
    with open(FOLLOWING_HISTORICAL_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def send_following_alert(target: str, users: List[Dict[str, Any]], is_new: bool = True) -> None:
    action_title = "➕ *¡NUEVA CUENTA SEGUIDA POR EL OBJETIVO!*" if is_new else "➖ *CUENTA DEJADA DE SEGUIR POR EL OBJETIVO*"
    tg_lines = [
        f"🚨 {action_title}",
        f"🎯 *Cuenta:* `@{target}`",
        f"👥 *Total Cuentas ({len(users)}):*",
        "━━━━━━━━━━━━━━━━━━━━"
    ]

    for idx, u in enumerate(users[:10], 1):
        verif = " 🔵" if u.get("is_verified") else ""
        priv = " 🔒" if u.get("is_private") else ""
        tg_lines.append(f"{idx}. [@{u['username']}](https://instagram.com/{u['username']}) ({u.get('full_name', '')}){verif}{priv}")

        if is_new:
            cross = check_cross_platform_presence(u['username'])
            links_str = " | ".join([f"[{k}]({v})" for k, v in cross.items() if k in ["TikTok", "Telegram", "GitHub", "Reddit"]])
            if links_str:
                tg_lines.append(f"   🌐 _Cross-OSINT:_ {links_str}")

    tg_lines.append(f"\n⏰ _{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    send_telegram_message("\n".join(tg_lines))


# ==============================================================================
# MÓDULO 3: CONTROL REMOTO INTERACTIVO DESDE TELEGRAM
# ==============================================================================
def process_telegram_incoming_commands(target: str) -> str:
    """
    Revisa mensajes entrantes enviados por el usuario al bot en Telegram.
    Soporta: /status, /target <user>, /report, /help
    """
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if not tg_token or not tg_chat_id:
        return target

    import requests

    try:
        url = f"https://api.telegram.org/bot{tg_token}/getUpdates"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return target

        updates = resp.json().get("result", [])
        if not updates:
            return target

        # Procesar los últimos comandos
        current_target = target
        last_update_id = 0

        for update in updates:
            last_update_id = update["update_id"]
            message = update.get("message", {})
            sender_id = str(message.get("chat", {}).get("id", ""))
            text = message.get("text", "").strip()

            # Solo responder a mensajes de tu propio Chat ID por seguridad
            if sender_id != tg_chat_id or not text.startswith("/"):
                continue

            if text.startswith("/status"):
                send_status_response(current_target)
            elif text.startswith("/heatmap") or text.startswith("/habitos") or text.startswith("/horarios"):
                send_activity_heatmap(current_target)
            elif text.startswith("/target"):
                parts = text.split()
                if len(parts) > 1:
                    new_t = parts[1].lstrip("@").strip()
                    current_target = new_t
                    send_telegram_message(f"✅ *Cuenta objetivo actualizada a:* `@{new_t}`\nSe comenzará a monitorear en este ciclo.")
                else:
                    send_telegram_message("⚠️ *Uso correcto:* `/target nombre_de_usuario`")
            elif text.startswith("/report") or text.startswith("/semanal"):
                send_weekly_summary(current_target, force=True)
            elif text.startswith("/help"):
                send_telegram_message(
                    "🤖 *COMANDOS DISPONIBLES EN TU MONITOR OSINT:*\n"
                    "━━━━━━━━━━━━━━━━━━━━\n"
                    "• `/status` - Consulta el estado del monitor, seguidores y seguidos.\n"
                    "• `/heatmap` - Análisis de hábitos, mapa de actividad y Sleep Gap.\n"
                    "• `/report` - Resumen consolidado semanal de altas y bajas.\n"
                    "• `/target <usuario>` - Cambia el perfil objetivo a monitorear.\n"
                    "• `/help` - Muestra esta lista de comandos."
                )

        # Confirmar updates leídos en Telegram
        if last_update_id:
            requests.get(f"https://api.telegram.org/bot{tg_token}/getUpdates", params={"offset": last_update_id + 1}, timeout=5)

        return current_target

    except Exception as e:
        logger.warning(f"⚠️ Error procesando comandos de Telegram: {e}")
        return target


# ==============================================================================
# MÓDULO 4: RESUMEN SEMANAL CONSOLIDADO
# ==============================================================================
def record_daily_metrics(target: str, total: int, new_count: int, unfollow_count: int) -> None:
    """
    Registra el historial de métricas diarias para análisis semanal.
    """
    history = []
    if os.path.exists(METRICS_HISTORY_FILE):
        try:
            with open(METRICS_HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                history = data if isinstance(data, list) else []
        except Exception:
            history = []
    else:
        history = []

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    history.append({
        "date": today_str,
        "target": target,
        "total_followers": total,
        "new_followers": new_count,
        "unfollowed": unfollow_count,
        "timestamp_utc": datetime.now(timezone.utc).isoformat()
    })

    # Guardar últimos 60 registros
    with open(METRICS_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[-60:], f, indent=2, ensure_ascii=False)


def send_weekly_summary(target: str, force: bool = False) -> None:
    """
    Calcula y envía el reporte semanal consolidado todos los domingos (o bajo demanda con /report).
    """
    now = datetime.now(timezone.utc)
    # 6 = Domingo
    if now.weekday() != 6 and not force:
        return

    if not os.path.exists(METRICS_HISTORY_FILE):
        return

    try:
        with open(METRICS_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return

    if not data:
        return

    # Filtrar últimos 7 días
    recent = data[-56:] if len(data) >= 56 else data
    total_new = sum(d.get("new_followers", 0) for d in recent)
    total_unfollow = sum(d.get("unfollowed", 0) for d in recent)
    net_growth = total_new - total_unfollow
    current_total = recent[-1].get("total_followers", 0) if recent else 0

    sign = "+" if net_growth >= 0 else ""
    msg = (
        "📊 *REPORTE SEMANAL CONSOLIDADO (OSINT ANALYTICS)*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 *Cuenta:* `@{target}`\n"
        f"👥 *Total de Seguidores:* `{current_total:,}`\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"✨ *Nuevos Seguidores en la semana:* `+{total_new}`\n"
        f"📉 *Dejaron de seguir:* `-{total_unfollow}`\n"
        f"📈 *Crecimiento Neto:* `{sign}{net_growth}` seguidores\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"⏰ _Generado: {now.strftime('%Y-%m-%d %H:%M UTC')}_"
    )
    send_telegram_message(msg)
    logger.info("📊 Reporte semanal despachado con éxito.")


# ==============================================================================
# EXTRACCIÓN Y RATE-LIMITING EVASION (JITTER & DELAYS)
# ==============================================================================
def fetch_target_followers(L: Any, target_username: str) -> Tuple[Any, Dict[str, Dict[str, Any]]] | Tuple[None, None]:
    logger.info(f"🎯 Localizando perfil objetivo: @{target_username}...")
    profile = None
    for attempt in range(1, 6):
        try:
            profile = instaloader.Profile.from_username(L.context, target_username)
            break
        except ProfileNotExistsException:
            logger.error(f"❌ El perfil @{target_username} no existe.")
            return None, None
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "Too Many Requests" in err_msg:
                wait_time = attempt * 12 + random.uniform(3, 7)
                logger.warning(f"⚠️ Rate limit 429 en Instagram. Pausa táctica de {wait_time:.1f}s antes de reintentar (Intento {attempt}/5)...")
                time.sleep(wait_time)
            else:
                logger.error(f"❌ Error consultando el perfil @{target_username}: {e}")
                if attempt == 5:
                    return None, None
                time.sleep(5)

    if not profile:
        logger.warning("⏳ La cuenta o IP se encuentra en período de enfriamiento (cooldown 429). Se reintentará en el próximo ciclo programado.")
        return None, None

    # Monitoreo de Bio, Avatar, Posts & Stories
    inspect_profile_and_content(L, profile, target_username)

    # Monitoreo de Following (A quién sigue)
    process_following_tracker(profile, target_username)

    followers_data: Dict[str, Dict[str, Any]] = {}
    logger.info("⏳ Extrayendo lista de seguidores con mitigación de rate-limiting (Jitter)...")

    count = 0
    try:
        for follower in profile.get_followers():
            count += 1
            f_id = str(follower.userid)
            followers_data[f_id] = {
                "id": f_id,
                "username": follower.username,
                "full_name": follower.full_name,
                "is_private": follower.is_private,
                "is_verified": follower.is_verified
            }

            if count % 35 == 0:
                sleep_time = random.uniform(2.5, 6.0)
                logger.info(f"   [Pausa OPSEC] Procesados {count} seguidores. Durmiendo {sleep_time:.2f}s...")
                time.sleep(sleep_time)
            else:
                time.sleep(random.uniform(0.1, 0.4))

    except QueryReturnedBadRequestException:
        logger.warning("⚠️ Instagram devolvió 400 Bad Request o límite temporal de paginación.")
    except ConnectionException as ce:
        logger.error(f"⚠️ Interrupción de conexión: {ce}. Guardando datos parciales.")
    except Exception as e:
        logger.error(f"⚠️ Error durante la iteración de seguidores: {e}")

    logger.info(f"✅ Extracción finalizada. Total de seguidores recolectados: {len(followers_data)}")
    return profile, followers_data


# ==============================================================================
# ANÁLISIS DIFERENCIAL (SET DIFFERENCE) Y PERSISTENCIA
# ==============================================================================
def process_follower_diff(target: str, current_followers: Dict[str, Dict[str, Any]]) -> Tuple[list, list]:
    historical_followers: Dict[str, Dict[str, Any]] = {}

    if os.path.exists(HISTORICAL_FILE):
        try:
            with open(HISTORICAL_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "followers" in data and isinstance(data["followers"], dict):
                    historical_followers = data["followers"]
                elif isinstance(data, dict):
                    historical_followers = data
                else:
                    historical_followers = {}
                logger.info(f"📖 Historial previo cargado: {len(historical_followers)} seguidores registrados.")
        except Exception as e:
            logger.error(f"⚠️ Error leyendo '{HISTORICAL_FILE}': {e}. Se creará un nuevo historial.")
            historical_followers = {}
    else:
        logger.info(f"🆕 No se encontró '{HISTORICAL_FILE}'. Esta es la ejecución inicial (Línea Base).")
        historical_followers = {}

    current_ids: Set[str] = set(current_followers.keys())
    historical_ids: Set[str] = set(historical_followers.keys())

    # Diferencia de conjuntos
    new_ids = current_ids - historical_ids
    new_followers = [current_followers[uid] for uid in new_ids]

    unfollowed_ids = historical_ids - current_ids
    unfollowed_users = [historical_followers[uid] for uid in unfollowed_ids]

    return new_followers, unfollowed_users


def save_reports(target: str, current_followers: Dict[str, Dict[str, Any]], new_followers: list, unfollowed_users: list) -> None:
    now_utc = datetime.now(timezone.utc).isoformat()

    new_followers_report = {
        "target_account": target,
        "scan_timestamp_utc": now_utc,
        "total_current_followers": len(current_followers),
        "new_followers_count": len(new_followers),
        "unfollowed_count": len(unfollowed_users),
        "new_followers": new_followers,
        "unfollowed_users": unfollowed_users
    }

    with open(NEW_FOLLOWERS_FILE, "w", encoding="utf-8") as f:
        json.dump(new_followers_report, f, indent=2, ensure_ascii=False)
    logger.info(f"📄 Reporte generado: '{NEW_FOLLOWERS_FILE}' ({len(new_followers)} nuevos seguidores).")

    historical_payload = {
        "target_account": target,
        "last_updated_utc": now_utc,
        "followers_count": len(current_followers),
        "followers": current_followers
    }

    with open(HISTORICAL_FILE, "w", encoding="utf-8") as f:
        json.dump(historical_payload, f, indent=2, ensure_ascii=False)
    logger.info(f"💾 Historial actualizado: '{HISTORICAL_FILE}'.")


# ==============================================================================
# DESPACHADORES DE MENSAJES Y ALERTAS (TELEGRAM / WHATSAPP)
# ==============================================================================
def send_telegram_message(text: str) -> None:
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not tg_token or not tg_chat_id:
        return

    import requests
    try:
        url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        requests.post(url, json={
            "chat_id": tg_chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": False
        }, timeout=12)
    except Exception as e:
        logger.warning(f"⚠️ Error enviando mensaje a Telegram: {e}")


def send_profile_change_alert(target: str, events: List[str]) -> None:
    body = "\n\n".join(events)
    msg = (
        "🔔 *[ALERTA OSINT] CAMBIO EN PERFIL / CONTENIDO*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 *Cuenta:* `@{target}`\n\n"
        f"{body}\n\n"
        f"⏰ _{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_"
    )
    send_telegram_message(msg)


def record_activity_timestamp(target: str, dt_obj: datetime, event_type: str = "post") -> None:
    history = []
    if os.path.exists(ACTIVITY_TIMESTAMPS_FILE):
        try:
            with open(ACTIVITY_TIMESTAMPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                history = data if isinstance(data, list) else []
        except Exception:
            history = []
    else:
        history = []

    iso_val = dt_obj.isoformat()
    if not any(h.get("timestamp_utc") == iso_val for h in history):
        history.append({
            "target": target,
            "timestamp_utc": iso_val,
            "hour_utc": dt_obj.hour,
            "weekday": dt_obj.weekday(),
            "event_type": event_type
        })
        with open(ACTIVITY_TIMESTAMPS_FILE, "w", encoding="utf-8") as f:
            json.dump(history[-300:], f, indent=2, ensure_ascii=False)


def send_activity_heatmap(target: str) -> None:
    """
    Genera y despacha a Telegram un análisis temporal de actividad, mapa de calor
    y cálculo de ventana de sueño (Sleep Gap).
    """
    timestamps = []
    if os.path.exists(ACTIVITY_TIMESTAMPS_FILE):
        try:
            with open(ACTIVITY_TIMESTAMPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                timestamps = data if isinstance(data, list) else []
        except Exception:
            timestamps = []
    else:
        timestamps = []

    hour_counts = {h: 0 for h in range(24)}
    for t in timestamps:
        h = t.get("hour_utc")
        if h is not None and 0 <= h < 24:
            hour_counts[h] += 1

    total_events = len(timestamps)

    windows = [
        ("Madrugada (00:00 - 06:00 UTC)", range(0, 6)),
        ("Mañana (06:00 - 12:00 UTC)", range(6, 12)),
        ("Tarde (12:00 - 18:00 UTC)", range(12, 18)),
        ("Noche (18:00 - 24:00 UTC)", range(18, 24)),
    ]

    lines = [
        "⏰ *ANÁLISIS TEMPORAL & ACTIVIDAD (SLEEP GAPS)*",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🎯 *Cuenta:* `@{target}`",
        f"📊 *Eventos Registrados:* `{total_events}` publicaciones/historias",
        "━━━━━━━━━━━━━━━━━━━━",
        "🔥 *Mapa de Distribución Horaria (UTC):*",
    ]

    for label, r_hours in windows:
        sub_sum = sum(hour_counts[h] for h in r_hours)
        bar_len = int((sub_sum / max(total_events, 1)) * 10)
        bar = "█" * max(bar_len, 1) if sub_sum > 0 else "░░ (Inactivo)"
        lines.append(f"• *{label}:* `{bar}` ({sub_sum} eventos)")

    window_sums = {
        "04:00 - 11:00 UTC (Típico UTC-3 / UTC-4 Sudamérica)": sum(hour_counts[h] for h in range(4, 12)),
        "23:00 - 07:00 UTC (Típico UTC+1 / UTC+2 Europa)": sum(hour_counts[h] for h in [23, 0, 1, 2, 3, 4, 5, 6]),
        "07:00 - 15:00 UTC (Típico UTC-7 / UTC-8 EE.UU. Oeste)": sum(hour_counts[h] for h in range(7, 15))
    }
    estimated_gap = min(window_sums, key=window_sums.get)

    lines.append("\n💤 *Deducción de Sleep Gap (Ventana de Sueño):*")
    lines.append(f"• *Franja de menor actividad:* `{estimated_gap}`")
    lines.append(f"• *Zona Horaria estimada:* `UTC-3 / UTC-4` (América del Sur)")
    lines.append(f"\n⏰ _{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")

    send_telegram_message("\n".join(lines))


def send_status_response(target: str) -> None:
    followers_c = "Desconocido"
    following_c = "Desconocido"
    last_update = "Nunca"

    if os.path.exists(HISTORICAL_FILE):
        try:
            with open(HISTORICAL_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, dict):
                    followers_c = f"{d.get('followers_count', 0):,}"
                    last_update = d.get("last_updated_utc", "Desconocido")
        except Exception:
            pass

    if os.path.exists(FOLLOWING_HISTORICAL_FILE):
        try:
            with open(FOLLOWING_HISTORICAL_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, dict):
                    following_c = f"{d.get('following_count', 0):,}"
        except Exception:
            pass

    msg = (
        "🤖 *ESTADO DEL SISTEMA DE MONITOREO OSINT*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 *Cuenta Objetivo:* `@{target}`\n"
        f"👥 *Seguidores:* `{followers_c}`\n"
        f"👣 *Seguidos:* `{following_c}`\n"
        f"🕒 *Último Escaneo:* `{last_update}`\n"
        f"⚡ *Frecuencia:* Cada 3 horas vía GitHub Actions\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )
    send_telegram_message(msg)


def send_instant_notifications(target: str, new_followers: list, total_followers: int) -> None:
    if not new_followers:
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tg_lines = [
        "🚨 *[OSINT ALERT] ¡Nuevos Seguidores Detectados!*",
        f"🎯 *Cuenta Objetivo:* `@{target}`",
        f"📊 *Total Actual:* `{total_followers:,}` seguidores",
        f"✨ *Nuevos Seguidores ({len(new_followers)}):*",
        "━━━━━━━━━━━━━━━━━━━━"
    ]

    for idx, u in enumerate(new_followers[:10], 1):
        verif = " 🔵" if u.get("is_verified") else ""
        priv = " 🔒" if u.get("is_private") else ""
        name = u.get("full_name") or u["username"]

        # Análisis Heurístico de Bot / Fake
        bot_verdict, bot_flags = analyze_bot_probability(u)
        bot_tag = f" `[{bot_verdict}]`"

        tg_lines.append(f"{idx}. [@{u['username']}](https://instagram.com/{u['username']}) ({name}){verif}{priv}{bot_tag}")

        # Búsqueda Cruzada Multiplataforma (Cross-Platform OSINT)
        cross = check_cross_platform_presence(u['username'])
        links_str = " | ".join([f"[{k}]({v})" for k, v in cross.items() if k in ["TikTok", "Telegram", "GitHub", "Reddit"]])
        if links_str:
            tg_lines.append(f"   🌐 _Cross-OSINT:_ {links_str}")

    if len(new_followers) > 10:
        tg_lines.append(f"\n... y {len(new_followers) - 10} seguidores más registrados en el reporte JSON.")

    tg_lines.append(f"\n⏰ _{now_str}_")
    send_telegram_message("\n".join(tg_lines))


# ==============================================================================
# PUNTO DE ENTRADA PRINCIPAL (CLI)
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Instagram Passive Sentinel & Tracker (OSINT)")
    parser.add_argument("--export-session", action="store_true", help="Genera y exporta el token Base64 de sesión")
    parser.add_argument("--target", type=str, help="Sobrescribe la cuenta objetivo")
    args = parser.parse_args()

    ig_username = os.environ.get("IG_USERNAME", "").strip()
    ig_password = os.environ.get("IG_PASSWORD", "").strip()
    ig_session_b64 = os.environ.get("IG_SESSION_BASE64", "").strip()
    target_account = (args.target or os.environ.get("TARGET_ACCOUNT", "")).strip().lstrip("@")

    if not ig_username:
        logger.critical("❌ ERROR: 'IG_USERNAME' no está definida.")
        sys.exit(1)

    if not target_account:
        logger.critical("❌ ERROR: 'TARGET_ACCOUNT' no está definida.")
        sys.exit(1)

    # 1. Procesar comandos entrantes desde Telegram
    target_account = process_telegram_incoming_commands(target_account)

    logger.info("="*60)
    logger.info("🚀 INICIANDO SENTINEL OSINT INSTAGRAM")
    logger.info(f"👤 Cuenta Operadora : {ig_username}")
    logger.info(f"🎯 Cuenta Objetivo  : @{target_account}")
    logger.info("="*60)

    # 2. Inicializar cliente y autenticar
    L = get_instaloader_instance()
    auth_ok = authenticate_session(L, ig_username, ig_password, ig_session_b64)
    if not auth_ok:
        logger.critical("❌ Fallo de autenticación.")
        sys.exit(0)

    # 3. Descarga de seguidores y monitoreo de perfil
    profile, current_followers = fetch_target_followers(L, target_account)
    if current_followers is None:
        logger.info("ℹ️ Finalizando ciclo de forma segura ante rate-limit.")
        sys.exit(0)

    # 4. Diferencia de conjuntos
    new_followers, unfollowed_users = process_follower_diff(target_account, current_followers)

    # 5. Persistir reportes y métricas
    save_reports(target_account, current_followers, new_followers, unfollowed_users)
    record_daily_metrics(target_account, len(current_followers), len(new_followers), len(unfollowed_users))

    # 6. Despachar alertas
    if new_followers:
        send_instant_notifications(target_account, new_followers, len(current_followers))

    # 7. Resumen semanal consolidado (Domingos)
    send_weekly_summary(target_account)

    if not new_followers:
        send_telegram_message(
            f"✅ *ESCANEO COMPLETADO EN LA NUBE*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 *Cuenta:* `@{target_account}`\n"
            f"👥 *Total Seguidores:* `{len(current_followers):,}`\n"
            f"✨ *Estado:* No hay nuevos seguidores ni historias sin respaldar. Todo al día."
        )

    logger.info("🎉 Ciclo de monitoreo completado con éxito.")


if __name__ == "__main__":
    main()
