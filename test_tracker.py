#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test unitario y de integración offline para tracker.py
Simula dos ejecuciones consecutivas para validar:
1. Creación de la línea base (seguidores_historicos.json).
2. Detección de nuevos seguidores y unfollowers vía set-difference.
3. Formato y timestamps de nuevos_seguidores.json.
"""

import sys
import json
import os
from pathlib import Path

# Configurar stdout para evitar errores de codificación en consolas Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from tracker import process_follower_diff, save_reports, HISTORICAL_FILE, NEW_FOLLOWERS_FILE

def test_full_pipeline():
    try:
        print("[1/4] Limpiando archivos previos de prueba...")
        if HISTORICAL_FILE.exists():
            HISTORICAL_FILE.unlink()
        if NEW_FOLLOWERS_FILE.exists():
            NEW_FOLLOWERS_FILE.unlink()

        target = "cuenta_prueba_osint"

        # --- SIMULACIÓN 1: PRIMER ESCANEO (LÍNEA BASE) ---
        print("\n[2/4] Ejecutando SIMULACIÓN 1: Primer escaneo (Línea base)...")
        mock_scan_1 = {
            "1001": {"id": "1001", "username": "usuario_antiguo_1", "full_name": "Ana Perez", "is_private": False, "is_verified": False},
            "1002": {"id": "1002", "username": "usuario_antiguo_2", "full_name": "Carlos Gomez", "is_private": True, "is_verified": False},
            "1003": {"id": "1003", "username": "usuario_antiguo_3", "full_name": "Tech Brand", "is_private": False, "is_verified": True},
        }

        new_1, unfollow_1 = process_follower_diff(target, mock_scan_1)
        save_reports(target, mock_scan_1, new_1, unfollow_1)

        assert len(new_1) == 3, f"Esperados 3 nuevos en escaneo inicial, obtenidos: {len(new_1)}"
        assert len(unfollow_1) == 0, f"Esperados 0 unfollowers, obtenidos: {len(unfollow_1)}"
        assert HISTORICAL_FILE.exists(), "No se generó seguidores_historicos.json"
        assert NEW_FOLLOWERS_FILE.exists(), "No se generó nuevos_seguidores.json"
        print(" -> OK: Línea base creada exitosamente.")

        # --- SIMULACIÓN 2: SEGUNDO ESCANEO (NUEVOS SEGUIDORES + UNFOLLOW) ---
        print("\n[3/4] Ejecutando SIMULACIÓN 2: Detección diferencial...")
        # '1002' dejó de seguir, y entran '1004' y '1005'
        mock_scan_2 = {
            "1001": {"id": "1001", "username": "usuario_antiguo_1", "full_name": "Ana Perez", "is_private": False, "is_verified": False},
            "1003": {"id": "1003", "username": "usuario_antiguo_3", "full_name": "Tech Brand", "is_private": False, "is_verified": True},
            "1004": {"id": "1004", "username": "nuevo_follower_x", "full_name": "Laura Sol", "is_private": False, "is_verified": False},
            "1005": {"id": "1005", "username": "nuevo_follower_y", "full_name": "Marcos Diaz", "is_private": True, "is_verified": True},
        }

        new_2, unfollow_2 = process_follower_diff(target, mock_scan_2)
        save_reports(target, mock_scan_2, new_2, unfollow_2)

        assert len(new_2) == 2, f"Esperados 2 nuevos seguidores, obtenidos: {len(new_2)}"
        assert len(unfollow_2) == 1, f"Esperado 1 unfollower, obtenido: {len(unfollow_2)}"
        
        new_usernames = {u["username"] for u in new_2}
        assert new_usernames == {"nuevo_follower_x", "nuevo_follower_y"}
        assert unfollow_2[0]["username"] == "usuario_antiguo_2"
        print(" -> OK: Diferencia de conjuntos validada (2 nuevos detectados, 1 unfollower).")

        # --- VERIFICACIÓN DEL REPORTE FINAL ---
        print("\n[4/4] Validando estructura de nuevos_seguidores.json...")
        with open(NEW_FOLLOWERS_FILE, "r", encoding="utf-8") as f:
            report = json.load(f)
        
        print(json.dumps(report, indent=2, ensure_ascii=False))
        assert report["new_followers_count"] == 2
        assert "scan_timestamp_utc" in report
        
        print("\n>>> TODOS LOS TESTS PASARON EXITOSAMENTE <<<")
    finally:
        print("\n[Limpieza] Eliminando archivos temporales de prueba para dejar el repo limpio...")
        if HISTORICAL_FILE.exists():
            HISTORICAL_FILE.unlink()
        if NEW_FOLLOWERS_FILE.exists():
            NEW_FOLLOWERS_FILE.unlink()

if __name__ == "__main__":
    test_full_pipeline()
