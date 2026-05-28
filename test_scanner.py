#!/usr/bin/env python3
"""
Tests básicos para JGScan
Ejecutar con: python test_scanner.py
"""

import sys
import unittest
sys.path.insert(0, ".")

from scanner import parsear_puertos, validar_objetivo, SERVICE_DB, RIESGO_ORDEN

class TestParsearPuertos(unittest.TestCase):
    def test_puerto_unico(self):
        self.assertEqual(parsear_puertos("80"), [80])

    def test_varios_puertos(self):
        self.assertEqual(parsear_puertos("22,80,443"), [22, 80, 443])

    def test_rango(self):
        self.assertEqual(parsear_puertos("20-22"), [20, 21, 22])

    def test_combinado(self):
        result = parsear_puertos("22,80,100-102")
        self.assertEqual(result, [22, 80, 100, 101, 102])

    def test_sin_duplicados(self):
        result = parsear_puertos("80,80,80")
        self.assertEqual(result, [80])

class TestServiceDB(unittest.TestCase):
    def test_puertos_criticos_catalogados(self):
        criticos = [p for p, info in SERVICE_DB.items() if info["riesgo"] == "CRÍTICO"]
        self.assertIn(445, criticos, "SMB debería ser CRÍTICO")
        self.assertIn(23,  criticos, "Telnet debería ser CRÍTICO")

    def test_todos_tienen_campos(self):
        for puerto, info in SERVICE_DB.items():
            self.assertIn("name",   info, f"Puerto {puerto} sin nombre")
            self.assertIn("riesgo", info, f"Puerto {puerto} sin riesgo")
            self.assertIn("nota",   info, f"Puerto {puerto} sin nota")

    def test_riesgo_valores_validos(self):
        validos = set(RIESGO_ORDEN.keys())
        for puerto, info in SERVICE_DB.items():
            self.assertIn(info["riesgo"], validos,
                f"Puerto {puerto} tiene riesgo inválido: {info['riesgo']}")

class TestValidarObjetivo(unittest.TestCase):
    def test_ip_valida(self):
        self.assertEqual(validar_objetivo("127.0.0.1"), "127.0.0.1")

    def test_hostname_local(self):
        result = validar_objetivo("localhost")
        self.assertEqual(result, "127.0.0.1")

if __name__ == "__main__":
    print("Ejecutando tests de JGScan...\n")
    unittest.main(verbosity=2)
