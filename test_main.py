"""
Несколько проверок на две главные функции: уровень угрозы и определение класса.

Запуск:  python test_main.py     (или python -m unittest test_main)

Тесты не ходят в сеть: данные берутся из data/raw, а классификатор проверяется
на крошечном ручном индексе.
"""
import unittest

import main


class ThreatLevelTest(unittest.TestCase):
    def test_бэкдор_это_high(self):
        self.assertEqual(main.threat_level(["Backdoor"], [], 20), "HIGH")

    def test_загрузчик_это_medium(self):
        self.assertEqual(main.threat_level(["Trojan-Dropper"], [], 20), "MEDIUM")

    def test_реклама_это_low(self):
        self.assertEqual(main.threat_level(["Adware"], [], 3), "LOW")

    def test_берём_самый_опасный_класс_из_списка(self):
        self.assertEqual(main.threat_level(["Trojan", "Backdoor"], [], 20), "HIGH")

    def test_связь_с_apt_поднимает_на_ступень(self):
        self.assertEqual(main.threat_level(["Adware"], [], 3), "LOW")
        self.assertEqual(main.threat_level(["Adware"], ["APT28"], 3), "MEDIUM")

    def test_класс_не_определён(self):
        self.assertEqual(main.threat_level([], [], 0), "LOW")
        self.assertEqual(main.threat_level([], [], 15), "MEDIUM")


class ClassifyTest(unittest.TestCase):
    """Проверяем порядок источников: ETDA, потом название, потом вердикт VT."""

    etda = {
        "quasarrat": {"name": "QuasarRAT", "types": ["backdoor", "keylogger"], "groups": ["APT 32"]},
    }

    def test_класс_из_etda(self):
        sample = {"signature": "QuasarRAT"}
        classes, _, groups, source = main.classify(sample, {"found": False}, self.etda)
        self.assertEqual(classes, ["Backdoor", "Trojan-Spy"])
        self.assertEqual(groups, ["APT 32"])
        self.assertEqual(source, "etda")

    def test_класс_по_хвосту_названия(self):
        sample = {"signature": "RustyStealer"}
        classes, _, _, source = main.classify(sample, {"found": False}, self.etda)
        self.assertEqual(classes, ["Trojan-PSW"])
        self.assertEqual(source, "heuristic")

    def test_класс_по_вердикту_virustotal(self):
        sample = {"signature": None}
        vt = {"found": True, "categories": ["ransomware"], "names": ["noon"]}
        classes, _, _, source = main.classify(sample, vt, self.etda)
        self.assertEqual(classes, ["Trojan-Ransom"])
        self.assertEqual(source, "vt")

    def test_ничего_не_нашлось(self):
        sample = {"signature": None}
        classes, _, _, source = main.classify(sample, {"found": False}, self.etda)
        self.assertEqual(classes, [])
        self.assertEqual(source, "none")


if __name__ == "__main__":
    unittest.main()
