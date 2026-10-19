"""Тесты патчера. Запуск: python -I tests/test_patcher.py (из папки patcher/ или любой другой).

Покрывает: совпадение результата с эталонной сборкой, идемпотентность, промежуточное состояние
(только группа login_addr), отказ на чужих байтах, режим --check-only, запрет патчить на месте,
--copy-to с бэкапом и целостность самого манифеста (его sha256-ожидания = реальным файлам).
"""
import filecmp
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHER = os.path.join(os.path.dirname(HERE), "patch_albion.py")
ROOT = os.path.dirname(os.path.dirname(HERE))
ORIG = os.path.join(ROOT, "game", "GameAssembly.dll")
REF = os.path.join(ROOT, "work", "GameAssembly.dll")
MANIFEST = os.path.join(os.path.dirname(HERE), "manifest.json")
TMP = os.path.join(HERE, "tmp")

fails = []


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def run(*args):
    p = subprocess.run([sys.executable, "-I", PATCHER] + list(args), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + detail))
    if not cond:
        fails.append(name)


def main():
    if os.path.isdir(TMP):
        shutil.rmtree(TMP)
    os.makedirs(TMP)
    import json
    man = json.load(open(MANIFEST, encoding="utf-8"))

    check("манифест: заявленные sha256 соответствуют реальным файлам",
          man["build"]["sha256_original"] == sha(ORIG) and man["build"]["sha256_patched"] == sha(REF),
          "%s / %s" % (sha(ORIG), sha(REF)))

    out1 = os.path.join(TMP, "full", "GameAssembly.dll")
    rc, so, se = run(ORIG, "-o", out1, "--cmp-with", REF)
    check("полный патч оригинала: код 0", rc == 0, se or so)
    check("полный патч оригинала: результат побитово = эталон work/GameAssembly.dll",
          os.path.isfile(out1) and filecmp.cmp(out1, REF, shallow=False), out1)
    check("полный патч оригинала: sha256 выхода назван эталоном в выводе",
          "sha256 выхода = эталон манифеста" in so and sha(REF) in so, so[-400:])
    check("полный патч оригинала: отчёт записан",
          os.path.isfile(os.path.join(TMP, "full", "patch_report.txt")))

    out2 = os.path.join(TMP, "again", "GameAssembly.dll")
    rc, so, se = run(REF, "-o", out2)
    check("идемпотентность: код 0 на уже пропатченном", rc == 0, se or so)
    check("идемпотентность: все 8 сайтов помечены 'уже пропатчено'",
          so.count("УЖЕ ПРОПАТЧЕНО") == 8, str(so.count("УЖЕ ПРОПАТЧЕНО")))
    check("идемпотентность: выход побитово = вход", os.path.isfile(out2) and filecmp.cmp(out2, REF, shallow=False))
    check("идемпотентность: изменённых байт 0", "0 байт)" in so.split("ИТОГ")[1][:120], so.split("ИТОГ")[1][:200])

    out3 = os.path.join(TMP, "login_only", "GameAssembly.dll")
    rc, so, se = run(ORIG, "-o", out3, "--group", "login_addr")
    check("промежуточное состояние: только группа login_addr (6 сайтов)", rc == 0 and so.count("ПРИМЕНЕНО") == 6,
          se or so[-300:])
    check("промежуточное состояние: BE-байты ещё не тронуты",
          open(out3, "rb").read()[0x19077ed:0x19077f2] == bytes.fromhex("e8befa06ff"))
    out3b = os.path.join(TMP, "login_then_be", "GameAssembly.dll")
    rc, so, se = run(out3, "-o", out3b, "--cmp-with", REF)
    check("промежуточное состояние: добивка BE-группой даёт эталон", rc == 0 and filecmp.cmp(out3b, REF, shallow=False),
          se or so[-300:])
    check("промежуточное состояние: login-сайты во втором прогоне помечены 'уже пропатчено'",
          so.count("УЖЕ ПРОПАТЧЕНО") == 6, str(so.count("УЖЕ ПРОПАТЧЕНО")))

    bad = os.path.join(TMP, "bad", "GameAssembly.dll")
    os.makedirs(os.path.dirname(bad))
    shutil.copy2(ORIG, bad)
    with open(bad, "r+b") as f:
        f.seek(0xb277df + 1)
        f.write(bytes([f.read(1)[0] ^ 0xFF]))
    out4 = os.path.join(TMP, "bad_out", "GameAssembly.dll")
    rc, so, se = run(bad, "-o", out4)
    check("чужие байты: остановка с кодом 2", rc == 2, "rc=%d" % rc)
    check("чужие байты: назван адрес сайта и ожидаемые байты",
          "0x180b291df" in (so + se) and "488b0dd20a" in (so + se), (so + se)[-400:])
    check("чужие байты: выходной файл не создан", not os.path.exists(out4))

    out5 = os.path.join(TMP, "chk", "GameAssembly.dll")
    rc, so, se = run(ORIG, "-o", out5, "--check-only")
    check("--check-only: код 0 и ничего не записано",
          rc == 0 and not os.path.exists(out5) and os.path.isfile(os.path.join(TMP, "chk", "patch_report.txt")),
          se or so[-300:])
    check("--check-only: все 8 сайтов помечены 'будет изменено'", so.count("БУДЕТ ИЗМЕНЕНО") == 8,
          str(so.count("БУДЕТ ИЗМЕНЕНО")))

    rc, so, se = run(ORIG, "-o", ORIG)
    check("патч на месте запрещён (код 3, объяснение)", rc == 3 and "совпадает со входным" in (so + se), "rc=%d" % rc)

    client = os.path.join(TMP, "client")
    os.makedirs(client)
    shutil.copy2(ORIG, os.path.join(client, "GameAssembly.dll"))
    out6 = os.path.join(TMP, "cp", "GameAssembly.dll")
    rc, so, se = run(ORIG, "-o", out6, "--copy-to", client)
    baks = [n for n in os.listdir(client) if n.startswith("GameAssembly.dll.bak-")]
    check("--copy-to: код 0, файл клиента стал эталонным",
          rc == 0 and filecmp.cmp(os.path.join(client, "GameAssembly.dll"), REF, shallow=False), se or so[-300:])
    check("--copy-to: старый файл сохранён в бэкап", len(baks) == 1 and sha(ORIG) == sha(os.path.join(client, baks[0])),
          str(baks))

    rc, so, se = run(REF, "-o", os.path.join(TMP, "mismatch", "GameAssembly.dll"))
    check("вход = эталон пропатченного: помечено и результат тот же",
          rc == 0 and "уже с правками" in so and filecmp.cmp(os.path.join(TMP, "mismatch", "GameAssembly.dll"), REF, shallow=False),
          se or so[-300:])

    out7 = os.path.join(TMP, "strict", "GameAssembly.dll")
    rc, so, se = run(bad, "-o", out7, "--strict-sha")
    check("--strict-sha: сборка не опознана -> остановка (код 2), файл не записан",
          rc == 2 and "--strict-sha" in (so + se) and not os.path.exists(out7), "rc=%d" % rc)

    print("")
    print("%s (%d)" % ("ВСЕ ТЕСТЫ ПРОЙДЕНЫ" if not fails else "ЕСТЬ ПРОВАЛЫ: " + ", ".join(fails), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
