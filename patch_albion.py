"""Прозрачный патчер клиента Albion Online для локального сервера.

Вход  : оригинальный GameAssembly.dll сборки 1.32.030.345319.
Выход : его копия с правками из manifest.json (только байты из манифеста, ничего больше).
Исходный файл не меняется никогда: пишется отдельный выходной файл.

Все правки живут в manifest.json: адрес (VA), байты ДО и ПОСЛЕ, смысл и доказательство.
Код ниже их не придумывает, а только: находит смещение в файле по таблице секций PE,
сверяет каждый сайт байт-в-байт (плюс куда реально ссылается инструкция), применяет,
и пишет отчёт с полным списком изменений.

Команды:
  python patch_albion.py --list                 показать, что и как меняет патч
  python patch_albion.py                        патчить ../game/GameAssembly.dll -> out/
  python patch_albion.py <вход.dll> -o <выход.dll>
  python patch_albion.py -o <выход.dll> --copy-to <папка клиента>   (бэкап + копия)
  python patch_albion.py --check-only           только сверка, ничего не пишет
  python patch_albion.py --group battleye       только одна группа правок

Код возврата: 0 = успех, 2 = файл не подошёл (не совпали байты/сборка), 3 = ошибка ввода-вывода.
"""
import argparse
import filecmp
import hashlib
import json
import os
import shutil
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_IN = os.path.join(ROOT, "game", "GameAssembly.dll")
DEFAULT_OUT = os.path.join(HERE, "out", "GameAssembly.dll")
DEFAULT_MANIFEST = os.path.join(HERE, "manifest.json")
NAME, VER = "patch_albion", "1.0"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def s32(b):
    return struct.unpack("<i", b)[0]


def fmt_disp(d):
    return ("+%#x" % d) if d >= 0 else ("-%#x" % -d)


class Image:
    """Минимальный читатель PE: таблица секций + переход VA -> смещение в файле."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.d = bytearray(f.read())
        d = self.d
        if d[:2] != b"MZ":
            raise ValueError("нет сигнатуры MZ - это не PE-файл")
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise ValueError("нет сигнатуры PE")
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        sizeofopt = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic != 0x20B:
            raise ValueError("ожидается PE32+ (64 бит), magic=%#x" % magic)
        self.image_base = struct.unpack_from("<Q", d, opt + 0x18)[0]
        sec = opt + sizeofopt
        self.secs = []
        for i in range(nsec):
            name = d[sec + 40 * i: sec + 40 * i + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", d, sec + 40 * i + 8)
            self.secs.append((name, va, vsize, rawsize, raw))

    def sec_of(self, va):
        rva = va - self.image_base
        for name, sva, vsize, rawsize, raw in self.secs:
            if sva <= rva < sva + max(vsize, rawsize):
                return name, raw + rva - sva
        raise ValueError("адрес %#x вне секций (image base %#x)" % (va, self.image_base))

    def off(self, va):
        return self.sec_of(va)[1]

    def qword(self, va):
        return struct.unpack_from("<Q", self.d, self.off(va))[0]


class Stop(Exception):
    pass


def hexs(b):
    return b.hex()


def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def verify_site(img, data, site, apply):
    """Сверяет семантику сайта и возвращает (status, строки пояснений).

    status: 'ok' (нужные байты на месте, патчить не надо), 'apply' (оригинал, применить),
            'would' (оригинал, но запись не делается).
    """
    va = int(site["va"], 16)
    before = bytes.fromhex(site["before"])
    after = bytes.fromhex(site["after"])
    if len(before) != len(after):
        raise Stop("манифест: before/after разной длины на %#x" % va)
    name, off = img.sec_of(va)
    cur = bytes(data[off: off + len(before)])
    v = site.get("verify") or {}
    info = []

    if "asm" in v:
        want_op = bytes.fromhex(v["opcode_at_minus3"])
        got_op = bytes(data[off - 3: off])
        if got_op != want_op:
            raise Stop("%#x: по %#x байты %s, ожидалось %s (%s) - другой билд клиента?"
                       % (va, va - 3, hexs(got_op), hexs(want_op), v["asm"]))
        info.append("затронута инструкция %s (по %#x), меняется только её смещение" % (v["asm"], va - 3))
    if "call_target" in v:
        if cur[0] != 0xE8 and cur != after:
            raise Stop("%#x: это не call (первый байт %#02x)" % (va, cur[0]))
        if cur[0] == 0xE8:
            t = va + 5 + s32(cur[1:5])
            want = int(v["call_target"], 16)
            if t != want:
                raise Stop("%#x: call ведёт в %#x, ожидалось %#x" % (va, t, want))
            info.append("call ведёт в %#x (= ci7.bo) -> будет выключен пятью nop" % t)
    if "jmp_target" in v:
        t = va + 5 + s32(after[1:5])
        if t != int(v["jmp_target"], 16):
            raise Stop("манифест: after даёт jmp в %#x, а заявлено %#x" % (t, v["jmp_target"]))
        info.append("после правки: jmp в %#x" % t)
    if "old_target" in v or "new_target" in v:
        old_t = int(v["old_target"], 16) if "old_target" in v else None
        new_t = int(v["new_target"], 16) if "new_target" in v else None
        if new_t is not None:
            want_disp = struct.pack("<i", new_t - (va + 4))
            if hexs(after[len(after) - 4:]) != hexs(want_disp):
                raise Stop("манифест: after не соответствует new_target %#x" % new_t)
        if cur == before and old_t is not None:
            t = va + 4 + s32(cur[len(cur) - 4:])
            if t != old_t:
                raise Stop("%#x: загрузка ведёт в %#x, ожидалось %#x" % (va, t, old_t))
            info.append("было: слот строки %#x" % t)
        if cur == after and new_t is not None:
            t = va + 4 + s32(cur[len(cur) - 4:])
            if t != new_t:
                raise Stop("%#x: загрузка ведёт в %#x, ожидалось %#x" % (va, t, new_t))
            info.append("сейчас: слот строки %#x" % t)
        if cur == before and new_t is not None:
            info.append("станет: слот строки %#x" % new_t)

    if cur == after:
        return "ok", name, off, info
    if cur == before:
        if not apply:
            return "would", name, off, info
        data[off: off + len(before)] = after
        return "apply", name, off, info
    raise Stop("%#x: байты %s, ожидалось %s (оригинал) или %s (уже пропатчено) - другой билд клиента?"
               % (va, hexs(cur), hexs(before), hexs(after)))


def main():
    ap = argparse.ArgumentParser(description="Прозрачный патчер клиента Albion Online (см. README.md)")
    ap.add_argument("inp", nargs="?", default=DEFAULT_IN, help="входной GameAssembly.dll (по умолчанию ../game/)")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT, help="куда записать патченый файл")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST, help="манифест правок (по умолчанию рядом со скриптом)")
    ap.add_argument("--report", default=None, help="файл отчёта (по умолчанию рядом с выходным файлом)")
    ap.add_argument("--group", action="append", default=None, help="применить только группу (id, можно несколько раз)")
    ap.add_argument("--check-only", action="store_true", help="только сверка: ничего не писать")
    ap.add_argument("--list", action="store_true", help="показать содержимое манифеста и выйти")
    ap.add_argument("--copy-to", default=None, help="после патча скопировать результат в папку клиента (старый файл -> .bak-<sha8>-<время>)")
    ap.add_argument("--cmp-with", default=None, help="после записи побитово сравнить результат с этим файлом (эталон)")
    ap.add_argument("--strict-sha", action="store_true", help="останавливаться, если sha256 входа не равен ожидаемому для этой сборки (по умолчанию только предупреждение)")
    args = ap.parse_args()

    rep = []

    def say(line=""):
        rep.append(line)
        print(line)

    try:
        man = load_manifest(args.manifest)
    except OSError as e:
        print("не прочитать манифест:", e, file=sys.stderr)
        return 3
    build = man["build"]

    if args.list:
        say("Патчер клиента Albion Online %s - правки из манифеста:" % VER)
        say("сборка: %s" % build["name"])
        say("входной (оригинальный) sha256 : %s" % build["sha256_original"])
        say("эталон пропатченного sha256   : %s" % build["sha256_patched"])
        for c in man.get("checks", []):
            say("проверка предпосылки: слот %s должен содержать %#x - %s" % (c["va"], int(c["expect_u64"], 16), c["note"]))
        for g in man["groups"]:
            say("")
            say("группа %-12s %s" % (g["id"], g["title"]))
            say("  метод: %s" % g["method"])
            say("  как:   %s" % g["how"])
            say("  чем доказано: %s" % g["evidence"])
            for s in g["sites"]:
                say("    %-14s %s -> %s   %s" % (s["va"], s["before"], s["after"], s["note"]))
        return 0

    src, dst = args.inp, args.out
    if os.path.normcase(os.path.abspath(src)) == os.path.normcase(os.path.abspath(dst)):
        print("выходной файл совпадает со входным - на месте не патчим (режим --in-place не предусмотрен)", file=sys.stderr)
        return 3
    if not os.path.isfile(src):
        print("нет входного файла:", src, file=sys.stderr)
        return 3

    try:
        img = Image(src)
    except (OSError, ValueError) as e:
        print("не разобрать PE-заголовки %s: %s" % (src, e), file=sys.stderr)
        return 2

    data = bytearray(img.d)
    src_sha = sha256_file(src)
    ref_patched = build["sha256_patched"]

    say("=== Патч клиента Albion Online (локальная версия) ===")
    say("инструмент : %s %s (python %s, только стандартная библиотека)" % (NAME, VER, sys.version.split()[0]))
    say("манифест   : %s" % os.path.abspath(args.manifest))
    say("вход       : %s" % os.path.abspath(src))
    say("sha256 входа: %s" % src_sha)
    say("сборка по манифесту: %s (image base %#x)" % (build["name"], img.image_base))

    if img.image_base != int(build["image_base"], 16):
        say("ОСТАНОВКА: image base %#x, в манифесте %s" % (img.image_base, build["image_base"]))
        return 2
    want_sha = build["sha256_original"]
    if src_sha == want_sha:
        say("sha256 совпал с оригинальной сборкой из манифеста - билд опознан")
    elif src_sha == ref_patched:
        say("sha256 = эталон пропатченного: файлы уже с правками, дальше — сверка каждого сайта по байтам")
    else:
        msg = ("sha256 входа не равен ожидаемому для оригинальной сборки (%s).\n"
               "  Сверка каждого сайта по байтам всё равно будет: если это тот же билд (пересобранный\n"
               "  или уже с частью правок) - патч применим; если билд другой - остановка на первом\n"
               "  несовпадении байтов. Строгая сверка сборки: --strict-sha." % want_sha)
        say("ВНИМАНИЕ: %s" % msg)
    if args.strict_sha and src_sha != want_sha:
        say("ОСТАНОВКА (--strict-sha): нужен оригинальный файл сборки, заявленной в манифесте.")
        return 2

    problems = []
    for c in man.get("checks", []):
        va = int(c["va"], 16)
        want = int(c["expect_u64"], 16)
        try:
            got = img.qword(va)
        except ValueError as e:
            problems.append(str(e))
            continue
        if got != want:
            problems.append("слот %s = %#x, ожидалось %#x - %s" % (c["va"], got, want, c["note"]))
        else:
            say("проверка предпосылки: слот %s = %#x - OK" % (c["va"], got))
    if problems:
        say("ОСТАНОВКА: проверка предпосылок не прошла:")
        for p in problems:
            say("  " + p)
        return 2

    selected = [g for g in man["groups"] if not args.group or g["id"] in args.group]
    if not selected:
        print("группа не найдена; доступны:", ", ".join(g["id"] for g in man["groups"]), file=sys.stderr)
        return 3

    apply = not args.check_only
    counts = {"apply": 0, "ok": 0, "would": 0}
    changed_bytes = would_bytes = 0
    say("")
    for g in selected:
        say("--- группа %s: %s" % (g["id"], g["title"]))
        say("    метод: %s" % g["method"])
        say("    как:   %s" % g["how"])
        say("    чем доказано: %s" % g["evidence"])
        for s in g["sites"]:
            site_after = bytes.fromhex(s["after"])
            try:
                st, sec, off, info = verify_site(img, data, s, apply)
            except Stop as e:
                say("ОСТАНОВКА: %s" % e)
                return 2
            counts[st] += 1
            n = len(site_after)
            if st == "apply":
                changed_bytes += n
            elif st == "would":
                would_bytes += n
            tag = {"apply": "ПРИМЕНЕНО", "ok": "УЖЕ ПРОПАТЧЕНО", "would": "БУДЕТ ИЗМЕНЕНО"}[st]
            say("    [%-*s] %s  (секция %s, смещение в файле %#x, %d байт)"
                % (14, tag, s["va"], sec, off, n))
            say("        %s -> %s" % (s["before"], s["after"]))
            say("        %s" % s["note"])
            for line in info:
                say("        [проверено] %s" % line)

    out_sha = hashlib.sha256(bytes(data)).hexdigest()
    say("")
    say("ИТОГ: применено %d сайта (%d байт), уже пропатчено %d, будет изменено %d сайта (%d байт)"
        % (counts["apply"], changed_bytes, counts["ok"], counts["would"], would_bytes))
    say("sha256 выхода: %s" % out_sha)
    if not apply:
        say("режим --check-only: файл не записан")
    elif out_sha == ref_patched:
        say("sha256 выхода = эталон манифеста (%s) - патч даёт ровно ту сборку, что проверялась в игре" % ref_patched)
    else:
        say("ВНИМАНИЕ: sha256 выхода != эталон манифеста %s" % ref_patched)

    report_path = args.report or os.path.join(os.path.dirname(os.path.abspath(dst)), "patch_report.txt")
    rdir = os.path.dirname(os.path.abspath(report_path))
    if rdir:
        os.makedirs(rdir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(rep) + "\n")
    print("отчёт записан: %s" % os.path.abspath(report_path))

    if apply:
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        print("патченый файл записан: %s" % os.path.abspath(dst))
        if args.cmp_with:
            if not os.path.isfile(args.cmp_with):
                print("нет файла для сравнения:", args.cmp_with, file=sys.stderr)
                return 3
            same = filecmp.cmp(dst, args.cmp_with, shallow=False)
            print("побитовое сравнение с %s: %s" % (os.path.abspath(args.cmp_with),
                                                   "идентичен" if same else "ЕСТЬ ОТЛИЧИЯ"))
            if not same:
                return 2
        if args.copy_to:
            tgt_dir = args.copy_to
            if not os.path.isdir(tgt_dir):
                print("нет папки клиента:", tgt_dir, file=sys.stderr)
                return 3
            tgt = os.path.join(tgt_dir, os.path.basename(dst))
            if os.path.exists(tgt):
                bak = "%s.bak-%s-%s" % (tgt, sha256_file(tgt)[:8], time.strftime("%Y%m%d-%H%M%S"))
                shutil.move(tgt, bak)
                print("старый файл сохранён: %s" % bak)
            shutil.copy2(dst, tgt)
            print("скопировано в клиента: %s" % tgt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
