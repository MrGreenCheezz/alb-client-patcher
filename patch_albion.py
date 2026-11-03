#!/usr/bin/env python3
"""Albion Online client patcher (dynamic locator).

This patcher does not hardcode client addresses. It locates patch sites from
stable invariants:
  - IL2CPP global-metadata.dat string literals -> encoded string-ref slots in
    GameAssembly.dll .data -> rip-relative references in executable code.
  - server redirect: rewrite only rip-relative content-mov disp32 values that
    load the six built-in login/status string objects, pointing them at the
    in-client "127.0.0.1:5055" string object.
  - anti-cheat startup: locate the BattlEye Init-like function by a wildcarded
    x64 instruction signature and NOP its single direct E8 call site.
  - optional safety patch: jump over the "BattlEye init failed" message load.
"""

import argparse
import bisect
import hashlib
import re
import struct
import sys
from pathlib import Path
from collections import defaultdict

EXIT_OK = 0
EXIT_ERROR = 1

DEFAULT_DEV_STRING = "127.0.0.1:5055"
DEFAULT_SERVER_STRINGS = (
    "loginserver.live.albion.zone:5055",
    "live02-loginserver.sg.albion.zone:5055",
    "live03-loginserver.ams.albion.zone:5055",
    "live01-win-status.dc02.albion.zone:5055",
    "live03-win-status.ams.albion.zone:5055",
    "live02-win-status.sg.albion.zone:5055",
)
DEFAULT_BE_ANCHOR = "InitAntiCheat()"
DEFAULT_BE_FAIL_STRING = "Unable to call Init() for BattlEye"
INSURANCE_REL32 = 0x7B
INSURANCE_TARGET_PREFIX = b"\x48\x8b\x7c\x24\x38"

BE_INIT_SIG = re.compile(
    rb"\x40\x53\x48\x83\xec\x20"
    rb"\x80\x3d....\x00"
    rb"\x48\x8b\xda\x75\x13"
    rb"\x48\x8d\x0d...."
    rb"\xe8...."
    rb"\xc6\x05....\x01"
    rb"\x48\x8b\x0d...."
    rb"\x83\xb9\xe4\x00\x00\x00\x00\x75\x05"
    rb"\xe8....\x33\xc9"
    rb"\xe8....\x84\xc0\x75\x24"
    rb"\x48\x8b\x0d...."
    rb"\x83\xb9\xe4\x00\x00\x00\x00\x75\x05"
    rb"\xe8....\x33\xd2\x48\x8b\xcb"
    rb"\x48\x83\xc4\x20\x5b"
    rb"\xe9...."
    rb"\x48\x83\xc4\x20\x5b\xc3",
    re.DOTALL,
)


class PatcherError(Exception):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, block=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(block)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class Metadata:
    """v27+ IL2CPP global-metadata string-literal decoder.

    The decoder follows LibCpp2IL 2022.1.x for Unity 2022/2023 metadata.
    Albion 1.32.x tested here uses version 39.
    """

    MAGIC = 0xFAB11BAF

    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 24:
            raise PatcherError("metadata file is too small")
        magic, version = struct.unpack_from("<Ii", self.data, 0)
        if magic != self.MAGIC:
            raise PatcherError("bad metadata magic: expected %08x, got %08x"
                               % (self.MAGIC, magic))
        self.version = version
        if version < 27:
            raise PatcherError("metadata version %d is not supported (need v27+)"
                               % version)
        self.string_lit_off, self.string_lit_size = struct.unpack_from("<ii", self.data, 8)
        self.string_data_off, self.string_data_size = struct.unpack_from("<ii", self.data, 20)
        if self.string_lit_size <= 0:
            raise PatcherError("empty string literal table")
        self.record_size = 4 if version >= 35 else 8
        self.count = self.string_lit_size // self.record_size
        starts = []
        for i in range(self.count):
            off = self.string_lit_off + i * self.record_size
            if version >= 35:
                data_index = struct.unpack_from("<i", self.data, off)[0]
            else:
                data_index = struct.unpack_from("<i", self.data, off + 4)[0]
            starts.append(self.string_data_off + data_index)
        self._starts = starts
        self._ends = [starts[i + 1] for i in range(self.count - 1)] + [self.string_data_off + self.string_data_size]
        self._index_cache = {}

    def literal(self, i):
        return self.data[self._starts[i]:self._ends[i]].decode("utf-8", "replace")

    def string_indices(self, text):
        if text not in self._index_cache:
            hits = []
            encoded = text.encode("utf-8")
            for i in range(self.count):
                if self._starts[i] < len(self.data) and self._ends[i] <= len(self.data):
                    if self.data[self._starts[i]:self._ends[i]] == encoded:
                        hits.append(i)
            self._index_cache[text] = hits
        return self._index_cache[text]

    def unique_index(self, text):
        hits = self.string_indices(text)
        if len(hits) != 1:
            raise PatcherError("metadata string %r: expected exactly 1 literal index, got %d"
                               % (text, len(hits)))
        return hits[0]

    def x_candidates(self, idx):
        base = 0xA0000000
        if self.version >= 27:
            shifted = idx << 1
            return [base | shifted | 1, base | shifted]
        return [base | idx]


class PE:
    def __init__(self, data):
        self.d = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        self.base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
        off = pe + 24 + opt_size
        self.secs = []
        for i in range(nsec):
            end = off + 40 * i
            name = data[end:end + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rawsz, raw = struct.unpack_from("<IIII", data, end + 8)
            chars = struct.unpack_from("<I", data, end + 36)[0]
            self.secs.append(dict(name=name, vaddr=vaddr, vsize=vsize,
                                  raw=raw, rawsz=rawsz, chars=chars,
                                  va=self.base + vaddr))
        self.exec_secs = [s for s in self.secs if s["chars"] & 0x20000000 and s["rawsz"]]
        self.data_secs = [s for s in self.secs if not (s["chars"] & 0x20000000) and s["vsize"]]
        self.functions = self._pdata_functions()
        self._starts = [f[0] for f in self.functions]
        self._func_map = {f[0]: tuple(f) for f in self.functions}

    def sec_of(self, va):
        for s in self.secs:
            if s["va"] <= va < s["va"] + max(s["vsize"], s["rawsz"]):
                return s
        return None

    def foff(self, va):
        s = self.sec_of(va)
        if s is None:
            return None
        d = va - s["va"]
        if d >= s["rawsz"]:
            return None
        return s["raw"] + d

    def read_va(self, va, n):
        o = self.foff(va)
        if o is None:
            return None
        return self.d[o:o + n]

    def sec_bytes(self, s):
        vsize = max(s["vsize"], 0)
        rawsz = min(s["rawsz"], len(self.d) - s["raw"]) if s["raw"] + s["rawsz"] <= len(self.d) else 0
        avail = self.d[s["raw"]:s["raw"] + rawsz]
        if len(avail) >= vsize:
            return avail[:vsize]
        return avail + b"\x00" * (vsize - len(avail))

    def _pdata_functions(self):
        out = []
        for s in self.secs:
            if s["name"] != ".pdata" or not s["rawsz"]:
                continue
            d = self.sec_bytes(s)
            for i in range(0, len(d) - 11, 12):
                b, e = struct.unpack_from("<II", d, i)
                if 0 < b < e:
                    out.append((self.base + b, self.base + e))
        out.sort()
        ded = []
        for b, e in out:
            if ded and b < ded[-1][1]:
                if e > ded[-1][1]:
                    ded[-1][1] = e
                continue
            ded.append([b, e])
        return [(b, e) for b, e in ded]

    def func_of(self, va):
        i = bisect.bisect_right(self._starts, va) - 1
        if i >= 0 and va < self.functions[i][1]:
            return tuple(self.functions[i])
        return None

    def func_by_start(self, va):
        return self._func_map.get(va)

    def next_after(self, va):
        i = bisect.bisect_left(self._starts, va)
        if i < len(self._starts) and self._starts[i] == va and i + 1 < len(self._starts):
            return tuple(self.functions[i + 1])
        return None


def data_sections(pe, primary_only=True):
    primary = [s for s in pe.data_secs if s["name"].startswith(".data")]
    if primary_only:
        return primary
    return primary or pe.data_secs


def scan_values(pe, values, sections):
    wanted = set(values)
    out = defaultdict(set)
    for s in sections:
        raw = pe.sec_bytes(s)
        for i in range(0, max(0, len(raw) - 7), 4):
            lo = struct.unpack_from("<I", raw, i)[0]
            hi = struct.unpack_from("<I", raw, i + 4)[0]
            if hi == 0 and lo in wanted:
                out[lo].add(s["va"] + i)
    return out


def find_slots_for_strings(pe, md, strings, strict=True):
    x_to_string = {}
    for s in strings:
        if strict:
            idxs = [md.unique_index(s)]
        else:
            idxs = md.string_indices(s)
            if len(idxs) != 1:
                if strict:
                    raise PatcherError("string %r has %d indices" % (s, len(idxs)))
                continue
        for x in md.x_candidates(idxs[0]):
            x_to_string.setdefault(x, set()).add(s)
    if not x_to_string:
        return {}
    res = defaultdict(set)
    for primary_only in (True, False):
        vals = scan_values(pe, x_to_string.keys(), data_sections(pe, primary_only=primary_only))
        for x, labels in x_to_string.items():
            for va in vals.get(x, ()):
                for label in labels:
                    res[label].add(va)
        if all(len(res.get(s, ())) == 1 for s in strings):
            break
        if primary_only:
            for k in list(res.keys()):
                if len(res[k]) != 1:
                    del res[k]
    return res


def scan_rip_sites(pe, wanted_slots, opcodes):
    wanted = set(wanted_slots)
    out = defaultdict(set)
    if not wanted:
        return out
    for s in pe.exec_secs:
        raw = pe.sec_bytes(s)
        base_va = s["va"]
        for opc in opcodes:
            for rex in (0x48, 0x4C):
                pat = bytes([rex, opc])
                start = 0
                while True:
                    i = raw.find(pat, start)
                    if i < 0:
                        break
                    start = i + 2
                    if i + 6 >= len(raw):
                        continue
                    modrm = raw[i + 2]
                    if modrm & 0xC7 != 0x05:
                        continue
                    disp = struct.unpack_from("<i", raw, i + 3)[0]
                    site_va = base_va + i
                    target = (site_va + 7 + disp) & 0xFFFFFFFFFFFFFFFF
                    if target in wanted:
                        out[target].add(site_va)
    return out


def find_be_init_target(pe, quiet=False):
    matches = set()
    for s in pe.exec_secs:
        raw = pe.sec_bytes(s)
        base_va = s["va"]
        for m in BE_INIT_SIG.finditer(raw):
            va = base_va + m.start()
            f = pe.func_of(va)
            if f and f[0] == va:
                matches.add(va)
    if len(matches) != 1:
        raise PatcherError("BattlEye Init signature matched %d function starts: %s"
                           % (len(matches), ", ".join(hex(x) for x in sorted(matches))))
    target = next(iter(matches))
    if not quiet:
        print("BE Init-like target: 0x%x" % target)
    return target


def scan_e8_to_target(pe, target):
    sites = set()
    needle = b"\xe8"
    for s in pe.exec_secs:
        raw = pe.sec_bytes(s)
        base_va = s["va"]
        start = 0
        while True:
            i = raw.find(needle, start)
            if i < 0:
                break
            start = i + 1
            if i + 5 > len(raw):
                continue
            disp = struct.unpack_from("<i", raw, i + 1)[0]
            t = (base_va + i + 5 + disp) & 0xFFFFFFFFFFFFFFFF
            if t == target:
                sites.add(base_va + i)
    return sorted(sites)


def find_anchor_functions(pe, md, anchor_string, quiet=False):
    slots = find_slots_for_strings(pe, md, [anchor_string], strict=False)
    slot_list = sorted(slots.get(anchor_string, ()))
    if len(slot_list) != 1:
        if not quiet:
            print("BE anchor %r: %d slots (ignored)" % (anchor_string, len(slot_list)))
        return []
    refs = scan_rip_sites(pe, slot_list, (0x8B, 0x8D))
    funcs = set()
    for sites in refs.values():
        for va in sites:
            f = pe.func_of(va)
            if f:
                funcs.add(f[0])
    if not quiet:
        print("BE anchor %r: %d host function(s): %s"
              % (anchor_string, len(funcs), ", ".join(hex(x) for x in sorted(funcs))))
    return sorted(funcs)


def locate_be(pe, md, anchor_string, quiet=False):
    target = find_be_init_target(pe, quiet=quiet)
    inbound = scan_e8_to_target(pe, target)
    if len(inbound) == 1:
        site = inbound[0]
        raw = pe.read_va(site, 5)
        already = raw == b"\x90" * 5
        return {"target": target, "site": site, "already": already, "ambiguous": False}
    if len(inbound) == 0:
        anchors = find_anchor_functions(pe, md, anchor_string, quiet=quiet)
        if anchors:
            nxt = pe.next_after(anchors[0])
            if nxt and not quiet:
                print("BE call site already removed; no direct E8 inbound to 0x%x" % target)
        return {"target": target, "site": None, "already": True, "ambiguous": False}
    anchors = find_anchor_functions(pe, md, anchor_string, quiet=quiet)
    if len(anchors) == 1:
        nxt = pe.next_after(anchors[0])
        if nxt:
            inside = [s for s in inbound if nxt[0] <= s < nxt[1]]
            if len(inside) == 1:
                site = inside[0]
                raw = pe.read_va(site, 5)
                already = raw == b"\x90" * 5
                return {"target": target, "site": site, "already": already, "ambiguous": False}
    raise PatcherError("BE target 0x%x has %d inbound E8 calls; cannot pick a unique call site"
                       % (target, len(inbound)))


def locate_insurance(pe, md, fail_string, quiet=False):
    slots = find_slots_for_strings(pe, md, [fail_string], strict=False)
    slot_list = sorted(slots.get(fail_string, ()))
    if len(slot_list) != 1:
        return {"status": "skipped", "reason": "fail string has %d slots" % len(slot_list)}
    slot = slot_list[0]
    mov_sites = scan_rip_sites(pe, [slot], (0x8B,))
    lea_sites = scan_rip_sites(pe, [slot], (0x8D,))
    ms = sorted(mov_sites.get(slot, ()))
    ls = sorted(lea_sites.get(slot, ()))
    if len(ms) == 1:
        site = ms[0]
        f = pe.func_of(site)
        if f is None:
            return {"status": "skipped", "reason": "site not inside a .pdata function"}
        target = (site + 5 + INSURANCE_REL32) & 0xFFFFFFFFFFFFFFFF
        target_bytes = pe.read_va(target, len(INSURANCE_TARGET_PREFIX))
        if target_bytes != INSURANCE_TARGET_PREFIX:
            return {"status": "skipped", "reason": "target bytes at 0x%x are %s"
                    % (target, target_bytes.hex() if target_bytes else "None")}
        raw = pe.read_va(site, 3)
        already = pe.read_va(site, 5) == struct.pack("<Bi", 0xE9, INSURANCE_REL32)
        if already:
            return {"status": "already", "site": site, "target": target}
        if raw[:2] not in (b"\x48\x8b", b"\x4c\x8b"):
            return {"status": "skipped", "reason": "unexpected site bytes %s" % (pe.read_va(site, 7).hex(),)}
        return {"status": "patch", "site": site, "target": target, "func": f}
    if len(ms) == 0 and len(ls) >= 1:
        return {"status": "already", "site": ls[0], "target": None}
    return {"status": "skipped", "reason": "fail string xref pattern: mov=%d lea=%d" % (len(ms), len(ls))}


def analyze_server(pe, md, server_strings, dev_string, quiet=False):
    all_strings = list(server_strings) + [dev_string]
    slots = find_slots_for_strings(pe, md, all_strings, strict=True)
    for s in all_strings:
        if len(slots.get(s, ())) != 1:
            raise PatcherError("string %r matched %d slots; expected exactly 1"
                               % (s, len(slots.get(s, ()))))
    slot_of = {s: next(iter(slots[s])) for s in all_strings}
    dev = slot_of[dev_string]
    all_slots = set(slot_of.values())
    mov_sites = scan_rip_sites(pe, all_slots, (0x8B,))
    lea_sites = scan_rip_sites(pe, all_slots, (0x8D,))
    if not quiet:
        print("String slots found:")
        for s in all_strings:
            print("  0x%012x  %s" % (slot_of[s], s))
    patch_sites = []
    unpatched_count = 0
    already_count = 0
    for s in server_strings:
        slot = slot_of[s]
        ms = sorted(mov_sites.get(slot, ()))
        ls = sorted(lea_sites.get(slot, ()))
        if len(ms) == 1:
            patch_sites.append((ms[0], slot, s))
            unpatched_count += 1
        elif len(ms) == 0 and len(ls) >= 1:
            already_count += 1
        else:
            raise PatcherError("server string %r has %d content-mov refs and %d lea refs; expected 1+0 or 0+1"
                               % (s, len(ms), len(ls)))
    dev_movs = sorted(mov_sites.get(dev, ()))
    dev_leas = sorted(lea_sites.get(dev, ()))
    if unpatched_count == 0 and already_count == len(server_strings):
        if len(dev_movs) >= len(server_strings) + 3:
            status = "already"
        else:
            raise PatcherError("server strings look already-patched, but dev string has only %d content-mov refs"
                               % len(dev_movs))
    elif unpatched_count == len(server_strings):
        status = "patch"
    else:
        raise PatcherError("mixed server patch state: %d unpatched, %d already"
                           % (unpatched_count, already_count))
    patches = []
    if status == "patch":
        for site, slot, s in sorted(patch_sites):
            disp = struct.unpack_from("<i", pe.d, pe.foff(site) + 3)[0]
            current_target = (site + 7 + disp) & 0xFFFFFFFFFFFFFFFF
            new_disp = dev - (site + 7)
            if not (-0x80000000 <= new_disp <= 0x7FFFFFFF):
                raise PatcherError("disp32 for %r at 0x%x does not fit: 0x%x"
                                   % (s, site, new_disp & 0xFFFFFFFF))
            patches.append({"site": site, "role": s, "old_slot": slot,
                            "current_target": current_target, "new_disp": new_disp})
    if not quiet:
        print("Server patch state: %s (dev content-mov refs: %d at %s)"
              % (status, len(dev_movs), ", ".join(hex(x) for x in dev_movs[:12])))
        for p in patches:
            print("  site 0x%012x role=%-36s disp 0x%08x -> 0x%08x"
                  % (p["site"], p["role"], p["current_target"], p["new_disp"]))
        if status == "already":
            print("  all six server content-mov refs already point to the dev slot")
    return {"status": status, "patches": patches, "slots": slot_of,
            "dev": dev, "dev_movs": dev_movs, "dev_leas": dev_leas}


def apply_patches(pe, server_result, be_result, insurance_result, args):
    out = bytearray(pe.d)
    changes = []
    already = True

    if server_result["status"] == "patch":
        already = False
        for p in server_result["patches"]:
            disp_at = pe.foff(p["site"]) + 3
            old = out[disp_at:disp_at + 4]
            new = struct.pack("<i", p["new_disp"])
            out[disp_at:disp_at + 4] = new
            changes.append("server disp32 site=0x%x role=%s old=%s new=%s"
                           % (p["site"], p["role"], old.hex(), new.hex()))
    if not args.no_be and be_result:
        if not be_result["already"]:
            already = False
            site = be_result["site"]
            at = pe.foff(site)
            old = out[at:at + 5]
            out[at:at + 5] = b"\x90" * 5
            changes.append("BE call NOP site=0x%x target=0x%x old=%s new=9090909090"
                           % (site, be_result["target"], old.hex()))
        elif be_result["site"] is None:
            pass
        else:
            changes.append("BE call already NOP site=0x%x target=0x%x"
                           % (be_result["site"], be_result["target"]))
    if not args.no_insurance and insurance_result:
        if insurance_result["status"] == "patch":
            already = False
            site = insurance_result["site"]
            at = pe.foff(site)
            old = out[at:at + 5]
            new = struct.pack("<Bi", 0xE9, INSURANCE_REL32)
            out[at:at + 5] = new
            changes.append("insurance jmp site=0x%x target=0x%x old=%s new=%s"
                           % (site, insurance_result["target"], old.hex(), new.hex()))
        elif insurance_result["status"] == "already":
            changes.append("insurance already patched site=0x%x" % insurance_result["site"])
        elif insurance_result["status"] == "skipped":
            already = False
            print("Warning: optional insurance skipped: %s" % insurance_result["reason"])
    return out, changes, already


def patch_file(args):
    dll_path = Path(args.dll)
    md_path = Path(args.metadata)
    out_path = Path(args.output)
    if not dll_path.is_file():
        raise PatcherError("DLL not found: %s" % dll_path)
    if not md_path.is_file():
        raise PatcherError("metadata not found: %s" % md_path)
    print("Input DLL: %s" % dll_path)
    print("Metadata:  %s" % md_path)
    dll = dll_path.read_bytes()
    pe = PE(dll)
    print("PE: base 0x%x, %d sections, %d .pdata functions, %d exec bytes"
          % (pe.base, len(pe.secs), len(pe.functions), sum(s["rawsz"] for s in pe.exec_secs)))
    md = Metadata(md_path)
    print("Metadata: version %d, %d string literals, record_size %d"
          % (md.version, md.count, md.record_size))

    server_strings = args.server_string if args.server_string else list(DEFAULT_SERVER_STRINGS)
    server_result = analyze_server(pe, md, server_strings, args.dev_string, quiet=args.quiet)
    be_result = None
    if not args.no_be:
        be_result = locate_be(pe, md, args.be_anchor, quiet=args.quiet)
        if args.quiet:
            print("BE target=0x%x site=%s already=%s"
                  % (be_result["target"], hex(be_result["site"]) if be_result["site"] else "already",
                     be_result["already"]))
    insurance_result = None
    if not args.no_insurance:
        insurance_result = locate_insurance(pe, md, args.be_fail_string, quiet=args.quiet)
        if args.quiet:
            print("Insurance: %s %s"
                  % (insurance_result["status"],
                     ("site=0x%x target=%s"
                      % (insurance_result["site"], hex(insurance_result.get("target") or 0))
                      if insurance_result.get("site") else "")))

    out_bytes, changes, already = apply_patches(pe, server_result, be_result, insurance_result, args)
    if len(out_bytes) != len(dll):
        raise PatcherError("internal error: output size changed %d -> %d"
                           % (len(dll), len(out_bytes)))
    print("Changes: %d" % len(changes))
    for c in changes:
        print("  %s" % c)
    status = "already patched" if already and not any(ch.startswith("insurance skipped") for ch in changes) else "patched"
    if args.dry_run:
        print("Dry run: no file written. Planned output: %s" % out_path)
        print("Planned sha256: %s" % sha256_bytes(bytes(out_bytes)))
        return EXIT_OK, status
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(out_bytes))
    print("Wrote: %s" % out_path)
    print("Output sha256: %s" % sha256_file(out_path))
    return EXIT_OK, status


def main(argv=None):
    ap = argparse.ArgumentParser(description="Albion Online client patcher (dynamic, stdlib-only)")
    root = Path(__file__).resolve().parents[1]
    default_dll = root / "game" / "GameAssembly.dll"
    default_md = root / "game" / "Albion-Online_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    ap.add_argument("--dll", default=str(default_dll), help="GameAssembly.dll to patch")
    ap.add_argument("--metadata", default=str(default_md), help="global-metadata.dat for the same client build")
    ap.add_argument("--output", default=None, help="output DLL (default: input DLL path with .new appended)")
    ap.add_argument("--dev-string", default=DEFAULT_DEV_STRING, help="built-in replacement string")
    ap.add_argument("--server-string", action="append", default=[], help="original server string to redirect; repeatable")
    ap.add_argument("--be-anchor", default=DEFAULT_BE_ANCHOR, help="anti-cheat anchor string")
    ap.add_argument("--be-fail-string", default=DEFAULT_BE_FAIL_STRING, help="optional insurance anchor string")
    ap.add_argument("--no-be", action="store_true", help="do not patch BattlEye startup")
    ap.add_argument("--no-insurance", action="store_true", help="do not apply optional BattlEye message insurance")
    ap.add_argument("--dry-run", action="store_true", help="locate and report patches, do not write output")
    ap.add_argument("--quiet", action="store_true", help="print short reports only")
    args = ap.parse_args(argv)
    if args.output is None:
        args.output = str(Path(args.dll).with_name(Path(args.dll).name + ".new"))
    try:
        rc, status = patch_file(args)
        print("STATUS: %s" % status)
        return rc
    except PatcherError as e:
        print("ERROR: %s" % e)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
