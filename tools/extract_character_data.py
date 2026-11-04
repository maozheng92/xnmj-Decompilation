#!/usr/bin/env python3
"""Extract character/hero tables from 少女迷境 (xnmj) APK / Data.awb / AllConfig.bytes.

AllConfig.bytes is a packed binary of 526 Config.*SettingLO sheets produced by
the game's HybridCLR hot-update assembly (GameBase.dll). Each sheet is:

    7-bit length of the sheet blob
    category directory (usually one unnamed default category)
    7-bit row count
    rows: 7-bit unused prefix + fields in alphabetical order

Strings are .NET BinaryReader.ReadString (7-bit length + UTF-8).
Integers are 7-bit encoded. JSON blobs are stored as strings.

Data.awb is a custom archive: TEA-ECB encrypted index, plaintext payloads.
TEA key is ASCII "0123456789ABFFFF" interpreted as four little-endian uint32s.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterable

DELTA = 0x9E3779B9
TEA_KEY = (0x33323130, 0x37363534, 0x42413938, 0x46464646)  # "0123456789ABFFFF"
SHEET_LIST = Path(__file__).with_name("allconfig_sheets.txt")

DAMAGE_TYPE = {
    0: "unknown",
    1: "physical",
    2: "magic",
    3: "true",
}


class BinaryReader:
    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos
        self.n = len(data)

    def u8(self) -> int:
        if self.p >= self.n:
            raise EOFError(f"u8 at {self.p}/{self.n}")
        v = self.d[self.p]
        self.p += 1
        return v

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def f32(self) -> float:
        v = struct.unpack_from("<f", self.d, self.p)[0]
        self.p += 4
        return v

    def boolean(self) -> bool:
        return self.u8() != 0

    def v7(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            if b < 0x80:
                return result
            shift += 7
            if shift > 35:
                raise ValueError("7-bit int overflow")

    def string(self) -> str:
        n = self.v7()
        if n < 0 or self.p + n > self.n:
            raise ValueError(f"bad string length {n} at {self.p}")
        raw = self.d[self.p : self.p + n]
        self.p += n
        return raw.decode("utf-8")

    def strings(self) -> list[str]:
        n = self.v7()
        return [] if n == 0 else [self.string() for _ in range(n)]

    def ints(self) -> list[int]:
        n = self.v7()
        return [] if n == 0 else [self.v7() for _ in range(n)]

    def floats(self) -> list[float]:
        n = self.v7()
        return [] if n == 0 else [self.f32() for _ in range(n)]

    def vector2(self) -> list[float]:
        s = self.string()
        if not s:
            return [0.0, 0.0]
        parts = s.split("_")
        return [float(parts[0]), float(parts[1]) if len(parts) > 1 else 0.0]


def maybe_json(value: str) -> Any:
    if not value:
        return value
    s = value.strip()
    if s[:1] in "{[":
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return value
    return value


def tea_decrypt_ecb(buf: bytearray) -> None:
    k0, k1, k2, k3 = TEA_KEY
    for i in range(0, len(buf) - (len(buf) % 8), 8):
        y, z = struct.unpack_from("<II", buf, i)
        total = (DELTA * 32) & 0xFFFFFFFF
        for _ in range(32):
            z = (z - (((y << 4) + k2) ^ (y + total) ^ ((y >> 5) + k3))) & 0xFFFFFFFF
            y = (y - (((z << 4) + k0) ^ (z + total) ^ ((z >> 5) + k1))) & 0xFFFFFFFF
            total = (total - DELTA) & 0xFFFFFFFF
        struct.pack_into("<II", buf, i, y, z)


def parse_awb_index(awb: bytes) -> tuple[int, list[tuple[str, int, int]]]:
    """Return (data_offset, [(name, rel_offset, size), ...])."""
    head = bytearray(awb[:8])
    tea_decrypt_ecb(head)
    data_offset, count = struct.unpack_from("<II", head, 0)
    enc_len = (data_offset + 7) & ~7
    index = bytearray(awb[:enc_len])
    tea_decrypt_ecb(index)
    br = BinaryReader(bytes(index), 8)
    files = []
    for _ in range(count):
        name = br.string()
        rel = br.i32()
        size = br.v7()
        files.append((name, rel, size))
    return data_offset, files


def extract_awb_file(awb: bytes, data_offset: int, rel: int, size: int) -> bytes:
    start = data_offset + rel
    return awb[start : start + size]


def load_awb_from_apk(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read("assets/Data.awb")


def sheet_names() -> list[str]:
    return [ln.strip() for ln in SHEET_LIST.read_text(encoding="utf-8").splitlines() if ln.strip()]


def walk_sheets(data: bytes, names: list[str]) -> dict[str, int]:
    br = BinaryReader(data)
    intern_end = br.i32()
    size = br.i32()
    if size != len(data):
        raise ValueError(f"AllConfig size mismatch header={size} file={len(data)}")
    br.p = intern_end
    starts: dict[str, int] = {}
    for name in names:
        blob_size = br.v7()
        pos = br.p
        cat_n = br.v7()
        default_off = -1
        acc = 0
        for _ in range(cat_n):
            cname = br.string()
            sz = br.v7()
            if not cname:
                default_off = acc
            acc += sz
        starts[name] = br.p + (default_off if default_off != -1 else 0)
        br.p = pos + blob_size
    if br.p != len(data):
        raise ValueError(f"sheet walk ended at {br.p}, expected {len(data)}")
    return starts


def parse_intern_pool(data: bytes) -> list[str]:
    intern_end = struct.unpack_from("<I", data, 0)[0]
    br = BinaryReader(data, 8)
    n = br.v7()
    out = []
    for _ in range(n):
        if br.p >= intern_end:
            break
        out.append(br.string())
    return out


def parse_sheet(data: bytes, start: int, row_fn: Callable[[BinaryReader], dict]) -> list[dict]:
    br = BinaryReader(data, start)
    n = br.v7()
    rows = []
    for i in range(n):
        br.v7()  # MoveSheetOffset: unused per-row prefix
        try:
            rows.append(row_fn(br))
        except Exception as exc:
            raise RuntimeError(f"row {i}/{n} at {br.p}: {exc}") from exc
    return rows


def eff_path(br: BinaryReader) -> dict | None:
    if not br.boolean():
        return None
    return {
        "hold": br.boolean(),
        "isY": br.boolean(),
        "node": br.string(),
        "path": br.string(),
        "rotate": br.v7(),
        "scale": br.v7(),
    }


def eff_paths(br: BinaryReader) -> list[dict]:
    n = br.v7()
    if n == 0:
        return []
    out = []
    for _ in range(n):
        item = eff_path(br)
        if item is not None:
            out.append(item)
    return out


def parse_hero(br: BinaryReader) -> dict:
    return {
        "angerPlaySkills": maybe_json(br.string()),
        "attributes": maybe_json(br.string()),
        "bgColor": br.v7(),
        "bgName": br.string(),
        "camps": br.ints(),
        "damageType": br.v7(),
        "dropEffect": br.string(),
        "enName": br.string(),
        "enNameShort": br.string(),
        "fragmentAmount": br.v7(),
        "fragmentId": br.v7(),
        "hide": br.boolean(),
        "id": br.v7(),
        "initPosition": br.strings(),
        "initQuality": br.v7(),
        "initStar": br.v7(),
        "introduce": br.string(),
        "isCore": br.boolean(),
        "itemIcon": br.string(),
        "jobs": br.ints(),
        "name": br.string(),
        "newHide": br.boolean(),
        "normalPlaySkills": maybe_json(br.string()),
        "npcId": br.v7(),
        "pilgrimagePrayLottery": br.boolean(),
        "roleComponent": br.string(),
        "roleComponentPos": br.floats(),
        "roleComponentScale": br.f32(),
        "roleSkinId": br.v7(),
        "sortId": br.v7(),
        "trait": br.string(),
        "traitBg": br.v7(),
        "voice": br.string(),
        "dialogue": br.string(),
    }


def parse_camp(br: BinaryReader) -> dict:
    return {
        "attribute": br.string(),
        "clientRead": br.boolean(),
        "color": br.string(),
        "factionIcon": br.string(),
        "fetterPlaySkills": maybe_json(br.string()),
        "fighterFetterPlaySkills": maybe_json(br.string()),
        "id": br.v7(),
        "name": br.string(),
        "skillDescription": br.strings(),
    }


def parse_job(br: BinaryReader) -> dict:
    return {
        "attribute": br.string(),
        "fetterPlaySkills": maybe_json(br.string()),
        "fighterFetterPlaySkills": maybe_json(br.string()),
        "id": br.v7(),
        "jobIcon": br.string(),
        "name": br.string(),
        "skillDescription": br.strings(),
    }


def parse_quality(br: BinaryReader) -> dict:
    return {
        "iconBackground": br.string(),
        "id": br.v7(),
        "includeStars": br.ints(),
        "includeStars2": br.ints(),
        "name": br.string(),
    }


def parse_skin(br: BinaryReader) -> dict:
    return {
        "activeCosts": maybe_json(br.string()),
        "desc": br.string(),
        "getway": maybe_json(br.string()),
        "heroId": br.v7(),
        "icon": br.string(),
        "id": br.v7(),
        "isStar": br.boolean(),
        "name": br.string(),
        "playerDetailIcon": br.string(),
        "quality": br.v7(),
        "roleSkinId": br.v7(),
        "startSkin": br.boolean(),
    }


def parse_star(br: BinaryReader) -> dict:
    return {
        "descriptionId": br.v7(),
        "fragmentCost": br.v7(),
        "id": br.v7(),
        "initQuality": br.v7(),
        "otherCosts": maybe_json(br.string()),
        "showStar": br.v7(),
        "skillChange": br.v7(),
        "star": br.v7(),
        "starStage": br.v7(),
        "upgradeType": br.v7(),
    }


def parse_star_detail(br: BinaryReader) -> dict:
    return {
        "id": br.v7(),
        "settingId": br.v7(),
        "star": br.v7(),
        "starAttributes": maybe_json(br.string()),
        "starStage": br.v7(),
        "starStageAttributes": maybe_json(br.string()),
    }


def parse_quality_detail(br: BinaryReader) -> dict:
    return {
        "attributes": maybe_json(br.string()),
        "heroId": br.v7(),
        "id": br.v7(),
        "quality": br.v7(),
    }


def parse_play_skill(br: BinaryReader) -> dict:
    return {
        "battlePassives": br.string(),
        "battleSkills": br.strings(),
        "desc": br.string(),
        "elementType": br.v7(),
        "id": br.string(),
        "name": br.string(),
        "range": br.v7(),
        "skillAttribute": maybe_json(br.string()),
        "skillIcon": br.string(),
        "skillTag": br.v7(),
        "skillTagText": br.string(),
        "skillType": br.string(),
        "substitute": maybe_json(br.string()),
    }


def parse_skill_tag(br: BinaryReader) -> dict:
    return {"color": br.v7(), "id": br.v7(), "text": br.string()}


def parse_alternate(br: BinaryReader) -> dict:
    return {"id": br.v7(), "originId": br.v7()}


def parse_skin_cover(br: BinaryReader) -> dict:
    return {"defaultRoleskin": maybe_json(br.string()), "id": br.string()}


def parse_role_skin(br: BinaryReader) -> dict:
    return {
        "battleMiniIcon": br.string(),
        "body": br.string(),
        "bust": br.string(),
        "contacBubble": br.string(),
        "contactSound": br.string(),
        "criteReceivedSound": br.strings(),
        "cubeHeadIcon": br.string(),
        "cubeHeadIconBg": br.string(),
        "deadSound": br.strings(),
        "defaultBubble": br.string(),
        "defaultSound": br.string(),
        "destinyBubble": maybe_json(br.string()),
        "destinyEmenyBubble": maybe_json(br.string()),
        "destinyEmenySound": maybe_json(br.string()),
        "destinySound": maybe_json(br.string()),
        "detailHeadPic": br.string(),
        "failBubble": br.string(),
        "failSound": br.string(),
        "favorIcon": br.string(),
        "favorPortrait": br.string(),
        "hitSound": br.string(),
        "hpBarOffset": br.f32(),
        "icon": br.string(),
        "id": br.v7(),
        "image_card_bg": br.string(),
        "image_card_bg_spine": br.string(),
        "ImageDeviation": br.floats(),
        "ImageRotation": br.floats(),
        "ImageScale": br.f32(),
        "lineupBubble": br.strings(),
        "lineUpEffect": eff_paths(br),
        "lineUpMove": br.string(),
        "lineupSound": br.strings(),
        "listIcon": br.string(),
        "MvpBubble": br.string(),
        "MvpSound": br.string(),
        "name": br.string(),
        "OctagonIcon": br.string(),
        "PlotImageDeviation": br.vector2(),
        "PlotImageScale": br.f32(),
        "portrait": br.string(),
        "scale": br.f32(),
        "spBust": br.string(),
        "strenthBubble": br.strings(),
        "strenthSound": br.strings(),
        "suyueTalk": br.strings(),
        "suyueTouckTalk": br.strings(),
        "VictoryReverse": br.boolean(),
        "zonePic": br.string(),
    }


def parse_hero_global(br: BinaryReader) -> dict:
    return {"content": maybe_json(br.string()), "id": br.string()}


def compact(obj: Any) -> Any:
    """Drop empty values so art-heavy tables stay readable."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v = compact(v)
            if v in ("", None, [], {}, 0, 0.0, False):
                continue
            out[k] = v
        return out
    if isinstance(obj, list):
        return [compact(x) for x in obj if compact(x) not in ("", None, [], {})]
    return obj


def skill_ids_from_map(mapping: Any) -> list[str]:
    ids: list[str] = []
    seen = set()
    if not isinstance(mapping, dict):
        return ids
    for _star, skills in mapping.items():
        if not isinstance(skills, dict):
            continue
        for sid in skills:
            if sid not in seen:
                seen.add(sid)
                ids.append(sid)
    return ids


def alias_titles(intern: list[str], names: Iterable[str]) -> dict[str, list[str]]:
    name_set = set(names)
    out: dict[str, list[str]] = {n: [] for n in name_set}
    seen_norm: dict[str, set[str]] = {n: set() for n in name_set}
    for raw in intern:
        s = raw.strip().strip('"').replace("_x000a_", "").replace("_", "")
        s = " ".join(s.split())
        if not s or "专武" in s or "任务" in s:
            continue
        if not any(ch in s for ch in "★（()"):
            continue
        for name in name_set:
            if not name or not s.startswith(name) or s == name:
                continue
            if s in seen_norm[name]:
                continue
            seen_norm[name].add(s)
            out[name].append(s)
    return {k: v for k, v in out.items() if v}


def load_allconfig(args: argparse.Namespace) -> bytes:
    if args.allconfig:
        return Path(args.allconfig).read_bytes()
    awb_path = args.awb
    if args.apk:
        print(f"reading Data.awb from {args.apk} ...", file=sys.stderr)
        awb = load_awb_from_apk(Path(args.apk))
    elif awb_path:
        awb = Path(awb_path).read_bytes()
    else:
        raise SystemExit("provide --allconfig, --awb, or --apk")
    print(f"parsing AWB index ({len(awb)} bytes) ...", file=sys.stderr)
    data_offset, files = parse_awb_index(awb)
    wanted = {n: (rel, sz) for n, rel, sz in files if n in ("Data/AllConfig.bytes",)}
    if "Data/AllConfig.bytes" not in wanted:
        raise SystemExit("Data/AllConfig.bytes not in AWB catalog")
    rel, sz = wanted["Data/AllConfig.bytes"]
    blob = extract_awb_file(awb, data_offset, rel, sz)
    if args.dump_allconfig:
        Path(args.dump_allconfig).write_bytes(blob)
    return blob


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def collect_skill_summaries(skill_map: Any, skill_by_id: dict[str, dict]) -> list[dict]:
    rows = []
    if not isinstance(skill_map, dict):
        return rows
    for star, skills in sorted(skill_map.items(), key=lambda kv: int(kv[0]) if str(kv[0]).lstrip("-").isdigit() else 0):
        if not isinstance(skills, dict):
            continue
        entry = {"unlockStar": int(star) if str(star).lstrip("-").isdigit() else star, "skills": []}
        for sid, level in skills.items():
            info = skill_by_id.get(sid, {})
            entry["skills"].append(
                {
                    "id": sid,
                    "level": level,
                    "name": info.get("name", ""),
                    "desc": info.get("desc", ""),
                    "skillType": info.get("skillType", ""),
                    "elementType": info.get("elementType", 0),
                    "icon": info.get("skillIcon", ""),
                }
            )
        rows.append(entry)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apk", help="path to xnmj.apk")
    ap.add_argument("--awb", help="path to assets/Data.awb")
    ap.add_argument("--allconfig", help="path to already-extracted AllConfig.bytes")
    ap.add_argument("--dump-allconfig", help="write AllConfig.bytes here after AWB extract")
    ap.add_argument("--outdir", default="extracted", help="output directory")
    args = ap.parse_args()

    data = load_allconfig(args)
    names = sheet_names()
    print(f"AllConfig {len(data)} bytes, {len(names)} sheets", file=sys.stderr)
    starts = walk_sheets(data, names)
    intern = parse_intern_pool(data)

    heroes = parse_sheet(data, starts["Config.HeroSettingLO"], parse_hero)
    camps = parse_sheet(data, starts["Config.HeroCampSettingLO"], parse_camp)
    jobs = parse_sheet(data, starts["Config.HeroJobSettingLO"], parse_job)
    qualities = parse_sheet(data, starts["Config.HeroQualitySettingLO"], parse_quality)
    skins = parse_sheet(data, starts["Config.HeroSkinSettingLO"], parse_skin)
    stars = parse_sheet(data, starts["Config.HeroStarSettingLO"], parse_star)
    star_details = parse_sheet(data, starts["Config.HeroStarDetailSettingLO"], parse_star_detail)
    quality_details = parse_sheet(data, starts["Config.HeroQualityDetailSettingLO"], parse_quality_detail)
    play_skills = parse_sheet(data, starts["Config.PlaySkillSettingLO"], parse_play_skill)
    skill_tags = parse_sheet(data, starts["Config.PlaySkillTagSettingLO"], parse_skill_tag)
    alternates = parse_sheet(data, starts["Config.HeroAlternateSettingLO"], parse_alternate)
    skin_covers = parse_sheet(data, starts["Config.HeroSkinCoverSettingLO"], parse_skin_cover)
    globals_ = parse_sheet(data, starts["Config.HeroGlobalSettingLO"], parse_hero_global)
    try:
        role_skins = parse_sheet(data, starts["Config.RoleSkinLO"], parse_role_skin)
    except Exception as exc:
        print(f"warning: RoleSkinLO parse failed ({exc})", file=sys.stderr)
        role_skins = []

    camp_by_id = {c["id"]: c for c in camps}
    job_by_id = {j["id"]: j for j in jobs}
    quality_by_id = {q["id"]: q for q in qualities}
    skill_by_id = {s["id"]: s for s in play_skills}
    role_by_id = {r["id"]: r for r in role_skins}
    aliases = alias_titles(intern, (h["name"] for h in heroes))
    qdetail_by_hero: dict[int, list[dict]] = {}
    for row in quality_details:
        qdetail_by_hero.setdefault(row["heroId"], []).append(
            {"id": row["id"], "quality": row["quality"], "attributes": row["attributes"]}
        )
    skins_by_hero: dict[int, list[dict]] = {}
    for s in skins:
        skins_by_hero.setdefault(s["heroId"], []).append(s)
    alt_by_origin: dict[int, list[int]] = {}
    alt_origin: dict[int, int] = {}
    for a in alternates:
        alt_origin[a["id"]] = a["originId"]
        alt_by_origin.setdefault(a["originId"], []).append(a["id"])

    enriched = []
    for h in heroes:
        camp_names = [camp_by_id[c]["name"] for c in h["camps"] if c in camp_by_id]
        job_names = [job_by_id[j]["name"] for j in h["jobs"] if j in job_by_id]
        q = quality_by_id.get(h["initQuality"], {})
        rs = role_by_id.get(h["roleSkinId"], {})
        rec = dict(h)
        rec.update(
            {
                "qualityName": q.get("name", ""),
                "campNames": camp_names,
                "jobNames": job_names,
                "damageTypeName": DAMAGE_TYPE.get(h["damageType"], str(h["damageType"])),
                "aliases": aliases.get(h["name"], []),
                "normalSkillUnlocks": collect_skill_summaries(h["normalPlaySkills"], skill_by_id),
                "angerSkillUnlocks": collect_skill_summaries(h["angerPlaySkills"], skill_by_id),
                "skins": skins_by_hero.get(h["id"], []),
                "qualityGrowth": qdetail_by_hero.get(h["id"], []),
                "alternateOf": alt_origin.get(h["id"]),
                "alternates": alt_by_origin.get(h["id"], []),
                "roleSkin": compact(
                    {
                        "id": rs.get("id"),
                        "name": rs.get("name"),
                        "icon": rs.get("icon"),
                        "listIcon": rs.get("listIcon"),
                        "bust": rs.get("bust"),
                        "body": rs.get("body"),
                        "portrait": rs.get("portrait"),
                        "favorIcon": rs.get("favorIcon"),
                        "favorPortrait": rs.get("favorPortrait"),
                    }
                )
                if rs
                else {},
            }
        )
        enriched.append(rec)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    write_json(outdir / "heroes.json", enriched)
    write_json(outdir / "camps.json", camps)
    write_json(outdir / "jobs.json", jobs)
    write_json(outdir / "qualities.json", qualities)
    write_json(outdir / "skins.json", skins)
    write_json(outdir / "stars.json", stars)
    write_json(outdir / "star_details.json", star_details)
    write_json(outdir / "quality_details.json", quality_details)
    write_json(outdir / "play_skills.json", play_skills)
    write_json(outdir / "skill_tags.json", skill_tags)
    write_json(outdir / "alternates.json", alternates)
    write_json(outdir / "skin_covers.json", skin_covers)
    write_json(outdir / "role_skins.json", [compact(r) for r in role_skins])
    write_json(outdir / "hero_global.json", globals_)
    write_json(
        outdir / "catalog.json",
        {
            "allConfigBytes": len(data),
            "sheetCount": len(names),
            "internStrings": len(intern),
            "counts": {
                "heroes": len(heroes),
                "camps": len(camps),
                "jobs": len(jobs),
                "qualities": len(qualities),
                "skins": len(skins),
                "stars": len(stars),
                "starDetails": len(star_details),
                "qualityDetails": len(quality_details),
                "playSkills": len(play_skills),
                "skillTags": len(skill_tags),
                "alternates": len(alternates),
                "roleSkins": len(role_skins),
            },
            "sheets": names,
        },
    )

    csv_path = outdir / "heroes.csv"
    fieldnames = [
        "id",
        "name",
        "enName",
        "enNameShort",
        "aliases",
        "qualityId",
        "qualityName",
        "initStar",
        "camps",
        "campNames",
        "jobs",
        "jobNames",
        "damageType",
        "isCore",
        "hide",
        "newHide",
        "fragmentId",
        "fragmentAmount",
        "roleSkinId",
        "sortId",
        "itemIcon",
        "npcId",
        "trait",
        "introduce",
        "normalSkillIds",
        "angerSkillIds",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for h in enriched:
            w.writerow(
                {
                    "id": h["id"],
                    "name": h["name"],
                    "enName": h["enName"],
                    "enNameShort": h["enNameShort"],
                    "aliases": " / ".join(h["aliases"]),
                    "qualityId": h["initQuality"],
                    "qualityName": h["qualityName"],
                    "initStar": h["initStar"],
                    "camps": ",".join(map(str, h["camps"])),
                    "campNames": ",".join(h["campNames"]),
                    "jobs": ",".join(map(str, h["jobs"])),
                    "jobNames": ",".join(h["jobNames"]),
                    "damageType": h["damageType"],
                    "isCore": int(h["isCore"]),
                    "hide": int(h["hide"]),
                    "newHide": int(h["newHide"]),
                    "fragmentId": h["fragmentId"],
                    "fragmentAmount": h["fragmentAmount"],
                    "roleSkinId": h["roleSkinId"],
                    "sortId": h["sortId"],
                    "itemIcon": h["itemIcon"],
                    "npcId": h["npcId"],
                    "trait": h["trait"],
                    "introduce": h["introduce"],
                    "normalSkillIds": ",".join(skill_ids_from_map(h["normalPlaySkills"])),
                    "angerSkillIds": ",".join(skill_ids_from_map(h["angerPlaySkills"])),
                }
            )

    lines = [
        "# 角色数据",
        "",
        f"从 `AllConfig.bytes` 解析得到 **{len(heroes)}** 名角色、"
        f"**{len(camps)}** 个阵营、**{len(jobs)}** 个职业、"
        f"**{len(play_skills)}** 条技能。",
        "",
        "## 角色一览",
        "",
        "| ID | 名称 | 英文 | 品质 | 星 | 阵营 | 职业 | 核心 |",
        "|---:|------|------|------|---:|------|------|:----:|",
    ]
    for h in sorted(enriched, key=lambda x: x["id"]):
        lines.append(
            "| {id} | {name} | {en} | {q} | {star} | {camp} | {job} | {core} |".format(
                id=h["id"],
                name=h["name"],
                en=h["enName"],
                q=h["qualityName"],
                star=h["initStar"],
                camp="、".join(h["campNames"]) or "-",
                job="、".join(h["jobNames"]) or "-",
                core="是" if h["isCore"] else "",
            )
        )
    lines += [
        "",
        "## 文件",
        "",
        "| 文件 | 内容 |",
        "|------|------|",
        "| `heroes.json` / `heroes.csv` | 角色主表（含技能解锁、皮肤、成长） |",
        "| `camps.json` | 阵营 |",
        "| `jobs.json` | 职业 |",
        "| `qualities.json` | 品质（R–SP） |",
        "| `skins.json` | 角色皮肤 |",
        "| `play_skills.json` | 技能 |",
        "| `role_skins.json` | 立绘/头像资源 |",
        "| `star_details.json` / `quality_details.json` | 升星/升品属性 |",
        "| `catalog.json` | 全部 526 张配置表名 |",
        "",
        "重新导出：",
        "",
        "```bash",
        "python3 tools/extract_character_data.py --apk xnmj.apk --outdir extracted",
        "```",
        "",
    ]
    (outdir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        f"wrote {len(heroes)} heroes, {len(camps)} camps, {len(jobs)} jobs, "
        f"{len(play_skills)} skills -> {outdir}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
