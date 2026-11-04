# xnmj-Decompilation

从 `xnmj.apk`（少女迷境 / DazzleFun）里还原出的角色配置数据。

游戏是 Unity 2022.3 IL2CPP + HybridCLR 热更。角色表不在 `global-metadata.dat` 里，而在热更 DLL `GameBase.dll` 读写的 `Data/AllConfig.bytes`。

## 角色数据

导出结果在 [`extracted/`](extracted/README.md)：

- **53** 名角色（`HeroSettingLO`）
- 阵营、职业、品质、皮肤、立绘
- 2201 条 `PlaySkill`（含普攻 / 怒气技解锁）
- 升星、升品属性

主表：

- [`extracted/heroes.csv`](extracted/heroes.csv) — 方便表格查看
- [`extracted/heroes.json`](extracted/heroes.json) — 完整字段（属性、技能按星解锁、皮肤）

## 重新导出

需要 Git LFS 拉下 APK，然后：

```bash
git lfs pull
python3 tools/extract_character_data.py --apk xnmj.apk --outdir extracted
```

若已经解出 `assets/Data.awb` 或 `AllConfig.bytes`：

```bash
python3 tools/extract_character_data.py --awb Data.awb --outdir extracted
python3 tools/extract_character_data.py --allconfig AllConfig.bytes --outdir extracted
```

脚本只依赖 Python 3 标准库。

## 资源格式（简述）

1. APK 里的 `assets/Data.awb` 是自定义归档：目录用 32 轮 TEA-ECB 加密，payload 明文。密钥为 ASCII `0123456789ABFFFF`（按小端 uint32 解释）。
2. 目录项：`.NET BinaryReader` 字符串 + `int32` 相对偏移 + 7-bit 长度。payload 起始于目录头里的 `data_offset`。
3. `AllConfig.bytes` 前 8 字节是 intern 池结束偏移和文件长度，随后 526 张表按 `GameBase.dll` 中 `CsvLoadAll.GetInitAction` 的顺序排列。
4. 每张表：7-bit blob 长度 → 渠道目录（通常一个空名默认项）→ 7-bit 行数 → 行字段（字符串 7-bit 长度 UTF-8，整数 7-bit，JSON 以字符串存放）。
5. `HeroSettingLO` 在第 304 张表。字段顺序与 `InitBytes` 一致，例如 `id / name / camps / jobs / initQuality / initStar / attributes / normalPlaySkills / angerPlaySkills`。

没有把整包美术、完整反编译源码或服务器地址放进仓库。
