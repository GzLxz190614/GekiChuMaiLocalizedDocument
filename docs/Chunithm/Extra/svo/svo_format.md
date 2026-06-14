# SVO 文件格式分析 — 完整规格说明 

> **2026-06-14 修订要点 (深入实例语法 + 几何解码 + AVTS 结构纠正)**:
> 1. **AVTS 实为 chunk 目录表 (CHUNK DIRECTORY)**, 不只是名称池: 描述符块按 **stride 0x400**
>    排布, 块 k 的名字在 `0x80 + k*0x400`, `<u32 size><u32 file_offset>` 指针对在
>    `0x288 + k*0x400` (即块基址 +0x208)。加载器据此定位 YABX 与各 DDS/VBO/IBO 数据块。
> 2. **文件布局顺序纠正**: `YABX → DDS×N → VBO/IBO(文件末尾)`。几何**不在** YABX 与首个 DDS
>    之间 (那里只有 0~96B 对齐填充); VBO/IBO 追加在所有 DDS 之后, 位于文件最末。旧 §2 顺序作废。
> 3. **实例对象记录帧 = `<u16 tag=3><u32 size><body>`**; 字段序列化顺序 = **派生类字段在前,
>    基类字段在后** (各层按 schema 声明序)。对象引用列表编码 = `<u32 size><u32 count><count×u16 localID>`。
> 4. **已成功解码真实几何** (ntt_ahact_01): 20 顶点 / 30 索引 / stride=28 (PNCT) / UINT16 /
>    三角形带; 位置为合法 3D 坐标, 顶点色 0xFFFFFFFF。
> 5. **SVO 是完整 3D 场景容器**, 不止"贴图+网格": 含场景图 (Tree/Node 层级 + 每节点变换/4 矩阵)、
>    蒙皮 (mtxBind + maxInfluence)、morph/blend-shape、完整材质/着色器系统、贴图采样配置、
>    包围体 (球+盒)、渲染排序。详见新增 §14。
>
> **2026-06-11 修订要点 (基于 大四应用.exe IDA 复核 + 逐字节解析 svo 文件)**:
> 1. **推翻旧 §4.3 "Tag Byte" 模型**: 那些"标记字节"(0x06/0x0a/0x0d/0x11/0x21…) 实为
>    **u8 字符串长度前缀** (= strlen+1, 含结尾 `\0`)。由 `Yb_WriteString_LenPrefixed`
>    @0xEA2BB0 权威证实 (同 RFZ 已被推翻的 "tag=field_id+0x2711" 错误同类)。
> 2. **YABX schema 语法已完整、端到端验证**: 用确认的语法解析 `chu_barline_blue_v10.svo`
>    干净走完全部 19 个 stevia 类定义并精确落到实例数据边界。
> 3. **字段类型 = `<u8 flag><u16 inline_size>`**: 中间 u16 = 内联值字节数
>    (4=u32/f32, 2=u16 localID 引用, 1=bool, 12=vec3, 16=vec4/四元数/颜色, 48=4×3矩阵,
>    0=变长 TLV 字符串/对象数组)。旧 §4.4 的 `0x00040000` 之类编码作废。
> 4. **类头 = `01 <u8 base_ref> 00`**: 第二字节 = 基类的 1-based 索引 (0=无基类), 单继承。
> 5. AVTS / 名称池 / DDS / 材质参数 / 枚举 / 文件偏移等旧内容经复核基本正确, 予以保留。

---

## 1. 概述

SVO 是 GASE 大四韵律 街机 (大四应用.exe) 的 3D 模型资源格式。每个 `.svo` 自包含一个
完整渲染所需的对象图：场景树、网格几何、材质/着色器参数、贴图描述，并在文件末尾内嵌
标准 DDS 贴图。

**框架链**: `ruhuna (文件IO) → yabukita (序列化容器) → stevia (3D 引擎对象模型)`

SVO = **AVTS 外层封装** + **YABX 内层容器**:
- **AVTS**: 文件头 + 名称池 (集中存放所有 chunk/资源/文件名字符串)。
- **YABX**: yabukita 二进制序列化流, 自描述 schema (类型注册) + 根对象 `stevia::Database` 实例。
- 之后是被 chunk 名引用的 **VBO/IBO/DDS** 原始数据块。

> **与 RFZ 字体的关系 (回答用户疑问)**: RFZ 解压流开头是**裸 YABX** (ruhuna::Database 字体,
> 无 AVTS 外壳); 其纹理段内又内嵌一个**完整 SVO** (AVTS + 第二个 YABX, 内含 stevia::Database)。
> 故"解压流开头和 svo 数据里都有 YABX" —— 因为 YABX 是通用 yabukita 容器, 字体与 SVO 都用它,
> 只是根类不同 (ruhuna::Database vs stevia::Database)。AVTS 则是 SVO 专有的外层封装。

### 1.1 大四应用.exe 中已复核的关键函数 (本次重命名)

| 地址 | 新名 | 作用 |
|------|------|------|
| `0xE91400` | `Yb_ReadMagic_CreateProcessor` | 读 4B magic: `YABX`(LE) / `XBAY`(BE) 选反序列化处理器; 仅校验 magic, **不校验 hash** |
| `0xEA2BB0` | `Yb_WriteString_LenPrefixed` | 字符串写入器: mode≠0 → `<u8 len>` 前缀; mode=0 → `<u16 len>` 前缀; len 含 `\0` |
| `0xE91300` | `Yb_Finalize_PayloadSizeAndCRC` | 回填 payload_size + hash(~CRC32, 用 `Yb_CRC32_Table` @0x18FB268) |
| `0xE91570` | `RuhunaFontDB_Serialize` | ruhuna 字体 DB 写入器 (写 RFZ 解压流, 揭示原语方法表) |

序列化原语 (从 `RuhunaFontDB_Serialize` 调用点确认), 处理器 vtable 槽位:
`+32` = 写 u8/bool, `+40` = 写 u16, `+48` = 写 u32, `Yb_WriteString_LenPrefixed` = 写字符串。

> 大四应用.exe **只读 SVO 不写 SVO** —— stevia schema 由离线工具 `HndToSvo` 生成
> (故名称池里全是 `__HndToSvo__` 前缀)。二进制中只存在 ruhuna(字体)写入器与通用 yabukita **读取器**。

---

## 2. 文件整体结构

```
┌──────────────────────────────────────────────────────────────┐
│ AVTS Header + chunk 目录表 (变长, 填充至 YABX 起始)             │
│   "AVTS"(4B) + version u32(4B) + 描述符块×N (stride 0x400)      │
│   每块: 名字串@+0x80 + <u32 size><u32 file_off>@+0x208          │
├──────────────────────────────────────────────────────────────┤
│ YABX 容器 (yabukita 序列化流)  ← chunk[0] 指向此                │
│   "YABX"(4B)+ver+payload_size+hash(共16B)                      │
│   + 顶层头 + 命名空间表 + 类定义(schema) + 根对象实例            │
├──────────────────────────────────────────────────────────────┤
│ DDS 贴图段 (N 个标准 DDS 连续存放)  ← chunk[1..k] 指向此        │
│   注: YABX 与首个 DDS 之间仅有 0~96B 对齐填充                    │
├──────────────────────────────────────────────────────────────┤
│ VBO / IBO 几何数据块 (文件最末尾)  ← chunk[k+1..] 指向此        │
│   几何很小 (~数百字节~KB); 大文件体量主要来自 DDS 纹理          │
└──────────────────────────────────────────────────────────────┘
```

> **重要纠正**: 旧版假设几何 (VBO/IBO) 位于 YABX 与 DDS 之间, 实测**错误**。几何数据块
> 追加在**所有 DDS 之后, 文件最末尾**, 由 AVTS chunk 目录 (§3) 定位。即使 1.1MB 的大文件,
> YABX payload 仍保持 ~16KB, 几何仍仅数百字节~KB —— 文件体量几乎全部是 DDS 纹理。
> 实证: `ntt_ahact_01`(39KB) 与 `ntt_ahact_05`(152KB) 的 YABX payload **完全相同**(0x4170),
> 即同一几何, 仅纹理大小不同。

---

## 3. AVTS Header + chunk 目录表 (★ 本次纠正: 是目录表, 非仅名称池 ★)

### 3.1 结构

```
Offset  Size  Description
0x00    4     Magic: "AVTS" (0x53545641 LE)
0x04    4     Version: u32 LE (已知 4, 5, 6)
0x08    var   chunk 描述符块数组, 每块 stride = 0x400, 填充至 YABX 起始
```

AVTS 头之后是一组**定长描述符块** (stride **0x400**)。每块描述文件中的一个资源 chunk
(YABX 容器 / DDS 贴图 / VBO / IBO)。块 `k` 的字段相对其基址 `0x80 + k*0x400`:

| 块内偏移 | 字段 | 说明 |
|---------|------|------|
| `+0x00` (= 0x80+k*0x400) | name 字符串 | null 结尾, `__HndToSvo__<...>` |
| `+0x208` (= 0x288+k*0x400) | `u32 size` | 该 chunk 字节数 |
| `+0x20C` (= 0x28C+k*0x400) | `u32 file_offset` | 该 chunk 在文件中的绝对偏移 |

> 加载器遍历该目录: chunk[0] 总是 YABX 容器, 随后是各 DDS, 最后是 VBO/IBO。**这是定位
> 文件末尾几何块的权威途径** —— 无需扫描 magic, 直接读目录指针对即可。

### 3.2 版本差异

| 版本 | YABX 起始 | 示例文件 |
|------|----------|---------|
| 4    | 0x1080 | `chu_barline_*.svo`, `chu_goalline_*.svo`, `chu_notesfield_*.svo` |
| 5    | 0x1480 | `ntt_airdwtilt_*.svo`, `ntt_airuptilt_*.svo` |
| 6    | 0x1480 | `ntt_dmg_*.svo` |

### 3.3 实测目录 (两文件验证)

**chu_barline_blue_v10.svo (v4)** —— 解析得 4 个块:

| 块 | 名字 | size | file_offset |
|----|------|------|-------------|
| 0 | `…chu_barline_blue_v10.svo` (YABX) | 0x26C0 | 0x1080 |
| 1 | `…chu_barline_blue_v10.dds` (DDS) | 0x880 | 0x3780 |
| 2 | `…__PNT_0000.VBO` | 0x60 | 0x4000 |
| 3 | `…__PNT.IBO` | 0x0A | 0x4080 |

**ntt_ahact_01.svo (v5)** —— 解析得 5 个块:

| 块 | 名字 | size | file_offset |
|----|------|------|-------------|
| 0 | `…ntt_ahact_01.svo` (YABX) | 0x4180 | 0x1480 |
| 1 | `…ntt_ahact_01.dds` (DDS, 64×64 A8R8G8B8) | 0x3F80 | 0x5600 |
| 2 | `…ntt_ahact_eff.dds` (DDS, 8×64 DXT1) | 0x180 | 0x9580 |
| 3 | `…__PNCT_0000.VBO` | 0x230 (560) | 0x9700 |
| 4 | `…__PNCT.IBO` | 0x3C (60) | 0x9980 |

> 两例均印证布局: **YABX → DDS×N → VBO → IBO**, 几何在文件最末尾。0x1080 + 0x26C0 = 0x3740
> 为 barline 的 YABX 结束位置, DDS @0x3780 (中间约 0x40B 对齐)。chunk 名仍是 `__HndToSvo__`
> 前缀串, 但它们是目录块的组成部分, 不是孤立名称池。

---

## 4. YABX 容器 (★ 本次重写, 已 IDA + 字节双重验证 ★)

### 4.1 YABX Header (16 字节)

```
Offset  Size  Field          说明
0x00    4     Magic "YABX"   0x58424159 (LE); 大端变体 "XBAY"=0x59414258 (本游戏资源均小端)
0x04    4     version u32    固定 1
0x08    4     payload_size   = 容器总长 - 16 (实例数据区字节数); 由 Yb_Finalize 回填
0x0C    4     hash u32       = ~CRC32(payload) (Yb_CRC32_Table); 写入回填, **加载不校验**
```

> `Yb_ReadMagic_CreateProcessor` @0xE91400 仅比对 magic; `Yb_Finalize_PayloadSizeAndCRC`
> @0xE91300 用 `v8 = tbl[byte ^ (v8>>24)] ^ (v8<<8)` 迭代算 `~v8` 写回 hash。
> 因加载不校验, 修改内容后无需重算 hash (与 RFZ 结论一致)。

### 4.2 字符串编码 (两种, 由 `Yb_WriteString_LenPrefixed` @0xEA2BB0 权威确定)

`len = strlen + 1` (**含结尾 `\0`**), 写法二选一:

| 模式 | 编码 | 用途 |
|------|------|------|
| **短字符串** (mode≠0) | `<u8 len><chars\0>` | schema 内的类名、字段名、命名空间名、对象 localID 名 |
| **长字符串** (mode=0)  | `<u16 len><chars\0>` | 顶层头字符串、实例数据中的名称值 |

> ★ **这是对旧文档最重要的纠正**: 旧 §4.3 把 `0x06/0x0a/0x11/0x21` 等当成语义"标记字节",
> 实则它们就是 **u8 长度前缀**。例: `0x11` "yabukita::Object" → 0x11=17="yabukita::Object"+`\0` 长度;
> `0x21` "__HndToSvo__chu_barline_blue_v10" → 0x21=33。

### 4.3 顶层头 + 命名空间表

YABX header 之后 (chu_barline_blue_v10 @0x1090 起):

```
[u8 tag=0x04][u16 len][ "HndToSvo/svo\0" ]      ← 格式/转换器标识串 (长字符串, 但前置 1 字节 tag)
[u8 tag=0x07][u16 len][ "stevia::Database\0" ]  ← 根对象类名
[u8 0x00]                                        ← 分隔
[u8 len][ "__HndToSvo__<file>\0" ]               ← 根对象名 (短字符串)
── 命名空间表: 重复 <短字符串名><u32 id>, 以 u8 0x00 终止 ──
[u8 len]["yabukita\0"][u32 1005]
[u8 len]["stevia\0"]  [u32 1000]
[u8 0x00]                                        ← 命名空间表结束
```

> 顶层两串前各有 1 个 tag 字节 (0x04 / 0x07)；其确切语义未完全定死 (疑为根对象首两个
> 字段的类型/序号标记), 但对解析无碍——长度由其后的 u16 决定。

### 4.4 类定义 (schema / 类型注册) ★ 已端到端验证 ★

命名空间表之后是类定义序列, 每个类:

```
[u8 len][ "Namespace::ClassName\0" ]   ← 短字符串类名
[u8 0x01]                              ← 记录标志 (恒 0x01 = "类定义")
[u8 base_ref]                          ← 基类的 1-based 索引 (0 = 无基类); 单继承
[u8 0x00]                              ← 保留
── 字段列表: 重复每字段 ──
  [u8 len][ "_fieldName\0" ]           ← 短字符串字段名
  [u8 flag]                            ← 每字段标志 (0/1, 见下)
  [u16 inline_size]                    ← 内联值字节数 (0 = 变长 TLV)
[u8 0x00]                              ← 字段列表结束 (零长度名前缀作哨兵)
```

**`inline_size` (中间 u16) = 该字段在实例中内联存储的字节数**:

| size | 含义 |
|------|------|
| 0 | 变长 (TLV): 字符串、对象数组、对象引用列表 |
| 1 | bool / u8 |
| 2 | u16 (通常是 **localID 对象引用**) |
| 4 | u32 / s32 / f32 / 枚举 |
| 12 | Vector3 (3×f32) |
| 16 | Vector4 / Quaternion / Color (4×f32) |
| 48 | Matrix3x4 (12×f32) |

**`base_ref` (类头第二字节) = 基类 1-based 索引**, 实测自洽:
`Object`(0=无基) ← `Resource`(1→Object) ← `Database/State/Texture/Image/Mesh/Shape/Batch/`
`VertexBuffer/VertexDeclaration/IndexBuffer/Tree/Node`(2→Resource);
`Parameter/Variant/VertexElement`(1→Object, 轻量类直接继承 Object)。

**`flag` (每字段第一字节, 0/1)**: 观测到 0 与 1 两种取值, 与具体类型无单一对应
(同为 u32 标量, State 中 flag=1 而 Batch 中 flag=0)。疑为"可选/默认值/序列化门控"类标志,
其精确语义需进一步逆向通用读取器; 对**解析字节布局无影响** (布局完全由 `inline_size` 决定)。

### 4.5 完整 stevia 类层次与字段表 (从 chu_barline_blue_v10.svo schema 提取, 19 个类)

> 格式: `字段名 (size)`; size=2 标注为 `→localID`, size=0 标注为 `[TLV]`。

```
yabukita::Object                       (无基, 0 字段)
stevia::Resource : Object              _name[TLV] _flag(4) _fullName[TLV] _userParameter[TLV]
stevia::Database : Resource            _state[TLV] _mesh[TLV] _batch[TLV] _vertexBuffer[TLV]
                                       _indexBuffer[TLV] _vertexDeclaration[TLV] _texture[TLV]
                                       _image[TLV] _tree[TLV]
stevia::State : Resource               _fillType(4) _alphaRef(4) _depthBias(4) _depthBiasSlope(4)
                                       _cullMode(4) _transparentDoubleSide(1) _lighting[TLV]
                                       _maxInfluence(4) _uvSet(4) _blendOperation(4)
                                       _blendFactorSrc(4) _blendFactorDst(4) _shaderName[TLV]
                                       _texture[TLV] _textureRef[TLV]
stevia::Texture : Resource             _wrapU(4) _wrapV(4) _minFilter(4) _magFilter(4) _mipFilter(4)
                                       _anisoNumber(4) _lodBias(4) _id(4) _uvSetIndex(4)
                                       _uvSetName[TLV] _attributeName[TLV] _textureType[TLV]
                                       _image→localID(2)
stevia::Image : Resource               _height(4) _width(4) _maxMipmapLevel(4) _format(4)
                                       _compressCustomOption[TLV] _alphaMode(4) _fileName[TLV]
                                       _chunkFileName[TLV] _file→localID(2) _mipmapFileName[TLV]
                                       _dataSize(4)
stevia::Parameter : Object             _name[TLV] _value→localID(2) _userID(4)
stevia::Variant : Object               _variantType(4) _valueF32(4) _valueS32(4)
                                       _valueColor(16) _valueString[TLV]
stevia::Mesh : Resource                _shape[TLV] _sortGroup(4)
stevia::Shape : Resource               _state→localID(2) _batch→localID(2) _boundingSphere(16)
                                       _boundingBoxCenter(12) _boundingBoxSize(12)
                                       _sortDistanceOffset(4) _blendTargetName[TLV]
                                       _blendTargetBindMatrix[TLV] _meshBindMatrix(48)
stevia::Batch : Resource               _polygonNumber(4) _primitiveType(4) _primitiveNumber(4)
                                       _indexStart(4) _indexNumber(4) _startNumber(4) _endNumber(4)
                                       _vertexNumber(4) _vertexBufferList[TLV] _indexBuffer→localID(2)
stevia::VertexBuffer : Resource        _vertexNumber(4) _dataSize(4) _chunkFileName[TLV] _stride(4)
                                       _vertexDeclaration→localID(2) _billboardType(4)
stevia::VertexDeclaration : Resource   _vertexElement[TLV]
stevia::VertexElement : Object         _semantics(4) _elementType(4) _index(4)
stevia::IndexBuffer : Resource         _indexNumber(4) _chunkFileName[TLV] _indexType(4)
stevia::Tree : Resource                _blendTargetNumber(4) _node[TLV]
stevia::Node : Resource                _mesh→localID(2) _parent→localID(2) _child→localID(2)
                                       _sibling→localID(2) _blendIndex(4) _scale(12) _rotation(12)
                                       _quaternion(16) _translation(12) _mtxLocal(48) _mtxWorld(48)
                                       _mtxWorldInv(48) _mtxBind(48)
```

> 注意 `_rotation` size=12 (Vector3 欧拉角) 而 `_quaternion` size=16 (四元数), 两者并存。
> 场景图通过 `_mesh/_parent/_child/_sibling` 的 u16 localID 引用构成树。

### 4.6 实例数据语法 (★ 本次深入逆向, 已逐字节验证 ★)

类定义结束后是对象实例区。**每个对象记录**的帧格式 (与 RFZ ruhuna 实例同构):

```
[u16 class_tag][u32 body_size][body … body_size 字节]
```

> ★ **本次纠正 (三国志大战大模型验证)**: `class_tag` **不是固定的 3**, 而是该对象类的
> **1-based schema 索引** (与 §4.4 的 base_ref 同一编号体系)。即 `class_tag = 类在 schema 中
> 的 0-based 序号 + 1`。实测: Database(idx2)→3, State(idx3)→4, Texture(idx4)→5, Image(idx5)→6,
> Parameter(idx6)→7, Variant(idx7)→8。barline 根对象 tag=3 只是因为 Database 恰好是 idx2。
> 解析器据此 tag 即可定位对象的类与字段布局。

> 实例区在 schema 之后, 先有 4 字节引导 `<u16 0><u16 object_count>` (object_count = 总对象数,
> 如 m107=406), 随后是 object_count 个对象记录, 末尾可能有 1~5 字节对齐填充至 payload 边界。

**字段序列化顺序 = 派生类字段在前, 基类字段在后** (每一继承层按 schema 声明序输出)。
即与 §4.5 schema 的"派生→基"链反向展开。barline 根 `Database` 体 (152B) 逐字段:

| 顺序 | 来源类 | 字段 | 编码 | 字节 |
|------|--------|------|------|------|
| 1 | Database | 9 个类型化数组 (_state.._tree) | 每个 ref-list | 90 |
| 2 | Resource | _name | TLV 字符串 | 25 |
| 3 | Resource | _flag | u32 内联 | 4 |
| 4 | Resource | _fullName | TLV 字符串 | 25 |
| 5 | Resource | _userParameter | ref-list | 8 |

合计 90+25+4+25+8 = **152** ✓ 精确闭合。

**字段值三种编码**:

| 类型 | 编码 | 说明 |
|------|------|------|
| 内联标量 | `inline_size` 字节原值 | 4=u32/f32, 2=u16 localID, 1=bool, 12/16/48=向量/矩阵 |
| TLV 字符串 | `<u32 size><u16 strlen+1><chars\0>` | size = strlen+2 |
| 对象引用列表 | `<u32 size><u32 count><count × u16 localID>` | size = 4 + 2*count |

> 引用列表 count=1 时呈 `06 00 00 00 01 00 00 00 <u16 localID>` —— 即旧文档误认的
> "localID 表头" 实为单元素引用列表。

> **变长字段 (size=0) 的字符串/引用列表判别** (解析器实测可靠): 读 `<u32 tlv_size>` 后,
> 偷看其后 u32 `n`; 若 `tlv_size == 4 + 2*n` 则为引用列表 (`n` 个 u16 localID), 否则为
> TLV 字符串 (`<u16 strlen+1><chars\0>`)。该启发式在三国志大战全部对象上零误判。

> **localID 基址随文件而变**: barline 基址 0x2712(=10002); 三国志大战 m107 的引用为
> 10002/10153/10304… (基址 ~10000)。基址是 yabukita 运行时分配的对象句柄起点, 解析时
> 应以"实例区中第 k 个被创建对象 → 句柄 base+k"的方式动态建表, 不要硬编码 0x2712。

> **★ 全树解析验证 (2026-06-14)**: 上述语法 (class_tag=类索引+1 / 派生→基字段序 /
> 三种编码) 已在三国志大战 6 个文件 (174~792 对象, 含蒙皮角色) 上**逐对象、逐字段端到端走通**,
> 每个对象体长度精确闭合 (consumed==body_size), 解析终点恰好落在 payload 边界 (±1~5B 对齐填充)。
> 解出的材质参数 (ambient=[0.3,0.3,0.3,1] / diffuse=[0.7,0.7,0.7,1])、贴图 (512×512 format10)、
> Image/Texture 配置均语义合理。**SVO 实例层已具备完整可逆解析能力。**

**localID → 类映射** (从根 Database 的 9 个类型化数组推得, barline; localID 基址 0x2712):

| localID | 类 | localID | 类 |
|---------|----|---------|----|
| 0x2712 | State | 0x27A4 | VertexBuffer |
| 0x2713 | Texture | 0x27A5 | VertexDeclaration |
| 0x2714 | Image | 0x27A9 | IndexBuffer |
| 0x27A1 | Mesh | 0x27AA | Tree |
| 0x27A3 | Batch | | |

> localID 是对象数组内的句柄, 字段中的 u16 引用 (size=2) 据此解析对象指针。基址 0x2712
> 与 RFZ 字体 glyph localID 同源 (yabukita 通用机制)。

---

## 5. 几何数据块 (VBO / IBO)

`stevia::VertexBuffer._chunkFileName` / `IndexBuffer._chunkFileName` 是名称池里的
`__HndToSvo__…__PNT_NNNN.VBO` / `…__PNT.IBO` 串, 指向文件后段的原始几何数据块。
`_stride` (顶点步长)、`_vertexNumber`、`_dataSize`、`_indexNumber`、`_indexType` 等
度量均在 schema 实例里 (按 §4.4 内联)。

**IndexType 枚举**: 2 = UINT16 (2B/索引), 4 = UINT32 (4B/索引)。

> **简单模型 (barline/goalline/notesfield, 4 顶点平面)**: 旧文档曾推测其 VBO/IBO 运行时
> 程序化生成。结合 schema, 更准确的说法是: 这些模型仍有 VertexBuffer/IndexBuffer 对象与
> `__PNT_0000.VBO/__PNT.IBO` chunk 名, 几何数据块体量很小 (4 顶点 × stride)。

### 5.1 VertexElement 语义 / 类型 (推断自实例枚举值)

**_semantics** (VertexInputSemantics): 0=POSITION, 3=NORMAL, 5=TEXCOORD, 8=COLOR。
**_elementType** (VertexElementType): 0=FLOAT1, 1=FLOAT2, 2=FLOAT3, 3=FLOAT4, 8=UBYTE4。

### 5.2 顶点格式一览 (从 chunk 名 `__PNT/__PNCT` 等推断 + 实测 stride)

| 格式 | Stride | 布局 | 示例 |
|------|--------|------|------|
| `PNT` | 32B | P(f3=12)+N(f3=12)+T(f2=8) | barline, goalline, notesfield |
| `PNCT` | **28B** (实测) | P(f3=12)+N/C(打包 UBYTE4)+T | ntt_ahact, ntt_airdwtilt |
| `PNBTW` / `PNBTWW` | 变 | P+N+**B(骨骼索引)**+T+**W(权重)** | 三国志大战角色 (蒙皮) |
| `PNBCTW` / `PNBCTWW` | 变 | P+N+B+C(色)+T+W | 三国志大战带顶点色角色 |
| `P`/`PN`/`PT` | 12/24/20B | 见名 | 简单/无贴图/无光照模型 |

> ★ **三国志大战角色模型为蒙皮网格**: chunk 名出现 `B`(Blend/骨骼索引) 与 `W`(Weight/权重)
> 字段 (如 `PNBTWW_0000.VBO`), 配合 Node 树 (§4.5/§14.1) 的 `_mtxBind` 构成完整骨骼蒙皮。
> 单文件常有多个 VBO (不同子网格用不同顶点格式, 如 body_m106 = PNBTW + PNBTWW 两段)。
> 各字段精确偏移/类型由该 VBO 对应的 `VertexDeclaration._vertexElement[]`
> (每元素 _semantics/_elementType/_index) 权威给出 —— 解析时读 schema 实例即可, 无需猜测。

> ★ PNCT stride 实测为 **28**(ahact: 560/20=28), 非旧文档推测的 36。28B = 7×f32, 法线与
> 顶点色以打包形式 (UBYTE4) 占用, 颜色字节实测 0xFFFFFFFF (全白可见)。28 字节的法线/色/UV
> 精确子布局尚未完全定死 (见 §12), 但 Position(f3) 与 TexCoord 已可正确解出。

### 5.3 真实几何解码实例 (★ ntt_ahact_01, 已端到端解出 ★)

由 §3 AVTS 目录定位到 VBO@0x9700(560B) / IBO@0x9980(60B), 结合 schema 实例度量:

| 对象 | 字段 | 值 |
|------|------|----|
| VertexBuffer | _vertexNumber | 20 |
| | _dataSize | 560 (= 20 × 28 ✓) |
| | _stride | 28 (PNCT) |
| | _vertexDeclaration | localID 0x2834 |
| | _billboardType | 0 |
| IndexBuffer | _indexNumber | 30 |
| | _indexType | 2 (UINT16) → 30×2 = 60B ✓ |

**IBO 索引** (30 个 u16 @0x9980):
`0,2,4,5,4,10,1,6,6,9,9,7,11,10,11,5,11,3,8,13,14,12,18,16,19,17,15,13,14,14`。

> 索引含退化三角形 (重复对 6,6 / 9,9 / 14,14) → 这是 **三角形带 (TRIANGLE_STRIP)** 的
> 缝合标志, 用退化三角形把多条带子接成一个绘制调用。20 顶点 / 30 索引 ≈ 10 个三角形。
> Position 解出为合法 3D 坐标 (非噪声), 证实顶点格式与定位均正确。
> ahact_01 与 ahact_05 几何完全相同 (同一 YABX payload), 仅贴图尺寸不同。

---

## 6. DDS 贴图段

### 6.1 位置与提取

所有 DDS 紧随 YABX 容器+几何块之后, 连续存放无间隔。提取: 搜 `"DDS "` magic →
校验 `dwSize==124` → 读 `dwHeight/dwWidth/dwPitchOrLinearSize` → `128 + linearSize`
(或按 FourCC/位深算 mip 链) 切出完整 DDS → 跳至下一个。

### 6.2 DDS 头 (128B, 标准 DDSURFACEDESC2)

```
0x00 "DDS "  0x04 dwSize=124  0x0C dwHeight  0x10 dwWidth  0x14 dwPitchOrLinearSize
0x1C dwMipMapCount  0x4C PF.dwSize=32  0x54 dwFourCC  0x58 dwRGBBitCount  …位掩码…
0x80 像素数据
```

### 6.3 已知格式

| dwFourCC | 说明 | 块/像素大小 |
|----------|------|-----------|
| `DXT1` | BC1, 1-bit alpha | 8B/块 |
| `DXT5` | BC3, 8-bit alpha | 16B/块 |
| 0 (DDPF_RGB\|ALPHAPIXELS) | A8R8G8B8 未压缩 | w×h×4 |

> RFZ 字体内嵌 SVO 的纹理用的是 ARGB4444 (16bpp); SVO 模型贴图多为 DXT5 / A8R8G8B8 / DXT1。

### 6.4 文件名关联

`stevia::Image._fileName` = `<name>.dds`, `._chunkFileName` = `__HndToSvo__<name>.dds`;
`Texture._image` 经 u16 localID 关联到渲染状态。DDS 在文件中的出现顺序 = Image 对象定义顺序。

---

## 7. 版本差异汇总

| 版本 | YABX 起始 | 典型大小 | 贴图数 | 顶点格式 |
|------|----------|---------|--------|---------|
| 4 (早) | 0x1080 | 16-33KB | 1 | PNT |
| 4 (中) | 0x1080 | 90-100KB | 2 | PNCT |
| 5 | 0x1480 | 90-100KB | 2 | PNCT |
| 6 | 0x1480 | 200KB+ | 3 | PNCT (推测) |

---

## 8. 枚举值参考 (推断自实例数据)

| 枚举 | 值 |
|------|----|
| PrimitiveType | 3=TRIANGLE_LIST, 4=TRIANGLE_STRIP |
| CullMode | 0=NONE, 1=FRONT, 2=BACK |
| BlendFactor | 0=ZERO,1=ONE,2=SRC_COLOR,3=INV_SRC_COLOR,4=SRC_ALPHA,5=INV_SRC_ALPHA |
| BlendOperation | 0=ADD,1=SUB,2=REV_SUB,3=MIN,4=MAX |
| FillType | 0=SOLID,1=WIREFRAME,2=POINT |
| WrapMode | 0=REPEAT,1=CLAMP,2=MIRROR |
| FilterMode | 0=POINT,1=LINEAR,2=ANISOTROPIC |
| IndexType | 2=UINT16,4=UINT32 |

---

## 9. 材质参数列表 (stevia::Parameter / Variant, 名称池实测)

材质参数以 `stevia::Parameter`(`_name`/`_value`→Variant/`_userID`) + `stevia::Variant`
(`_variantType`/`_valueF32`/`_valueS32`/`_valueColor`(16B)/`_valueString`) 表达。
变体类型 `_variantType` 区分 f32 / s32 / color(vec4) / string。

### 9.1 基础光照
`ambient`/`diffuse`/`emissive`/`specular` (vec4 color), `shininess`/`opacity` (f32)。

### 9.2 SEGA 引擎参数 (`sea*`, 名称池实测)
`seaShaderType seaMaterialId seaBaseMapType seaDetailMap/Blend/Scale/Distance
seaAlphaSort seaEdgeAlpha[/Bias/Power/Scale] seaEnvironmentMapType seaExtUvScroll
seaIncandescenceMapType seaRamp seaReduction seaRimLightRate seaRimColor seaRimPow
seaSoftEdge seaSpecularMapType seaUseFresnel seaVertexShake` (其余见名)。

### 9.3 双层/卡通着色 (`ts*`, 名称池实测)
`tsShaderType tsDiffuseScale tsSpecularScale tsNormalMapType/Scale
tsDirectionLightingColor/Direction tsHemisphereLightingSky/Ground/Direction
tsLayerBlendFunction[2] tsLayerBlendFactorSrc[2]/Dst[2] tsEnableUVOffset tsEnableVertexColor
tsUVScrollUV0/1/2 tsUVScrollNormal/Specular/Incandescence tsIncandescenceScale
tsShadowCaster/Receiver tsPointLightingMode tsMaterialAnimation tsGlobalEnvironmentMap
tsVisibleToCamera/Reflection tsRoughness tsScatteringScale tsUserShader`。

### 9.4 `rdcp*` 参数 (名称池实测)
`rdcpColorAmp rdcpLightingType rdcpMultiTexType rdcpRamp rdcpRim rdcpRimColor rdcpRimPow`。

---

## 10. 文件偏移快速参考

### 10.1 chu_barline_blue_v10.svo (v4, 16,640B) — 已逐字节核对

| 偏移 | 内容 |
|------|------|
| 0x0000 | `AVTS` + version=4 |
| 0x0080 | AVTS chunk 目录 (块0=YABX, 块1=DDS, 块2=VBO, 块3=IBO; stride 0x400) |
| 0x0288 | 块0 指针对: size 0x26C0 / offset 0x1080 (YABX) |
| 0x1080 | YABX header (payload 0x26B0, hash 0x34F21EDB) |
| 0x1090 | 顶层头 + 命名空间表 |
| 0x10F2 | 类定义区 (19 类: yabukita::Object … stevia::Node) |
| 0x1912 | 类定义结束 → 实例区 (对象帧 <u16 3><u32 size><body>) |
| 0x3780 | DDS 贴图 (A8R8G8B8) |
| 0x4000 | VBO 几何块 (文件末尾); 0x4080: IBO |

### 10.2 ntt_airdwtilt_01.svo (v5, ~97KB)

| 偏移 | 内容 |
|------|------|
| 0x0000 | `AVTS` + version=5 |
| 0x1480 | YABX header |
| (后段) | 数据/几何 + DDS #1 (A8R8G8B8) + DDS #2 (DXT1) |

---

## 11. 解析流程 (供 svo_viewer.py 参考)

```
1. 校验 "AVTS" + 读 version
2. 解析 AVTS chunk 目录 (§3): 从 k=0 起, 块基址 0x80+k*0x400,
   读 name@+0x00 / size@+0x208 / file_offset@+0x20C, 直到越过 YABX 起始
   → 得到 YABX / DDS×N / VBO / IBO 各 chunk 的精确 (offset,size)
3. 解析 YABX (chunk[0]): 读 16B header (payload_size / hash)
   a. 顶层头 (tag+长串 ×2, 0x00, 短串根对象名)
   b. 命名空间表 (<短串><u32 id>… 直到 0x00)
   c. 类定义区: 循环 <短串类名><01><base_ref><00> + 字段(<短串名><u8 flag><u16 size>)… <00>
   d. 实例区: 每对象 <u16 tag=3><u32 body_size><body>; body 按"派生→基"序解字段
      (内联标量 / TLV 字符串 / ref-list <u32 size><u32 count><u16 ids>)
4. 用目录里的 VBO/IBO chunk (位于文件末尾) 配合实例的 _stride/_vertexNumber/
   _indexType 解出顶点/索引几何
5. 用目录里的 DDS chunk 直接切出贴图 (亦可搜 "DDS " magic 校验)
```

---

## 12. 待进一步逆向 (诚实标注)

- **每字段 `flag` (0/1) 精确语义**: 需逆向通用 yabukita **读取器** (schema → 类型树构建)。
  当前已知它**不影响字节布局** (布局由 inline_size 决定), 故不阻碍解包。
- **顶层两个 tag 字节 (0x04/0x07)**: 疑为根对象首两字段的类型/序号标记, 待读取器确认。
- **实例区精确字段顺序与对齐**: 已确认与 ruhuna RFZ 实例同构 (TLV + 内联标量 + localID),
  但 SVO 的多对象数组 (_mesh/_node[] 等) 嵌套展开顺序尚未逐字节走完全部对象。
- **AVTS 名称池内其余固定偏移指针** (除 0x288/0x28C 外是否还有) 未穷举。

> 旧文档 §1.1 提到的 `ceylon::resource::SVOLoader` / `air::SbSvoFileLoader` 等类名
> 来自早期符号/字符串检索, 本次未在 IDB 中以去修饰 C++ 名复核 (func_query 无命中),
> 暂保留为线索, 不作为已证实结论。

---

## 14. SVO 的完整用途 (★ 回答"是否只存贴图+模型" ★)

**结论: 否。SVO 是一个完整的 3D 场景容器 (full scene graph asset)**, 而不仅是
"一张贴图 + 一堆顶点"。从 §4.5 的 19 类 schema 可知, 单个 .svo 自包含以下全部信息:

### 14.1 场景图 / 骨骼层级 (Tree / Node)
`stevia::Tree` 持有 `_node[]` 列表; 每个 `stevia::Node` 用 `_parent/_child/_sibling`
(u16 localID) 构成树状层级, `_mesh` 引用挂在该节点的网格。每节点携带独立变换:
`_scale(vec3) / _rotation(欧拉vec3) / _quaternion(vec4) / _translation(vec3)`
以及 4 个矩阵 `_mtxLocal / _mtxWorld / _mtxWorldInv / _mtxBind(各 4×3)`。
→ 这就是**骨骼/关节体系**, 支持层级动画与世界/局部空间变换。

### 14.2 蒙皮 (Skinning)
`Node._mtxBind` (绑定姿势逆矩阵) + `State._maxInfluence` (每顶点最大骨骼影响数)
构成标准蒙皮管线所需数据。顶点经 mtxBind 反变换到骨骼空间, 按影响权重混合。

### 14.3 Morph / Blend-Shape (形变目标)
`Shape._blendTargetName` / `_blendTargetBindMatrix`, `Tree._blendTargetNumber`,
`Node._blendIndex` —— 一套混合形变 (表情/形状插值) 数据。

### 14.4 完整材质 / 着色器系统 (State + Parameter/Variant)
`stevia::State` 描述渲染状态 (混合因子/剔除/深度偏移/Alpha 参考/着色器名…),
并通过 `stevia::Parameter`(名→Variant) + `stevia::Variant`(f32/s32/color/string)
携带 **100+ 着色器参数** (§9: `sea*`/`ts*`/`rdcp*` 系列), 覆盖 UV 滚动、轮廓光、
菲涅尔、环境贴图、卡通分层混合等。→ SVO 自带完整外观, 不依赖外部材质文件。

### 14.5 贴图采样配置 (Texture / Image)
`Texture` 携带 wrap/filter/aniso/lodBias/uvSet 等采样器状态; `Image` 携带
height/width/format/mipmap/alphaMode 及 `_chunkFileName` 指向内嵌 DDS。

### 14.6 包围体与渲染排序 (剔除 / 排序)
`Shape._boundingSphere(球) + _boundingBoxCenter/_boundingBoxSize(盒)` 供视锥剔除;
`Mesh._sortGroup + Shape._sortDistanceOffset` 控制渲染排序;
`VertexBuffer._billboardType` 控制公告板朝向。

### 14.7 几何 (Mesh / Batch / VertexBuffer / IndexBuffer / VertexDeclaration)
绘制批次 (primitiveType/indexStart/indexNumber)、顶点缓冲 (stride/格式声明)、
索引缓冲 (UINT16/32)。真实数据块 (VBO/IBO) 在文件末尾, 由 AVTS 目录定位 (§3/§5)。

> **一句话**: .svo ≈ 一个微型 FBX/glTF —— 节点层级 + 蒙皮 + morph + 材质/着色器 +
> 采样器 + 包围体 + 排序 + 几何 + 内嵌纹理, 全部打包在一个文件里。贴图和网格只是其中两块。
> 大文件体量主要来自 DDS 纹理; 几何与场景图数据本身很小 (YABX payload 通常 ~16KB)。

---

## 15. 字体纹理 SVO 生成器 (`font/font_svo_pack.py`, 2026-06-14, 逐字节验证)

RFZ 字体的纹理段 (见 `rfz_unpack_spec.md §4.0`) 是一个**完整内嵌的 svo 容器**, 由资产管线
`HmfToSvo` 工具生成。它是 svo 的一个**退化特例**: 只含纹理 (Texture+Image), **无任何几何**
(VBO/IBO 缺席, VertexDeclaration/VertexElement 为空声明)。`font_svo_pack.py` 是该容器的
**可参数化重建器**, 支持任意页数 / 任意字体名 (旧 `rfz_pack.py` 只能整段模板复制纹理段)。

> **验证**: 对 14pt (2 页, AVTS v3) 与 240pt (1 页, AVTS v2) 两套源资产,
> `build_font_svo()` 产物与原始 `texture.svo` **逐字节一致** (内置 `--selftest`)。

### 15.1 对象布局 (localID 自 10001)

| localID | class_tag | 类 | 说明 |
|---------|-----------|----|----|
| 10001 | 3 | stevia::Database | 根; `_texture`/`_image`/`_vertexDeclaration` reflist |
| 10002 | 4 | stevia::VertexDeclaration "P" | 空 `_vertexElement` |
| 10003 | 5 | stevia::VertexElement | 固定空声明 |
| 10004 | 4 | stevia::VertexDeclaration "PN" | 空 |
| 10005/10006 | 5 | stevia::VertexElement ×2 | 固定空声明 |
| 10007+2p | 6 | stevia::Texture (页 p) | `_image`→Image; 采样器状态全默认 |
| 10008+2p | 7 | stevia::Image (页 p) | `_format=3`(ARGB4444), `_alphaMode=2`, `_flag=2`, `_dataSize`=DDS 字节数 |

VD/VE 这 5 个空对象 (实例 #1..#5) 是 `HmfToSvo` 工具恒发出的固定块, 各字体一致
(脚本以 146B base64 模板内嵌)。schema 区 (namespaces + 7 类定义) 同样字体无关, 以 787B base64 内嵌。

### 15.2 ★ 本次新确认的三处字节级细节 (旧 §3/§4 未覆盖) ★

1. **空字符串编码** (补充 §4.2): 空串 = `u32(2) + u16(0)` (inner 仅 2 字节, **无** `\0` 末尾);
   非空串才是 `u32(L+3) + u16(L+1) + chars + \0`。Texture 的 `_uvSetName`/`_attributeName`、
   Image 的 `_compressCustomOption` 等空字段均用前者。
2. **内层 YABX payload 对齐**: payload 末尾补零, 使 `(16 头 + payload)` 向上对齐到 **0x20**。
   补零**计入** `payload_size`(+0x08) 与 hash 的 CRC 覆盖范围。
   实测: 14pt payload 1984→2000 (补 16), 240pt 1588→1616 (补 28)。
3. **AVTS 目录条目的额外字段** (补充 §3.1, 旧文档只记 size@+0x208/offset@+0x20C):
   - `+0x200` u32 = **kind**: 内层 YABX=0, DDS 数据块=1。
   - `+0x204` u32 = **chunk 序号**: YABX=0, DDS 页=1,2,...。
   YABX 块这两字段恒为 0, 故旧文档未察觉。

### 15.3 hash = CRC-32/BZIP2

内层 YABX 的 hash(+0x0C) 经验证为 **CRC-32/BZIP2**(非反射, poly 0x04C11DB7,
init 0xFFFFFFFF, MSB-first, 末取反), 覆盖含对齐补零的整个 payload。
游戏仅当启动标志 bit2 置位才校验 (`sub_E91CC0` @ 大四应用.exe), 默认跳过, 但本器恒填正确值。

### 15.4 字段编码速查 (实例 body 内)

```
reflist : u32(4+2n) + u32(n) + n×u16(localID)        # 空表 = u32(4)+u32(0)
空串    : u32(2) + u16(0)
非空串  : u32(L+3) + u16(L+1) + chars + \0
u32     : 4 字节内联
ref     : u16 (localID)
对象帧  : u16(class_tag) + u32(body_size) + body
实例区头: u16(lead_a=0) + u16(obj_count=6+2×页数)
```

### 15.5 用法

```
python font_svo_pack.py <font_base> <page0.dds> [page1.dds ...] [-o out.svo]
  font_base 例: RFO_SEGAKAKUGOTHIC_DB_14pt  (= RHFONTDB 资源基名, 非 metadata.name)
python font_svo_pack.py --selftest <unpacked_dir>   # 与原 texture.svo 逐字节比对
```

> AVTS 头 version 随源资产工具版本而异 (实测 14pt=3, 240pt=2); 打包时若无参照默认 3,
> selftest 从参照 svo 的偏移 +4 读取并比对。

---

## 13. 参考

- `RE/rfz_unpack_spec.md` / `rfz_pack_spec.md`: YABX 容器 + ruhuna 实例同构参照, LZW 算法。
- IDA 函数: `Yb_ReadMagic_CreateProcessor`@0xE91400, `Yb_WriteString_LenPrefixed`@0xEA2BB0,
  `Yb_Finalize_PayloadSizeAndCRC`@0xE91300, `RuhunaFontDB_Serialize`@0xE91570,
  `Yb_CRC32_Table`@0x18FB268。
- [Microsoft DDS Format](https://docs.microsoft.com/en-us/windows/win32/direct3ddds/dx-graphics-dds-pguide)
