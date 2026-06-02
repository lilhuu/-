Source: 鹅厂 ACE 反作弊机制小面积剖析(1).pdf
Pages: 22

---

<!-- Page 1 -->

# 鹅厂 ACE 反作弊机制小面积剖析 江树

今天看到朋友不小心截取到的 ShellCode，感兴趣的朋友可以自己分析，个人认为有略微不合理的几个部分
## 叠个甲

免责声明：

合法性声明：本报告所涉及的所有内容仅限于学术性分析和研究目的，绝不构成对任何公司、软件或行为的攻击、恶意破坏或侵犯
其合法权益。所有信息的分析和讨论均基于公开资料和个人研究，且并不代表任何组织、公司或其他团体的立场。

责任声明：报告中的所有分析均为个人观点和理解，作者不对任何由此报告引起的后果负责。报告的发布目的仅为提供信息交流、
技术研究和讨论，而非用于商业或任何非法用途。

免责声明：本报告并未包含任何形式的恶意内容或违反法律的行为。报告所提到的腾讯公司、ACE反作弊技术或其他公司/技术的
名称，均仅用于技术分析和讨论，不应视为对其品牌、产品或服务的负面评价。作者尊重所有知识产权和公司合法权益。

合理使用声明：本报告中引用的所有资料和技术分析内容，均以学术研究为目的，符合合理使用的原则。若报告中有任何侵犯他人
知识产权的部分，欢迎相关权利人联系我们，作者将根据要求进行适当的修改或删除。

不承担任何法律责任：作者不对使用本报告内容而可能引起的任何法律责任或纠纷承担责任，所有分析和讨论仅限于技术领域的公
开研究。
声明无关内容：本报告与腾讯公司及其相关子公司、产品无关，任何因使用报告内容而引起的法律纠纷，均由报告使用者自负。
## ShellCode 概括

感觉是 C++写完之后，在编译的时候编译的 PIC 代码，形成了一长段的 ShellCode ，我一直尝试寻找这样的项目，但
是始终没有特别完美的，希望鹅厂考虑考虑开源出来给我用用。 ShellCode 的分析一点也不复杂，没有了 tvm就是好
看，不过多的赘述逆向的流程，我们只看结论：
### 相关行为

行为 依据

远程配置下载 cfg_download_wininet_CCD99999 在 0x33778 解析 wininet.dll API，并使用 URL 字符串
http://down.qq.com/iedsafe/gdp/pub/CCD99999.dat。

配置完整性/解码 cfg_verify_hash_decompress_lznt1 在 0x23A09 验证 16 字节头，检查 payload_size == total_size - 16，调
用 cfg_payload_hash64 在 0x26C9C，并使用 RtlDecompressBufferEx。

应用使用痕迹收 collect_app_usage_registry_traces 在 0x44E72 调度多个注册表收集器用于 AppCompat Store、UserAssist、
集 MuiCache、AppSwitched 及相关列表。

AppCompat 执 collect_appcompat_store_paths 在 0x44FA1 引用 SOFTWARE\Microsoft\Windows
行历史 NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store，枚举字符串条目，检查可执行路径形式，
并附加匹配结果。

UserAssist 历史 collect_userassist_count_paths 在 0x476AD 引用
记录 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-
9926F41749EA}\Count，标准化解码条目，并记录路径匹配。

MuiCache 历史 collect_muicache_friendlyapp_paths 在 0x48B98 引用 SOFTWARE\Classes\Local
记录 Settings\Software\Microsoft\Windows\Shell\MuiCache，解析 .FriendlyAppName，并记录应用路径/名称匹配。

Explorer collect_featureusage_appswitched_paths 在 0x49E7B 引用
AppSwitched 历 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched，提取切换应用路径，并记
史记录 录匹配项。

---

<!-- Page 2 -->

行为 依据

IDA 私有使用历 collect_hexrays_ida_history 在 0x50EBA 引用 SOFTWARE\Hex-Rays\IDA\History 和 SOFTWARE\Hex-
史记录 Rays\IDA\History64 ，枚举值，过滤匹配逻辑，并附加结果。

规则匹配与记录 match_recent_tool_evidence_and_emit 在 0x13748 匹配包括 IDA Pro、 ELang59、 X64DBG、 CheatEngine、
发射 VMProtect 的标签，然后调用 emit_detection_record_if_context_matches 在 0xC55B 。

配置规则应用 match_rule_config_evidence_and_emit 在 0x155E8 应用解码后的规则配置条目并发射匹配记录。

detect_procmon_filter_ports 在 0x1FAEA 引用 \ProcessMonitor23Port 、 \ProcessMonitor24Port 和
反分析/取证检测 FilterConnectCommunicationPort ； detect_sysmon_procmon_artifacts 在 0x1B9A8 引用 Sysmon/Procmon 驱
动/设备/过滤路径。

提升的检查能力 enable_sedebug_privilege 在 0x4D5F6 引用 SeDebugPrivilege ，表示在进程/系统检查助手之前调整了特权。

### 函数总结

0x33778 -> cfg_download_wininet_CCD99999

0x23A09 -> cfg_verify_hash_decompress_lznt1

0x227E1 -> resolve_ntdll_compression_apis

0x26C9C -> cfg_payload_hash64

0x44E72 -> collect_app_usage_registry_traces

0x44FA1 -> collect_appcompat_store_paths

0x476AD -> collect_userassist_count_paths

0x48B98 -> collect_muicache_friendlyapp_paths

0x49E7B -> collect_featureusage_appswitched_paths

0x50EBA -> collect_hexrays_ida_history

0x13748 -> match_recent_tool_evidence_and_emit

0x155E8 -> match_rule_config_evidence_and_emit

0x1FAEA -> detect_procmon_filter_ports

0x1B9A8 -> detect_sysmon_procmon_artifacts

0x1B406 -> resolve_GetProcessMemoryInfo_psapi

0x4D5F6 -> enable_sedebug_privilege

0xC8B3 -> embedded_CCD99999_config_driver

0xC55B -> emit_detection_record_if_context_matches

0x1447B -> is_filetime_within_days
### 基本流程

embedded_CCD99999_config_driver 在 0xC8B3 包含或驱动一个 2737 字节的配置块路径，并调用下游配置/规则匹配
逻辑。

cfg_download_wininet_CCD99999 在 0x33778 可以从 down.qq.com 下载相同的规则块。

cfg_verify_hash_decompress_lznt1 在 0x23A09 验证/解压该块。

---

<!-- Page 3 -->

collect_app_usage_registry_traces 在 0x44E72 收集本地历史遗留物。

match_recent_tool_evidence_and_emit 在 0x13748 和 match_rule_config_evidence_and_emit 在 0x155E8 将
遗留物与标签/规则进行比较。

emit_detection_record_if_context_matches 在 0xC55B 在上下文匹配时通过回调/函数指针发射记录
## 关键函数分析
### 函数：0x155E8 match_rule_config_evidence_and_emit

#### 函数定位

入口：

0x155E8 match_rule_config_evidence_and_emit

调用方：

0x15553 sub_15553

#### 检测策略（不是了哥们你扫我工程项目干啥？）

1. 确认输入盘符路径有效。

2. 定位类似 X:$RECYCLE.BIN 的目录。

3. 枚举其中条目。

4. 对条目路径/名称做特征匹配。

5. 匹配一组工程/工具文件特征：

.sln -> VS2022

.dpr -> Delphi

.pro -> QT

.e -> ELang59

.i64 -> IDA Pro

.ct -> CheatEngine

.vprj -> HuoShan

.xpr -> Vivado

CMakeLists.txt -> CMake

6. 对命中的文件检查时间窗口，窗口为 0x5B4 = 1460 天。

7. 再检查上下文字符串匹配。

8. 调用 emit_detection_record_if_context_matches 生成检测记录。

#### 关键流程

sub_15553 会构造 A:\ 到 Z:\，逐个调用本函数

__int64 __fastcall sub_15553(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
__int64 result; // rax
unsigned __int16 i; // [rsp+20h] [rbp-18h]
unsigned __int16 v8[4]; // [rsp+28h] [rbp-10h] BYREF

---

<!-- Page 4 -->

__int64 v9; // [rsp+30h] [rbp-8h] BYREF

memset(v8, 0, sizeof(v8));
v8[1] = ':';
v8[2] = '\\';
for ( i = 'A'; ; ++i )
{
result = i;
if ( i > (unsigned int)'Z' ) //到Z盘才放过
break;
v8[0] = i; //当前选中盘符
match_rule_config_evidence_and_emit((__int64)&v9, a2, v8, a4, a5, a6);
}
return result;
}

关键全局变量：

dword_80F80 初始化标志
qword_80F90 全局基准路径/字符串对象
qword_80FA0 工具特征表，按 0x50 字节一个 entry
qword_80FB0 计数器，每 9 次触发一次 sub_5AF31(1)

依据：

0x15605 read dword_80F80
0x1561B write dword_80F80 |= 1
0x1562E qword_80F90 = sub_320A2(...)
0x15853 cmp qword_80FA0, 0
0x15861 alloc 0x2D0 bytes
0x1587B qword_80FA0 = allocated table
0x164CB qword_80FB0++
0x164EA qword_80FB0 % 9
0x164FA call sub_5AF31(1)

我们给出基于伪代码优化后的代码，大概是这样

void match_rule_config_evidence_and_emit(Context *ctx, wchar_t *root_path)
{
init_once_global_baseline();

if (!root_path || !qword_80F90)
return;

if (!same_drive_or_prefix(qword_80F90, root_path))
return;

if (!passes_global_path_filters(root_path))
return;

// 目标类似 "C:\$RECYCLE.BIN"
if (!ends_or_matches(root_path + 1, L":\\$RECYCLE.BIN"))
return;

DirList entries;
init_dir_list(&entries);

---

<!-- Page 5 -->

if (!enumerate_target_directory(&entries, root_path))
return;

RuleTable *table = get_or_build_tool_rule_table();

for each entry in entries {
ScratchBuf evidence_path;

// 第一组：entry 0..2，受 ctx->flag_28 影响
if (ctx->flag_28) {
for (i = 0; i < 3; i++) {
if (entry_matches_rule(ctx, entry, table[i]) &&
enrich_evidence(evidence_path, root_path, entry) &&
is_filetime_within_days(ctx, entry.filetime, 1460) &&
string_match(ctx->filter_at_30, evidence_path)) {
emit_detection_record(table[i].label, evidence_path, entry);
}
}
}

// 第二组：entry 3..7
for (i = 3; i < 8; i++) {
if (entry_matches_rule(ctx, entry, table[i]) &&
enrich_evidence(evidence_path, root_path, entry) &&
is_filetime_within_days(ctx, entry.filetime, 1460) &&
string_match(ctx->filter_at_30, evidence_path)) {
emit_detection_record(table[i].label, evidence_path, entry);
}
}

// 特殊规则：CMakeLists.txt -> CMake
if (entry_does_not_match("CMakeLists.txt") &&
enrich_evidence(evidence_path, root_path, entry) &&
is_filetime_within_days(ctx, entry.filetime, 1460) &&
string_match(ctx->filter_at_30, evidence_path)) {
emit_detection_record("CMake", evidence_path, entry);
}

// 递归/子条目处理
foreach child in entry.children {
enrich_evidence(evidence_path, root_path, child);
match_rule_config_evidence_and_emit(ctx, evidence_path);
}
}

cleanup(entries);
}

#### 逐段分析

##### 1.初始化全局基准

0x15605 mov eax, dword_80F80
0x1560B and eax, 1
0x15610 jnz 0x15635
0x15618 or eax, 1

---

<!-- Page 6 -->

0x1561B dword_80F80 = eax
0x15621 call sub_30AD3
0x15629 call sub_320A2
0x1562E qword_80F90 = rax

含义：

if (!(dword_80F80 & 1)) {
dword_80F80 |= 1;
qword_80F90 = build_global_baseline_path();
}

这是 once-init 模式。 qword_80F90 后面会拿来和当前 root_path 比较。

##### 2.参数和基准检查

0x15635 cmp arg_8, 0
0x15640 cmp qword_80F90, 0
0x1564A return

含义：

if (!root_path || !qword_80F90)
return;

##### 3.盘符/路径前缀检查

0x1564F 读取 qword_80F90[0]
0x1566C 读取 root_path[0]
0x15678 cmp
0x1567A jnz 0x157A0

含义：比较两个宽字符首字符，大概率是盘符。若当前盘符不等于基准盘符，跳到另一条路径检查逻辑。

随后多次调用：

0x15688 sub_320C1
0x156AD call [vtable+0x88]
0x156C3 sub_320E0
0x156E8 call [vtable+0x88]
0x156FE sub_3211E
0x15723 call [vtable+0x88]
0x15735 sub_320A2
0x1575A call [vtable+0x88]
0x1576C sub_320FF
0x15791 call [vtable+0x88]

这些是若干全局路径对象与 root_path 做比较。任一失败则：

0x1579B return

行为上是路径白名单/环境路径条件过滤。

---

<!-- Page 7 -->

##### 4.定位 $RECYCLE.BIN

0x157A0 引用 ":\$RECYCLE.BIN"
0x157AF call sub_15085
0x157B7 call sub_1530D
0x157C4 rax = root_path
0x157CC add rax, 2
0x157ED call [vtable+0x88]
0x157F5 如果不匹配则 return

含义：

target_suffix = L":\\$RECYCLE.BIN";
if (!compare(root_path + 1, target_suffix))
return;

这里 root_path 是宽字符串， add rax, 2 等于跳过第一个 wchar_t ，也就是把 C:\ 变成 :\ 开头再和
:\$RECYCLE.BIN 相关路径比
较。该函数明显面向回收站路径,残留路径检测。

##### 5.枚举目录

0x157FC init local object var_178
0x1581D call sub_23EBB(var_178, root_path, 1)
0x15822 保存返回值
0x1582D 如果失败 cleanup + return
0x15849 call sub_254BA
0x1584E var_3A0 = rax

含义：

DirEnum enum;
init(&enum);

if (!enumerate(root_path, recursive_or_flag_1))
return;

entries = get_entries(enum);

var_3A0 后面被 sub_10937 获取数量、 sub_10946 取元素，所以它是一个列表/数组对象。

##### 6.构造工具特征表

首次进入时：

0x15853 cmp qword_80FA0, 0
0x15861 alloc 0x2D0
0x1587B qword_80FA0 = allocated
0x158A3 memset(qword_80FA0, 0, 0x2D0)

随后按 0x50 stride 写入 9 个规则 entry 。每个 entry 至少包含两个字段：

entry + 0x00 文件名/扩展名模式

entry + 0x10 对应标签

---

<!-- Page 8 -->

具体表：

文件扩展名 对应工具 证据位置 工具位置

.sln VS2022 0x158B5 0x1591B

.dpr Delphi 0x15980 0x159E6

.pro QT 0x15A4B 0x15AB1

.e ELang59 0x15B16 0x15B7C

.i64 IDA Pro 0x15BE1 0x15C47

.ct CheatEngine 0x15CAC 0x15D12

.vprj HuoShan 0x15D77 0x15DDD

.xpr Vivado 0x15E42 0x15EA8

CMakeLists.txt CMake 0x15F0D 0x1645E

##### 7.第一组规则：entry 0~2

0x15FA7 读取 ctx+0x28
0x15FAD 如果为 0，跳过第一组
0x15FC7 j < 3

第一组只在 ctx->flag_28 为真时启用（说明认为他们的危害性次级），规则 index 是 0~2：

.sln / VS2022
.dpr / Delphi
.pro / Q

时间窗口过滤：

0x160CE mov r8d, 0x5B4
0x160E1 call is_filetime_within_days
0x5B4 = 1460 天 约 4 年窗口。

##### 8.第二组规则：entry 3~7

0x16172 j = 3
0x16186 j < 8

规则 index 是 3~7：

.e -> ELang59
.i64 -> IDA Pro
.ct -> CheatEngine
.vprj -> HuoShan
.xpr -> Vivado

这组不依赖 ctx+0x28 ，哦天啊，易语言和 CheatEngine 的危害性都已经相提并论了吗？

---

<!-- Page 9 -->

##### 9.记录输出函数

命中后进入：

0xC55B emit_detection_record_if_context_matches

其逻辑：

if (sub_60B1D(unk_80200, context_string)) {
if (*callback)
callback(...);
}

所以 0x155E8 并不直接上传/写出，它调用一个回调式输出器。这个输出器会先检查上下文是否匹配，再调用外部回调写
入检测结果。好棒的设计模式，感觉几年代码白写了。
### 函数：0x13748 match_recent_tool_evidence_and_emit

__int64 __fastcall match_recent_tool_evidence_and_emit(
_BYTE *ctx,
int a2,
int unused_or_temp,
__int64 scan_ctx,
int a5,
int a6
);

scan_ctx 很关键：

scan_ctx + 40 ：本函数设置的“已发现工具痕迹”标志。

scan_ctx + 48 ：路径/上下文匹配表，传给 sub_60B1D。

scan_ctx + 64 ：当前 Unix 时间秒，用于和 FILETIME 转换后的时间比较。

#### 检测条件

1.最近 1460 天内出现过

2.路径/字符串命中上下文规则

#### 主扫描流程（这里的检测就很合理了，用于检测“作弊开发者”）

函数先初始化一个 5 槽容器 v426，然后按类别依次收集和遍历：

标签 收集来源 说明

IDA Pro collect_hexrays_ida_history枚举 SOFTWARE\Hex-Rays\IDA\History 和 SOFTWARE\Hex-
Rays\IDA\History64

ELang59 sub_56E08 关联字符串 SOFTWARE\FlySky\E\Recent File List

X64DBG sub_575EB 解析 x64dbg 配置/近期文件痕迹，出现 [Recent Files]、
Breakpoint、Disassembly

CheatEngine sub_58826 收集 Cheat Engine 相关近期痕迹

---

<!-- Page 10 -->

标签 收集来源 说明

VMProtect sub_59A89 读取 %ls\VMProtect Software\VMProtect\VMProtect.dat，解
析 ... 项

#### 整体伪代码

init_tool_lists(lists);

ida_list = collect_hexrays_ida_history(lists);
scan_and_emit(ida_list, "IDA Pro");

elang_list = collect_elang_recent_files(lists);
scan_and_emit(elang_list, "ELang59");

x64dbg_list = collect_x64dbg_recent_files(lists);
scan_and_emit(x64dbg_list, "X64DBG");

ce_list = collect_cheatengine_recent_files(lists);
scan_and_emit(ce_list, "CheatEngine");

vmp_list = collect_vmprotect_projects(lists);
scan_and_emit(vmp_list, "VMProtect");

if (scan_ctx->found_any_tool_evidence) {
vs_list = collect_vs2022_recent_evidence();
scan_and_emit(vs_list, "VS2022");

exec_history = collect_app_usage_registry_traces();
for each item in exec_history:
if (!is_allowlisted_by_qword_80DB0(item))
emit(item, "ExecuteHistroy");
}

cleanup(lists);
return 1;
## 云配置解密

http://down.qq.com/iedsafe/gdp/pub/CCD99999.dat 是加密的文件，解密流程较为简单，完全在 ShellCode 中

解密后的结果是这样的，是一套完整的规则，用于 ACE 进一步的检测

{
"index": 17,
"offset": 1558,
"size": 76,
"count": 7,
"rule_id": 2248395492402470350,
"strings": [
{
"offset": 0,
"group_id": 2,
"raw_hex": "c7ece1e5f0c1eae3edeae1",
"decoded": "CheatEngine"

---

<!-- Page 11 -->

},
{
"offset": 17,
"group_id": 2,
"raw_hex": "e5f4f4e0e5f0e5d8e8ebe7e5e8d8f0e1e9f4",
"decoded": "appdata\\local\\temp"
},
{
"offset": 41,
"group_id": null,
"raw_hex": "f7f0f6f1e7f0f1f6e1f7aaf7f5e8edf0e1",
"decoded": "structures.sqlite"
}
]
}

### 结论

地址 当前名称 角色

0x33778 cfg_download_wininet_CCD99999 下载配置并将下载的字节传递给解码器。

0x227E1 resolve_ntdll_compression_apis 解析 ntdll 的压缩导出函数。

0x23A09 cfg_verify_hash_decompress_lznt1 解析头部，验证大小/哈希，分配缓冲区，调用解压函
数。

0x26C9C cfg_payload_hash64 自定义64位完整性哈希。

### 容器格式

.dat 容器以固定的16字节小端头开始：

struct CCD99999_HEADER {
uint32_t compressed_size; // +0x00
uint32_t decompressed_size; // +0x04
uint64_t payload_hash; // +0x08
};

uint8_t payload[compressed_size]; // 从+0x10开始

对于当前文件：

文件大小 = 2737
压缩大小 = 2721
解压大小 = 4394
负载哈希 = 0x19ED88DA92FCA61F
负载偏移 = 0x10
负载大小 = 2737 - 16 = 2721

### 下载路径

功能： cfg_download_wininet_CCD99999 在 0x33778 。

引用的字符串：

---

<!-- Page 12 -->

0x8C810 : %ls\wininet.dll

0x8C830 : InternetOpenW

0x8C840 : InternetOpenUrlW

0x8C858 : InternetReadFile

0x8C878 : InternetCloseHandle

0x8C890 : VMS

0x841B0 : http://down.qq.com/iedsafe/gdp/pub/CCD99999.dat

代码证据：

0x3384C 解析 "InternetOpenW"
0x3388A 解析 "InternetOpenUrlW"
0x338C8 解析 "InternetReadFile"
0x33906 解析 "InternetCloseHandle"
0x339AB 调用 InternetOpenW(..., L"VMS", ...)
0x339E7 调用 InternetOpenUrlW(..., url, ...)
0x33A17 循环调用 InternetReadFile(..., 0x10000, &bytes_read)
0x33C20 调用 resolve_ntdll_compression_apis(..., 2, ...)
0x33C40 调用 cfg_verify_hash_decompress_lznt1(downloaded_blob, api_ctx, downloaded_size)

手动推论：如果使用本地 CCD99999.dat 文件，解码器可以跳过这一步。下载的字节是输入到相同的验证/解压函数中
的。
### 压缩API解析器

功能： resolve_ntdll_compression_apis 在 0x227E1 。

引用的字符串：

0x89118 : RtlCompressBuffer

0x89130 : RtlDecompressBufferEx

0x89148 : RtlGetCompressionWorkSpaceSize

代码证据：

0x228A4 构建/加载 "ntdll.dll"
0x228CA 解析 "RtlCompressBuffer"
0x228EC 将解析的指针存储在 api_ctx + 0x30
0x228FC 解析 "RtlDecompressBufferEx"
0x2291E 将解析的指针存储在 api_ctx + 0x38
0x2292E 解析 "RtlGetCompressionWorkSpaceSize"
0x22950 将解析的指针存储在 api_ctx + 0x40

在 0x33C20 的调用：

0x33C13 mov ... 2
0x33C20 调用 resolve_ntdll_compression_apis

Windows的压缩格式 2 对应 COMPRESSION_FORMAT_LZNT1 。

---

<!-- Page 13 -->

### 头部验证

功能： cfg_verify_hash_decompress_lznt1 在 0x23A09 。

相关指令：

0x23A2C cmp blob, 0
0x23A37 cmp total_size, 0
0x23A50 cmp qword ptr [api_ctx+0x30], 0
0x23A5F cmp qword ptr [api_ctx+0x38], 0
0x23A6E cmp qword ptr [api_ctx+0x40], 0
0x23A83 cmp total_size, 0x10
0x23AA2 mov eax, [blob+0x00] ; compressed_size
0x23AAB sub total_size, 0x10
0x23AAF cmp compressed_size, total_size-0x10
0x23AC3 add blob, 0x10 ; payload 指针
0x23AE9 mov rax, [blob_header+0x08] ; 存储哈希
0x23AED cmp calculated_hash, stored_hash

等效验证：

if (blob == NULL || total_size == 0)
fail;
if (!api_ctx->RtlCompressBuffer ||
!api_ctx->RtlDecompressBufferEx ||
!api_ctx->RtlGetCompressionWorkSpaceSize)
fail;
if (total_size < 0x10)
fail;

compressed_size = read_u32_le(blob + 0x00);
decompressed_size = read_u32_le(blob + 0x04);
stored_hash = read_u64_le(blob + 0x08);
payload = blob + 0x10;

if (compressed_size != total_size - 0x10)
fail;

Python 等效：

if len(raw) < 16:
raise ValueError("too small")

compressed_size = int.from_bytes(raw[0:4], "little")
decompressed_size = int.from_bytes(raw[4:8], "little")
stored_hash = int.from_bytes(raw[8:16], "little")
payload = raw[16:]

if compressed_size != len(payload):
raise ValueError("payload size mismatch")

### 自定义哈希算法

功能： cfg_payload_hash64 在 0x26C9C 。

调用位置：

---

<!-- Page 14 -->

0x23AD3 mov edx, compressed_size
0x23AD5 mov rcx, payload
0x23ADA 调用 cfg_payload_hash64
0x23AED cmp calculated_hash, [header+0x08]

在 0x26C9C 内部的指令级证据：

0x26CC1 h = 0
0x26CCA i = 0
0x26CDF 比较 i 与 size
0x26CE9 i & 1

偶数索引路径：
0x26CF5 h << 7
0x26D02 加载 payload[i]
0x26D06 与字节进行异或
0x26D0E h >> 3
0x26D12 异或
0x26D15 混合 = 结果

奇数索引路径：
0x26D21 h << 0x0B
0x26D2E 加载 payload[i]
0x26D32 与字节进行异或
0x26D3A h >> 5
0x26D3E 异或
0x26D41 非 rax
0x26D44 混合 = 结果

公共路径：
0x26D53 h ^= 混合
0x26D63 mask 0x7FFFFFFFFFFFFFFF
0x26D7D 比较与 0x1000000000000000
0x26D9D 当低于阈值时加上 0x1000000000000000

C样式等效算法：

uint64_t ccd_hash64(const uint8_t *payload, uint64_t size) {
if (!payload || !size)
return 0;

uint64_t h = 0;
for (uint64_t i = 0; i < size; i++) {
uint64_t b = payload[i];
uint64_t mixed;

if (i & 1)
mixed = ~((h >> 5) ^ b ^ (h << 11));
else
mixed = ((h >> 3) ^ b ^ (h << 7));

h ^= mixed;
}

h &= 0x7FFFFFFFFFFFFFFFULL;
if (h < 0x1000000000000000ULL)

---

<!-- Page 15 -->

h += 0x1000000000000000ULL;

return h;
}

Python等效：

def ccd_hash64(payload: bytes) -> int:
if not payload:
return 0

h = 0
mask = 0xFFFFFFFFFFFFFFFF

for i, b in enumerate(payload):
if i & 1:
mixed = ~(((h >> 5) ^ b ^ ((h << 11) & mask)) & mask)
else:
mixed = (h >> 3) ^ b ^ ((h << 7) & mask)

h = (h ^ mixed) & mask

h &= 0x7FFFFFFFFFFFFFFF
if h < 0x1000000000000000:
h += 0x1000000000000000
return h

对于当前样本：

ccd_hash64(raw[0x10:]) = 0x19ED88DA92FCA61F

### 工作区和输出分配

功能： cfg_verify_hash_decompress_lznt1 在 0x23A09 。

工作区调用：

0x23B15 读取压缩格式来自 api_ctx+0x00
0x23B28 调用 qword ptr [api_ctx+0x40] ; RtlGetCompressionWorkSpaceSize
0x23B2F 检查 NTSTATUS >= 0
0x23B43 分配工作区大小
0x23B5A 存储工作区指针到 api_ctx+0x08

输出分配：

0x23B7D mov eax, [header+0x04] ; decompressed_size
0x23B8A div 0x1000
0x23B91 imul eax, 0x1000
0x23B97 add eax, 0x2000
0x23BB3 分配输出分配大小
0x23BD4 存储输出指针到 api_ctx+0x20
0x23BFA 存储解压缩大小到 api_ctx+0x28

等效：

---

<!-- Page 16 -->

RtlGetCompressionWorkSpaceSize(format, &workspace_size, &fragment_size);

decompressed_size = read_u32_le(blob + 0x04);
output_alloc_size = (decompressed_size / 0x1000) * 0x1000 + 0x2000;
output = alloc(output_alloc_size);
memset(output, 0, output_alloc_size);

对于当前样本：

decompressed_size = 4394 = 0x112A
output_alloc_size = (0x112A / 0x1000) * 0x1000 + 0x2000
= 0x1000 + 0x2000
= 0x3000

### LZNT1解压

功能： cfg_verify_hash_decompress_lznt1 在 0x23A09 。

调用证据：

0x23C2F r9 = payload 指针
0x23C3C r8d = decompressed_size
0x23C48 rdx = output 指针
0x23C54 ecx = 压缩格式
0x23C5F 调用 qword ptr [api_ctx+0x38] ; RtlDecompressBufferEx
0x23C66 检查状态 >= 0
0x23C82 比较最终大小与解压缩大小
0x23CA3 成功时返回 api_ctx + 0x20

目标 Windows 调用是：

NTSTATUS RtlDecompressBufferEx(
USHORT CompressionFormat, // 2 = LZNT1
PUCHAR UncompressedBuffer, // 输出
ULONG UncompressedBufferSize, // 解压后的大小来自头部
PUCHAR CompressedBuffer, // payload 在 blob+0x10
ULONG CompressedBufferSize, // 压缩大小来自头部
PULONG FinalUncompressedSize, // 本地 final_size
PVOID WorkSpace // 之前分配的工作区
);

Python等效：

import ctypes
from ctypes import POINTER, byref, c_ulong, c_ushort, c_void_p

COMPRESSION_FORMAT_LZNT1 = 2

def rtl_lznt1_decompress(payload: bytes, decompressed_size: int) -> bytes:
ntdll = ctypes.WinDLL("ntdll")

get_workspace = ntdll.RtlGetCompressionWorkSpaceSize
get_workspace.argtypes = [c_ushort, POINTER(c_ulong), POINTER(c_ulong)]
get_workspace.restype = c_ulong

---

<!-- Page 17 -->

decompress = ntdll.RtlDecompressBufferEx
decompress.argtypes = [
c_ushort,
c_void_p,
c_ulong,
c_void_p,
c_ulong,
POINTER(c_ulong),
c_void_p,
]
decompress.restype = c_ulong

workspace_size = c_ulong(0)
fragment_size = c_ulong(0)
status = get_workspace(COMPRESSION_FORMAT_LZNT1, byref(workspace_size),
byref(fragment_size))
if status:
raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")

output_alloc_size = (decompressed_size // 0x1000) * 0x1000 + 0x2000
output = ctypes.create_string_buffer(output_alloc_size)
workspace = ctypes.create_string_buffer(max(workspace_size.value, fragment_size.value, 1))
final_size = c_ulong(0)

status = decompress(
COMPRESSION_FORMAT_LZNT1,
output,
output_alloc_size,
ctypes.c_char_p(payload),
len(payload),
byref(final_size),
workspace,
)
if status:
raise RuntimeError(f"RtlDecompressBufferEx failed: 0x{status:08X}")
if final_size.value != decompressed_size:
raise RuntimeError(f"decoded size mismatch: {final_size.value} != {decompressed_size}")

return output.raw[:final_size.value]

### 完整手动解码器

import ctypes
from ctypes import POINTER, byref, c_ulong, c_ushort, c_void_p
from pathlib import Path

COMPRESSION_FORMAT_LZNT1 = 2
MASK64 = 0xFFFFFFFFFFFFFFFF

def read_u32le(b: bytes, off: int) -> int:
return int.from_bytes(b[off:off + 4], "little")

def read_u64le(b: bytes, off: int) -> int:
return int.from_bytes(b[off:off + 8], "little")

def ccd_hash64(payload: bytes) -> int:
if not payload:

---

<!-- Page 18 -->

return 0

h = 0
for i, byte in enumerate(payload):
if i & 1:
mixed = ~(((h >> 5) ^ byte ^ ((h << 11) & MASK64)) & MASK64)
else:
mixed = (h >> 3) ^ byte ^ ((h << 7) & MASK64)
h = (h ^ mixed) & MASK64

h &= 0x7FFFFFFFFFFFFFFF
if h < 0x1000000000000000:
h += 0x1000000000000000
return h

def lznt1_decompress(payload: bytes, decompressed_size: int) -> bytes:
ntdll = ctypes.WinDLL("ntdll")

get_workspace = ntdll.RtlGetCompressionWorkSpaceSize
get_workspace.argtypes = [c_ushort, POINTER(c_ulong), POINTER(c_ulong)]
get_workspace.restype = c_ulong

decompress = ntdll.RtlDecompressBufferEx
decompress.argtypes = [
c_ushort,
c_void_p,
c_ulong,
c_void_p,
c_ulong,
POINTER(c_ulong),
c_void_p,
]
decompress.restype = c_ulong

workspace_size = c_ulong(0)
fragment_size = c_ulong(0)
status = get_workspace(COMPRESSION_FORMAT_LZNT1, byref(workspace_size),
byref(fragment_size))
if status:
raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")

output_alloc_size = (decompressed_size // 0x1000) * 0x1000 + 0x2000
output = ctypes.create_string_buffer(output_alloc_size)
workspace = ctypes.create_string_buffer(max(workspace_size.value, fragment_size.value, 1))
final_size = c_ulong(0)

status = decompress(
COMPRESSION_FORMAT_LZNT1,
output,
output_alloc_size,
ctypes.c_char_p(payload),
len(payload),
byref(final_size),
workspace,
)
if status:
raise RuntimeError(f"RtlDecompressBufferEx failed: 0x{status:08X}")
if final_size.value != decompressed_size:

---

<!-- Page 19 -->

raise RuntimeError("decompressed size mismatch")

return output.raw[:final_size.value]

def decode_ccd99999_dat(path: str) -> bytes:
raw = Path(path).read_bytes()
if len(raw) < 0x10:
raise ValueError("file too small")

compressed_size = read_u32le(raw, 0x00)
decompressed_size = read_u32le(raw, 0x04)
stored_hash = read_u64le(raw, 0x08)
payload = raw[0x10:]

if compressed_size != len(payload):
raise ValueError("compressed size mismatch")

calculated_hash = ccd_hash64(payload)
if calculated_hash != stored_hash:
raise ValueError(f"hash mismatch: {calculated_hash:016X} != {stored_hash:016X}")

return lznt1_decompress(payload, decompressed_size)

if __name__ == "__main__":
decoded = decode_ccd99999_dat("CCD99999.dat")
Path("CCD99999.decoded.manual.bin").write_bytes(decoded)
print(len(decoded))

### 验证值

输入文件大小 : 2737
负载偏移 : 0x10
负载大小 : 2721
头部压缩大小 : 2721
头部解压大小 : 4394
头部哈希 : 0x19ED88DA92FCA61F
计算的哈希 : 0x19ED88DA92FCA61F
解码大小 : 4394
解码 SHA256 : 216b779814821dc22399aa224e5c68d6af4b20890410eb01634860a50431b534

### 还原为文本

在外部容器解码后，输出并非纯文本，而是一个紧凑的二进制规则表。当前解码的 Blob 直接以规则块开始。由于内部解
析比外部解码的证据较弱，因为完整的规则消费者尚未完全类型化，但它是可复现的，并且与
match_rule_config_evidence_and_emit （ 0x155E8 ）中的规则消费者行为以及观察到的块布局相匹配。

#### 块布局

观察到的规则块格式：

---

<!-- Page 20 -->

struct RULE_BLOCK {
uint32_t block_size; // 总块大小，包括此16字节头
uint32_t count; // 规则条件/组计数
uint64_t rule_id; // 稳定的规则ID/哈希值
uint8_t body[]; // block_size - 16字节
};

解析器遍历：

p = 0
while p + 16 <= len(decoded):
while p < len(decoded) and decoded[p] == 0:
p += 1

size = u32le(decoded[p:p+4])
count = u32le(decoded[p+4:p+8])
rule_id = u64le(decoded[p+8:p+16])

if size < 16 or size > len(decoded) - p:
stop

body = decoded[p+16:p+size]
parse body fields
p += size

对于当前解码的 Blob：

decoded_size = 4394
first block offset = 0x0000
first block size = 0x33 / 51
parsed blocks = 54

#### 字符串编码

规则字符串是按字节进行 XOR 编码的，使用密钥 0x84 。

decoded_string_bytes = bytes(encoded_byte ^ 0x84 for encoded_byte in encoded_bytes)

脚本使用两种字段形式：

形式 A：

uint32_t group_id; // 如果 <= 0xFF 时被接受
uint16_t length;
uint8_t xor84_bytes[length];

形式 B：

uint16_t length;
uint8_t xor84_bytes[length];

形式 A 通常标记规则条件中的第一个字符串字段。形式 B 用于捕获组字段后面的子字段。

---

<!-- Page 21 -->

#### 具体示例

规则 0 从解码偏移量 0x0000 开始：

offset 0x0000:
33 00 00 00 block_size = 0x33 / 51
04 00 00 00 count = 4
94 6F CE 3C 0C F7 90 11 rule_id = 0x1190F70C3CCE6F94

规则 0 的正文：

02 00 00 00 07 00 CD C0 C5 A4 D4 F6 EB
02 00 00 00 07 00 ED E0 E5 AA E0 E8 E8
07 00 ED E0 E5 AA EF E1 FD

字段解码：

形式 A: group_id=2, len=7, raw=CD C0 C5 A4 D4 F6 EB
XOR 84: 49 44 41 20 50 72 6F = "IDA Pro"

形式 A: group_id=2, len=7, raw=ED E0 E5 AA E0 E8 E8
XOR 84: 69 64 61 2E 64 6C 6C = "ida.dll"

形式 B: len=7, raw=ED E0 E5 AA EF E1 FD
XOR 84: 69 64 61 2E 6B 65 79 = "ida.key"

规则 1 从解码偏移量 0x0033 开始：

size=83, count=1, id=0x121C651C8D020554

恢复的字段：

raw=C0 E6 E3 D2 ED E1 F3 -> "DbgView"
raw=E0 E6 E3 F2 ED E1 F3 C7 E8 E5 F7 F7 -> "dbgviewClass"

规则 2 从解码偏移量 0x0086 开始：

size=52, count=5, id=0x138C87762B5C389F

恢复的字段：

raw=C1 C8 E5 EA E3 B1 BD -> "ELang59"
raw=D7 EB E2 F0 F3 E5 F6 E1 D8 C2 E8 FD D7 EF FD D8 C1 -> "Software\FlySky\E"

#### 字符串恢复脚本

def xor84(data: bytes) -> bytes:
return bytes(b ^ 0x84 for b in data)

def parse_rule_strings(body: bytes):
i = 0
out = []

---

<!-- Page 22 -->

n = len(body)

while i < n:
if i + 6 <= n:
group_id = int.from_bytes(body[i:i+4], "little")
length = int.from_bytes(body[i+4:i+6], "little")
if group_id <= 0xFF and 0 < length < 200 and i + 6 + length <= n:
raw = body[i+6:i+6+length]
out.append((i, group_id, xor84(raw)))
i += 6 + length
continue

if i + 2 <= n:
length = int.from_bytes(body[i:i+2], "little")
if 0 < length < 200 and i + 2 + length <= n:
raw = body[i+2:i+2+length]
out.append((i, None, xor84(raw)))
i += 2 + length
continue

i += 1

return out
