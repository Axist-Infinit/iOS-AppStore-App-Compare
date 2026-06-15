#!/usr/bin/env python3
"""
Generate the worked-example artifacts for the Android bundled-library matcher.

This produces, fully offline and deterministically, a realistic demo:

  * a small synthetic open-source library ("demolib") published across three
    versions as **JVM .class JARs** -- exactly how Maven Central / Google Maven
    ship a library (the reference corpus);

  * a candidate **APK** that bundles demolib 1.1.0 in **Dalvik .dex** form, with
    its packages/classes/members **renamed (obfuscated)** and version metadata
    absent, mixed in with unrelated "app" classes as noise -- exactly the hard
    case the matcher is built for.

Reference (JVM) and candidate (DEX) are built from the *same* structural class
specs, so the demo genuinely exercises the cross-format + obfuscation-resilient
matching path. Run ``run_demo.sh`` afterwards to score the candidate against the
corpus.

Pure standard library. No JVM, no Android SDK, no apktool/dex2jar required.
"""
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent


# ===========================================================================
# Shared structural specification (the single source of truth for both formats)
# ===========================================================================

@dataclass
class M:  # method spec
    name: str
    ret: str
    params: list[str]
    access: int


@dataclass
class F:  # field spec
    name: str
    desc: str
    access: int


@dataclass
class ClassSpec:
    name: str                       # internal name, e.g. "com/demolib/HttpClient"
    super_name: str                 # "" for java/lang/Object-less; here always set
    interfaces: list[str] = field(default_factory=list)
    fields: list[F] = field(default_factory=list)
    methods: list[M] = field(default_factory=list)
    access: int = 0x0001            # ACC_PUBLIC (interfaces add the flags below)


ACC_PUBLIC, ACC_PRIVATE, ACC_STATIC = 0x0001, 0x0002, 0x0008
ACC_INTERFACE, ACC_ABSTRACT = 0x0200, 0x0400

OBJ = "java/lang/Object"
STR = "Ljava/lang/String;"


def _http_client(extra_methods: list[M]) -> ClassSpec:
    return ClassSpec(
        "com/demolib/HttpClient", OBJ,
        fields=[F("timeout", "I", ACC_PRIVATE),
                F("pool", "Lcom/demolib/ConnectionPool;", ACC_PRIVATE)],
        methods=[
            M("<init>", "V", [], ACC_PUBLIC),
            M("newCall", "Lcom/demolib/Call;", ["Lcom/demolib/Request;"], ACC_PUBLIC),
            M("connect", "Z", [STR, "I"], ACC_PUBLIC),
        ] + extra_methods,
    )


_BASE_CLASSES = [
    ClassSpec(
        "com/demolib/Request", OBJ, interfaces=["java/io/Serializable"],
        fields=[F("url", STR, ACC_PRIVATE)],
        methods=[
            M("<init>", "V", [STR], ACC_PUBLIC),
            M("url", STR, [], ACC_PUBLIC),
            M("header", "Lcom/demolib/Request;", [STR, STR], ACC_PUBLIC),
        ],
    ),
    ClassSpec(
        "com/demolib/Call", OBJ, access=ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT,
        methods=[
            M("execute", "Lcom/demolib/Response;", [], ACC_PUBLIC | ACC_ABSTRACT),
            M("cancel", "V", [], ACC_PUBLIC | ACC_ABSTRACT),
        ],
    ),
    ClassSpec(
        "com/demolib/Response", OBJ,
        fields=[F("code", "I", ACC_PRIVATE), F("body", STR, ACC_PRIVATE)],
        methods=[
            M("<init>", "V", ["I"], ACC_PUBLIC),
            M("code", "I", [], ACC_PUBLIC),
            M("body", STR, [], ACC_PUBLIC),
        ],
    ),
    ClassSpec(
        "com/demolib/ConnectionPool", OBJ,
        fields=[F("max", "I", ACC_PRIVATE)],
        methods=[
            M("<init>", "V", [], ACC_PUBLIC),
            M("evictAll", "V", [], ACC_PUBLIC),
            M("size", "I", [], ACC_PUBLIC),
        ],
    ),
]

_INTERCEPTOR = ClassSpec(
    "com/demolib/Interceptor", OBJ, access=ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT,
    methods=[M("intercept", "Lcom/demolib/Response;", ["Lcom/demolib/Request;"],
              ACC_PUBLIC | ACC_ABSTRACT)],
)
_CACHE = ClassSpec(
    "com/demolib/Cache", OBJ,
    fields=[F("path", STR, ACC_PRIVATE)],
    methods=[
        M("<init>", "V", [STR], ACC_PUBLIC),
        M("get", "Lcom/demolib/Response;", ["Lcom/demolib/Request;"], ACC_PUBLIC),
        M("clear", "V", [], ACC_PUBLIC),
    ],
)
_DISPATCHER = ClassSpec(
    "com/demolib/Dispatcher", OBJ,
    fields=[F("running", "I", ACC_PRIVATE)],
    methods=[
        M("<init>", "V", [], ACC_PUBLIC),
        M("enqueue", "V", ["Lcom/demolib/Call;"], ACC_PUBLIC),
    ],
)

# Version corpus. 1.0.0 -> base; 1.1.0 adds Interceptor+Cache; 2.0.0 also adds
# Dispatcher AND changes HttpClient's shape (extra method) so its signature
# diverges from the 1.x line -- the structural change a version bump introduces.
LIB_VERSIONS: dict[str, list[ClassSpec]] = {
    "1.0.0": [_http_client([])] + _BASE_CLASSES,
    "1.1.0": [_http_client([])] + _BASE_CLASSES + [_INTERCEPTOR, _CACHE],
    "2.0.0": [_http_client([M("addInterceptor", "V", ["Lcom/demolib/Interceptor;"], ACC_PUBLIC)])]
             + _BASE_CLASSES + [_INTERCEPTOR, _CACHE, _DISPATCHER],
}

BUNDLED_VERSION = "1.1.0"   # what the candidate APK actually ships


# ===========================================================================
# Obfuscation: rename internal packages/classes/members; keep framework types.
# ===========================================================================

def obfuscate(specs: list[ClassSpec]) -> list[ClassSpec]:
    name_map = {s.name: f"a/{chr(ord('a') + i)}" for i, s in enumerate(specs)}

    def ren_type(desc: str) -> str:
        # rewrite array dims + Lcom/demolib/X; -> La/y;  (framework types untouched)
        arr = ""
        while desc.startswith("["):
            arr += "["
            desc = desc[1:]
        if desc.startswith("L") and desc.endswith(";"):
            inner = desc[1:-1]
            if inner in name_map:
                return arr + "L" + name_map[inner] + ";"
        return arr + desc

    def ren_internal(name: str) -> str:
        return name_map.get(name, name)

    out = []
    for s in specs:
        out.append(ClassSpec(
            name=ren_internal(s.name),
            super_name=ren_internal(s.super_name),
            interfaces=[ren_internal(i) for i in s.interfaces],
            # member names scrambled; constructors keep <init> (obfuscators do too)
            fields=[F(f"f{j}", ren_type(f.desc), f.access) for j, f in enumerate(s.fields)],
            methods=[M(m.name if m.name in ("<init>", "<clinit>") else f"m{j}",
                       ren_type(m.ret), [ren_type(p) for p in m.params], m.access)
                     for j, m in enumerate(s.methods)],
            access=s.access,
        ))
    return out


def noise_classes(n: int) -> list[ClassSpec]:
    """Unrelated 'app' classes so the candidate is a realistic superset."""
    out = []
    rets = ["V", "I", "Z", STR, "Ljava/lang/Object;"]
    for i in range(n):
        out.append(ClassSpec(
            f"x/app/N{i}", OBJ,
            fields=[F("f", "I", ACC_PRIVATE)] if i % 2 else [],
            methods=[
                M("<init>", "V", [], ACC_PUBLIC),
                M("run", rets[i % len(rets)], ["I"] * (i % 4), ACC_PUBLIC),
            ],
        ))
    return out


# ===========================================================================
# JVM .class writer
# ===========================================================================

def build_jvm_class(spec: ClassSpec) -> bytes:
    pool: list[bytes] = []
    utf8_idx: dict[str, int] = {}
    class_idx: dict[str, int] = {}

    def add(entry: bytes) -> int:
        pool.append(entry)
        return len(pool)   # 1-based index of the entry just added

    def utf8(s: str) -> int:
        if s not in utf8_idx:
            raw = s.encode("utf-8")
            utf8_idx[s] = add(struct.pack(">BH", 1, len(raw)) + raw)
        return utf8_idx[s]

    def cls(name: str) -> int:
        if name not in class_idx:
            n = utf8(name)
            class_idx[name] = add(struct.pack(">BH", 7, n))
        return class_idx[name]

    this_c = cls(spec.name)
    super_c = cls(spec.super_name) if spec.super_name else 0
    iface_c = [cls(i) for i in spec.interfaces]
    fields = [(f.access, utf8(f.name), utf8(f.desc)) for f in spec.fields]
    methods = [(m.access, utf8(m.name), utf8("(" + "".join(m.params) + ")" + m.ret))
               for m in spec.methods]

    out = bytearray()
    out += b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52)
    out += struct.pack(">H", len(pool) + 1)
    for e in pool:
        out += e
    out += struct.pack(">HHH", spec.access, this_c, super_c)
    out += struct.pack(">H", len(iface_c))
    for c in iface_c:
        out += struct.pack(">H", c)
    out += struct.pack(">H", len(fields))
    for acc, n, d in fields:
        out += struct.pack(">HHHH", acc, n, d, 0)
    out += struct.pack(">H", len(methods))
    for acc, n, d in methods:
        out += struct.pack(">HHHH", acc, n, d, 0)
    out += struct.pack(">H", 0)
    return bytes(out)


def build_jar(specs: list[ClassSpec], path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for s in specs:
            z.writestr(s.name + ".class", build_jvm_class(s))


# ===========================================================================
# Dalvik .dex writer (lax: valid enough for the kit's structural reader)
# ===========================================================================

def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _shorty(desc: str) -> str:
    return "L" if desc[0] in "[L" else desc


class DexBuilder:
    def __init__(self) -> None:
        self.strings: dict[str, int] = {}
        self.strings_l: list[str] = []
        self.types: dict[str, int] = {}
        self.types_l: list[str] = []
        self.protos: dict[tuple, int] = {}
        self.protos_l: list[tuple] = []      # (shorty, ret, params)
        self.fields: dict[tuple, int] = {}
        self.fields_l: list[tuple] = []      # (cls, type, name)
        self.methods: dict[tuple, int] = {}
        self.methods_l: list[tuple] = []     # (cls, proto_idx, name)
        self.classes: list[dict] = []

    def s(self, v: str) -> int:
        if v not in self.strings:
            self.strings[v] = len(self.strings_l)
            self.strings_l.append(v)
        return self.strings[v]

    def t(self, desc: str) -> int:
        if desc not in self.types:
            self.s(desc)
            self.types[desc] = len(self.types_l)
            self.types_l.append(desc)
        return self.types[desc]

    def proto(self, ret: str, params: tuple) -> int:
        key = (ret, params)
        if key not in self.protos:
            self.s(_shorty(ret) + "".join(_shorty(p) for p in params))
            self.t(ret)
            for p in params:
                self.t(p)
            self.protos[key] = len(self.protos_l)
            self.protos_l.append((_shorty(ret) + "".join(_shorty(p) for p in params), ret, params))
        return self.protos[key]

    def field(self, cls: str, typ: str, name: str) -> int:
        self.t(cls); self.t(typ); self.s(name)
        key = (cls, typ, name)
        if key not in self.fields:
            self.fields[key] = len(self.fields_l)
            self.fields_l.append(key)
        return self.fields[key]

    def method(self, cls: str, ret: str, params: tuple, name: str) -> int:
        pidx = self.proto(ret, params)
        self.t(cls); self.s(name)
        key = (cls, ret, params, name)
        if key not in self.methods:
            self.methods[key] = len(self.methods_l)
            self.methods_l.append((cls, pidx, name))
        return self.methods[key]

    def add_class(self, spec: ClassSpec) -> None:
        cls = "L" + spec.name + ";"
        self.t(cls)
        sup = ("L" + spec.super_name + ";") if spec.super_name else None
        if sup:
            self.t(sup)
        ifaces = ["L" + i + ";" for i in spec.interfaces]
        for i in ifaces:
            self.t(i)
        flds = [(self.field(cls, f.desc, f.name), f.access) for f in spec.fields]
        mtds = [(self.method(cls, m.ret, tuple(m.params), m.name), m.access, m.name)
                for m in spec.methods]
        self.classes.append({"cls": cls, "super": sup, "ifaces": ifaces,
                             "fields": flds, "methods": mtds, "access": spec.access})

    def build(self) -> bytes:
        ns, nt, npr = len(self.strings_l), len(self.types_l), len(self.protos_l)
        nf, nm, nc = len(self.fields_l), len(self.methods_l), len(self.classes)
        off_str = 112
        off_typ = off_str + ns * 4
        off_pro = off_typ + nt * 4
        off_fld = off_pro + npr * 12
        off_mth = off_fld + nf * 8
        off_cls = off_mth + nm * 8
        end_fixed = off_cls + nc * 32
        data_start = (end_fixed + 3) & ~3

        data = bytearray()

        # 1) type lists (4-aligned), deduped by tuple of type indices.
        type_list_off: dict[tuple, int] = {}

        def type_list(type_indices: tuple) -> int:
            if not type_indices:
                return 0
            if type_indices not in type_list_off:
                while (data_start + len(data)) % 4:
                    data.append(0)
                type_list_off[type_indices] = data_start + len(data)
                data.extend(struct.pack("<I", len(type_indices)))
                for ti in type_indices:
                    data.extend(struct.pack("<H", ti))
            return type_list_off[type_indices]

        proto_params_off = []
        for _shorty_s, _ret, params in self.protos_l:
            proto_params_off.append(type_list(tuple(self.types[p] for p in params)))
        class_iface_off = []
        for c in self.classes:
            class_iface_off.append(type_list(tuple(self.types[i] for i in c["ifaces"])))

        # 2) string data
        string_data_off = []
        for sval in self.strings_l:
            string_data_off.append(data_start + len(data))
            raw = sval.encode("utf-8")    # demo strings are ASCII -> MUTF-8 == UTF-8
            data.extend(_uleb(len(sval)))
            data.extend(raw)
            data.append(0)

        # 3) class data
        class_data_off = []
        for c in self.classes:
            if not c["fields"] and not c["methods"]:
                class_data_off.append(0)
                continue
            static_f = sorted((i, a) for i, a in c["fields"] if a & ACC_STATIC)
            inst_f = sorted((i, a) for i, a in c["fields"] if not (a & ACC_STATIC))
            direct_m = sorted((i, a) for i, a, n in c["methods"]
                              if (a & ACC_STATIC) or (a & ACC_PRIVATE) or n in ("<init>", "<clinit>"))
            virtual_m = sorted((i, a) for i, a, n in c["methods"]
                               if not ((a & ACC_STATIC) or (a & ACC_PRIVATE) or n in ("<init>", "<clinit>")))
            class_data_off.append(data_start + len(data))
            data.extend(_uleb(len(static_f)))
            data.extend(_uleb(len(inst_f)))
            data.extend(_uleb(len(direct_m)))
            data.extend(_uleb(len(virtual_m)))
            for group in (static_f, inst_f):
                prev = 0
                for idx, acc in group:
                    data.extend(_uleb(idx - prev)); prev = idx
                    data.extend(_uleb(acc))
            for group in (direct_m, virtual_m):
                prev = 0
                for idx, acc in group:
                    data.extend(_uleb(idx - prev)); prev = idx
                    data.extend(_uleb(acc))
                    data.extend(_uleb(0))   # code_off (none)

        # --- fixed sections ---
        sec = bytearray()
        for off in string_data_off:
            sec += struct.pack("<I", off)
        for desc in self.types_l:
            sec += struct.pack("<I", self.strings[desc])
        for j, (shorty, ret, params) in enumerate(self.protos_l):
            sec += struct.pack("<III", self.strings[shorty], self.types[ret], proto_params_off[j])
        for cls, typ, name in self.fields_l:
            sec += struct.pack("<HHI", self.types[cls], self.types[typ], self.strings[name])
        for cls, pidx, name in self.methods_l:
            sec += struct.pack("<HHI", self.types[cls], pidx, self.strings[name])
        for j, c in enumerate(self.classes):
            super_idx = self.types[c["super"]] if c["super"] else 0xFFFFFFFF
            sec += struct.pack("<IIIIIIII",
                               self.types[c["cls"]], c["access"], super_idx,
                               class_iface_off[j], 0xFFFFFFFF, 0,
                               class_data_off[j], 0)

        pad = bytes((data_start - end_fixed))
        body = sec + pad + bytes(data)

        header = bytearray(112)
        header[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", header, 32, 112 + len(body))   # file_size
        struct.pack_into("<I", header, 36, 112)               # header_size
        struct.pack_into("<I", header, 40, 0x12345678)        # endian_tag
        struct.pack_into("<I", header, 56, ns); struct.pack_into("<I", header, 60, off_str)
        struct.pack_into("<I", header, 64, nt); struct.pack_into("<I", header, 68, off_typ)
        struct.pack_into("<I", header, 72, npr); struct.pack_into("<I", header, 76, off_pro)
        struct.pack_into("<I", header, 80, nf); struct.pack_into("<I", header, 84, off_fld)
        struct.pack_into("<I", header, 88, nm); struct.pack_into("<I", header, 92, off_mth)
        struct.pack_into("<I", header, 96, nc); struct.pack_into("<I", header, 100, off_cls)
        struct.pack_into("<I", header, 104, len(data)); struct.pack_into("<I", header, 108, data_start)
        return bytes(header) + body


def build_apk(specs: list[ClassSpec], path: Path) -> None:
    dex = DexBuilder()
    for s in specs:
        dex.add_class(s)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", dex.build())
        z.writestr("AndroidManifest.xml", b"\x00demo")   # token noise


# ===========================================================================
# Orchestration
# ===========================================================================

def main() -> int:
    lib_dir = HERE / "lib_versions"
    app_dir = HERE / "app"
    lib_dir.mkdir(parents=True, exist_ok=True)
    app_dir.mkdir(parents=True, exist_ok=True)

    for version, specs in LIB_VERSIONS.items():
        jar = lib_dir / f"demolib-{version}.jar"
        build_jar(specs, jar)
        print(f"[+] reference (JVM JAR)  demolib {version}: {len(specs)} classes -> {jar.name}")

    candidate_specs = obfuscate(LIB_VERSIONS[BUNDLED_VERSION]) + noise_classes(40)
    apk = app_dir / "obfuscated-app.apk"
    build_apk(candidate_specs, apk)
    print(f"[+] candidate (DEX APK)  bundles demolib {BUNDLED_VERSION} obfuscated + 40 "
          f"app classes -> {apk.name}")
    print("[i] candidate has NO version metadata and renamed packages/classes/members.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
