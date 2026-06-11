#!/usr/bin/env python3
"""
Obfuscation-resilient fingerprinting and version matching for Android/JVM
open-source libraries.

The matching problem
--------------------
You have a compiled library bundled inside an app. Its version metadata has been
stripped and its names have been obfuscated by R8/ProGuard. You want to know
*which* open-source library it is and, more usefully, *which version*, so you
can map it to known CVEs / license terms.

Why this works despite obfuscation
----------------------------------
R8/ProGuard rename a library's *own* packages, classes and members. They do
**not**, and structurally cannot:

  * rename references to the platform/runtime SDK (``java/*``, ``javax/*``,
    ``android/*``, ``kotlin/*`` ...), because those symbols are resolved against
    code the obfuscator does not own;
  * change the *shape* of the code -- how many methods/fields a class has, how
    many arguments each method takes, the primitive-vs-reference shape of each
    signature, or the class/interface relationships.

So we build, for each class, a signature out of exactly the things obfuscation
preserves:

  * each method as ``(normalized-access, descriptor-with-internal-types-wildcarded)``
  * each field as ``(normalized-access, type-with-internal-types-wildcarded)``
  * the framework-anchored super/interface shape.

Internal (renamable) types collapse to a single wildcard token ``L*;`` while
framework types are kept verbatim. The class's own name is discarded. The result
is a 64-bit *class signature* that is identical for the same class before and
after obfuscation, and identical whether it was compiled to JVM ``.class`` or
Dalvik ``.dex`` -- both share the descriptor grammar.

A *library-version profile* is the set of class signatures for that version
(plus surviving string-constant anchors). Matching an unknown app against the
corpus reduces to set-containment: how many of a reference version's class
signatures are present in the app.

  * ``containment`` = |ref ∩ cand| / |ref|   -> "is this library present, and
    how completely?" (the app is a superset: library + app code + other libs).
  * Among versions of the same library that clear a presence threshold, the one
    with the highest containment -- tie-broken by exclusive-signature coverage
    and string-anchor overlap -- is the bundled version.

This is the LibScout/LibRadar family of techniques, reduced to the standard
library and to the parts that survive aggressive obfuscation.

Pure standard library only.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from android_bytecode import ClassUnit, MethodInfo, FieldInfo

PROFILE_SCHEMA = "android-library-structural-profile-v1"

# Type prefixes the obfuscator leaves untouched -- our stable anchors. Anything
# else is treated as library/app-internal and wildcarded.
STABLE_TYPE_PREFIXES: tuple[str, ...] = (
    "java/", "javax/", "android/", "androidx/", "dalvik/", "sun/",
    "org/w3c/", "org/xml/", "org/json/", "org/apache/http/", "org/xmlpull/",
    "junit/", "kotlin/", "kotlinx/",
)

# Access-flag bits that are semantically stable across JVM<->DEX and across
# obfuscation. (synthetic/bridge/varargs bits are intentionally excluded.)
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_ENUM = 0x4000
_STABLE_ACCESS_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC |
                       ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT | ACC_ENUM)

# MinHash configuration for fast pre-screening of large corpora.
MINHASH_K = 64
_MIX = 0x9E3779B97F4A7C15
_MASK64 = (1 << 64) - 1

_TYPE_TOKEN_RE = re.compile(r"\[*(?:L[^;]*;|[VZBSCIJFD])")


def _is_stable_type(internal_or_desc: str) -> bool:
    name = internal_or_desc
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    name = name.lstrip("[")
    if name.startswith("L"):
        name = name[1:]
    return name.startswith(STABLE_TYPE_PREFIXES)


def normalize_type(desc: str) -> str:
    """Normalize a single type descriptor, wildcarding internal reference types.

    Primitives and array dimensionality are preserved exactly. Reference types
    are kept verbatim when they belong to a stable (framework) package, else
    collapsed to ``L*;``. Array element types are normalized in place.
    """
    arr = 0
    while desc[arr:arr + 1] == "[":
        arr += 1
    prefix = "[" * arr
    base = desc[arr:]
    if base.startswith("L") and base.endswith(";"):
        inner = base[1:-1]
        if inner.startswith(STABLE_TYPE_PREFIXES):
            return prefix + base
        return prefix + "L*;"
    # primitive (V Z B S C I J F D) or already-degenerate -- keep as-is.
    return prefix + base


def normalize_descriptor(descriptor: str) -> str:
    """Normalize every type token inside a method descriptor ``(args)ret``."""
    if "(" not in descriptor:
        return normalize_type(descriptor) if descriptor else ""
    args_part = descriptor[descriptor.index("(") + 1:descriptor.rindex(")")]
    ret_part = descriptor[descriptor.rindex(")") + 1:]
    args = [normalize_type(t) for t in _TYPE_TOKEN_RE.findall(args_part)]
    return "(" + "".join(args) + ")" + normalize_type(ret_part)


def _normalize_access(access: int) -> int:
    return access & _STABLE_ACCESS_MASK


def _method_token(m: MethodInfo) -> str:
    # Constructors/static-initializers keep their (stable) special names; every
    # other name is obfuscation-noise and dropped.
    special = m.name if m.name in ("<init>", "<clinit>") else ""
    return f"{_normalize_access(m.access)}:{special}:{normalize_descriptor(m.descriptor)}"


def _field_token(f: FieldInfo) -> str:
    return f"{_normalize_access(f.access)}:{normalize_type(f.descriptor)}"


def _anchor(internal_name: str) -> str:
    """Keep a framework super/interface name; wildcard a renamable one."""
    if not internal_name:
        return ""
    return internal_name if internal_name.startswith(STABLE_TYPE_PREFIXES) else "*"


def class_signature(cu: ClassUnit) -> int:
    """Compute the 64-bit obfuscation-resilient signature of one class.

    Order-independent: members are sorted so that member reordering (which
    obfuscators do) does not change the signature.
    """
    methods = sorted(_method_token(m) for m in cu.methods)
    fields = sorted(_field_token(f) for f in cu.fields)
    ifaces = sorted(_anchor(i) for i in cu.interfaces)
    canonical = "\n".join([
        "S:" + _anchor(cu.super_name),
        "I:" + ",".join(ifaces),
        "F:" + ";".join(fields),
        "M:" + ";".join(methods),
    ])
    digest = hashlib.blake2b(canonical.encode("utf-8", "replace"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def _string_anchor_hash(s: str) -> int:
    digest = hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


# String constants worth anchoring on: long enough to be meaningful, and not the
# obfuscation-friendly short/symbol-like noise.
_GOOD_STRING_RE = re.compile(r"[ -~]{6,200}$")


def _useful_strings(cu: ClassUnit) -> Iterable[str]:
    for s in cu.string_constants:
        if _GOOD_STRING_RE.match(s) and not s.startswith("L") and "/" not in s[:1]:
            yield s


def minhash(values: set[int], k: int = MINHASH_K) -> list[int]:
    """k-permutation MinHash over a set of 64-bit values (stable, dependency-free)."""
    if not values:
        return [0] * k
    sig = []
    for j in range(k):
        salt = ((j + 1) * _MIX) & _MASK64
        best = _MASK64
        for v in values:
            h = ((v ^ salt) * _MIX) & _MASK64
            if h < best:
                best = h
        sig.append(best)
    return sig


def minhash_similarity(a: list[int], b: list[int]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    eq = sum(1 for x, y in zip(a, b) if x == y)
    return eq / len(a)


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass
class LibraryProfile:
    name: str                      # library identity, e.g. "com.squareup.okhttp3:okhttp"
    version: str                   # version label, e.g. "4.9.3" ("" if unknown)
    formats: list[str]             # source bytecode formats, ["jvm"] / ["dex"]
    n_classes: int                 # classes contributing signatures
    class_sigs: list[int]          # unique class signatures (the fingerprint)
    string_sigs: list[int]         # unique string-anchor hashes
    minhash: list[int]             # MinHash of class_sigs (fast pre-screen)
    source: str = ""               # artifact path/coordinate the profile came from

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": PROFILE_SCHEMA,
            "name": self.name,
            "version": self.version,
            "formats": self.formats,
            "n_classes": self.n_classes,
            "source": self.source,
            # hex strings keep the JSON compact and language-agnostic.
            "class_sigs": [f"{s:016x}" for s in self.class_sigs],
            "string_sigs": [f"{s:016x}" for s in self.string_sigs],
            "minhash": [f"{s:016x}" for s in self.minhash],
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "LibraryProfile":
        return cls(
            name=obj.get("name", ""),
            version=obj.get("version", ""),
            formats=obj.get("formats", []),
            n_classes=int(obj.get("n_classes", 0)),
            class_sigs=[int(x, 16) for x in obj.get("class_sigs", [])],
            string_sigs=[int(x, 16) for x in obj.get("string_sigs", [])],
            minhash=[int(x, 16) for x in obj.get("minhash", [])],
            source=obj.get("source", ""),
        )


def build_profile(units, name: str, version: str = "", source: str = "") -> LibraryProfile:
    """Fingerprint parsed units (an :class:`ArtifactUnits`) into a profile."""
    sigs: set[int] = set()
    strings: set[int] = set()
    contributing = 0
    for cu in units.classes:
        # A class needs *some* structure to be a reliable anchor; pure marker
        # classes (no methods, no fields) are too collision-prone to count.
        if not cu.methods and not cu.fields:
            continue
        sigs.add(class_signature(cu))
        contributing += 1
        for s in _useful_strings(cu):
            strings.add(_string_anchor_hash(s))
    return LibraryProfile(
        name=name,
        version=version,
        formats=sorted(units.formats),
        n_classes=contributing,
        class_sigs=sorted(sigs),
        string_sigs=sorted(strings),
        minhash=minhash(sigs),
        source=source,
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class MatchScore:
    name: str
    version: str
    containment: float        # |ref ∩ cand| / |ref|  -- primary presence metric
    jaccard: float            # |ref ∩ cand| / |ref ∪ cand|
    matched_classes: int
    ref_classes: int
    string_overlap: float     # |ref_str ∩ cand_str| / |ref_str|
    minhash_est: float        # MinHash containment estimate (pre-screen)

    def to_row(self) -> dict[str, Any]:
        return {
            "library": self.name,
            "version": self.version,
            "containment": f"{self.containment:.4f}",
            "jaccard": f"{self.jaccard:.4f}",
            "matched_classes": self.matched_classes,
            "ref_classes": self.ref_classes,
            "string_overlap": f"{self.string_overlap:.4f}",
            "minhash_est": f"{self.minhash_est:.4f}",
        }


def score_profile(reference: LibraryProfile, candidate_sigs: set[int],
                  candidate_strings: set[int], cand_minhash: list[int]) -> MatchScore:
    ref_sigs = set(reference.class_sigs)
    inter = ref_sigs & candidate_sigs
    containment = len(inter) / len(ref_sigs) if ref_sigs else 0.0
    union = len(ref_sigs | candidate_sigs)
    jaccard = len(inter) / union if union else 0.0

    ref_str = set(reference.string_sigs)
    str_inter = ref_str & candidate_strings
    string_overlap = len(str_inter) / len(ref_str) if ref_str else 0.0

    # MinHash similarity is symmetric (Jaccard-like); we keep it as a cheap
    # corroboration of the exact intersection, not as the decision metric.
    mh = minhash_similarity(reference.minhash, cand_minhash)

    return MatchScore(
        name=reference.name,
        version=reference.version,
        containment=containment,
        jaccard=jaccard,
        matched_classes=len(inter),
        ref_classes=len(ref_sigs),
        string_overlap=string_overlap,
        minhash_est=mh,
    )


def rank_versions(references: list[LibraryProfile], candidate: LibraryProfile,
                  min_containment: float = 0.10) -> list[MatchScore]:
    """Score every reference profile against the candidate, best first.

    Ranking key models the version-identification logic:
      1. containment (is the library present, how completely)
      2. jaccard     (penalize versions carrying classes the app lacks -> the
                      bundled version should have few unmatched-but-expected classes)
      3. string_overlap (surviving literal anchors as a final tie-breaker)
    """
    cand_sigs = set(candidate.class_sigs)
    cand_strings = set(candidate.string_sigs)
    scores = [score_profile(ref, cand_sigs, cand_strings, candidate.minhash)
              for ref in references]
    scores = [s for s in scores if s.containment >= min_containment]
    scores.sort(key=lambda s: (s.containment, s.jaccard, s.string_overlap, s.matched_classes),
                reverse=True)
    return scores


def group_best_by_library(scores: list[MatchScore]) -> list[MatchScore]:
    """Collapse to the single best-scoring version per library identity."""
    best: dict[str, MatchScore] = {}
    for s in scores:
        cur = best.get(s.name)
        if cur is None or (s.containment, s.jaccard, s.string_overlap) > \
                (cur.containment, cur.jaccard, cur.string_overlap):
            best[s.name] = s
    out = list(best.values())
    out.sort(key=lambda s: (s.containment, s.jaccard), reverse=True)
    return out
