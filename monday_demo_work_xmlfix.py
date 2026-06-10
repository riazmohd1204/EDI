import os, re, json, html, hashlib, pickle

from typing import List, Dict, Tuple, Any, Set, Optional

from dataclasses import dataclass

from datetime import datetime

import numpy as np

import pandas as pd

import streamlit as st

import faiss

from openai import AzureOpenAI

from collections import Counter
import io

# =========================================================================================

# UI CHROME

# =========================================================================================

st.set_page_config(

    page_title="Hybrid EDI Analyzer",

    page_icon="🤖",

    layout="wide",

    initial_sidebar_state="expanded"

)

st.markdown("""

    <style>

    .main { padding: 2rem; }

    .stButton>button {

        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);

        color: white; border-radius: 10px; border: none;

        padding: 0.75rem 2rem; font-weight: bold;

    }

    .analysis-box {

        background: #f8f9fa; border-left: 4px solid #667eea;

        padding: 1rem; border-radius: 8px; margin: 1rem 0;

    }

    .match-score {

        font-size: 2rem; font-weight: bold;

        color: #667eea; text-align: center;

    }

    </style>

""", unsafe_allow_html=True)

# =========================================================================================

# STANDARD TAG REGISTRY (for deterministic matching)

# =========================================================================================

X12_STANDARD_TAGS = {

    'ISA', 'IEA', 'GS', 'GE', 'ST', 'SE',

    'BEG', 'REF', 'PER', 'FOB', 'ITD', 'DTM', 'TD5', 'TD3', 'TD4',

    'N1', 'N2', 'N3', 'N4', 'N9',

    'PO1', 'PID', 'MEA', 'QTY', 'CUR', 'PRI',

    'CTT', 'AMT', 'SAC', 'ITD', 'TXI',

    'TA1', 'AK1', 'AK2', 'AK3', 'AK4', 'AK5', 'AK9',

    'NTE', 'MSG', 'LIN', 'SN1', 'PRF', 'OTI', 'CAD'

}

EDIFACT_STANDARD_TAGS = {

    'UNA', 'UNB', 'UNZ', 'UNG', 'UNE', 'UNH', 'UNT',

    'BGM', 'DTM', 'FTX', 'RFF', 'DOC', 'MOA', 'CUX', 'PAT', 'PCD',

    'NAD', 'CTA', 'COM', 'LOC', 'TOD',

    'LIN', 'PIA', 'IMD', 'MEA', 'QTY', 'PRI', 'TAX',

    'ALC', 'PCD', 'MOA', 'RNG',

    'UNS', 'CNT',

    'UCI', 'UCM',

    'ALI', 'GIN', 'RCS', 'EQD', 'SEL', 'TDT', 'HAN'

}

# =========================================================================================

# CROSS-FORMAT MAPPING (DETERMINISTIC)

# =========================================================================================

CROSS_FORMAT_TAG_MAP = {

    'ISA': 'UNB', 'GS': 'UNG', 'ST': 'UNH', 'SE': 'UNT', 'GE': 'UNE', 'IEA': 'UNZ',

    'BEG': 'BGM', 'REF': 'RFF', 'DTM': 'DTM', 'N1': 'NAD', 'N3': 'NAD', 'N4': 'NAD',

    'FOB': 'TOD', 'ITD': 'PAT', 'PER': 'CTA', 'N9': 'FTX',

    'PO1': 'LIN', 'PID': 'IMD', 'QTY': 'QTY', 'CUR': 'CUX', 'PRI': 'PRI',

    'CTT': 'CNT', 'AMT': 'MOA',

}

CROSS_FORMAT_TAG_MAP_REVERSE = {v: k for k, v in CROSS_FORMAT_TAG_MAP.items() if k != v}

CROSS_FORMAT_QUAL_MAP = {

    ('NAD', 'BY'): ('N1', 'BY'), ('NAD', 'SU'): ('N1', 'SU'),

    ('NAD', 'ST'): ('N1', 'ST'), ('NAD', 'BT'): ('N1', 'BT'),

    ('NAD', 'DP'): ('N1', 'DP'), ('NAD', 'IV'): ('N1', 'IV'),

    ('DTM', '2'): ('DTM', '002'), ('DTM', '137'): ('DTM', '050'),

    ('DTM', '35'): ('DTM', '011'), ('DTM', '171'): ('DTM', '037'),

    ('RFF', 'ON'): ('REF', 'PO'), ('RFF', 'DQ'): ('REF', 'DQ'),

    ('RFF', 'IV'): ('REF', 'IV'), ('RFF', 'AAN'): ('REF', 'AAN'),

    ('MOA', '79'): ('AMT', 'TT'), ('MOA', '86'): ('AMT', '1'),

    ('MOA', '9'): ('AMT', 'N'),

}

CROSS_FORMAT_QUAL_MAP_REVERSE = {v: k for k, v in CROSS_FORMAT_QUAL_MAP.items()}

TRANSACTION_TYPE_MAP = {

    ('850', 'ORDERS'): 'PURCHASE_ORDER',

    ('855', 'ORDRSP'): 'PO_RESPONSE',

    ('860', 'ORDCHG'): 'PO_CHANGE',

    ('810', 'INVOIC'): 'INVOICE',

    ('856', 'DESADV'): 'ADVANCE_SHIP_NOTICE',

    ('997', 'CONTRL'): 'ACKNOWLEDGMENT',

    ('820', 'REMADV'): 'PAYMENT_ADVICE',

    ('846', 'INVRPT'): 'INVENTORY_REPORT',

}

# =========================================================================================

# LLM PROMPTS (IMPROVED)

# =========================================================================================

PROMPTS = {

    "compare_segments": """Compare two EDI segment signatures and return semantic similarity.

Segment 1: {seg1}

Segment 2: {seg2}

Consider:

- Are they functionally equivalent?

- Do qualifiers indicate similar business meaning?

- Could they serve the same purpose in a transaction?

Return JSON only:

{{

  "similarity_score": 0.0-1.0,

  "reasoning": "brief explanation",

  "equivalent": true/false

}}""",

   

    "analyze_unknown_tag": """Analyze this unknown/custom EDI segment and infer its purpose.

Segment: {segment}

Context: Appears in {format} {transaction_type} transaction

What is the likely business purpose? What standard segment is it most similar to?

Return JSON only:

{{

  "purpose": "brief description",

  "similar_to": ["list", "of", "standard", "segments"],

  "confidence": 0.0-1.0

}}""",

    "extract_metadata": """Analyze this EDI document and extract key metadata.

EDI:

{edi_content}

Return JSON only:

{{

  "format": "X12|EDIFACT|UNKNOWN",

  "message_type": "e.g., 850 or ORDERS",

  "semantic_type": "PURCHASE_ORDER|INVOICE|...",

  "sender_id": "string or empty"

}}""",

    "generate_xslt": """You are an XSLT expert. Your task: **Update the matched XSLT so it uses values from a NEW EDI document—without adding any new segments, loops, or qualifiers.**
 
Mode: **UPDATE-ONLY (no insertions)**
- Modify existing mapping blocks in place to pull values from the new EDI.
- Do **not** create any new elements, templates, loops, attributes, or qualifiers.
- You may delete or hard-disable **incorrect** or **wrong-scope** logic that already exists.
 
**CRITICAL INSTRUCTION**
- You MUST scan for and replace **hardcoded EDI values** that appear in the current XSLT.
- If you return 0 changes, explain **exactly why** (see "IF YOU FIND ZERO HARDCODED VALUES").
- **Do not** add "missing" qualifiers, segments, or new mapping blocks. That is the job of a separate **automerge** step.
 
Inputs
- **Original XSLT Template (matched)**:
{xslt_content}
 
- **TARGET EDI (extract new values from here)**:
{edi_content}
 
----------------------------------------------------------------
NEVER SYNTHESIZE / PRESENCE GUARDS (HARD RULES)
----------------------------------------------------------------
- **ABSENCE = NO INSERT.** If a source path/value is missing in the EDI, leave the target empty; do **not** invent a value.
- **No new qualifiers.** Use only the qualifiers that already appear in the **existing XSLT** or in **existing variables/paths**. Do **not** introduce qualifiers that aren't already referenced by the current template.
- **Same-tag only.** Keep BGM-driven fields from BGM, DTM from DTM, RFF from RFF, etc. **No cross-tag fallbacks.**
- **No new scope blocks.** Do not add header or line-item blocks. **Update only what exists.**
- **Examples are illustrative only.** Any example below is for pattern recognition, **not** a license to insert a new block.
 
Reference presence macros (for reading the EDI safely; do not create new blocks if they don't exist):
- Header DTM 137: `$c/S_DTM/C_C507[D_2005='137']/D_2380`
- Header DTM 64:  `$c/S_DTM/C_C507[D_2005='64']/D_2380`
- Item DTM 171:  `$it/S_DTM/C_C507[D_2005='171']/D_2380`
- Item RFF <QUAL>: `$it/G_SG28/S_RFF/C_C506[D_1153='<QUAL>']/D_1154`
- Header RFF <QUAL>: `$c/G_SG6/S_RFF/C_C506[D_1153='<QUAL>']/D_1154`
 
----------------------------------------------------------------
WHAT TO FIND & REPLACE (UPDATE IN PLACE ONLY)
----------------------------------------------------------------
Find **hardcoded values** embedded in the XSLT and switch them to pull from the new EDI (without changing structure):
1) Dates (e.g., YYYYMMDD literals in `<DATUM>...</DATUM>` or `select="'20250115'"`)
2) Purchase order numbers / document numbers (e.g., in BGM/BEG variables)
3) Reference IDs (RFF/REF)
4) Company/party names (NAD/N1)
5) Sender/receiver IDs (UNB/ISA, etc.)
6) Qualifier **comparisons** that are hardcoded strings may be updated only if the **same comparison already exists**—do not add new qualifier cases.
 
**Do NOT replace**:
- XPath expressions, variables, or functions themselves (e.g., `concat()`, `$vars`, `../path/@attr`) unless they contain a hardcoded literal value that should now come from the new EDI.
- Structure (no new templates/loops/elements).
 
----------------------------------------------------------------
SCOPE ENFORCEMENT (UPDATE-ONLY)
----------------------------------------------------------------
- Keep header logic **outside** item loops; item logic **inside** the existing item loop.
- **Do not** create new E1EDK** or E1EDP** blocks. If an existing block is wrong-scope (e.g., item DTM+64 in `E1EDP03`), you may **delete** or hard-disable it (see Deletions).
- **No cross-scope promotions**. Do not move header values into line items or vice versa.
 
----------------------------------------------------------------
OUTPUT SANITIZATION (REQUIRED)
----------------------------------------------------------------
- Remove legacy banner/comment blocks copied from old templates (e.g., comments containing:
  `Create Date:`, `Created By:`, `Change Date:`, `Changed By:`, `EDI Team`, `Customers`, long asterisk dividers).
- Preserve your own output structure and all namespaces.
- Keep any existing project comment style; do not add marketing banners.
 
----------------------------------------------------------------
PROCESS
----------------------------------------------------------------
1) Scan every line of the XSLT for **hardcoded literals** tied to EDI content.
2) For each literal, locate the corresponding value in the **TARGET EDI** (same tag, same scope).
3) **Update in place**: change only the value selection (e.g., `xsl:value-of select="..."` or attribute select) to read from the EDI path. Do not add blocks.
4) For wrong-scope existing logic (e.g., line-item `DTM+64` in `E1EDP03`), **delete** or wrap with an always-false guard.
5) Produce JSON with the **complete modified XSLT** and a **changes** array.
 
----------------------------------------------------------------
DELETIONS / SUPPRESSIONS (ALLOWED)
----------------------------------------------------------------
- Prefer true deletion of obsolete/wrong-scope existing blocks (e.g., any `E1EDP03` tied to `D_2005='64'` inside an item loop).
- If risky, wrap the existing block in an always-false guard and add a comment like:
  `<!-- UPDATE-ONLY: disabled wrong-scope block; review -->`
- Every deletion/disable must appear in the `"changes"` list with `"operation": "delete"` (or `"update"` if guarded).
 
----------------------------------------------------------------
PATTERN EXAMPLES (ILLUSTRATIVE — DO NOT INSERT NEW BLOCKS)
----------------------------------------------------------------
- Header date update pattern (if an **existing** header E1EDK03 block already uses a hardcoded date):
  `<DATUM><xsl:value-of select="$c/S_DTM/C_C507[D_2005='137']/D_2380"/></DATUM>`
- Item requested date update pattern (if an **existing** E1EDP03 for 171 already exists):
  `<DATUM><xsl:value-of select="$it/S_DTM/C_C507[D_2005='171']/D_2380"/></DATUM>`
- Reference update pattern (if an **existing** E1EDK02/E1EDP02 block already exists):
  `<BELNR><xsl:value-of select="...appropriate RFF path..."/></BELNR>`
 
> These are examples only. **Do not** create these blocks if they don't already exist.
 
----------------------------------------------------------------
REQUIRED SELF-CHECK (HARD REQUIREMENT)
----------------------------------------------------------------
- **No insertions** were made (no new templates/elements/loops/attributes/comments that didn't exist before, except comment removals for sanitization).
- **No new qualifiers** were introduced. Only qualifiers already present in the existing XSLT logic may appear.
- **No cross-tag fallbacks** used.
- Any wrong-scope existing logic was deleted or guarded (and recorded in `changes`).
- Legacy banner/comments removed.
 
Compliance object (append to JSON):
{
  "update_only": true,
  "no_insertions": true/false,
  "no_new_qualifiers": true/false,
  "no_cross_tag_fallbacks": true/false,
  "legacy_banner_removed": true/false,
  "wrong_scope_blocks_removed_or_guarded": true/false,
  "notes": "any caveats"
}
 
----------------------------------------------------------------
MANDATORY OUTPUT FORMAT (JSON ONLY)
----------------------------------------------------------------
Return:
 
{
  "modified_xslt": "Complete XSLT with ALL in-place updates applied (no omissions)",
  "changes": [
    {
      "context_line": "Nearest template/for-each line showing where the update happened",
      "old_value": "Exact hardcoded value or previous select()",
      "new_value": "New select()/value-of path reading from TARGET EDI",
      "reasoning": "Same tag & scope; update-only. (cite the exact source path used from EDI)",
      "operation": "update|delete"
    }
  ],
  "compliance": {
    "update_only": true,
    "no_insertions": true/false,
    "no_new_qualifiers": true/false,
    "no_cross_tag_fallbacks": true/false,
    "legacy_banner_removed": true/false,
    "wrong_scope_blocks_removed_or_guarded": true/false,
    "notes": "any caveats"
  }
}
 
----------------------------------------------------------------
IF YOU FIND ZERO HARDCODED VALUES
----------------------------------------------------------------
{
  "modified_xslt": "original xslt unchanged",
  "changes": [
    {
      "context_line": "N/A",
      "old_value": "N/A",
      "new_value": "N/A",
      "reasoning": "EXPLANATION: The XSLT uses only variables/XPath without hardcoded EDI literals. No insertions allowed in update-only mode."
    }
  ],
  "compliance": {
    "update_only": true,
    "no_insertions": true,
    "no_new_qualifiers": true,
    "no_cross_tag_fallbacks": true,
    "legacy_banner_removed": true/false,
    "wrong_scope_blocks_removed_or_guarded": true/false,
    "notes": "any caveats"
  }
}
""",
 
    "merge_xslts": """Merge XSLTs by adding ONLY the truly missing mappings, placed at the CORRECT scope determined by the source EDI path. Keep the primary stylesheet verbatim unless fixing wrong-scope logic.
 
INPUTS
- Missing segments: {missing_elements}
- Primary XSLT:
{primary_xslt}
- Supplementary XSLT:
{supplementary_xslt}
- (Optional) Repo hints: {repo_hints}
 
SCOPE DECISION — MUST FOLLOW UPLOADED EDI SOURCE
----------------------------------------------------------------
 
For each missing qualifier Q:
 
1️⃣ SEARCH the uploaded EDI for exact paths containing Q:
    - HEADER paths:
      $c/S_DTM/C_C507[D_2005=Q]/D_2380
      $c/G_SG6/S_RFF/C_C506[D_1153=Q]/D_1154
    - ITEM paths:
      $it/S_DTM/C_C507[D_2005=Q]/D_2380
      $it/G_SG28/S_RFF/C_C506[D_1153=Q]/D_1154
 
2️⃣ APPLY these rules:
    ✅ If Q exists ONLY in HEADER → insert ONLY HEADER block (E1EDK**)
    ✅ If Q exists ONLY in ITEM   → insert ONLY ITEM block (E1EDP**)
    ✅ If Q exists in BOTH → insert ONE HEADER + ONE ITEM block
    ❌ If Q exists in NEITHER → DO NOT INSERT ANYTHING
 
3️⃣ Presence guard MUST use the EXACT detected path(s)
4️⃣ NEVER insert the same qualifier in header and item unless BOTH paths exist
5️⃣ NEVER retain wrong-scope legacy blocks — delete them
 
Wrong-Scope Guard (final lock):
If a wrong-scope mapping for Q already exists in the primary XSLT:
- DELETE IT (preferred)
- If unsure, wrap in always-false `<xsl:if test="false()">` with review comment
 
EXAMPLE (Mutual Exclusion in Practice):
Uploaded EDI shows:
- DTM+64 → ONLY under LIN
- RFF+ADE → ONLY under header
- RFF+CR → ONLY under header
 
✅ Correct merged result:
 
Qualifier    Header    Line-Item    Decision
DTM 64       ❌         ✅         Insert ONLY in item (E1EDP03)
ADE          ✅         ❌         Insert ONLY in header (E1EDK02)
CR           ✅         ❌         Insert ONLY in header (E1EDK02)
 
This rule enforces exactly that - no ambiguity.
 
DONOR FRAGMENT REUSE
- Reuse smallest working fragment from supplementary/repo that matches SEGMENT, QUALIFIER, and SCOPE
- Normalize variable names (e.g., `$it`) without changing behavior
 
MAPPING RULES
- Header DTM/RFF/NAD/CUX/BGM → E1EDK** (e.g., E1EDK02, E1EDK03)
- Item DTM/RFF/QTY/PRI/PIA/IMD → E1EDP** (e.g., E1EDP03 for dates, E1EDP02 for refs)
- Never emit item dates into E1EDP20 or item refs into E1EDP21
 
IDEMPOTENT & MARKERS
- If equivalent logic exists at correct scope, UPDATE IN PLACE; otherwise insert ONCE
- Header marker: `<!-- AI-GENERATED (automerge/header): <purpose> -->`
- Item marker:   `<!-- AI-GENERATED (merge/line-item): <purpose> -->`
 
ITEM LOOP ANCHOR
- EDIFACT: `<xsl:for-each select=\"(($c/G_SG25)[position() &lt;= 999999])\">` and set `<xsl:variable name=\"it\" select=\".\"/>`
- X12: use existing PO1 loop with `$it` alias
 
INSERTION TEMPLATES (patterns)
- Header pattern:
  <!-- AI-GENERATED (automerge/header): RFF-CR -->
  <xsl:if test=\"$c/G_SG6/S_RFF/C_C506[D_1153='CR']/D_1154 != ''\">
    <E1EDK02 SEGMENT=\"1\">
      <QUALF>CR</QUALF>
      <BELNR><xsl:value-of select=\"$c/G_SG6/S_RFF/C_C506[D_1153='CR']/D_1154\"/></BELNR>
    </E1EDK02>
  </xsl:if>
 
- Item pattern (inside LIN loop, using $it):
  <!-- AI-GENERATED (merge/line-item): DTM-171 -->
  <xsl:if test=\"$it/S_DTM/C_C507[D_2005='171']/D_2380 != ''\">
    <E1EDP03 SEGMENT=\"1\">
      <IDDAT>171</IDDAT>
      <DATUM><xsl:value-of select=\"$it/S_DTM/C_C507[D_2005='171']/D_2380\"/></DATUM>
    </E1EDP03>
  </xsl:if>
 
SELF-CHECK (must be TRUE before returning)
- All line-item markers are INSIDE the item loop; none outside.
- All header markers are OUTSIDE the item loop.
- No header-only paths yielded E1EDP**; no item-only paths yielded E1EDK**.
- No duplicates of the same qualifier at the same scope.
 
RETURN (JSON ONLY)
{
  "merged_xslt": "COMPLETE merged XSLT (no ellipses)",
  "changes": [
    {
      "context_line": "nearest template/for-each anchor",
      "old_value": "N/A (new insertion)" | "deleted block" | "previous line(s)",
      "new_value": "representative new line(s) or 'N/A (deletion)'",
      "reasoning": "(automerge/header) or (merge/line-item), cite exact source path",
      "operation": "insert" | "update" | "delete"
    }
  ],
  "compliance": {
    "markers_present": true/false,
    "item_loop_anchor": "XPath used for items",
    "idempotent": true/false,
    "notes": "any caveats"
  },
  "scope_checks": {
    "no_header_logic_in_item_loop": true/false,
    "no_item_logic_in_header": true/false,
    "line_item_markers_inside_loop": true/false,
    "header_markers_outside_loop": true/false
  },
  "dedupe_checks": {
    "no_duplicate_header_blocks": true/false,
    "no_duplicate_item_blocks": true/false
  }
}
"""
 
}

# =========================================================================================

# HELPERS

# =========================================================================================

def fill_prompt(tpl: str, **kw) -> str:

    out = tpl

    for k, v in kw.items():

        out = out.replace("{" + k + "}", str(v))

    return out

def detect_standard(text: str) -> str:

    t = (text or "").strip()

    if t.startswith("ISA") or ("*" in t and "~" in t): return "X12"

    if t.startswith("UNA") or t.startswith("UNB") or ("+" in t and "'" in t) or "UNH+" in t: return "EDIFACT"

    return "UNKNOWN"

def split_segments_x12(text: str) -> List[str]:

    text = text.replace("\r","").replace("\n","")

    return [s for s in text.split("~") if s.strip()]

def split_segments_edifact(text: str) -> List[str]:

    text = text.replace("\r","").replace("\n","")

    return [s for s in text.split("'") if s.strip()]

def parse_structured_segments(raw: str, std: str) -> List[List[str]]:

    out = []

    if std == "X12":

        for s in split_segments_x12(raw):

            m = re.match(r"^([A-Z0-9]{2,6})(?:\*(.*))?$", s)

            if m:

                tag = m.group(1)

                body = m.group(2) or ""

                elems = [tag] + (body.split("*") if body != "" else [])

                out.append(elems)

    elif std == "EDIFACT":

        for s in split_segments_edifact(raw):

            m = re.match(r"^([A-Z0-9]{2,6})(?:\+(.*))?$", s)

            if m:

                tag = m.group(1)

                body = m.group(2) or ""

                elems = [tag] + (body.split("+") if body != "" else [])

                out.append(elems)

            else:

                parts = s.split("+")

                out.append(parts)

    return out

def normalize_preview(seg: List[str]) -> str:

    return " | ".join(seg)

def get_base_filename(fname: str) -> str:

    return os.path.splitext(fname)[0].lower()

def _normalize_id(s: str) -> str:

    return re.sub(r'[^A-Za-z0-9]', '', (s or '').strip().upper())

def _safe_percent(x: float) -> float:

    try:

        return float(x)

    except Exception:

        return 0.0

def is_custom_segment(tag: str, std: str) -> bool:

    if not tag:

        return False

    if std == "X12" and tag.startswith('Z'):

        return True

    if std == "X12":

        return tag not in X12_STANDARD_TAGS

    elif std == "EDIFACT":

        return tag not in EDIFACT_STANDARD_TAGS

    return True

# =========================================================================================

# DETERMINISTIC METADATA EXTRACTION

# =========================================================================================

def extract_metadata_deterministic(text: str) -> Dict[str, str]:

    std = detect_standard(text)

    segs = parse_structured_segments(text, std)

   

    message_type = "UNKNOWN"

    sender_id = ""

   

    if std == "X12":

        for s in segs:

            if s[0] == "ST" and len(s) > 1:

                message_type = s[1]

                break

        for s in segs:

            if s[0] == "ISA" and len(s) > 6:

                sender_id = s[6]

                break

        if not sender_id:

            for s in segs:

                if s[0] == "GS" and len(s) > 2:

                    sender_id = s[2]

                    break

                   

    elif std == "EDIFACT":

        for s in segs:

            if s[0] == "UNH" and len(s) > 2:

                message_type = s[2].split(":")[0]

                break

        for s in segs:

            if s[0] == "UNB" and len(s) > 2:

                sender_id = s[2].split(":")[0]

                break

   

    semantic_type = "UNKNOWN"

    for (x12_type, edifact_type), sem_type in TRANSACTION_TYPE_MAP.items():

        if message_type == x12_type or message_type == edifact_type:

            semantic_type = sem_type

            break

   

    return {

        "format": std,

        "message_type": message_type,

        "semantic_type": semantic_type,

        "sender_id": sender_id

    }

# =========================================================================================

# HYBRID STRUCTURAL MATCHER

# =========================================================================================

class StructuralMatcher:

    def __init__(self, llm_engine=None, config=None):

        self.llm = llm_engine

        self.config = config

        self.llm_cache = {}

        self.unknown_tag_cache = {}

        self.stats = {

            "deterministic_matches": 0,

            "cross_format_matches": 0,

            "llm_adaptive_matches": 0,

            "cache_hits": 0

        }

   

    def is_exact_match(self, sig1: Tuple[str, str], sig2: Tuple[str, str]) -> bool:

        return sig1 == sig2

   

    def is_cross_format_match(self, sig1: Tuple[str, str], sig2: Tuple[str, str],

                                std1: str, std2: str) -> bool:

        if std1 == std2:

            return False

       

        tag1, qual1 = sig1

        tag2, qual2 = sig2

       

        if std1 == "X12" and std2 == "EDIFACT":

            expected_tag = CROSS_FORMAT_TAG_MAP.get(tag1)

            if expected_tag == tag2:

                if (not qual1 and not qual2) or (qual1 == qual2):

                    return True

        elif std1 == "EDIFACT" and std2 == "X12":

            expected_tag = CROSS_FORMAT_TAG_MAP.get(tag2)

            if expected_tag == tag1:

                if (not qual1 and not qual2) or (qual1 == qual2):

                    return True

       

        if std1 == "EDIFACT" and std2 == "X12":

            key = (tag1, qual1)

            if key in CROSS_FORMAT_QUAL_MAP:

                expected = CROSS_FORMAT_QUAL_MAP[key]

                return (tag2, qual2) == expected

       

        if std1 == "X12" and std2 == "EDIFACT":

            key = (tag1, qual1)

            if key in CROSS_FORMAT_QUAL_MAP_REVERSE:

                expected = CROSS_FORMAT_QUAL_MAP_REVERSE[key]

                return (tag2, qual2) == expected

       

        return False

   

    def llm_semantic_match(self, sig1: Tuple[str, str], sig2: Tuple[str, str],

                            std1: str, std2: str) -> float:

        if not self.llm or not self.config.llm_adaptive_matching:

            return 0.0

       

        cache_key = (sig1, sig2, std1, std2)

        if cache_key in self.llm_cache:

            self.stats["cache_hits"] += 1

            return self.llm_cache[cache_key]

       

        seg1_str = f"{sig1[0]}:{sig1[1]}" if sig1[1] else sig1[0]

        seg2_str = f"{sig2[0]}:{sig2[1]}" if sig2[1] else sig2[0]

       

        prompt = fill_prompt(PROMPTS["compare_segments"],

                             seg1=f"{seg1_str} ({std1})",

                             seg2=f"{seg2_str} ({std2})")

       

        result = self.llm.call_llm(prompt)

        if isinstance(result, dict) and "similarity_score" in result:

            score = float(result.get("similarity_score", 0.0))

        else:

            score = 0.0

       

        self.llm_cache[cache_key] = score

        return score

   

    def match_score(self, sig1: Tuple[str, str], sig2: Tuple[str, str],

                    std1: str, std2: str) -> Tuple[float, str]:

        tag1, qual1 = sig1

        tag2, qual2 = sig2

       

        if self.is_exact_match(sig1, sig2):

            self.stats["deterministic_matches"] += 1

            return (1.0, "exact")

       

        if self.is_cross_format_match(sig1, sig2, std1, std2):

            self.stats["cross_format_matches"] += 1

            return (1.0, "cross_format")

       

        is_custom1 = is_custom_segment(tag1, std1)

        is_custom2 = is_custom_segment(tag2, std2)

       

        if is_custom1 or is_custom2:

            score = self.llm_semantic_match(sig1, sig2, std1, std2)

            if score > 0:

                self.stats["llm_adaptive_matches"] += 1

                return (score, "llm_adaptive")

       

        return (0.0, "no_match")

   

    def get_stats(self) -> Dict:

        return self.stats.copy()

# =========================================================================================

# STRUCTURAL SETS

# =========================================================================================

REPEAT_THRESHOLD = 8

QUAL_VARIETY_THRESHOLD = 5

def _mode_cap(nums: List[int], cap: int) -> int:

    if not nums:

        return 0

    m = Counter(nums).most_common(1)[0][0]

    return min(m, cap)

def _sig_generic(tag: str, s: List[str], std: str):

    if len(s) <= 1:

        return False, None, None

    q_raw = (s[1] or "").strip().upper()

    q = q_raw.split(":", 1)[0] if std == "EDIFACT" else q_raw

    if re.fullmatch(r"[A-Z0-9]{1,4}", q):

        return True, (tag, q), None

    return False, None, None

def _sig_lin(tag: str, s: List[str], std: str):

    n = max(0, len(s) - 1)

    pos2_empty = (len(s) > 2 and ((s[2] or "").strip() == ""))

    has_composite_at_pos3 = (len(s) > 3 and (":" in (s[3] or "")))

    n_cap = min(n, 9)

    shape = f"S{n_cap}" + ("C" if has_composite_at_pos3 else "") + ("E" if pos2_empty else "")

    return True, ("LIN", shape), None

def _sig_po1(tag: str, s: List[str], std: str):

    n = max(0, len(s) - 1)

    return True, ("PO1", f"L{min(n, 99)}"), None

def _sig_cux(tag: str, s: List[str], std: str):

    added, pair, extra = _sig_generic(tag, s, std)

    if len(s) > 1:

        parts = (s[1] or "").upper().split(":")

        if len(parts) >= 2:

            cur = (parts[1] or "").strip().upper()

            if re.fullmatch(r"[A-Z]{3}", cur):

                extra = (tag, f"CUR_{cur}")

    return True, pair, extra

def _sig_cur(tag: str, s: List[str], std: str):

    added, pair, extra = _sig_generic(tag, s, std)

    if len(s) > 2:

        cur = (s[2] or "").strip().upper()

        if re.fullmatch(r"[A-Z]{3}", cur):

            extra = (tag, f"CUR_{cur}")

    return True, pair, extra

def _sig_qty(tag: str, s: List[str], std: str):

    added, pair, extra = _sig_generic(tag, s, std)

    if std == "EDIFACT" and len(s) > 1:

        parts = (s[1] or "").upper().split(":")

        if len(parts) >= 3:

            unit = (parts[2] or "").strip().upper()

            if re.fullmatch(r"[A-Z0-9]{1,4}", unit):

                extra = (tag, f"U_{unit}")

    return True, pair, extra

def _sig_cnt_ctt(tag: str, s: List[str], std: str):

    return True, None, None

def _sig_envelope_control(tag: str, s: List[str], std: str):

    return True, None, None

def _sig_dtm(tag: str, s: List[str], std: str):

    if std == "X12" and len(s) > 1:

        date_type = (s[1] or "").strip().upper()

        if re.fullmatch(r"[A-Z0-9]{1,4}", date_type):

            return True, (tag, date_type), None

    elif std == "EDIFACT" and len(s) > 1:

        comp = (s[1] or "").strip()

        parts = comp.split(":")

        if len(parts) >= 1:

            date_type = (parts[0] or "").strip().upper()

            if re.fullmatch(r"[A-Z0-9]{1,4}", date_type):

                return True, (tag, date_type), None

    return True, None, None

def _sig_amt_moa(tag: str, s: List[str], std: str):

    if std == "X12" and len(s) > 1:

        amt_type = (s[1] or "").strip().upper()

        if re.fullmatch(r"[A-Z0-9]{1,4}", amt_type):

            return True, (tag, amt_type), None

    elif std == "EDIFACT" and len(s) > 1:

        comp = (s[1] or "").strip()

        parts = comp.split(":")

        if len(parts) >= 1:

            amt_type = (parts[0] or "").strip().upper()

            if re.fullmatch(r"[A-Z0-9]{1,4}", amt_type):

                return True, (tag, amt_type), None

    return True, None, None

def _sig_ref_rff(tag: str, s: List[str], std: str):

    if std == "X12" and len(s) > 1:

        ref_type = (s[1] or "").strip().upper()

        if re.fullmatch(r"[A-Z0-9]{1,4}", ref_type):

            return True, (tag, ref_type), None

    elif std == "EDIFACT" and len(s) > 1:

        comp = (s[1] or "").strip()

        parts = comp.split(":")

        if len(parts) >= 1:

            ref_type = (parts[0] or "").strip().upper()

            if re.fullmatch(r"[A-Z0-9]{1,4}", ref_type):

                return True, (tag, ref_type), None

    return True, None, None

def _sig_pri(tag: str, s: List[str], std: str):

    n = max(0, len(s) - 1)

    return True, (tag, f"PRICE_{min(n, 9)}"), None

def _sig_pid_imd(tag: str, s: List[str], std: str):

    n = max(0, len(s) - 1)

    return True, (tag, f"DESC_{min(n, 9)}"), None

def _sig_mea(tag: str, s: List[str], std: str):

    n = max(0, len(s) - 1)

    return True, (tag, f"MEAS_{min(n, 9)}"), None

SIGNATURE_REGISTRY = {

    "LIN": _sig_lin, "PO1": _sig_po1,

    "CUX": _sig_cux, "CUR": _sig_cur, "QTY": _sig_qty,

    "CNT": _sig_cnt_ctt, "CTT": _sig_cnt_ctt,

    "DTM": _sig_dtm,

    "AMT": _sig_amt_moa, "MOA": _sig_amt_moa,

    "REF": _sig_ref_rff, "RFF": _sig_ref_rff,

    "PRI": _sig_pri, "PID": _sig_pid_imd, "IMD": _sig_pid_imd, "MEA": _sig_mea,

    "ISA": _sig_envelope_control, "IEA": _sig_envelope_control,

    "GS": _sig_envelope_control, "GE": _sig_envelope_control,

    "ST": _sig_envelope_control, "SE": _sig_envelope_control,

    "UNA": _sig_envelope_control, "UNB": _sig_envelope_control,

    "UNZ": _sig_envelope_control, "UNG": _sig_envelope_control,

    "UNE": _sig_envelope_control, "UNH": _sig_envelope_control,

    "UNT": _sig_envelope_control,

}

def _structural_sets(raw: str, normalize_cross_format: bool = False) -> Tuple[Set[str], Set[Tuple[str, str]]]:

    std = detect_standard(raw)

    segs = parse_structured_segments(raw, std)

    tags, tag_quals = set(), set()

    if not segs:

        return tags, tag_quals

    per_tag_stats = {}

    for s in segs:

        if not s:

            continue

        tag = (s[0] or "").strip().upper()

        if not tag:

            continue

        tags.add(tag)

        d = per_tag_stats.setdefault(tag, {"count": 0, "qual_set": set(), "lengths": []})

        d["count"] += 1

        d["lengths"].append(max(0, len(s) - 1))

        if len(s) > 1:

            q_raw = (s[1] or "").strip().upper()

            q_tok = q_raw.split(":", 1)[0] if std == "EDIFACT" else q_raw

            if re.fullmatch(r"[A-Z0-9]{1,4}", q_tok):

                d["qual_set"].add(q_tok)

    auto_shape_unknown = set()

    excluded_segments = {

        "LIN", "PO1", "PRI", "PID", "IMD", "MEA",

        "ISA", "IEA", "GS", "GE", "ST", "SE",

        "UNA", "UNB", "UNZ", "UNG", "UNE", "UNH", "UNT",

        "CNT", "CTT"

    }

    for tag, st in per_tag_stats.items():

        if tag in excluded_segments:

            continue

        if st["count"] >= REPEAT_THRESHOLD and len(st["qual_set"]) >= QUAL_VARIETY_THRESHOLD:

            auto_shape_unknown.add(tag)

    modal_len = {tag: _mode_cap(st["lengths"], 99) for tag, st in per_tag_stats.items()}

    emitted_shape_once = set()

    for s in segs:

        if not s:

            continue

        tag = (s[0] or "").strip().upper()

        if not tag:

            continue

        handler = SIGNATURE_REGISTRY.get(tag)

        if handler:

            added, pair, extra = handler(tag, s, std)

            if added and pair:

                tag_quals.add(pair)

            if extra:

                tag_quals.add(extra)

            continue

        if tag in auto_shape_unknown:

            if tag not in emitted_shape_once:

                n = modal_len.get(tag, 0)

                tag_quals.add((tag, f"R{min(n, 99)}"))

                emitted_shape_once.add(tag)

        added, pair, extra = _sig_generic(tag, s, std)

        if added and pair:

            tag_quals.add(pair)

        if extra:

            tag_quals.add(extra)

    return tags, tag_quals

def _pretty_tqs(tqs: Set[Tuple[str, str]]) -> List[str]:

    return [f"{t}:{q}" for (t, q) in sorted(tqs)]

def query_coverage_score_hybrid(query_text: str, doc_text: str, matcher: StructuralMatcher) -> Dict[str, Any]:

    q_std = detect_standard(query_text)

    d_std = detect_standard(doc_text)

   

    q_tags, q_tqs = _structural_sets(query_text)

    d_tags, d_tqs = _structural_sets(doc_text)

   

    w_tag, w_tq = 1.0, 2.0

   

    matched_tags = set()

    matched_tqs = set()

    missing_tags = set()

    missing_tqs = set()

   

    match_details = []

   

    for q_tag in q_tags:

        best_match = None

        best_score = 0.0

       

        for d_tag in d_tags:

            score, match_type = matcher.match_score((q_tag, ""), (d_tag, ""), q_std, d_std)

            if score > best_score:

                best_score = score

                best_match = (d_tag, match_type)

       

        if best_score >= 0.7:

            matched_tags.add(q_tag)

            if best_match:

                match_details.append({

                    "query": q_tag,

                    "match": best_match[0],

                    "type": best_match[1],

                    "score": best_score

                })

        else:

            missing_tags.add(q_tag)

   

    for q_tq in q_tqs:

        best_match = None

        best_score = 0.0

       

        for d_tq in d_tqs:

            score, match_type = matcher.match_score(q_tq, d_tq, q_std, d_std)

            if score > best_score:

                best_score = score

                best_match = (d_tq, match_type)

       

        if best_score >= 0.7:

            matched_tqs.add(q_tq)

            if best_match:

                match_details.append({

                    "query": f"{q_tq[0]}:{q_tq[1]}",

                    "match": f"{best_match[0][0]}:{best_match[0][1]}",

                    "type": best_match[1],

                    "score": best_score

                })

        else:

            missing_tqs.add(q_tq)

   

    query_total = w_tag * len(q_tags) + w_tq * len(q_tqs)

    matched_total = w_tag * len(matched_tags) + w_tq * len(matched_tqs)

   

    coverage = (matched_total / query_total * 100) if query_total > 0 else 100.0

   

    return {

        "coverage_pct": coverage,

        "matched_tags": matched_tags,

        "matched_tqs": matched_tqs,

        "missing_tags": missing_tags,

        "missing_tqs": missing_tqs,

        "query_tag_count": len(q_tags),

        "query_tq_count": len(q_tqs),

        "matched_tag_count": len(matched_tags),

        "matched_tq_count": len(matched_tqs),

        "match_details": match_details

    }

def _sample_segments_for_signatures(segs: List[List[str]], want_tags: Set[str],

                                      want_tag_quals: Set[Tuple[str, str]], limit: int = 12) -> List[str]:

    out: List[str] = []

    want_tags = set(want_tags or [])

    want_tq = set(want_tag_quals or [])

    def _wants_tag_only(tag: str) -> bool:

        return tag in want_tags or any(t == tag for (t, _) in want_tq)

    for s in segs:

        if not s:

            continue

        tag = (s[0] or "").strip().upper()

        hit = False

        if tag in want_tags:

            hit = True

        if len(s) > 1:

            q = (s[1] or "").strip().upper()

            if (tag, q) in want_tq:

                hit = True

        if not hit and _wants_tag_only(tag):

            hit = True

        if hit:

            out.append(normalize_preview(s))

            if len(out) >= limit:

                break

    return out

# =========================================================================================

# CUSTOMER INFO

# =========================================================================================

def extract_customer_info(raw: str) -> Dict[str, str]:

    std = detect_standard(raw)

    segs = parse_structured_segments(raw, std)

    sender = None

    parties: Dict[str, str] = {}

    if std == "X12":

        for s in segs:

            if s and s[0] == "ISA" and len(s) > 6:

                sender = s[6].strip(); break

        if not sender:

            for s in segs:

                if s and s[0] == "GS" and len(s) > 2:

                    sender = s[2].strip(); break

        for s in segs:

            if s and s[0] == "N1" and len(s) > 2:

                qual = (s[1] or "").strip().upper()

                name = (s[2] or "").strip()

                if qual in {"BY","SU","ST","BT"} and name:

                    parties[qual] = name

    elif std == "EDIFACT":

        for s in segs:

            if s and s[0] == "UNB" and len(s) > 2:

                sender = s[2].split(":",1)[0].strip(); break

        for s in segs:

            if s and s[0] == "NAD" and len(s) > 1:

                qual = (s[1] or "").strip().upper()

                name = None

                for field in s[2:6]:

                    if field and not re.fullmatch(r"[0-9:]+", field) and len(field.strip()) > 1:

                        name = field.strip(); break

                if qual in {"BY","SU","ST","BT"} and name:

                    parties[qual] = name

    sender_norm = _normalize_id(sender)

    name = None

    cmap = st.session_state.get("customer_mapping") or {}

    if sender_norm:

        name = cmap.get(sender_norm)

    if not name:

        for q in ("BY","SU","ST","BT"):

            if parties.get(q):

                name = parties[q]; break

    return {"sender_id": sender or "", "sender_id_norm": sender_norm, "customer_name": name or "Unknown"}

# =========================================================================================

# LLM ENGINE (IMPROVED)

# =========================================================================================

@dataclass

class Config:

    azure_endpoint: str = "https://edi-resource.openai.azure.com/"
    api_key: str = ""  # Set your Azure OpenAI API key here or via environment variable
    api_version: str = "2024-02-01"
    embedding_model: str = "text-embedding-3-small"
    llm_model: str = "gpt-4.1"
    indexing_model: str = "gpt-4.1"

    max_tokens: int = 16000

    temperature: float = 0.2

    batch_size: int = 10

    skip_customer_identification: bool = True

    cache_embeddings: bool = True

   

    matching_mode: str = "hybrid"

    llm_adaptive_matching: bool = True

    llm_confidence_threshold: float = 0.7

   

    use_simple_summary: bool = False

    use_signal_embeddings: bool = True

    use_multiview: bool = False

   

    precompute_structure: bool = True

class LLMEngine:

    def __init__(self, config: Config):

        self.config = config

        self.client = AzureOpenAI(

            api_key=config.api_key,

            azure_endpoint=config.azure_endpoint,

            api_version=config.api_version

        ) if config.api_key and config.azure_endpoint else None

        self.total_calls = 0

        self.embedding_calls = 0

        self.llm_calls = 0

    def _supports_json_mode(self, model: str) -> bool:

        m = (model or "").lower()

        return any(x in m for x in ["gpt-4.1"])

    def call_llm(self, prompt: str, *, json_mode: bool = True, use_indexing_model: bool = False) -> Dict:

        if not self.client:

            return {"error": "LLM not configured"}

        self.llm_calls += 1; self.total_calls += 1

        model = self.config.indexing_model if use_indexing_model else self.config.llm_model

        params = {

            "model": model,

            "messages": [

                {"role":"system","content": "You are an expert EDI analyst. Return ONLY valid JSON."},

                {"role":"user","content": prompt}

            ],

            "temperature": self.config.temperature,

            "max_tokens": self.config.max_tokens

        }

        if json_mode and self._supports_json_mode(model):

            params["response_format"] = {"type":"json_object"}

        try:

            rsp = self.client.chat.completions.create(**params)

            content = rsp.choices[0].message.content

            if json_mode:

                try:

                    return json.loads(content)

                except Exception:

                    try:

                        stripped = content.strip().strip("```json").strip("```")

                        return json.loads(stripped)

                    except Exception as e:

                        return {"parse_error": str(e), "raw_content": content}

            return {"response": content}

        except Exception as e:

            return {"error": str(e)}

    def create_embedding(self, text: str) -> np.ndarray:

        if not self.client:

            return np.zeros(1536, dtype=np.float32)

        self.embedding_calls += 1; self.total_calls += 1

        try:

            txt = text[:8000] if len(text) > 8000 else text

            resp = self.client.embeddings.create(input=txt, model=self.config.embedding_model)

            vec = np.asarray(resp.data[0].embedding, dtype=np.float32)

            n = np.linalg.norm(vec)

            return vec / n if n > 0 else vec

        except Exception as e:

            st.error(f"Embedding failed: {e}")

            return np.zeros(1536, dtype=np.float32)

    def get_stats(self) -> Dict:

        return {"total_calls": self.total_calls, "llm_calls": self.llm_calls, "embedding_calls": self.embedding_calls}

# =========================================================================================

# SMART XSLT GENERATION (NEW)

# =========================================================================================

def add_missing_xslt_elements(xslt_content: str) -> Tuple[str, List[str]]:

    """Add missing critical XSLT elements if needed.

   

    Returns: (fixed_xslt, list_of_fixes)

    """

    fixes = []

    fixed = xslt_content

   

    # Check for output declaration

    if '<xsl:output' not in fixed:

        # Find where to insert (after stylesheet opening tag)

        import re

        match = re.search(r'<xsl:stylesheet[^>]*>', fixed)

        if match:

            insert_pos = match.end()

            output_decl = '\n  <!-- AI generated: Added missing output declaration -->\n  <xsl:output method="xml" indent="yes" encoding="UTF-8"/>\n'

            fixed = fixed[:insert_pos] + output_decl + fixed[insert_pos:]

            fixes.append("Added <xsl:output> declaration")

   

    # Check for root template

    if 'match="/"' not in fixed and "match='/'" not in fixed:

        # Find where to insert (after xsl:output or stylesheet tag)

        import re

       

        # Try to find where first template starts

        first_template = re.search(r'<xsl:template', fixed)

       

        if first_template:

            insert_pos = first_template.start()

           

            # Detect root element name from existing templates

            root_elem = "IDOC"  # Default

           

            root_template = f'''  <!-- AI generated: Added missing root template -->

  <xsl:template match="/">

    <{root_elem}>

      <xsl:apply-templates/>

    </{root_elem}>

  </xsl:template>

 

'''

           

            fixed = fixed[:insert_pos] + root_template + fixed[insert_pos:]

            fixes.append("Added root template match='/'")

   

    return fixed, fixes

def remove_legacy_banner(xsl: str) -> str:
    """
    Remove legacy banner comment blocks from XSLT.
    
    Removes the old banner comment block that looks like:
    <!--  **************************************************************
     Create Date:	26-SEPT-2022 	Created By:	Chitranjana
     Change Date:   20-NOV-2023     Changed By: Hamsha
     EDI Team	:	Solar EDI Team 
     Customers	:	EUROFIEL CONFECCIÓN,S.A.(SPF)(8429107009761
    ) and EUROFIEL CONFECCIÓN S.A. (CTF)(8429107000003)
     ************************************************************** -->
    
    Args:
        xsl: XSLT content as string
        
    Returns:
        XSLT content with legacy banners removed
    """
    import re
    
    # Pattern 1: Match banners with long lines of asterisks at start and end
    pattern1 = re.compile(
        r'<!--\s*\*{10,}[\s\S]*?\*{10,}\s*-->',
        re.IGNORECASE
    )
    
    # Pattern 2: Match banners containing Create Date, Change Date, EDI Team, or Customers
    pattern2 = re.compile(
        r'<!--\s*\*{3,}[\s\S]*?(?:Create\s*Date|Change\s*Date|EDI\s*Team|Customers).*?\*{3,}\s*-->',
        re.IGNORECASE | re.DOTALL
    )
    
    # Remove both patterns
    result = pattern1.sub('', xsl)
    result = pattern2.sub('', result)
    
    return result

def generate_xslt_smart(xslt_content: str, edi_content: str, llm_engine) -> Dict:

    """Generate XSLT with smart handling for any file size."""

   

    # For most files, use direct generation

    prompt = fill_prompt(PROMPTS["generate_xslt"],

                       xslt_content=xslt_content,

                       edi_content=edi_content)

   

    result = llm_engine.call_llm(prompt, json_mode=True, use_indexing_model=True)

   

    # Validate result

    if result.get('error') or result.get('parse_error'):

        return result

   

    if not result.get('changes'):

        if not result.get('modified_xslt'):

            result['modified_xslt'] = xslt_content

        if not result.get('changes'):

            result['changes'] = []

   

    # Add AI-generated header to modified XSLT

    if result.get('modified_xslt'):

        modified_xslt = result['modified_xslt']

       

        # Check if header already exists

        if '<!-- AI GENERATED XSLT' not in modified_xslt:

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

           

            ai_header = f"""<!--
═══════════════════════════════════════════════════════════════════════════════
    AI GENERATED XSLT - REQUIRES HUMAN REVIEW
   
    This XSLT was automatically modified by replacing hardcoded values
    with values from a new EDI document.
   
    IMPORTANT: Review all lines marked with "AI generated, review needed"
    before using in production.
   
    Generated: {timestamp}
    Changes: {len(result.get('changes', []))} value(s) replaced
═══════════════════════════════════════════════════════════════════════════════
-->

"""

           

            # Insert after XML declaration or at start

            if '<?xml' in modified_xslt:

                parts = modified_xslt.split('?>', 1)

                if len(parts) == 2:

                    result['modified_xslt'] = parts[0] + '?>\n' + ai_header + parts[1]

            else:

                result['modified_xslt'] = ai_header + modified_xslt

   

    return result

    """Generate XSLT with smart handling for any file size."""

   

    # For most files, use direct generation

    prompt = fill_prompt(PROMPTS["generate_xslt"],

                       xslt_content=xslt_content,

                       edi_content=edi_content)

   

    result = llm_engine.call_llm(prompt, json_mode=True, use_indexing_model=True)

   

    # Validate result

    if result.get('error') or result.get('parse_error'):

        return result

   

    if not result.get('changes'):

        if not result.get('modified_xslt'):

            result['modified_xslt'] = xslt_content

        if not result.get('changes'):

            result['changes'] = []

   

    # Add AI-generated header to modified XSLT

    if result.get('modified_xslt'):

        modified_xslt = result['modified_xslt']

       

        # Check if header already exists

        if '<!-- AI GENERATED XSLT' not in modified_xslt:

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

           

            ai_header = f"""<!--
═══════════════════════════════════════════════════════════════════════════════
    AI GENERATED XSLT - REQUIRES HUMAN REVIEW
   
    This XSLT was automatically modified by replacing hardcoded values
    with values from a new EDI document.
   
    IMPORTANT: Review all lines marked with "AI generated, review needed"
    before using in production.
   
    Generated: {timestamp}
    Changes: {len(result.get('changes', []))} value(s) replaced
═══════════════════════════════════════════════════════════════════════════════
-->

"""

           

            # Insert after XML declaration or at start

            if '<?xml' in modified_xslt:

                parts = modified_xslt.split('?>', 1)

                if len(parts) == 2:

                    result['modified_xslt'] = parts[0] + '?>\n' + ai_header + parts[1]

            else:

                result['modified_xslt'] = ai_header + modified_xslt

   

    return result

# =========================================================================================

# EDI TO XML CONVERSION

# =========================================================================================

def edi_to_xml(edi_content: str) -> str:
    """Convert EDI to SAP BTP IS canonical XML format using LLM-based parsing."""
   
    # Detect format first
    std = detect_standard(edi_content)
   
    if std not in ["X12", "EDIFACT"]:
        return "<e>Unknown EDI format - cannot convert</e>"
   
    # Check if LLM engine is available
    if 'llm_engine' not in st.session_state or not st.session_state.llm_engine:
        return "<e>LLM Engine not initialized. Please connect to Azure OpenAI first.</e>"
   
    if not st.session_state.llm_engine.client:
        return "<e>Azure OpenAI client not configured. Please check your credentials.</e>"
   
    # Prepare the LLM prompt with task instructions from your screenshot
    prompt = f"""Your Task:
- Convert the EDIFACT Orders into the **SAP BTP IS canonical XML format**.
CRITICAL RULES:
1. ALL segment tags MUST have S_ prefix: <S_UNB>, <S_UNH>, <S_BGM>, <S_DTM>, <S_NAD>, etc.
2. Composites use C_ prefix: <C_S001>, <C_S002>, <C_C002>, etc.
3. Data elements use D_ prefix: <D_0001>, <D_0002>, etc.
4. Preserve ALL values from EDI segments - do not lose any data
5. Use namespace: xmlns:ns0="urn:sap.com:typeName:b2b:em:edifact"

STRUCTURE:
<ns0:Interchange xmlns:ns0="urn:sap.com:typeName:b2b:em:edifact">
  <S_UNA>...</S_UNA>
  <S_UNB>
    <C_S001>
      <D_0001>value</D_0001>
      <D_0002>value</D_0002>
    </C_S001>
  </S_UNB>
  <M_ORDERS>
    <S_UNH>...</S_UNH>
    <S_BGM>...</S_BGM>
    <S_DTM>...</S_DTM>
    <G_SG2>
      <S_NAD>...</S_NAD>
    </G_SG2>
    <S_UNT>...</S_UNT>
  </M_ORDERS>
  <S_UNZ>...</S_UNZ>
</ns0:Interchange>

INPUT EDI:
{edi_content}

Return only valid XML starting with <?xml version="1.0" encoding="UTF-8"?>"""

    try:
        # Call the LLM using your existing LLMEngine
        # Use json_mode=False to get raw XML text instead of JSON
        result = st.session_state.llm_engine.call_llm(
            prompt,
            json_mode=False,  # We want XML text, not JSON
            use_indexing_model=True  # Use the indexing model for this task
        )
       
        # Check if there was an error
        if "error" in result:
            return f"<e>LLM call failed: {result['error']}</e>"
       
        # Extract the response content
        xml_output = result.get("response", "").strip()
       
        if not xml_output:
            return "<e>LLM returned empty response</e>"
       
        # Extract XML if wrapped in markdown code blocks
        if '```xml' in xml_output:
            xml_output = xml_output.split('```xml')[1].split('```')[0].strip()
        elif '```' in xml_output:
            xml_output = xml_output.split('```')[1].split('```')[0].strip()
       
        # Validate it's proper XML
        if not xml_output.startswith('<?xml'):
            xml_output = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_output
       
        # Basic validation that it's XML
        try:
            from lxml import etree
            etree.fromstring(xml_output.encode('utf-8'))
        except Exception as e:
            return f"<e>LLM generated invalid XML: {str(e)}</e>"
       
        return xml_output
       
    except Exception as e:
        # Fallback to basic structure on error
        return f"<e>LLM conversion failed: {str(e)}</e>"

# =========================================================================================

# VALIDATION PIPELINE

# =========================================================================================

def validate_against_schema(xml_content: str, xsd_schema: str) -> Dict[str, Any]:

    """Validate XML/IDOC against XSD schema."""

    try:

        from lxml import etree

       

        # Parse schema and XML

        schema_doc = etree.fromstring(xsd_schema.encode('utf-8'))

        schema = etree.XMLSchema(schema_doc)

       

        xml_doc = etree.fromstring(xml_content.encode('utf-8'))

       

        # Validate

        is_valid = schema.validate(xml_doc)

       

        errors = []

        if not is_valid:

            for error in schema.error_log:

                errors.append({

                    "line": error.line,

                    "column": error.column,

                    "message": error.message,

                    "level": error.level_name

                })

       

        return {

            "valid": is_valid,

            "errors": errors,

            "total_errors": len(errors)

        }

   

    except ImportError:

        return {

            "valid": False,

            "errors": [{"message": "lxml not installed. Run: pip install lxml"}],

            "total_errors": 1

        }

    except Exception as e:

        return {

            "valid": False,

            "errors": [{"message": f"Validation error: {str(e)}"}],

            "total_errors": 1

        }

def extract_field_value(xml_content: str, xpath: str) -> str:

    """Extract field value from XML using XPath."""

    try:

        from lxml import etree

        xml_doc = etree.fromstring(xml_content.encode('utf-8'))

        result = xml_doc.xpath(xpath)

        if result:

            if isinstance(result[0], str):

                return result[0]

            else:

                return result[0].text or ""

        return ""

    except:

        return ""

def compare_outputs(generated_output: str, expected_output: str) -> Dict[str, Any]:

    """Compare generated IDOC with expected output."""

    try:

        from lxml import etree

        from difflib import unified_diff

       

        # Parse both XMLs

        gen_doc = etree.fromstring(generated_output.encode('utf-8'))

        exp_doc = etree.fromstring(expected_output.encode('utf-8'))

       

        # Normalize and compare

        gen_str = etree.tostring(gen_doc, pretty_print=True, encoding='unicode')

        exp_str = etree.tostring(exp_doc, pretty_print=True, encoding='unicode')

       

        # Calculate similarity

        gen_lines = gen_str.splitlines()

        exp_lines = exp_str.splitlines()

       

        diff = list(unified_diff(exp_lines, gen_lines, lineterm=''))

       

        differences = []

        for line in diff:

            if line.startswith('+ ') or line.startswith('- '):

                differences.append(line)

       

        similarity = 100.0 - (len(differences) / max(len(gen_lines), len(exp_lines)) * 100)

       

        return {

            "similar": similarity > 95.0,

            "similarity_pct": similarity,

            "differences": differences[:50],  # First 50 differences

            "total_differences": len(differences)

        }

   

    except Exception as e:

        return {

            "similar": False,

            "similarity_pct": 0.0,

            "differences": [f"Comparison error: {str(e)}"],

            "total_differences": 1

        }

def validate_field_mappings(edi_content: str, idoc_content: str, mappings: List[Dict]) -> List[Dict]:

    """Validate that EDI fields correctly map to IDOC fields.

   

    mappings format: [

        {"edi_segment": "BEG", "edi_element": 3, "idoc_xpath": "//BELNR", "field_name": "PO Number"},

        {"edi_segment": "DTM", "edi_element": 2, "idoc_xpath": "//DATUM", "field_name": "Date"}

    ]

    """

   

    results = []

   

    # Parse EDI

    std = detect_standard(edi_content)

    edi_segs = parse_structured_segments(edi_content, std)

   

    for mapping in mappings:

        edi_seg = mapping["edi_segment"]

        edi_elem = mapping["edi_element"]

        idoc_xpath = mapping["idoc_xpath"]

        field_name = mapping["field_name"]

       

        # Extract EDI value

        edi_value = ""

        for seg in edi_segs:

            if seg and seg[0] == edi_seg:

                if len(seg) > edi_elem:

                    edi_value = seg[edi_elem]

                break

       

        # Extract IDOC value

        idoc_value = extract_field_value(idoc_content, idoc_xpath)

       

        # Compare

        match = (edi_value.strip() == idoc_value.strip())

       

        results.append({

            "field_name": field_name,

            "edi_value": edi_value,

            "idoc_value": idoc_value,

            "match": match,

            "edi_location": f"{edi_seg}*{edi_elem}",

            "idoc_location": idoc_xpath

        })

   

    return results

def check_mandatory_fields(idoc_content: str, mandatory_xpaths: List[Dict]) -> List[Dict]:

    """Check if mandatory IDOC fields are populated.

   

    mandatory_xpaths format: [

        {"xpath": "//E1EDK01/BELNR", "field_name": "Document Number"},

        {"xpath": "//E1EDK01/DATUM", "field_name": "Document Date"}

    ]

    """

   

    results = []

   

    for field in mandatory_xpaths:

        xpath = field["xpath"]

        field_name = field["field_name"]

       

        value = extract_field_value(idoc_content, xpath)

       

        is_present = bool(value and value.strip())

       

        results.append({

            "field_name": field_name,

            "xpath": xpath,

            "present": is_present,

            "value": value if is_present else "MISSING"

        })

   

    return results

def generate_validation_report(validation_results: Dict) -> str:

    """Generate a text report of validation results."""

   

    lines = []

    lines.append("=" * 80)

    lines.append("XSLT TRANSFORMATION VALIDATION REPORT")

    lines.append("=" * 80)

    lines.append("")

   

    # Schema Validation

    if "schema_validation" in validation_results:

        schema = validation_results["schema_validation"]

        lines.append("📋 SCHEMA VALIDATION")

        lines.append("-" * 80)

        if schema["valid"]:

            lines.append("✅ Status: VALID")

        else:

            lines.append(f"❌ Status: INVALID ({schema['total_errors']} errors)")

            for error in schema["errors"][:10]:

                lines.append(f"   Line {error.get('line', '?')}: {error['message']}")

        lines.append("")

   

    # Output Comparison

    if "output_comparison" in validation_results:

        comp = validation_results["output_comparison"]

        lines.append("🔍 OUTPUT COMPARISON")

        lines.append("-" * 80)

        if comp["similar"]:

            lines.append(f"✅ Status: MATCH ({comp['similarity_pct']:.1f}% similar)")

        else:

            lines.append(f"⚠️  Status: DIFFERENCES FOUND ({comp['similarity_pct']:.1f}% similar)")

            lines.append(f"   Total differences: {comp['total_differences']}")

        lines.append("")

   

    # Field Mapping Validation

    if "field_mappings" in validation_results:

        mappings = validation_results["field_mappings"]

        lines.append("🗺️  FIELD MAPPING VALIDATION")

        lines.append("-" * 80)

       

        matched = sum(1 for m in mappings if m["match"])

        total = len(mappings)

       

        lines.append(f"Matched: {matched}/{total} fields")

        lines.append("")

       

        for m in mappings:

            status = "✅" if m["match"] else "❌"

            lines.append(f"{status} {m['field_name']}")

            lines.append(f"   EDI ({m['edi_location']}):  {m['edi_value']}")

            lines.append(f"   IDOC ({m['idoc_location']}): {m['idoc_value']}")

            lines.append("")

   

    # Mandatory Fields

    if "mandatory_fields" in validation_results:

        fields = validation_results["mandatory_fields"]

        lines.append("⚠️  MANDATORY FIELDS CHECK")

        lines.append("-" * 80)

       

        present = sum(1 for f in fields if f["present"])

        total = len(fields)

       

        lines.append(f"Present: {present}/{total} fields")

        lines.append("")

       

        for f in fields:

            status = "✅" if f["present"] else "❌"

            lines.append(f"{status} {f['field_name']}: {f['value']}")

   

    lines.append("")

    lines.append("=" * 80)

    lines.append("END OF REPORT")

    lines.append("=" * 80)

   

    return "\n".join(lines)

def transform_with_xslt(xml_content: str, xslt_content: str, use_saxonc: bool = False) -> Dict[str, str]:
    if use_saxonc:
        try:
            from saxonche import PySaxonProcessor
            with PySaxonProcessor(license=False) as proc:
                xslt_proc = proc.new_xslt30_processor()
               
                # Parse the stylesheet first
                xslt_exec = xslt_proc.compile_stylesheet(stylesheet_text=xslt_content)
               
                # Parse the XML document
                doc_builder = proc.new_document_builder()
                xml_node = doc_builder.parse_xml(xml_text=xml_content)
               
                # Transform
                xslt_exec.set_initial_match_selection(xdm_value=xml_node)
                result = xslt_exec.apply_templates_returning_string()
               
                return {"success": True, "output": result, "method": "SaxonC"}
               
        except ImportError:
            st.warning("⚠️ SaxonC not available. Falling back to lxml.")
        except Exception as e:
            return {"success": False, "output": f"SaxonC Error: {str(e)}", "method": "SaxonC"}

# =========================================================================================

# RAG DATABASE

# =========================================================================================

def build_signal_text(raw: str) -> str:

    std = detect_standard(raw)

    segs = parse_structured_segments(raw, std)

    out = []

    for s in segs[:50]:

        if not s: continue

        if s[0] in ("BEG", "BGM", "REF", "RFF", "N1", "NAD", "PO1", "LIN"):

            out.append(":".join(s[:3]))

    return "\n".join(out)

class RAGDatabase:

    def __init__(self, llm_engine: LLMEngine, customer_mapping: Dict[str, str] = None):

        self.llm_engine = llm_engine

        self.customer_mapping = customer_mapping or {}

        self.index = None

        self.documents = []

        self.vec_meta = []

        self.cache_dir = "edi_cache"

        self.matcher = StructuralMatcher(llm_engine, llm_engine.config if llm_engine else None)

        os.makedirs(self.cache_dir, exist_ok=True)

    def _cache_path(self, name: str, typ: str) -> str:

        return os.path.join(self.cache_dir, f"{hashlib.md5(name.encode()).hexdigest()}_{typ}.pkl")

    def _load(self, name: str, typ: str):

        p = self._cache_path(name, typ)

        if os.path.exists(p):

            with open(p,'rb') as f: return pickle.load(f)

        return None

    def _save(self, name: str, typ: str, data):

        with open(self._cache_path(name,typ),'wb') as f: pickle.dump(data,f)

    def build_index(self, edi_files: List[Tuple[str, str]], xslt_files: List[Tuple[str, str]] = None):

        xslt_dict = {get_base_filename(fname): content for fname, content in (xslt_files or [])}

        embeddings = []

        self.vec_meta = []

        total = len(edi_files)

        pbar = st.progress(0); info = st.empty()

        for i, (fname, content) in enumerate(edi_files):

            base_fname = get_base_filename(fname)

            doc = {'filename': fname, 'content': content}

            doc['xslt_content'] = xslt_dict.get(base_fname, None)

            doc['customer_info'] = extract_customer_info(content)

            doc['metadata'] = extract_metadata_deterministic(content)

            if st.session_state.config.precompute_structure:

                cached = self._load(fname, 'structural_sets') if st.session_state.config.cache_embeddings else None

                if cached is None:

                    tags, tqs = _structural_sets(content)

                    cached = (tags, tqs)

                    if st.session_state.config.cache_embeddings:

                        self._save(fname, 'structural_sets', cached)

                doc['_struct_tags'] = cached[0]

                doc['_struct_tqs'] = cached[1]

            vtext = build_signal_text(content)

            key = "embedding_single"

            cached_emb = self._load(fname, key) if st.session_state.config.cache_embeddings else None

            if cached_emb is None:

                vec = self.llm_engine.create_embedding(vtext)

                if st.session_state.config.cache_embeddings:

                    self._save(fname, key, vec)

            else:

                vec = cached_emb

           

            embeddings.append(vec)

            self.vec_meta.append({"doc_idx": len(self.documents), "view": "single"})

            self.documents.append(doc)

            info.text(f"Indexing {i+1}/{total}"); pbar.progress((i+1)/total)

        if embeddings:

            E = np.array(embeddings).astype('float32')

            self.index = faiss.IndexFlatIP(E.shape[1])

            self.index.add(E)

        stats = self.llm_engine.get_stats()

        st.success(f"✅ Indexed {len(self.documents)} docs")

        st.info(f"API calls: {stats['total_calls']} (LLM {stats['llm_calls']}, Emb {stats['embedding_calls']})")

    def save_index(self, idx_path="edi_index.faiss", meta_path="edi_meta.pkl"):

        if self.index is None or not self.documents: return False

        faiss.write_index(self.index, idx_path)

        with open(meta_path,'wb') as f:

            pickle.dump({"documents": self.documents, "vec_meta": self.vec_meta}, f)

        return True

    def load_index(self, idx_path="edi_index.faiss", meta_path="edi_meta.pkl"):

        if not (os.path.exists(idx_path) and os.path.exists(meta_path)): return False

        self.index = faiss.read_index(idx_path)

        with open(meta_path,'rb') as f:

            payload = pickle.load(f)

        self.documents = payload.get("documents", [])

        self.vec_meta = payload.get("vec_meta", [])

       

        for doc in self.documents:

            if '_struct_tags' not in doc and st.session_state.config.precompute_structure:

                tags, tqs = _structural_sets(doc.get('content', ''))

                doc['_struct_tags'] = tags

                doc['_struct_tqs'] = tqs

        return True

    def search(self, query_content: str, top_k: int = 3) -> List[Dict]:

        if self.index is None or not self.documents:

            return []

        meta = extract_metadata_deterministic(query_content)

        q_sem = meta.get('semantic_type', '')

        q_fmt = meta.get('format', 'UNKNOWN')

        q_type = meta.get('message_type', '')

        qvec = self.llm_engine.create_embedding(build_signal_text(query_content)).reshape(1, -1)

        k = min(max(top_k * 10, 50), len(self.vec_meta))

        D, I = self.index.search(qvec, k)

       

        candidates = []

        for idx, vec_score in zip(I[0], D[0]):

            if idx == -1:

                continue

            doc_idx = self.vec_meta[idx]["doc_idx"]

            doc = self.documents[doc_idx]

           

            coverage_info = query_coverage_score_hybrid(query_content, doc.get('content', ''), self.matcher)

           

            candidates.append({

                "doc_idx": doc_idx,

                "vector_score": float(vec_score),

                "structural_score": coverage_info['coverage_pct'],

                "coverage_info": coverage_info

            })

        candidates.sort(key=lambda x: x['structural_score'], reverse=True)

        results = []

        seen_customers = set()

       

        for cand in candidates:

            doc_idx = cand["doc_idx"]

            doc = self.documents[doc_idx]

           

            dm = doc.get('metadata', {})

            d_sem = dm.get('semantic_type', '')

            d_fmt = dm.get('format', 'UNKNOWN')

            d_type = dm.get('message_type', '')

            keep = (q_sem == d_sem) if q_sem and d_sem else (q_type == d_type)

            if not keep:

                continue

            customer = doc.get('customer_info', {}).get('customer_name', 'Unknown')

            if not st.session_state.config.skip_customer_identification and customer != 'Unknown':

                if customer in seen_customers:

                    continue

                seen_customers.add(customer)

            results.append({

                "doc_idx": doc_idx,

                "document": doc,

                "vector_score": cand["vector_score"],

                "structural_score": cand["structural_score"],

                "coverage_info": cand["coverage_info"],

                "metadata": dm,

                "customer_info": doc.get('customer_info', {}),

                "is_cross_format": q_fmt != d_fmt,

                "format_pair": f"{q_fmt}↔{d_fmt}" if q_fmt != d_fmt else d_fmt

            })

            if len(results) >= top_k:

                break

        return results

    def route_missing_by_sets(self,

                              missing_tags: Set[str],

                              missing_tqs: Set[Tuple[str, str]],

                              *,

                              exclude_doc_idx: int = None,

                              top_n: int = 10) -> Tuple[List[Dict[str, Any]], bool]:

        total_need = len(missing_tags) + 2*len(missing_tqs)

        rows: List[Dict[str, Any]] = []

        if total_need <= 0:

            return [], True

        for di, doc in enumerate(self.documents):

            if exclude_doc_idx is not None and di == exclude_doc_idx:

                continue

           

            if st.session_state.config.precompute_structure and '_struct_tags' in doc:

                dtags = doc['_struct_tags']

                dtqs = doc['_struct_tqs']

            else:

                dtags, dtqs = _structural_sets(doc.get("content", ""))

           

            hit_tags = missing_tags & dtags

            hit_tqs = missing_tqs & dtqs

            score = len(hit_tags) + 2*len(hit_tqs)

            if score <= 0:

                continue

           

            content = doc.get("content", "")

            std = detect_standard(content)

            segs = parse_structured_segments(content, std)

           

            segment_examples = []

            for s in segs:

                if not s:

                    continue

                tag = (s[0] or "").strip().upper()

               

                if tag in hit_tags or (len(s) > 1 and (tag, (s[1] or "").strip().upper().split(":")[0] if std == "EDIFACT" else (s[1] or "").strip().upper()) in hit_tqs):

                    qual = (s[1] or "").strip().upper().split(":")[0] if (std == "EDIFACT" and len(s) > 1) else ((s[1] or "").strip().upper() if len(s) > 1 else "")

                    segment_examples.append({

                        "element": f"{tag}:{qual}" if qual else tag,

                        "full_segment": normalize_preview(s)

                    })

                   

                    if len(segment_examples) >= 10:

                        break

           

            rows.append({

                "doc_idx": di,

                "filename": doc.get('filename', 'Unknown File'),

                "customer": (doc.get("customer_info") or {}).get("customer_name", "Unknown"),

                "hit_tags": sorted(list(hit_tags)),

                "hit_tqs": _pretty_tqs(hit_tqs),

                "segment_examples": segment_examples,

                "score": score,

                "coverage": score / float(max(1, total_need))

            })

        rows.sort(key=lambda r: r["score"], reverse=True)

        single = False

        if rows:

            if rows[0]["coverage"] >= 1.0:

                single = True

            elif rows[0]["coverage"] >= 0.90:

                single = True

        return rows[:top_n], single

# =========================================================================================

# RENDER FUNCTIONS

# =========================================================================================

def _render_analysis(i: int, query_content: str, candidate_content: str, top_customer: str):

    result = st.session_state.search_results[i]

    coverage_info = result.get('coverage_info', {})

   

    if not coverage_info:

        matcher = st.session_state.rag_db.matcher

        coverage_info = query_coverage_score_hybrid(query_content, candidate_content, matcher)

   

    coverage_pct = coverage_info["coverage_pct"]

    missing_pct = 100.0 - coverage_pct

    st.markdown("### 📐 Structural Coverage (Hybrid Matching)")

    st.markdown(f"<div class='analysis-box'>", unsafe_allow_html=True)

   

    col1, col2 = st.columns([1, 2])

    with col1:

        color = '#28a745' if coverage_pct >= 95 else '#ffc107' if coverage_pct >= 80 else '#dc3545'

        st.markdown(f"<h1 style='color: {color}; text-align: center; margin: 0;'>{coverage_pct:.1f}%</h1>", unsafe_allow_html=True)

        st.markdown(f"<p style='color: #666; text-align: center; margin: 0;'>Query Coverage</p>", unsafe_allow_html=True)

   

    with col2:

        st.write(f"**Tags Matched:** {coverage_info['matched_tag_count']}/{coverage_info['query_tag_count']}")

        st.write(f"**Tag:Qualifiers Matched:** {coverage_info['matched_tq_count']}/{coverage_info['query_tq_count']}")

       

        if coverage_pct >= 95:

            st.success("✅ Excellent coverage")

        elif coverage_pct >= 80:

            st.warning("⚠️ Good coverage")

        else:

            st.error("❌ Partial coverage")

   

    st.markdown("</div>", unsafe_allow_html=True)

    match_details = coverage_info.get('match_details', [])

    if match_details:

        with st.expander("🔍 Matching Strategy Breakdown", expanded=False):

            strategy_counts = Counter(d['type'] for d in match_details)

           

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric("Exact Matches", strategy_counts.get('exact', 0))

            with col2:

                st.metric("Cross-Format", strategy_counts.get('cross_format', 0))

            with col3:

                st.metric("LLM Adaptive", strategy_counts.get('llm_adaptive', 0))

           

            llm_matches = [d for d in match_details if d['type'] == 'llm_adaptive']

            if llm_matches:

                st.markdown("**🤖 LLM Adaptive Matches:**")

                for m in llm_matches[:10]:

                    st.write(f"• `{m['query']}` → `{m['match']}` (score: {m['score']:.2f})")

    missing_tags = coverage_info["missing_tags"]

    missing_tqs = coverage_info["missing_tqs"]

   

    if not missing_tags and not missing_tqs:

        st.success("✅ **Complete match!** All query elements found.")

    else:

        st.markdown(f"### 🔍 Missing Query Elements ({missing_pct:.1f}%)")

       

        if missing_tags:

            st.markdown("**Missing Tags:**")

            st.code(", ".join(sorted(list(missing_tags))), language="text")

       

        if missing_tqs:

            st.markdown("**Missing Tag:Qualifiers:**")

            st.code(", ".join(_pretty_tqs(missing_tqs)), language="text")

        query_segs = parse_structured_segments(query_content, detect_standard(query_content))

        examples = _sample_segments_for_signatures(query_segs, set(missing_tags), set(missing_tqs), limit=8)

        if examples:

            st.markdown("**Examples from your query:**")

            for ex in examples[:5]:

                st.code(ex, language="text")

        st.markdown("---")

        st.markdown("### 🎯 Where to Find Missing Elements")

       

        rows, single = st.session_state.rag_db.route_missing_by_sets(

            missing_tags, missing_tqs,

            exclude_doc_idx=result.get("doc_idx"),

            top_n=10

        )

        if not rows:

            st.info("ℹ️ No other files contain these elements.")

        else:

            customer_map = {}

            for r in rows:

                cust = r["customer"]

                if cust not in customer_map or r["score"] > customer_map[cust]["score"]:

                    customer_map[cust] = r

           

            unique_rows = sorted(customer_map.values(), key=lambda x: x["score"], reverse=True)

           

            top_coverage = unique_rows[0]["coverage"] if unique_rows else 0

           

            if top_coverage >= 0.90:

                r = unique_rows[0]

                missing_coverage_pct = missing_pct * r['coverage']

                st.success(f"🟢 **Single-Source Solution!**")

                st.info(f"**{r['customer']}** covers **{missing_coverage_pct:.1f}%** of your query "

                        f"(≈{r['coverage']*100:.0f}% of missing elements)")

               

                if r.get("segment_examples"):

                    st.markdown(f"### {r['customer']}")

                    st.markdown("**Missing Elements:**")

                    elements = [ex["element"] for ex in r["segment_examples"]]

                    st.write(", ".join(elements))

                   

                    st.markdown("**Example Segments:**")

                    for ex in r["segment_examples"]:

                        st.code(ex["full_segment"], language="text")

                       

            else:

                st.info(f"🔵 **Multi-Source Solution** (non-overlapping coverage to cover {missing_pct:.1f}%):")

               

                remaining_tags = missing_tags.copy()

                remaining_tqs = missing_tqs.copy()

                total_need = len(missing_tags) + 2 * len(missing_tqs)

                cumulative = 0.0

                for r in unique_rows[:5]:

                    doc_idx = r["doc_idx"]

                    doc = st.session_state.rag_db.documents[doc_idx]

                    dtags = doc.get("_struct_tags", set())

                    dtqs = doc.get("_struct_tqs", set())

                   

                    hit_tags = remaining_tags & dtags

                    hit_tqs = remaining_tqs & dtqs

                    score = len(hit_tags) + 2 * len(hit_tqs)

                    if score <= 0:

                        continue

                   

                    contrib = (score / total_need) * missing_pct

                    cumulative += contrib

                   

                    segment_examples = []

                    for ex in r.get("segment_examples", []):

                        elem = ex["element"]

                        if ':' in elem:

                            tag, qual = elem.split(':', 1)

                            if (tag, qual) in hit_tqs:

                                segment_examples.append(ex)

                        elif elem in hit_tags:

                            segment_examples.append(ex)

                   

                    if segment_examples:

                        st.markdown(f"### {r['customer']} (adds {contrib:.1f}%)")

                       

                        elements = [ex["element"] for ex in segment_examples]

                        st.markdown(f"**Missing Elements:** {', '.join(elements)}")

                       

                        st.markdown("**Example Segments:**")

                        for ex in segment_examples:

                            st.code(ex["full_segment"], language="text")

                       

                        st.markdown("---")

                   

                    remaining_tags -= hit_tags

                    remaining_tqs -= hit_tqs

                   

                    if not remaining_tags and not remaining_tqs:

                        break

               

                if cumulative >= missing_pct * 0.95:

                    st.success(f"✅ **Complete!** Above files provide ~{cumulative:.1f}% of query.")

                else:

                    remaining = missing_pct - cumulative

                    st.warning(f"⚠️ ~{remaining:.1f}% still not found in database.")

def _render_xslt_viewer(i: int, matched_document: Dict):

    st.markdown("### 📄 XSLT Viewer")

   

    xslt_content = matched_document.get('xslt_content')

    if not xslt_content:

        st.error("No XSLT found for this document")

        return

   

    matched_filename = matched_document.get('filename', 'matched_file')

    base_name = get_base_filename(matched_filename)

   

    st.info(f"📄 Viewing XSLT for: **{matched_filename}**")

   

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric("File Size", f"{len(xslt_content)} chars")

    with col2:

        line_count = xslt_content.count('\n') + 1

        st.metric("Lines", line_count)

    with col3:

        template_count = xslt_content.count('<xsl:template')

        st.metric("Templates", template_count)

   

    tab1, tab2, tab3 = st.tabs(["📝 XSLT Code", "🔍 Template Summary", "📥 Download"])

   

    with tab1:

        st.markdown("### Full XSLT Content")

        st.code(xslt_content, language="xml", line_numbers=True)

   

    with tab2:

        st.markdown("### Template Overview")

       

        import re

        templates = re.findall(r'<xsl:template[^>]*match=["\']([^"\']+)["\']', xslt_content)

        named_templates = re.findall(r'<xsl:template[^>]*name=["\']([^"\']+)["\']', xslt_content)

       

        if templates:

            st.markdown("**Match Templates:**")

            for idx, template in enumerate(templates, 1):

                st.write(f"{idx}. `{template}`")

       

        if named_templates:

            st.markdown("**Named Templates:**")

            for idx, template in enumerate(named_templates, 1):

                st.write(f"{idx}. `{template}`")

       

        if not templates and not named_templates:

            st.info("No templates found in XSLT")

       

        st.markdown("---")

        st.markdown("**Hardcoded Values Found:**")

       

        hardcoded_values = []

        for m in re.finditer(r"(?:select|value|test)=['\"](.+?)['\"]", xslt_content):

            value = m.group(1).strip()

            if not any(char in value for char in ['/', '@', '$', '[', '{', ':', '(', ')']) and value:

                if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):

                    value = value.strip("'\"")

                hardcoded_values.append(value)

       

        if hardcoded_values:

            values = [v for v in set(hardcoded_values) if len(v) > 2 and not v.lower() in ('true', 'false', '0', '1', 'name')]

           

            if values:

                st.write(f"Found {len(values)} unique hardcoded value(s):")

                for val in values[:10]:

                    st.code(val, language="text")

                if len(values) > 10:

                    st.caption(f"... and {len(values) - 10} more")

            else:

                st.info("✅ No obvious hardcoded values found (XSLT uses dynamic XPath or variables)")

        else:

            st.info("✅ No obvious hardcoded values found (XSLT uses dynamic XPath or variables)")

   

    with tab3:

        st.markdown("### Download XSLT")

       

        st.download_button(

            label="💾 Download Original XSLT",

            data=xslt_content,

            file_name=f"{base_name}.xslt",

            mime="application/xml",

            type="primary"

        )

       

        st.success(f"📥 Click above to download: `{base_name}.xslt`")

       

        st.markdown("---")

        st.markdown("**XSLT Metadata:**")

        st.write(f"**Source EDI:** {matched_filename}")

        st.write(f"**File Size:** {len(xslt_content)} characters")

        st.write(f"**Lines:** {xslt_content.count(chr(10)) + 1}")

def _render_xslt_merge_ui(merged_result: Dict, primary_filename: str, query_edi_content: str, result_index: int):

    st.markdown("---")

    st.markdown("### 🧩 Auto-Merged XSLT Result")

   

    if not merged_result or "merged_xslt" not in merged_result or not merged_result.get("merged_xslt"):

        st.error("❌ Merge operation failed or returned no content.")

        if merged_result:

            if "error" in merged_result:

                st.error(f"**LLM API Error:** {merged_result['error']}")

            if "parse_error" in merged_result:

                st.error(f"**JSON Parse Error:** {merged_result['parse_error']}")

                with st.expander("🔍 Raw LLM Response", expanded=False):

                    st.code(merged_result.get("raw_content", "No raw content available."), language="text")

        return

    merged_xslt = merged_result.get("merged_xslt", "")

    explanation = merged_result.get("explanation", "No explanation provided.")

    tab1, tab2, tab3 = st.tabs(["📊 Merge Summary", "✨ Merged XSLT", "📥 Download"])

    with tab1:

        st.markdown("#### LLM Merge Actions")

        st.info("The LLM performed the following actions to create the merged file:")

        for line in explanation.split('- '):

            if line.strip():

                st.markdown(f"- {line.strip()}")

    with tab2:

        st.markdown("#### Complete Merged XSLT Code")

        st.code(merged_xslt, language='xml', line_numbers=True)

    with tab3:

        st.markdown("#### Download Merged File")

        suggested_name = f"{get_base_filename(primary_filename)}_merged.xslt"

        st.download_button(

            label="💾 Download Merged XSLT",

            data=merged_xslt,

            file_name=suggested_name,

            mime="application/xml",

            type="primary"

        )

        st.success(f"Click the button to download the new file as `{suggested_name}`.")

       

        st.info("💡 Go to the 'Transform & Validate' tab to test this merged XSLT!")

       

        st.markdown("---")

        st.markdown("**ℹ️ About AI-Merged XSLTs:**")

        st.write("• Header comment identifies AI-generated file")

        st.write("• Inline comments mark added templates and logic")

        st.write("• Review all 'AI generated' sections before production")

def _render_xslt_generation(i: int, query_edi_content: str, matched_document: Dict):

    st.markdown("### 🎯 XSLT Generation (LLM Adaptive)")

   

    xslt_content = matched_document.get('xslt_content')

    if not xslt_content:

        st.error("No XSLT found for this document")

        return

   

    matched_filename = matched_document.get('filename', 'matched_file')

   

    result = st.session_state.search_results[i]

    coverage_info = result.get('coverage_info', {})

    coverage_pct = coverage_info.get('coverage_pct', 0.0) if coverage_info else 0.0

   

    st.info(f"📄 Using XSLT from: **{matched_filename}** (covers {coverage_pct:.1f}% of your query)")

    modified_xslt_key = f"modified_xslt_{i}"

   

    generation_result = st.session_state.modified_xslts.get(modified_xslt_key)

    if generation_result:

        modified_xslt = generation_result["modified_xslt"]

        changes = generation_result["changes"]

    else:

        modified_xslt = xslt_content

        changes = []

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric("Model Used", st.session_state.config.indexing_model if st.session_state.llm_engine and st.session_state.llm_engine.client else "N/A")

    with col2:

        st.metric("Original Lines", xslt_content.count('\n') + 1)

    with col3:

        st.metric("XSLT Changes", len(changes))

    tab1, tab2, tab3, tab4 = st.tabs(["📊 Changes Summary", "🔍 Original XSLT", "✨ Modified XSLT", "📥 Download"])

    with tab1:

        st.markdown("### Changes Made by LLM")

        if not changes:

            st.warning("⚠️ LLM found no hardcoded values to replace.")

            st.info("Possible reasons:\n- XSLT uses only XPath variables\n- No EDI-specific hardcoded values present\n- Values couldn't be matched to target EDI")

        else:

            st.success(f"✅ LLM replaced {len(changes)} value(s)")

           

            df_changes = pd.DataFrame(changes)

            df_changes = df_changes.rename(columns={'context_line': 'Context', 'old_value': 'Old Value', 'new_value': 'New Value', 'reasoning': 'Reason'})

            st.dataframe(df_changes[['Reason', 'Old Value', 'New Value', 'Context']], use_container_width=True)

           

            with st.expander("📝 Detailed Changes", expanded=True):

                for idx, change in enumerate(changes[:20], 1):

                    st.markdown(f"**Change #{idx}**")

                    col_a, col_b = st.columns(2)

                    with col_a:

                        st.code(f"OLD: {change.get('old_value', change.get('Old Value', ''))}", language="text")

                    with col_b:

                        st.code(f"NEW: {change.get('new_value', change.get('New Value', ''))}", language="text")

                    st.caption(f"Context: `{change.get('context_line', change.get('Context', ''))}`")

                    st.caption(f"Reason: {change.get('reasoning', change.get('Reason', ''))}")

                    st.markdown("---")

                   

                    if len(changes) > 20:

                        st.info(f"... and {len(changes) - 20} more changes")

    with tab2:

        st.markdown("### Original XSLT (from matched file)")

        st.code(xslt_content, language="xml", line_numbers=True)

    with tab3:

        st.markdown("### Modified XSLT (with your EDI values)")

        st.code(modified_xslt, language="xml", line_numbers=True)

    with tab4:

        st.markdown("### Download Generated XSLT")

       

        base_name = get_base_filename(matched_filename)

        suggested_name = f"{base_name}_llm_generated.xslt"

       

        st.download_button(

            label="💾 Download XSLT",

            data=modified_xslt,

            file_name=suggested_name,

            mime="application/xml",

            type="primary"

        )

       

        st.success(f"📥 Click above to download as: `{suggested_name}`")

       

        st.info("💡 After auto-merge (if needed), go to the 'Transform & Validate' tab to test the final XSLT!")

       

        st.markdown("---")

        st.markdown("**ℹ️ About AI-Generated XSLTs:**")

        st.write("• Header comment marks file as AI-generated")

        st.write("• Inline comments show where values were changed")

        st.write("• Review all marked sections before production use")

    st.markdown("---")

    st.markdown("## 🔧 Multi-Source XSLT Guidance")

   

    missing_tags = coverage_info.get('missing_tags', set())

    missing_tqs = coverage_info.get('missing_tqs', set())

    missing_pct = 100.0 - coverage_pct

   

    if not missing_tags and not missing_tqs:

        st.success("✅ **Perfect Match!** This XSLT covers 100% of your query.")

        st.info("No additional XSLTs needed - you're all set!")

    elif coverage_pct >= 95:

        st.success(f"✅ **Excellent Coverage!** Only {missing_pct:.1f}% missing.")

        st.info("Minor gaps - may not need additional XSLTs")

    else:

        st.warning(f"⚠️ **Partial Coverage:** {missing_pct:.1f}% of query elements not covered by this XSLT")

       

        st.markdown("### 📚 Additional XSLTs to Consider")

        st.caption("These files contain segments missing from your primary XSLT:")

       

        with st.spinner("Analyzing other files for missing elements..."):

            rows, single = st.session_state.rag_db.route_missing_by_sets(

                missing_tags,

                missing_tqs,

                exclude_doc_idx=result.get("doc_idx"),

                top_n=10

            )

       

        if not rows:

            st.info("ℹ️ No other files in database contain these missing elements.")

            st.caption("You may need to create these XSLT sections manually.")

        else:

            customer_map = {}

            for r in rows:

                cust = r["customer"]

                if cust not in customer_map or r["score"] > customer_map[cust]["score"]:

                    customer_map[cust] = r

           

            unique_rows = sorted(customer_map.values(), key=lambda x: x["score"], reverse=True)

            best_supplementary_source = None

            for row in unique_rows:

                doc = st.session_state.rag_db.documents[row['doc_idx']]

                if doc.get('xslt_content'):

                    best_supplementary_source = row

                    break

           

            if best_supplementary_source:

                merge_button_key = f"automerge_{i}"

                if st.button("🤖 Auto-Merge with Best Source", key=merge_button_key, help=f"Merges this XSLT with logic from {best_supplementary_source['filename']}"):

                    with st.spinner("🤖 LLM is performing the XSLT merge... This may take a moment."):

                        primary_xslt = modified_xslt

                        supp_doc = st.session_state.rag_db.documents[best_supplementary_source['doc_idx']]

                        supplementary_xslt = supp_doc.get('xslt_content', '')

                        missing_elements = ", ".join(sorted(list(missing_tags)) + _pretty_tqs(missing_tqs))

                       

                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                       

                        merge_prompt = fill_prompt(

                            PROMPTS["merge_xslts"],

                            primary_xslt=primary_xslt,

                            supplementary_xslt=supplementary_xslt,

                            missing_elements=missing_elements,

                            timestamp=timestamp

                        )

                       

                        merge_result = st.session_state.llm_engine.call_llm(merge_prompt, use_indexing_model=True)

                        # Remove legacy banner comments from merged XSLT
                        if "merged_xslt" in merge_result:
                            merge_result["merged_xslt"] = remove_legacy_banner(merge_result["merged_xslt"])

                        print(merge_result) 
                        st.session_state.merged_xslt_result[i] = merge_result

                        st.rerun()

           

            if i in st.session_state.merged_xslt_result:

                _render_xslt_merge_ui(st.session_state.merged_xslt_result[i], matched_filename, st.session_state.query_content, i)

            for idx, row in enumerate(unique_rows[:3], 1):

                supplement_coverage = missing_pct * row['coverage']

               

                with st.expander(

                    f"🔹 Source #{idx}: {row['customer']} - Adds {supplement_coverage:.1f}% coverage",

                    expanded=(idx == 1)

                ):

                    col_a, col_b = st.columns([2, 1])

                   

                    with col_a:

                        st.write(f"**File:** {row['filename']}")

                        st.write(f"**Covers:** {row['coverage']*100:.1f}% of missing elements")

                        st.write(f"**Adds to total:** {supplement_coverage:.1f}% of your query")

                       

                        matched_missing = sorted(list(row.get('hit_tags', []))) + sorted(row.get('hit_tqs', []))

                        if matched_missing:

                            st.markdown("**Segments to add from this XSLT:**")

                            segment_list = ", ".join([f"`{seg}`" for seg in matched_missing[:10]])

                            st.markdown(segment_list)

                            if len(matched_missing) > 10:

                                st.caption(f"... and {len(matched_missing) - 10} more")

                   

                    with col_b:

                        doc = st.session_state.rag_db.documents[row['doc_idx']]

                        supplement_xslt = doc.get('xslt_content')

                       

                        if supplement_xslt:

                            st.download_button(

                                label="📥 Download XSLT",

                                data=supplement_xslt,

                                file_name=f"{get_base_filename(doc['filename'])}.xslt",

                                mime="application/xml",

                                key=f"download_supp_{i}_{idx}"

                            )

                            st.success("✅ XSLT available")

                        else:

                            st.caption("⚠️ No XSLT for this file")

           

            st.markdown("---")

            st.markdown("### 📋 Merge Instructions")

           

            total_potential = coverage_pct + sum(

                missing_pct * r['coverage']

                for r in unique_rows[:3]

            )

            st.info(f"""

            **🎯 Recommended Approach:**

           

            1.  🚀 **Use the "Auto-Merge" button** above for an AI-generated starting point.

            2.  ✅ **Start with primary XSLT** (downloaded above) - covers {coverage_pct:.1f}%

            3.  📥 **Download supplementary XSLTs** (buttons above)

            4.  🔍 **Identify missing segments** (listed in each section)

            5.  ✂️ **Copy relevant sections** from supplementary XSLTs

            6.  📝 **Paste into primary XSLT** at appropriate locations

            7.  ✅ **Potential total coverage:** {min(total_potential, 100.0):.1f}%

            **💡 Tip:** Look for `<xsl:template>` sections that match the segment names listed above.

            """)

            st.markdown("### 📊 Coverage Summary")

            summary_data = {

                "Source": ["Primary Match"] + [f"Supplement {i+1}" for i in range(len(unique_rows[:3]))],

                "File": [matched_filename] + [r['filename'] for r in unique_rows[:3]],

                "Coverage": [f"{coverage_pct:.1f}%"] + [f"+{missing_pct * r['coverage']:.1f}%" for r in unique_rows[:3]],

                "Has XSLT": ["✅"] + ["✅" if st.session_state.rag_db.documents[r['doc_idx']].get('xslt_content') else "❌" for r in unique_rows[:3]]

            }

            st.table(pd.DataFrame(summary_data))

def load_customer_mapping(file_obj) -> Dict[str, str]:

    try:

        df = pd.read_csv(file_obj, dtype=str, header=0)

    except:

        file_obj.seek(0)

        df = pd.read_excel(file_obj, dtype=str, header=0)

    mapping = {}

    if not df.empty and len(df.columns) >= 2:

        for _, row in df.iterrows():

            key = _normalize_id(str(row.iloc[0]))

            value = str(row.iloc[1]).strip() if pd.notna(row.iloc[1]) else ""

            if key and key.lower() not in ['nan', 'none']:

                mapping[key] = value

    return mapping

# =========================================================================================

# SESSION & APP

# =========================================================================================

def init_session_state():

    if 'rag_db' not in st.session_state: st.session_state.rag_db = None

    if 'config' not in st.session_state: st.session_state.config = Config()

    if 'llm_engine' not in st.session_state: st.session_state.llm_engine = None

    if 'database_ready' not in st.session_state: st.session_state.database_ready = False

    if 'customer_mapping' not in st.session_state: st.session_state.customer_mapping = {}

    if 'query_content' not in st.session_state: st.session_state.query_content = None

    if 'search_results' not in st.session_state: st.session_state.search_results = []

    if 'analysis_cache' not in st.session_state: st.session_state.analysis_cache = {}

    if 'merged_xslt_result' not in st.session_state: st.session_state.merged_xslt_result = {}

    if 'modified_xslts' not in st.session_state: st.session_state.modified_xslts = {}

    if 'active_view' not in st.session_state: st.session_state.active_view = {}

def main():

    init_session_state()

    st.title("🤖 Hybrid EDI Analyzer")

    st.markdown("*Deterministic + LLM Adaptive*")

    with st.sidebar:

        st.header("⚙️ Azure OpenAI")

        st.session_state.config.azure_endpoint = st.text_input("Endpoint", type="password", value=st.session_state.config.azure_endpoint)

        st.session_state.config.api_key = st.text_input("API Key", type="password", value=st.session_state.config.api_key)

        st.session_state.config.embedding_model = st.text_input("Embedding Model", value=st.session_state.config.embedding_model)

        st.session_state.config.llm_model = st.text_input("LLM Model", value=st.session_state.config.llm_model)

        st.session_state.config.indexing_model = st.text_input("Indexing/XSLT Model", value=st.session_state.config.indexing_model)

       

        st.header("🎯 Matching Mode")

        st.session_state.config.matching_mode = st.selectbox(

            "Strategy",

            ["hybrid", "pure_structural", "semantic_only"],

            help="Hybrid = deterministic first, LLM for unknowns"

        )

       

        if st.session_state.config.matching_mode == "hybrid":

            st.session_state.config.llm_adaptive_matching = st.checkbox("🤖 Enable LLM Adaptive", value=True)

            st.session_state.config.llm_confidence_threshold = st.slider("LLM Match Threshold", 0.5, 1.0, 0.7)

       

        st.header("⚡ Options")

        st.session_state.config.precompute_structure = st.checkbox("Pre-compute Structure", value=True)

        st.session_state.config.cache_embeddings = st.checkbox("Cache", value=True)

        st.session_state.config.skip_customer_identification = st.checkbox("Skip Customer Dedup", value=True)

       

        st.markdown("---")

        st.markdown("### 📦 Dependencies")

        st.caption("**Required for transformation & validation:**")

        st.code("pip install lxml", language="bash")

        st.caption("**For XSLT 2.0/3.0 support (RECOMMENDED):**")

        st.code("pip install saxonche", language="bash")

        st.info("💡 Most XSLTs use XSLT 2.0+ features. Install SaxonC to avoid errors!")

       

        st.markdown("---")

        st.markdown("### 📖 Quick Guide")

        with st.expander("How to use Validation", expanded=False):

            st.markdown("""

            **Validation Pipeline Steps:**

           

            1. **Generate/Merge XSLT**

               - Click "Generate XSLT" to adapt XSLT

               - Use "Auto-Merge" if needed

           

            2. **Transform**

               - Go to "Transform" tab

               - Click "Run Transformation"

           

            3. **Validate**

               - Go to "Validate" tab

               - Upload XSD schema (optional)

               - Upload expected output (optional)

               - Configure field mappings

               - Click "Validate IDOC"

           

            4. **Review Results**

               - Check validation metrics

               - Review field mappings

               - Download validation report

           

            **Validation Types:**

            - 📋 **Schema**: Validates against IDOC XSD

            - 🔍 **Comparison**: Compares with expected output

            - 🗺️ **Field Mapping**: EDI → IDOC field checks

            - ⚠️ **Mandatory**: Checks required fields

            """)

       

        if st.button("🔗 Connect"):

            st.session_state.llm_engine = LLMEngine(st.session_state.config)

            if st.session_state.llm_engine.client:

                 st.success("Connected")

            else:

                 st.warning("Connected (LLM client not fully configured - check keys)")

       

        if st.session_state.llm_engine and st.session_state.llm_engine.client:

            if st.button("🧪 Test LLM"):

                test_prompt = "Return JSON with one key 'test' and value 'success': "

                test_result = st.session_state.llm_engine.call_llm(test_prompt, json_mode=True)

                st.json(test_result)

       

        st.markdown("---")

       

        if st.button("💾 Save Index"):

            if st.session_state.rag_db and st.session_state.rag_db.save_index():

                st.success("Saved")

            else:

                st.error("Nothing to save")

       

        if st.button("📂 Load Index"):

            if not st.session_state.llm_engine:

                st.error("Connect first")

            else:

                st.session_state.rag_db = RAGDatabase(st.session_state.llm_engine, st.session_state.customer_mapping)

                if st.session_state.rag_db.load_index():

                    st.session_state.database_ready = True

                    st.success(f"Loaded {len(st.session_state.rag_db.documents)} docs")

                else:

                    st.error("No index found")

       

        if st.session_state.llm_engine:

            stats = st.session_state.llm_engine.get_stats()

            st.metric("API Calls", stats["total_calls"])

           

            if st.session_state.rag_db:

                matcher_stats = st.session_state.rag_db.matcher.get_stats()

                st.markdown("**Matching Stats:**")

                st.write(f"Deterministic: {matcher_stats['deterministic_matches']}")

                st.write(f"Cross-format: {matcher_stats['cross_format_matches']}")

                st.write(f"LLM Adaptive: {matcher_stats['llm_adaptive_matches']}")

                st.write(f"Cache hits: {matcher_stats['cache_hits']}")

    tab1, tab2, tab3, tab4 = st.tabs(["📚 Build Database", "🔍 Search & Match", "🔄 Transform & Validate","Mapping Specification"])

    with tab1:

        st.header("Build Database")

        mapping_file = st.file_uploader("Customer Mapping (optional)", type=["csv","xlsx"])

        if mapping_file:

            st.session_state.customer_mapping = load_customer_mapping(mapping_file)

            st.success(f"Loaded {len(st.session_state.customer_mapping)} mappings")

        edi_files = st.file_uploader("EDI Files", type=["edi","txt","x12"], accept_multiple_files=True)

        if edi_files: st.info(f"{len(edi_files)} files ready")

        xslt_files = st.file_uploader("XSLT (optional)", type=["xslt","xsl"], accept_multiple_files=True)

        if edi_files and st.button("🚀 Build", type="primary"):

            if not st.session_state.llm_engine:

                st.error("Connect first")

            else:

                edi_data = [(f.name, f.read().decode("utf-8","ignore")) for f in edi_files]

                xslt_data = [(f.name, f.read().decode("utf-8","ignore")) for f in (xslt_files or [])]

                st.session_state.rag_db = RAGDatabase(st.session_state.llm_engine, st.session_state.customer_mapping)

                with st.spinner("Building..."):

                    st.session_state.rag_db.build_index(edi_data, xslt_data)

                    st.session_state.database_ready = True

    with tab2:

        if not st.session_state.database_ready:

            st.warning("Build database first")

            st.stop()

        qfile = st.file_uploader("Query File", type=['edi','txt','x12'])

        top_k = st.slider("Results", 1, 10, 3)

        if qfile and st.button("🔍 Search", type="primary"):

            st.session_state.query_content = qfile.read().decode('utf-8', errors='ignore')

            with st.spinner("Searching..."):

                st.session_state.search_results = st.session_state.rag_db.search(st.session_state.query_content, top_k)

            st.session_state.analysis_cache = {}

            st.session_state.merged_xslt_result = {}

            st.session_state.modified_xslts = {}

            st.session_state.active_view = {}

        results = st.session_state.search_results

        if not results:

            st.info("Upload query and search")

            st.stop()

        st.success(f"✅ Found {len(results)} matches")

        st.info(f"🎯 Ranked by structural coverage (hybrid: {st.session_state.config.matching_mode})")

        st.markdown("---")

        for i, result in enumerate(results):

            customer = result['customer_info'].get('customer_name', 'Unknown')

            with st.expander(f"📄 #{i+1}: {customer}", expanded=(i == 0)):

                col1, col2 = st.columns([1, 3])

                with col1:

                    score = result.get('structural_score', 0.0)

                    st.markdown(f"<div class='match-score'>{score:.1f}%</div>", unsafe_allow_html=True)

                    st.caption("Structural coverage")

                with col2:

                    st.write(f"**Format:** {result['metadata'].get('format', 'Unknown')}")

                    st.write(f"**Type:** {result['metadata'].get('message_type', 'Unknown')}")

                    st.write(f"**Customer:** {customer}")

                    if result.get('is_cross_format'):

                        st.success(f"🔄 {result.get('format_pair', '')}")

               

                has_xslt = result['document'].get('xslt_content') is not None

               

                if has_xslt:

                    col_a, col_b, col_c = st.columns(3)

                    with col_a:

                        if st.button("🔬 Analyze", key=f"analyze_{i}"):

                            st.session_state.active_view[i] = "analyze"

                    with col_b:

                        if st.button("📄 View XSLT", key=f"view_xslt_{i}"):

                            st.session_state.active_view[i] = "view_xslt"

                    with col_c:

                        if st.button("🎯 Generate XSLT", key=f"gen_xslt_{i}"):

                            st.session_state.active_view[i] = "generate_xslt"

                           

                            xslt_content = result['document'].get('xslt_content')

                            if xslt_content and st.session_state.llm_engine and st.session_state.llm_engine.client:

                                with st.spinner("🤖 LLM analyzing and generating new XSLT..."):

                                    # Show debug info

                                    with st.expander("🔍 Debug Info", expanded=False):

                                        st.info(f"📏 XSLT length: {len(xslt_content):,} chars")

                                        st.info(f"📏 EDI length: {len(st.session_state.query_content):,} chars")

                                        st.info(f"🤖 Model: {st.session_state.config.indexing_model}")

                                        st.info(f"🎯 Max tokens: {st.session_state.config.max_tokens}")

                                   

                                    # Use smart generation

                                    generation_result = generate_xslt_smart(

                                        xslt_content,

                                        st.session_state.query_content,

                                        st.session_state.llm_engine

                                    )

                                   

                                    # Display raw result in debug mode

                                    with st.expander("🔍 Debug: Raw LLM Response", expanded=False):

                                        st.json(generation_result)

                                   

                                    # Handle errors

                                    if generation_result.get('error'):

                                        st.error(f"❌ LLM API Error: {generation_result['error']}")

                                    elif generation_result.get('parse_error'):

                                        st.error(f"❌ JSON Parse Error: {generation_result['parse_error']}")

                                        st.code(generation_result.get('raw_content', 'No content'), language="text")

                                    else:

                                        modified_xslt = generation_result.get('modified_xslt', xslt_content)

                                        changes = generation_result.get('changes', [])

                                        # Remove legacy banner comments
                                        modified_xslt = remove_legacy_banner(modified_xslt)

                                       

                                        # Store result

                                        modified_xslt_key = f"modified_xslt_{i}"

                                        st.session_state.modified_xslts[modified_xslt_key] = {

                                            "modified_xslt": modified_xslt,

                                            "changes": changes

                                        }

                                       

                                        if not changes:

                                            st.warning("⚠️ LLM found 0 changes. Check debug info above.")

                            elif not xslt_content:

                                st.error("❌ No base XSLT content found.")

                            else:

                                st.warning("⚠️ LLM not configured. Cannot generate XSLT.")

                   

                    active_view = st.session_state.active_view.get(i)

                    if active_view == "analyze":

                        _render_analysis(i, st.session_state.query_content, result['document']['content'], customer)

                    elif active_view == "view_xslt":

                        _render_xslt_viewer(i, result['document'])

                    elif active_view == "generate_xslt":

                        _render_xslt_generation(i, st.session_state.query_content, result['document'])

                else:

                    col_a, col_b = st.columns(2)

                    with col_a:

                        if st.button("🔬 Analyze", key=f"analyze_{i}"):

                            st.session_state.active_view[i] = "analyze"

                    with col_b:

                        st.caption("⚠️ No XSLT available")

                    if st.session_state.active_view.get(i) == "analyze":

                        _render_analysis(i, st.session_state.query_content, result['document']['content'], customer)

    with tab3:

        st.header("🔄 Transform & Validate")

       

        if not st.session_state.search_results:

            st.warning("⚠️ Search for matches first (go to 'Search & Match' tab)")

            st.stop()

       

        if not st.session_state.query_content:

            st.warning("⚠️ No query EDI uploaded. Go to 'Search & Match' tab first.")

            st.stop()

       

        st.info("This is the final step: Transform your EDI using the complete XSLT (after Generate + Auto-Merge) and validate the output.")

       

        # Select which result to use

        st.markdown("### Step 1: Select XSLT Source")

       

        result_options = []

        for i, result in enumerate(st.session_state.search_results):

            customer = result['customer_info'].get('customer_name', 'Unknown')

            score = result.get('structural_score', 0.0)

            result_options.append(f"Match #{i+1}: {customer} ({score:.1f}%)")

       

        selected_result_idx = st.selectbox(

            "Choose which match to use:",

            range(len(result_options)),

            format_func=lambda x: result_options[x]

        )

       

        # Determine which XSLT to use (merged > modified > original)

        st.markdown("### Step 2: XSLT Selection")

       

        selected_result = st.session_state.search_results[selected_result_idx]

        original_xslt = selected_result['document'].get('xslt_content')

       

        if not original_xslt:

            st.error(f"❌ Match #{selected_result_idx+1} has no XSLT file")

            st.stop()

       

        # Check for merged XSLT

        merged_xslt_key = selected_result_idx

        modified_xslt_key = f"modified_xslt_{selected_result_idx}"

       

        final_xslt = original_xslt

        xslt_source = "original"

       

        if merged_xslt_key in st.session_state.merged_xslt_result:

            merged_result = st.session_state.merged_xslt_result[merged_xslt_key]

            if merged_result.get("merged_xslt"):

                final_xslt = merged_result["merged_xslt"]

                xslt_source = "merged"

        elif modified_xslt_key in st.session_state.modified_xslts:

            modified_result = st.session_state.modified_xslts[modified_xslt_key]

            if modified_result.get("modified_xslt"):

                final_xslt = modified_result["modified_xslt"]

                xslt_source = "modified"

       

        # Display which XSLT is being used

        col1, col2, col3 = st.columns(3)

        with col1:

            if xslt_source == "merged":

                st.success("✅ Using **Merged XSLT** (best)")

            elif xslt_source == "modified":

                st.info("ℹ️ Using **Modified XSLT**")

            else:

                st.warning("⚠️ Using **Original XSLT**")

       

        with col2:

            st.metric("XSLT Lines", final_xslt.count('\n') + 1)

       

        with col3:

            st.metric("Source Match", selected_result['customer_info'].get('customer_name', 'Unknown'))

       

        if xslt_source == "original":

            st.warning("💡 **Tip:** Go back to 'Search & Match' tab and click 'Generate XSLT' and/or 'Auto-Merge' to improve coverage before transforming!")

       

        # Preview XSLT

        with st.expander("📄 Preview Final XSLT", expanded=False):

            st.code(final_xslt, language="xml", line_numbers=True)

       

        # Transformation section

        st.markdown("---")

        st.markdown("### Step 3: Run Transformation")

       

        col_opt1, col_opt2 = st.columns(2)

        with col_opt1:

            use_saxonc_final = st.checkbox("Use SaxonC (if installed)", value=False,

                                          help="SaxonC supports XSLT 3.0. Falls back to lxml if not available.")

        with col_opt2:

            show_xml_final = st.checkbox("Show intermediate XML", value=True)

       

        auto_fix_xslt = st.checkbox("🔧 Auto-fix XSLT (add missing elements)", value=True,

                                   help="Automatically adds missing <xsl:output> and root template if needed")

       

        if st.button("▶️ Transform EDI to IDOC", type="primary"):

            # Auto-fix XSLT if enabled

            working_xslt = final_xslt

            auto_fixes = []

           

            if auto_fix_xslt:

                working_xslt, auto_fixes = add_missing_xslt_elements(final_xslt)

                if auto_fixes:

                    st.success(f"🔧 Auto-fix applied: {', '.join(auto_fixes)}")

                    with st.expander("📝 View Auto-Fix Details", expanded=False):

                        st.write("The following elements were automatically added to your XSLT:")

                        for fix in auto_fixes:

                            st.write(f"✅ {fix}")

                        st.info("💡 You can download the fixed XSLT after transformation")

           

            # Pre-flight checks

            st.markdown("**Pre-flight Checks:**")

           

            checks_passed = True

            critical_issues = []

           

            # Check 0: XSLT version compatibility

            import re

            version_match = re.search(r'version=["\'](\d+\.\d+)["\']', working_xslt)

            xslt_version = version_match.group(1) if version_match else "1.0"

           

            # Check for XSLT 2.0/3.0 features

            has_v2_features = any([

                'if (' in working_xslt and 'then' in working_xslt and 'else' in working_xslt,

                'xsl:function' in working_xslt,

                'xsl:for-each-group' in working_xslt,

                'xsl:analyze-string' in working_xslt,

                'xsl:result-document' in working_xslt,

            ])

           

            if (xslt_version != "1.0" or has_v2_features) and not use_saxonc_final:

                st.error(f"❌ CRITICAL: XSLT {xslt_version} detected but using lxml (XSLT 1.0 only)")

                st.error("🔧 **SOLUTION:** Check the 'Use SaxonC' box above and try again")

                critical_issues.append("xslt_version")

                checks_passed = False

            elif xslt_version != "1.0" or has_v2_features:

                st.success(f"✅ XSLT {xslt_version} detected - using SaxonC")

            else:

                st.success(f"✅ XSLT {xslt_version} - compatible with lxml")

           

            # Check 1: XSLT has output declaration

            if '<xsl:output' not in working_xslt:

                st.error("❌ CRITICAL: XSLT missing <xsl:output> - cannot produce output")

                if not auto_fix_xslt:

                    st.error("🔧 **SOLUTION:** Check 'Auto-fix XSLT' box above")

                    critical_issues.append("no_output")

                    checks_passed = False

            else:

                st.success("✅ XSLT has output declaration")

           

            # Check 2: XSLT has root template

            if "match=\"/\"" not in working_xslt and "match='/'" not in working_xslt:

                st.error("❌ CRITICAL: XSLT missing root template - cannot process document")

                if not auto_fix_xslt:

                    st.error("🔧 **SOLUTION:** Check 'Auto-fix XSLT' box above")

                    critical_issues.append("no_root")

                    checks_passed = False

            else:

                st.success("✅ XSLT has root template")

           

            # Check 3: XSLT has templates

            template_count = working_xslt.count('<xsl:template')

            if template_count == 0:

                st.error("❌ XSLT has no templates!")

                st.stop()

            else:

                st.success(f"✅ XSLT has {template_count} template(s)")

           

            # Stop if critical issues

            if critical_issues:

                st.error("⛔ Cannot proceed with critical issues. Fix the issues above and try again.")

                st.stop()

           

            st.markdown("---")

           

            with st.spinner("🔄 Running complete transformation pipeline..."):

               

                # Step 1: EDI to XML

                st.markdown("**Step 1: Converting EDI to XML...**")

                xml_content = edi_to_xml(st.session_state.query_content)

               

                if show_xml_final:

                    with st.expander("📄 Intermediate XML", expanded=False):

                        # Check XML size to prevent browser memory issues
                        xml_size = len(xml_content)
                        max_display_size = 50000  # 50KB limit for display
                        
                        if xml_size > max_display_size:
                            st.warning(f"⚠️ XML is large ({xml_size:,} characters). Showing first {max_display_size:,} characters only.")
                            st.code(xml_content[:max_display_size] + "\n\n... [XML truncated for display] ...", language="xml", line_numbers=True)
                            st.info(f"📊 Full XML size: {xml_size:,} characters")
                        else:
                            st.code(xml_content, language="xml", line_numbers=True)

                        st.download_button(

                            label="💾 Download XML",

                            data=xml_content,

                            file_name="edi_converted.xml",

                            mime="application/xml",

                            key="dl_xml_final"

                        )

               

                # Step 2: Apply XSLT

                st.markdown("**Step 2: Applying XSLT transformation...**")

                transform_result = transform_with_xslt(xml_content, working_xslt, use_saxonc_final)

               

                if transform_result["success"]:

                    st.success(f"✅ Transformation successful using {transform_result['method']}")

                   

                    idoc_output = transform_result.get("output", "")

                   

                    # Check if output is valid

                    if not idoc_output or idoc_output is None:

                        st.error("❌ Transformation succeeded but returned no output. Check XSLT logic.")

                        st.stop()

                   

                    # Save to session state

                    st.session_state["final_transform_data"] = {

                        "xml": xml_content,

                        "idoc": idoc_output,

                        "xslt_source": xslt_source,

                        "working_xslt": working_xslt,  # Save the auto-fixed version

                        "auto_fixes": auto_fixes

                    }

                   

                    # Display output

                    st.markdown("**IDOC Output:**")

                   

                    # Safe check for output format

                    try:

                        if idoc_output.strip().startswith('<?xml') or idoc_output.strip().startswith('<'):
                            # Check IDOC output size to prevent browser memory issues
                            idoc_size = len(idoc_output)
                            max_display_size = 50000  # 50KB limit for display
                            
                            if idoc_size > max_display_size:
                                st.warning(f"⚠️ IDOC output is large ({idoc_size:,} characters). Showing first {max_display_size:,} characters only.")
                                st.code(idoc_output[:max_display_size] + "\n\n... [IDOC output truncated for display] ...", language="xml", line_numbers=True)
                                st.info(f"📊 Full IDOC size: {idoc_size:,} characters")
                            else:
                                st.code(idoc_output, language="xml", line_numbers=True)

                        else:

                            st.code(idoc_output, language="text")

                    except AttributeError:

                        st.error("❌ Output format error. Raw output:")

                        st.code(str(idoc_output), language="text")

                   

                    # Download

                    col_dl1, col_dl2 = st.columns(2)

                   

                    with col_dl1:

                        st.download_button(

                            label="💾 Download IDOC",

                            data=idoc_output,

                            file_name="final_idoc_output.xml",

                            mime="application/xml",

                            type="primary",

                            key="dl_idoc_final"

                        )

                   

                    with col_dl2:

                        if auto_fixes:

                            st.download_button(

                                label="💾 Download Fixed XSLT",

                                data=working_xslt,

                                file_name="auto_fixed.xslt",

                                mime="application/xml",

                                key="dl_fixed_xslt"

                            )

                   

                    st.success("🎉 Transformation complete! Now validate below ↓")

                   

                else:

                    st.error(f"❌ Transformation failed using {transform_result['method']}")

                   

                    # Show error details

                    error_output = transform_result.get("output", "Unknown error")

                    st.code(error_output, language="text")

                   

                    # Troubleshooting guide

                    st.markdown("---")

                    st.markdown("### 🔧 Troubleshooting Guide")

                   

                    with st.expander("Common Issues & Solutions", expanded=True):

                        st.markdown("""

                        **1. XSLT Version Mismatch (Most Common)**

                        - ❌ Error: "could not compile select expression 'if...then...else'"

                        - ❌ Your XSLT uses XSLT 2.0/3.0 syntax but lxml only supports 1.0

                        - ✅ Solution: **Check the "Use SaxonC" box** and try again

                        - ✅ Or install SaxonC: `pip install saxonche`

                       

                        **2. Empty Output / NoneType Error**

                        - ❌ XSLT doesn't match XML structure

                        - ❌ XSLT missing output templates

                        - ✅ Solution: Check intermediate XML (above) and verify XSLT has matching templates

                       

                        **3. 'No matching template' Error**

                        - ❌ XSLT templates don't match XML element names

                        - ✅ Solution: Your EDI uses elements like `<BEG01>`, `<DTM02>` - ensure XSLT matches these

                       

                        **4. AttributeError: 'NoneType'**

                        - ❌ XSLT transformation returned no result

                        - ✅ Solution: XSLT needs `<xsl:output>` and proper root template

                       

                        **Example Fix for Version Issue:**

                        ```xml

                        <!-- XSLT 2.0 (won't work with lxml) -->

                        <xsl:value-of select="if ($x != '') then $x else $y"/>

                       

                        <!-- XSLT 1.0 (works with lxml) -->

                        <xsl:choose>

                          <xsl:when test="$x != ''">

                            <xsl:value-of select="$x"/>

                          </xsl:when>

                          <xsl:otherwise>

                            <xsl:value-of select="$y"/>

                          </xsl:otherwise>

                        </xsl:choose>

                        ```

                       

                        **Quick Fix:**

                        Just check "Use SaxonC (if installed)" above and re-run!

                        """)

                   

                    # Debug information

                    with st.expander("🔍 Debug Information", expanded=False):

                        st.markdown("**Check these:**")

                        st.write("1. Does your XSLT have `<xsl:output>` declaration?")

                        st.write("2. Does it have a root template `<xsl:template match='/'>`?")

                        st.write("3. Do template match patterns align with XML structure?")

                       

                        st.markdown("**Your XML Structure:**")

                        st.code(xml_content[:1000], language="xml")

                       

                        st.markdown("**Your XSLT (first 50 lines):**")

                        xslt_preview = '\n'.join(working_xslt.split('\n')[:50])

                        st.code(xslt_preview, language="xml")

       

        # Validation section

        if "final_transform_data" in st.session_state:

            st.markdown("---")

            st.markdown("### Step 4: Validation Pipeline")

           

            transformed_data = st.session_state["final_transform_data"]

            xml_content = transformed_data["xml"]

            idoc_content = transformed_data["idoc"]

           

            st.success("✅ Transformation data available for validation")

           

            # Validation options

            validation_types = st.multiselect(

                "Select validation types:",

                ["Schema Validation", "Output Comparison", "Field Mapping", "Mandatory Fields"],

                default=["Field Mapping", "Mandatory Fields"],

                key="final_val_types"

            )

           

            # File uploads

            col_upload1, col_upload2 = st.columns(2)

           

            with col_upload1:

                xsd_file = None

                if "Schema Validation" in validation_types:

                    xsd_file = st.file_uploader("Upload IDOC XSD Schema", type=["xsd", "xml"], key="final_xsd")

           

            with col_upload2:

                expected_file = None

                if "Output Comparison" in validation_types:

                    expected_file = st.file_uploader("Upload Expected IDOC", type=["xml"], key="final_expected")

           

            # Field mappings

            field_mappings = []

            if "Field Mapping" in validation_types:

                with st.expander("⚙️ Configure Field Mappings", expanded=True):

                    use_common = st.checkbox("Use pre-defined common mappings", value=True, key="final_common_map")

                   

                    if use_common:

                        std = detect_standard(st.session_state.query_content)

                        if std == "X12":

                            field_mappings = [

                                {"edi_segment": "BEG", "edi_element": 3, "idoc_xpath": "//BELNR", "field_name": "PO Number"},

                                {"edi_segment": "DTM", "edi_element": 2, "idoc_xpath": "//DATUM", "field_name": "Document Date"},

                                {"edi_segment": "PO1", "edi_element": 2, "idoc_xpath": "//MENGE", "field_name": "Quantity"},

                            ]

                        else:  # EDIFACT

                            field_mappings = [

                                {"edi_segment": "BGM", "edi_element": 2, "idoc_xpath": "//BELNR", "field_name": "Document Number"},

                                {"edi_segment": "DTM", "edi_element": 1, "idoc_xpath": "//DATUM", "field_name": "Document Date"},

                                {"edi_segment": "LIN", "edi_element": 1, "idoc_xpath": "//POSEX", "field_name": "Line Item"},

                            ]

                       

                        st.info(f"✅ Using {len(field_mappings)} pre-defined mappings")

           

            # Mandatory fields

            mandatory_fields = []

            if "Mandatory Fields" in validation_types:

                with st.expander("⚙️ Configure Mandatory Fields", expanded=True):

                    use_common_mandatory = st.checkbox("Use common mandatory fields", value=True, key="final_common_mand")

                   

                    if use_common_mandatory:

                        mandatory_fields = [

                            {"xpath": "//BELNR", "field_name": "Document Number"},

                            {"xpath": "//DATUM", "field_name": "Document Date"},

                        ]

                        st.info(f"✅ Checking {len(mandatory_fields)} mandatory fields")

           

            # Run validation

            if st.button("🔍 Run Full Validation", type="primary", key="final_validate"):

                with st.spinner("🔍 Running comprehensive validation..."):

                    validation_results = {}

                   

                    # Schema validation

                    if "Schema Validation" in validation_types and xsd_file:

                        st.markdown("**Running schema validation...**")

                        xsd_content = xsd_file.read().decode('utf-8')

                        schema_result = validate_against_schema(idoc_content, xsd_content)

                        validation_results["schema_validation"] = schema_result

                   

                    # Output comparison

                    if "Output Comparison" in validation_types and expected_file:

                        st.markdown("**Comparing with expected output...**")

                        expected_content = expected_file.read().decode('utf-8')

                        comparison_result = compare_outputs(idoc_content, expected_content)

                        validation_results["output_comparison"] = comparison_result

                   

                    # Field mapping

                    if "Field Mapping" in validation_types and field_mappings:

                        st.markdown("**Validating field mappings...**")

                        mapping_result = validate_field_mappings(st.session_state.query_content, idoc_content, field_mappings)

                        validation_results["field_mappings"] = mapping_result

                   

                    # Mandatory fields

                    if "Mandatory Fields" in validation_types and mandatory_fields:

                        st.markdown("**Checking mandatory fields...**")

                        mandatory_result = check_mandatory_fields(idoc_content, mandatory_fields)

                        validation_results["mandatory_fields"] = mandatory_result

                   

                    # Display results

                    st.markdown("---")

                    st.markdown("## 📊 Validation Results")

                   

                    # Summary metrics

                    col1, col2, col3, col4 = st.columns(4)

                   

                    with col1:

                        if "schema_validation" in validation_results:

                            schema_ok = validation_results["schema_validation"]["valid"]

                            st.metric("Schema", "✅ Valid" if schema_ok else "❌ Invalid")

                   

                    with col2:

                        if "output_comparison" in validation_results:

                            pct = validation_results["output_comparison"]["similarity_pct"]

                            st.metric("Similarity", f"{pct:.1f}%")

                   

                    with col3:

                        if "field_mappings" in validation_results:

                            mappings = validation_results["field_mappings"]

                            matched = sum(1 for m in mappings if m["match"])

                            st.metric("Mappings", f"{matched}/{len(mappings)}")

                   

                    with col4:

                        if "mandatory_fields" in validation_results:

                            fields = validation_results["mandatory_fields"]

                            present = sum(1 for f in fields if f["present"])

                            st.metric("Mandatory", f"{present}/{len(fields)}")

                   

                    st.markdown("---")

                   

                    # Detailed results

                    if "schema_validation" in validation_results:

                        schema = validation_results["schema_validation"]

                        with st.expander("📋 Schema Validation Details", expanded=not schema["valid"]):

                            if schema["valid"]:

                                st.success("✅ IDOC is valid against XSD schema")

                            else:

                                st.error(f"❌ Found {schema['total_errors']} schema errors:")

                                for error in schema["errors"][:20]:

                                    st.code(f"Line {error.get('line', '?')}: {error['message']}", language="text")

                   

                    if "output_comparison" in validation_results:

                        comp = validation_results["output_comparison"]

                        with st.expander("🔍 Output Comparison", expanded=not comp["similar"]):

                            if comp["similar"]:

                                st.success(f"✅ Outputs match ({comp['similarity_pct']:.1f}% similar)")

                            else:

                                st.warning(f"⚠️ Found {comp['total_differences']} differences")

                                st.code("\n".join(comp["differences"][:30]), language="diff")

                   

                    if "field_mappings" in validation_results:

                        mappings = validation_results["field_mappings"]

                        with st.expander("🗺️ Field Mapping Validation", expanded=True):

                            df_mappings = pd.DataFrame(mappings)

                            st.dataframe(

                                df_mappings[['field_name', 'edi_value', 'idoc_value', 'match']],

                                use_container_width=True

                            )

                   

                    if "mandatory_fields" in validation_results:

                        fields = validation_results["mandatory_fields"]

                        with st.expander("⚠️ Mandatory Fields Check", expanded=True):

                            for field in fields:

                                if field["present"]:

                                    st.success(f"✅ {field['field_name']}: {field['value']}")

                                else:

                                    st.error(f"❌ {field['field_name']}: MISSING")

                   

                    # Generate report

                    st.markdown("---")

                    st.markdown("### 📄 Download Validation Report")

                   

                    report = generate_validation_report(validation_results)

                   

                    col_rep1, col_rep2 = st.columns([3, 1])

                   

                    with col_rep1:

                        st.text_area("Report Preview", report, height=300, key="final_report_preview")

                   

                    with col_rep2:

                        st.download_button(

                            label="💾 Download Report",

                            data=report,

                            file_name="validation_report.txt",

                            mime="text/plain",

                            type="primary",

                            key="dl_final_report"

                        )

                   

                    # Final verdict

                    st.markdown("---")

                   

                    all_passed = True

                    if "schema_validation" in validation_results and not validation_results["schema_validation"]["valid"]:

                        all_passed = False

                    if "field_mappings" in validation_results:

                        if not all(m["match"] for m in validation_results["field_mappings"]):

                            all_passed = False

                    if "mandatory_fields" in validation_results:

                        if not all(f["present"] for f in validation_results["mandatory_fields"]):

                            all_passed = False

                   

                    if all_passed:

                        st.balloons()

                        st.success("🎉 **ALL VALIDATIONS PASSED!** Your XSLT transformation is production-ready.")

                    else:

                        st.warning("⚠️ **SOME VALIDATIONS FAILED.** Review the details above and refine your XSLT.")

                        st.info("💡 Go back to 'Search & Match' tab to improve XSLT coverage with Generate/Auto-Merge")
    with tab4:
        st.header("📊 EDI Field Mapping & Export")
       
        st.markdown("""
        This feature allows you to extract specific fields from EDI files and export them in a standardized CSV format.
        Define mappings from EDI segments/elements to your target column names.
        """)
       
        # Standard column names - FIXED duplicate names
        STANDARD_COLUMNS = [
            "Header", "Name", "Customer_Name", "Sender_ID", "Prod_Version",
            "AFSMapName", "CPI_MapName", "SoldTo(AG)", "ShipTo(WE)", "MarkFor(WF)",
            "BillTo(RE)", "RDD", "CDD", "CustPO", "CustPODate",
            "Department", "RCVP", "YourRef1", "YourRef2", "YourRef3",
            "INCO1", "INCO2", "ZH01(VendorNo)", "ZH02(Freetext)", "CustMat",
            "UPC", "PCO", "MSRP", "RTL (Retail Price)", "ItemPrice",
            "SchQty", "ZI01", "ZM02", "PPckQty(001)", "ZSCC/Label",
            "ZOR", "ZMS0", "Prepack", "TP0", "BULK",
            "ECOM", "DTS(K02-007)", "Allowed", "NotAllowed", "Special Focus Areas",
            "Logical Derivation", "Status1", "Status2", "Status3", "Status4", "Status5"
        ]
       
        # Initialize session state for mappings
        if 'field_mappings_config' not in st.session_state:
            st.session_state.field_mappings_config = {}
       
        # Check if database has files
        if not st.session_state.query_content:
                    
            st.warning("⚠️ No query file found. Please upload a query file in the 'Search & Match' tab first.")
            st.info("💡 Go to Tab 2 → Upload Query File → then come back here")
            st.stop()
            
        st.markdown("---")
        st.markdown("### Step 1: Using Query File from Tab 2")
    
        st.success(f"✅ Using query file from Search & Match tab")
        st.info("📄 This will extract fields from the EDI file you uploaded in Tab 2")
    
        # Use the query file
        mapping_files = [("Query_File", st.session_state.query_content)]
       
        st.markdown("---")
        st.markdown("### Step 2: Configure Field Mappings")
       
        col_cfg1, col_cfg2 = st.columns([1, 1])
       
        with col_cfg1:
            use_predefined = st.checkbox("Use pre-defined common mappings", value=True, key="use_predefined_map")
       
        with col_cfg2:
            upload_mapping = st.file_uploader(
                "Or upload mapping config (JSON)",
                type=["json"],
                key="upload_map_config"
            )
       
        if use_predefined:
            st.info("📋 Using common EDI to field mappings")
           
            # Pre-defined mappings
            default_mappings = {
                "Customer_Name": {"segment": "N1", "qualifier": "BY", "element": 2},
                "Sender_ID": {"segment": "ISA", "element": 6},
                "SoldTo(AG)": {"segment": "N1", "qualifier": "ST", "element": 2},
                "ShipTo(WE)": {"segment": "N1", "qualifier": "ST", "element": 2},
                "BillTo(RE)": {"segment": "N1", "qualifier": "BT", "element": 2},
                "CustPO": {"segment": "BEG", "element": 3},
                "CustPODate": {"segment": "BEG", "element": 5},
                "RDD": {"segment": "DTM", "qualifier": "002", "element": 2},
                "CDD": {"segment": "DTM", "qualifier": "011", "element": 2},
                "YourRef1": {"segment": "REF", "qualifier": "PO", "element": 2},
                "UPC": {"segment": "PO1", "element": 7},
                "ItemPrice": {"segment": "PO1", "element": 4},
                "SchQty": {"segment": "PO1", "element": 2},
            }
           
            st.session_state.field_mappings_config = default_mappings
           
            with st.expander("📋 View/Edit Mapping Configuration", expanded=False):
                st.json(default_mappings)
               
        elif upload_mapping:
            try:
                mapping_config = json.load(upload_mapping)
                st.session_state.field_mappings_config = mapping_config
                st.success("✅ Mapping configuration loaded")
                with st.expander("📋 View Loaded Configuration"):
                    st.json(mapping_config)
            except Exception as e:
                st.error(f"❌ Error loading mapping file: {e}")
       
        # Manual mapping editor
        with st.expander("✏️ Add/Edit Custom Mappings", expanded=False):
            st.markdown("**Add a new field mapping:**")
           
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
           
            with col_m1:
                target_column = st.selectbox(
                    "Target Column",
                    STANDARD_COLUMNS,
                    key="new_map_column"
                )
           
            with col_m2:
                segment_tag = st.text_input("EDI Segment", "BEG", key="new_map_segment")
           
            with col_m3:
                element_num = st.number_input("Element #", min_value=1, value=3, key="new_map_element")
           
            with col_m4:
                qualifier_val = st.text_input("Qualifier (optional)", "", key="new_map_qual")
           
            if st.button("➕ Add Mapping", key="add_new_mapping"):
                new_mapping = {
                    "segment": segment_tag,
                    "element": element_num
                }
                if qualifier_val:
                    new_mapping["qualifier"] = qualifier_val
               
                st.session_state.field_mappings_config[target_column] = new_mapping
                st.success(f"✅ Added mapping for {target_column}")
                st.rerun()
       
        if st.session_state.field_mappings_config:
            st.info(f"📊 {len(st.session_state.field_mappings_config)} field(s) configured for extraction")
       
        st.markdown("---")
        st.markdown("### Step 3: Extract & Export Data")
       
        if not mapping_files:
            st.warning("⚠️ No files selected. Please select files in Step 1 to continue")
        elif not st.session_state.field_mappings_config:
            st.warning("⚠️ Configure field mappings in Step 2 to continue")
        else:
            if st.button("🚀 Extract Data from EDI Files", type="primary", key="extract_data"):
                with st.spinner("🔄 Extracting data from EDI files..."):
                   
                    extracted_data = []
                   
                    for filename, edi_content in mapping_files:
                        edi_std = detect_standard(edi_content)
                        edi_segs = parse_structured_segments(edi_content, edi_std)
                       
                        row_data = {"Filename": filename}
                       
                        for column_name, mapping_config in st.session_state.field_mappings_config.items():
                            target_segment = mapping_config.get("segment")
                            target_element = mapping_config.get("element")
                            target_qualifier = mapping_config.get("qualifier")
                           
                            extracted_value = ""
                           
                            for seg in edi_segs:
                                if not seg or not seg[0]:
                                    continue
                               
                                if seg[0] == target_segment:
                                    if target_qualifier:
                                        if len(seg) > 1:
                                            seg_qual = seg[1].split(":")[0] if edi_std == "EDIFACT" else seg[1]
                                            if seg_qual != target_qualifier:
                                                continue
                                   
                                    if len(seg) > target_element:
                                        extracted_value = seg[target_element]
                                        break
                           
                            row_data[column_name] = extracted_value
                       
                        extracted_data.append(row_data)
                   
                    if extracted_data:
                        df_extracted = pd.DataFrame(extracted_data)
                       
                        ordered_columns = ["Filename"] + [col for col in STANDARD_COLUMNS if col in df_extracted.columns]
                        df_extracted = df_extracted[ordered_columns]
                       
                        st.success(f"✅ Extracted data from {len(extracted_data)} file(s)")
                       
                        st.markdown("### 📊 Extracted Data Preview")
                        st.dataframe(df_extracted, use_container_width=True, height=400)
                       
                        col_stat1, col_stat2, col_stat3 = st.columns(3)
                        with col_stat1:
                            st.metric("Total Files", len(extracted_data))
                        with col_stat2:
                            st.metric("Fields Extracted", len(st.session_state.field_mappings_config))
                        with col_stat3:
                            non_empty = df_extracted.apply(lambda x: x.astype(bool).sum()).sum() - len(df_extracted)
                            st.metric("Values Extracted", int(non_empty))
                       
                        with st.expander("📈 Data Quality Report", expanded=False):
                            st.markdown("**Field Population Rate:**")
                            for col in df_extracted.columns:
                                if col == "Filename":
                                    continue
                                filled = df_extracted[col].astype(bool).sum()
                                rate = (filled / len(df_extracted)) * 100
                                st.write(f"**{col}:** {filled}/{len(df_extracted)} ({rate:.1f}%)")
                       
                        st.markdown("---")
                        st.markdown("### 📥 Export Options")
                       
                        col_exp1, col_exp2, col_exp3 = st.columns(3)
                       
                        with col_exp1:
                            csv_data = df_extracted.to_csv(index=False)
                            st.download_button(
                                label="💾 Download CSV",
                                data=csv_data,
                                file_name="edi_field_mapping_export.csv",
                                mime="text/csv",
                                type="primary",
                                key="dl_csv_mapping"
                            )
                       
                        with col_exp2:
                            try:
                                excel_buffer = io.BytesIO()
                                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                                    df_extracted.to_excel(writer, index=False, sheet_name='EDI Data')
                                excel_data = excel_buffer.getvalue()
                               
                                st.download_button(
                                    label="💾 Download Excel",
                                    data=excel_data,
                                    file_name="edi_field_mapping_export.xlsx",
                                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    key="dl_excel_mapping"
                                )
                            except ImportError:
                                st.warning("⚠️ Install openpyxl for Excel export: `pip install openpyxl`")
                       
                        with col_exp3:
                            json_data = df_extracted.to_json(orient='records', indent=2)
                            st.download_button(
                                label="💾 Download JSON",
                                data=json_data,
                                file_name="edi_field_mapping_export.json",
                                mime="application/json",
                                key="dl_json_mapping"
                            )
                       
                        st.markdown("---")
                        st.markdown("### 💾 Save Mapping Configuration")
                       
                        config_json = json.dumps(st.session_state.field_mappings_config, indent=2)
                        st.download_button(
                            label="💾 Download Mapping Config",
                            data=config_json,
                            file_name="field_mapping_config.json",
                            mime="application/json",
                            key="dl_config_mapping"
                        )
                       
                        st.success("✅ You can reuse this mapping config by uploading it in Step 2!")
                   
                    else:
                        st.error("❌ No data extracted. Check your mappings and EDI files.")

if __name__ == "__main__":
    main()