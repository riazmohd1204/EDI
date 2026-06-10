import os, re, json, html, hashlib, pickle
from typing import List, Dict, Tuple, Any
from dataclasses import dataclass
import numpy as np
import pandas as pd
import streamlit as st
import faiss
from openai import AzureOpenAI

#UI code
st.set_page_config(
    page_title="LLM-Based EDI Analyzer",
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

#x12 and edifact cross format rules
CROSS_FORMAT_RULES = """
Use semantic equivalence, not literal matching. Typical pairs:
- ISA ↔ UNB (interchange headers)
- ST ↔ UNH (message headers)
- BEG ↔ BGM (beginning of message / PO header)
- REF ↔ RFF (references)
- DTM ↔ DTM (date/time)
- N1 ↔ NAD (parties, with qualifiers BY, ST, SU, etc.)
- PO1 ↔ LIN (line items; EDIFACT attaches QTY/PRI under LIN)
- CTT ↔ CNT (totals)
- SE ↔ UNT (message trailer)
Ignore format-specific noise when judging semantic similarity (e.g., TD5, MTX, PER in X12).
Additional mappings for envelope and control:
- GS ↔ UNG (functional group header; optional in EDIFACT)
- GE ↔ UNE (functional group trailer)
- IEA ↔ UNZ (interchange trailer)
- TA1/997 ↔ CONTRL (acknowledgments)
Header and party segments:
- FOB ↔ TOD (shipment terms; use qualifiers like FOB-04 = '01' for Incoterms ↔ TOD-03)
- ITD ↔ PAT (terms of sale/payment; pair with DTM for due dates)
- PER ↔ CTA (contact information; e.g., PER-02 ↔ CTA-3412, PER-04 (TE) ↔ COM-3148 (TE))
- N9 ↔ FTX (free text/notes)
Detail and line item segments:
- PO1-01 ↔ LIN-1082 (line number)
- PO1-02/03 ↔ QTY-6060/6411 (quantity/UoM; qualifier 21 for ordered)
- PO1-04 ↔ PRI-5118 (unit price)
- PO1-06/07 ↔ PIA-7140/7143 (product IDs; e.g., 'VP' for vendor part ↔ 'SA')
Qualifier-based matching for precision:
- Parties: N1-BY ↔ NAD-BY (buyer), N1-ST ↔ NAD-ST (ship to), N1-SU ↔ NAD-SU (supplier)
- Addresses: N3/N4 ↔ NAD sub-elements (C059 for lines, 3164 city, 3251 ZIP, 3207 country via ISO 3166)
- References: REF-02 ('PO') ↔ RFF-1154 ('ON' for PO number)
- Dates: DTM-02 ('002') ↔ DTM-2380 ('2' for requested delivery)
- Validate against code lists (e.g., UN qualifiers, X12 128) to reduce false positives.
Transaction type equivalences:
- 850 ↔ ORDERS (purchase order)
- 855 ↔ ORDRSP (PO response)
- 860 ↔ ORDCHG (PO change)
- 810 ↔ INVOIC (invoice)
- 856 ↔ DESADV (advance ship notice)
- Prioritize matches within the same business context; lower score by 20-30% if types mismatch.
Weighted semantic scoring:
- High weight (2x): Identifiers (PO via BEG/BGM), dates (DTM), totals (CTT/CNT), quantities (PO1/QTY), prices (PO1/PRI), item IDs (PO1/PIA)
- Medium (1x): References (REF/RFF), parties (N1/NAD), terms (FOB/TOD)
- Low (0.5x): Text (N9/FTX), contacts (PER/CTA), optional segments
- Set compatibility 'GOOD' or higher if 80% high-weight elements match (e.g., quantities within 5% tolerance)
Contextual rules:
- Consider industry subsets (e.g., EANCOM in EDIFACT for consumer goods)
- Account for versions (e.g., X12 4010 vs. 5010, EDIFACT D96A vs. D01B); version mismatch lowers compatibility if key segments affected
- Normalize delimiters/lowercase for comparisons; disregard padding/newlines
- For conflicts (e.g., qualifier mismatches), flag as differences
"""
#prompts
PROMPTS = {
    "extract_metadata": """Analyze this EDI document and extract key metadata.
Rules:
- X12: Starts with ISA, uses * as element separator, ~ as segment terminator
- EDIFACT: Starts with UNA/UNB, uses + as element separator, ' as segment terminator
EDI:
{edi_content}
Return JSON only:
{{
  "format": "X12|EDIFACT|UNKNOWN",
  "message_type": "e.g., 850 or ORDERS",
  "semantic_type": "PURCHASE_ORDER|PO_RESPONSE|PO_CHANGE|INVOICE|...",
  "sender_id": "string or empty",
  "segment_types": ["..."],
  "line_count": 123,
  "business_summary": "one-liner",
  "key_identifiers": ["..."]
}}""",
    "create_searchable_summary": """Create a rich, format-agnostic summary for semantic search.
Cross-format guidance:
{cross_format_rules}
EDI:
{edi_content}
Output a 200-300 word paragraph capturing business meaning (buyer/seller, type, items, dates, refs).""",
    "compare_similarity": """Compare two EDI docs at a semantic level (may be different standards).
Guidance:
{cross_format_rules}
Prioritize matches on business-critical elements using qualifiers and weights for scoring.
If the two documents are identical or have no semantic differences, set similarity_score to 100.
Focus on structural differences: in key_differences, list only mismatched or missing tags and qualifiers (ignore values). For example, if query has new tag 'XX' or missing qualifier in 'N1', list them.
DOC1 (query, {doc1_format}):
{doc1_content}
DOC2 (match, {doc2_format}):
{doc2_content}
Return ONLY the JSON object. No additional text, no explanations, no markdown:
{{
  "similarity_score": 0,
  "structural_compatibility": "PERFECT|EXCELLENT|GOOD|PARTIAL|POOR",
  "template_compatible": false,
  "key_similarities": [],
  "key_differences": ["list of mismatched/missing tags or qualifiers, e.g., 'Missing qualifier in N1: BY', 'New tag in query: XX'"],
  "business_context": "",
  "cross_format_mappings": [],
  "is_replaceable": false,
  "difference_analysis": ""
}}""",
    "replace_values": """Based on the EDI document, replace corresponding values in the XSLT template.
Guidance: {cross_format_rules}
Use semantic mapping to identify which EDI fields (e.g., PO number from BEG/BGM) should replace placeholders or values in XSLT.
EDI: {edi_content}
XSLT: {xslt_content}
Return the full modified XSLT as a string only. No additional text or explanations."""
}

#helper functions
def _to_str(x):
    if isinstance(x, dict):
        return "; ".join(f"{k}={v}" for k, v in x.items())
    return str(x)

def _iter_str(xs):
    if isinstance(xs, (list, tuple, set)):
        for x in xs:
            yield _to_str(x)
    else:
        yield _to_str(xs)

def _strip_code_fences(s: str) -> str:
    if not isinstance(s, str):
        return s
    t = s.strip()
    if t.startswith("```") and t.endswith("```"):
        body = t[3:]
        body = body[body.find("\n")+1:] if "\n" in body else body
        t = body[:body.rfind("```")] if "```" in body else body
    for fence in ("```xml", "```XML", "```json", "```JSON"):
        if t.startswith(fence):
            body = t[len(fence):]
            body = body[body.find("\n")+1:] if "\n" in body else body
            t = body
            break
    return t.strip().strip("`").strip()

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

def mark_diff(a: str, b: str) -> Tuple[str, str, bool]:
    if a == b:
        return html.escape(a), html.escape(b), False
    return f"<mark>{html.escape(a)}</mark>", f"<mark>{html.escape(b)}</mark>", True

def get_base_filename(fname: str) -> str:
    return os.path.splitext(fname)[0].lower()

def _normalize_id(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9]', '', (s or '').strip().upper())

#for embeddings
def _mask_noise(text: str) -> str:
    t = text
    t = re.sub(r"\d{6,}", "<NUM>", t)       # long numeric blobs
    t = re.sub(r"[A-F0-9]{16,}", "<HEX>", t, flags=re.I)
    t = re.sub(r"\s+", " ", t)
    return t.lower()

def build_signal_text(raw: str) -> str:
    """Canonical header + parties + PO ref + first few line skeletons."""
    std = detect_standard(raw)
    segs = parse_structured_segments(raw, std)
    out = []

    def add(k, v):
        if v: out.append(f"{k}:{v}")

    # sender id
    if std == "X12":
        for s in segs:
            if s and s[0]=="ISA" and len(s)>6:
                add("sender", s[6]); break
    elif std == "EDIFACT":
        for s in segs:
            if s and s[0]=="UNB" and len(s)>2:
                add("sender", s[2].split(":")[0]); break

    # Message/PO id
    for s in segs:
        if std=="X12" and s[0]=="BEG" and len(s)>3:
            add("type","850"); add("po", s[3]); break
        if std=="EDIFACT" and s[0]=="BGM" and len(s)>2:
            add("type","ORDERS"); add("po", s[2].split(":")[0]); break

    # Parties
    for s in segs:
        if std=="X12" and s[0]=="N1" and len(s)>2 and s[1] in ("BY","SU","ST","BT"):
            add(s[1], s[2])
        if std=="EDIFACT" and s[0]=="NAD" and len(s)>1 and s[1] in ("BY","SU","ST","BT"):
            name = next((f for f in s[2:6] if f and not re.fullmatch(r"[0-9:]+", f)), "")
            add(s[1], name)

    # Reference
    for s in segs:
        if std=="X12" and s[0]=="REF" and len(s)>2 and s[1] in ("PO","ON"):
            add("ref", s[2]); break
        if std=="EDIFACT" and s[0]=="RFF" and len(s)>1 and s[1].startswith("ON"):
            add("ref", s[1].split(":")[1] if ":" in s[1] else s[1]); break

    # Dates
    for s in segs:
        if std=="X12" and s[0]=="DTM" and len(s)>2:
            add("dtm", f"{s[1]}:{s[2]}")
        if std=="EDIFACT" and s[0]=="DTM" and len(s)>1:
            add("dtm", s[1])

    # Line struct
    count = 0
    for s in segs:
        if std=="X12" and s[0]=="PO1":
            sku = next((x for x in s[6:8] if x), "")
            add("line", f"sku:{sku} qty:{(s[2] if len(s)>2 else '')} pri:{(s[4] if len(s)>4 else '')}")
            count += 1
        if std=="EDIFACT" and s[0]=="LIN":
            sku = next((x for x in s[3:6] if x), "")
            add("line", f"sku:{sku}")
            count += 1
        if count >= 12: break

    return _mask_noise("\n".join(out))

def build_signal_views(raw: str) -> Dict[str, str]:
    """Two compact views for multi-view retrieval."""
    std = detect_standard(raw)
    segs = parse_structured_segments(raw, std)
    header_bits, line_bits = [], []

    if std=="X12":
        for s in segs:
            if s[0]=="ISA" and len(s)>6: header_bits.append(f"sender:{s[6]}")
            if s[0]=="BEG" and len(s)>3: header_bits += [f"type:850", f"po:{s[3]}"]
            if s[0]=="REF" and len(s)>2 and s[1] in ("PO","ON"): header_bits.append(f"ref:{s[2]}")
            if s[0]=="N1" and len(s)>2 and s[1] in ("BY","SU","ST","BT"): header_bits.append(f"{s[1]}:{s[2]}")
            if s[0]=="DTM" and len(s)>2: header_bits.append(f"dtm:{s[1]}:{s[2]}")
    else:
        for s in segs:
            if s[0]=="UNB" and len(s)>2: header_bits.append(f"sender:{s[2].split(':')[0]}")
            if s[0]=="BGM" and len(s)>2: header_bits += [f"type:ORDERS", f"po:{s[2].split(':')[0]}"]
            if s[0]=="RFF" and len(s)>1 and s[1].startswith("ON"):
                ref = s[1].split(":")[1] if ":" in s[1] else s[1]
                header_bits.append(f"ref:{ref}")
            if s[0]=="NAD" and len(s)>1 and s[1] in ("BY","SU","ST","BT"):
                name = next((f for f in s[2:6] if f and not re.fullmatch(r"[0-9:]+", f)), "")
                header_bits.append(f"{s[1]}:{name}")
            if s[0]=="DTM" and len(s)>1: header_bits.append(f"dtm:{s[1]}")

    # Lines
    count = 0
    for s in segs:
        if std=="X12" and s[0]=="PO1":
            sku = next((x for x in s[6:8] if x), "")
            qty = s[2] if len(s)>2 else ""
            pri = s[4] if len(s)>4 else ""
            line_bits.append(f"sku:{sku} qty:{qty} pri:{pri}")
            count += 1
        if std=="EDIFACT" and s[0]=="LIN":
            sku = next((x for x in s[3:6] if x), "")
            line_bits.append(f"sku:{sku}")
            count += 1
        if count >= 20: break

    return {
        "signal_header": _mask_noise("\n".join(header_bits)),
        "signal_lines":  _mask_noise("\n".join(line_bits))
    }
#gap extraction
def _extract_unmatched_signature(key_differences: List[str], query_text: str) -> Tuple[set, Dict[str, set]]:
    std = detect_standard(query_text)
    qsegs = parse_structured_segments(query_text, std)
    query_tags = {s[0] for s in qsegs if s}
    tags, quals = set(), {}
    if not key_differences:
        return set(), {}
    pat_new_tag = re.compile(r"New tag in query:\s*([A-Z0-9]{2,6})")
    pat_missing_tag = re.compile(r"Missing tag(?: in (?:match|query))?:\s*([A-Z0-9]{2,6})")
    pat_missing_qual = re.compile(r"Missing qualifier in\s+([A-Z0-9]{2,6})\s*:\s*([A-Z0-9]{2,4})")
    for d in key_differences:
        m = pat_new_tag.search(d)
        if m and m.group(1) in query_tags: tags.add(m.group(1))
        m = pat_missing_tag.search(d)
        if m and m.group(1) in query_tags: tags.add(m.group(1))
        m = pat_missing_qual.search(d)
        if m and m.group(1) in query_tags:
            t, q = m.group(1), m.group(2)
            tags.add(t); quals.setdefault(t, set()).add(q)
    if not tags:
        all_caps = set(re.findall(r"\b[A-Z0-9]{2,6}\b", " ".join(key_differences)))
        tags = all_caps & query_tags
    return tags, quals

def _build_gap_pieces_from_query(query_text: str, tags: set, quals_by_tag: Dict[str, set]) -> List[str]:
    if not tags: return []
    std = detect_standard(query_text)
    segs = parse_structured_segments(query_text, std)
    pieces: List[str] = []
    for s in segs:
        if not s: continue
        tag = s[0]
        if tag not in tags: continue
        if tag in quals_by_tag and len(s) > 1:
            q = (s[1] or "").strip().upper()
            if q not in quals_by_tag[tag]: continue
        pieces.append(normalize_preview(s))
    return pieces[:30]

def _safe_percent(x: float) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0
    
#extraction+mappings
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

##llm engine
@dataclass
class Config:
    azure_endpoint: str = "add yours"
    api_key: str = "add yours"
    api_version: str = "add yours"
    embedding_model: str = "add yours"
    llm_model: str = "add yours"
    indexing_model: str = "add yours"
    max_tokens: int = 4000
    temperature: float = 0.2
    batch_size: int = 10
    skip_customer_identification: bool = True
    skip_metadata_extraction: bool = False
    cache_embeddings: bool = True
    use_simple_summary: bool = False
    # High-signal + multiview
    use_signal_embeddings: bool = True
    use_multiview: bool = True
    # scoring controls
    header_weight: float = 0.65          
    calibrate_display: bool = False
    calibrate_floor: float = 0.90

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
        self.system_message = "You are an expert EDI analyst. Use cross-standard knowledge, qualifiers, and semantic rules to analyze. Adapt to new or variant files by generalizing mappings. Return ONLY valid JSON when asked. No additional text."

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
                {"role":"system","content": self.system_message},
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
                        return {"parse_error": f"Failed to parse JSON from LLM response: {str(e)}", "raw_content": content}
            return {"response": content}
        except Exception as e:
            st.error(f"LLM call failed: {e}")
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

#rag db
class RAGDatabase:
    def __init__(self, llm_engine: LLMEngine, customer_mapping: Dict[str, str] = None):
        self.llm_engine = llm_engine
        self.customer_mapping = customer_mapping or {}
        self.index = None
        self.documents = []
        self.vec_meta = []  # [{doc_idx:int, view:str}]
        self.cache_dir = "edi_cache"
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

    def _ensure_customer_info(self, doc: Dict[str, Any]):
        if not doc.get("customer_info") or not doc["customer_info"].get("customer_name") or doc["customer_info"]["customer_name"] == "Unknown":
            info = extract_customer_info(doc.get("content",""))
            doc["customer_info"] = info

    def _embed_doc_views(self, fname: str, content: str) -> List[Tuple[np.ndarray, str]]:
        cfg = st.session_state.config
        out: List[Tuple[np.ndarray, str]] = []
        if cfg.use_multiview:
            views = build_signal_views(content) if cfg.use_signal_embeddings else {"summary": content[:2000]}
            for vname, vtext in views.items():
                key = f"embedding_{vname}"
                cached = self._load(fname, key) if cfg.cache_embeddings else None
                if cached is None:
                    vec = st.session_state.llm_engine.create_embedding(vtext)
                    if cfg.cache_embeddings: self._save(fname, key, vec)
                else:
                    vec = cached
                out.append((vec, vname))
        else:
            if cfg.use_signal_embeddings:
                vtext = build_signal_text(content)
            else:
                if cfg.use_simple_summary:
                    vtext = content[:2000]
                else:
                    sr = st.session_state.llm_engine.call_llm(
                        fill_prompt(PROMPTS["create_searchable_summary"], edi_content=content[:4000], cross_format_rules=CROSS_FORMAT_RULES),
                        json_mode=False, use_indexing_model=True
                    )
                    vtext = (sr.get("response", content[:2000]) if isinstance(sr, dict) else content[:2000])
            key = "embedding_single"
            cached = self._load(fname, key) if cfg.cache_embeddings else None
            if cached is None:
                vec = st.session_state.llm_engine.create_embedding(vtext)
                if cfg.cache_embeddings: self._save(fname, key, vec)
            else:
                vec = cached
            out.append((vec, "single"))
        return out

    def build_index(self, edi_files: List[Tuple[str, str]], xslt_files: List[Tuple[str, str]] = None):
        xslt_dict = {get_base_filename(fname): content for fname, content in (xslt_files or [])}
        embeddings = []
        self.vec_meta = []
        total = len(edi_files)
        pbar = st.progress(0); info = st.empty()

        for i, (fname, content) in enumerate(edi_files):
            base_fname = get_base_filename(fname)
            doc = {'filename': fname, 'content': content, 'content_hash': hashlib.sha256(content.encode()).hexdigest()}
            doc['xslt_content'] = xslt_dict.get(base_fname, None)
            doc['customer_info'] = extract_customer_info(content)

            if not st.session_state.config.skip_metadata_extraction:
                cached = self._load(fname, 'metadata') if st.session_state.config.cache_embeddings else None
                if cached is None:
                    meta = st.session_state.llm_engine.call_llm(
                        fill_prompt(PROMPTS["extract_metadata"], edi_content=content[:3000]),
                        use_indexing_model=True
                    )
                    if st.session_state.config.cache_embeddings: self._save(fname,'metadata', meta)
                else:
                    meta = cached
                doc['metadata'] = meta
            else:
                doc['metadata'] = {"format":"UNKNOWN","message_type":"UNKNOWN","semantic_type":""}

            vecs = self._embed_doc_views(fname, content)
            for vec, vname in vecs:
                embeddings.append(vec)
                self.vec_meta.append({"doc_idx": len(self.documents), "view": vname})

            self.documents.append(doc)
            info.text(f"Indexing {i+1}/{total}"); pbar.progress((i+1)/total)

        if embeddings:
            E = np.array(embeddings).astype('float32')
            self.index = faiss.IndexFlatIP(E.shape[1])
            self.index.add(E)

        stats = st.session_state.llm_engine.get_stats()
        st.success(f"✅ Indexed {len(self.documents)} docs ({len(self.vec_meta)} vectors {'(multi-view)' if st.session_state.config.use_multiview else ''})")
        st.info(f"API calls: total={stats['total_calls']} (LLM {stats['llm_calls']}, Emb {stats['embedding_calls']})")

    def save_index(self, idx_path="edi_index.faiss", meta_path="edi_meta.pkl"):
        if self.index is None or not self.documents: return False
        faiss.write_index(self.index, idx_path)
        payload = {"documents": self.documents, "vec_meta": self.vec_meta}
        with open(meta_path,'wb') as f: pickle.dump(payload, f)
        return True

    def load_index(self, idx_path="edi_index.faiss", meta_path="edi_meta.pkl"):
        if not (os.path.exists(idx_path) and os.path.exists(meta_path)): return False
        self.index = faiss.read_index(idx_path)
        with open(meta_path,'rb') as f:
            payload = pickle.load(f)
        if isinstance(payload, list):
            # backward compatibility
            self.documents = payload
            self.vec_meta = [{"doc_idx": i, "view": "single"} for i in range(len(self.documents))]
        else:
            self.documents = payload.get("documents", [])
            self.vec_meta = payload.get("vec_meta", [{"doc_idx": i, "view": "single"} for i in range(len(self.documents))])
        for doc in self.documents:
            self._ensure_customer_info(doc)
        return True

    def _embed_query_views(self, query_content: str) -> Dict[str, np.ndarray]:
        cfg = st.session_state.config
        views: Dict[str, str] = {}
        if cfg.use_multiview:
            views = build_signal_views(query_content) if cfg.use_signal_embeddings else {"summary": query_content[:2000]}
        else:
            if cfg.use_signal_embeddings:
                views = {"signal": build_signal_text(query_content)}
            else:
                if cfg.use_simple_summary:
                    views = {"slice": query_content[:2000]}
                else:
                    sr = st.session_state.llm_engine.call_llm(
                        fill_prompt(PROMPTS["create_searchable_summary"], edi_content=query_content[:4000], cross_format_rules=CROSS_FORMAT_RULES),
                        json_mode=False, use_indexing_model=True
                    )
                    views = {"summary": (sr.get("response", query_content[:2000]) if isinstance(sr, dict) else query_content[:2000])}
        out: Dict[str, np.ndarray] = {}
        for name, text in views.items():
            out[name] = st.session_state.llm_engine.create_embedding(text).reshape(1,-1)
        return out

    def search(self, query_content: str, top_k: int = 3) -> List[Dict]:
        if self.index is None or not self.documents: return []

        meta = st.session_state.llm_engine.call_llm(
            fill_prompt(PROMPTS["extract_metadata"], edi_content=query_content[:3000]),
            use_indexing_model=True
        )
        q_sem = meta.get('semantic_type','') if isinstance(meta, dict) else ''
        q_fmt = meta.get('format','UNKNOWN') if isinstance(meta, dict) else 'UNKNOWN'
        q_type = meta.get('message_type','') if isinstance(meta, dict) else ''

        qviews = self._embed_query_views(query_content)

        view_weights = {"signal_header": st.session_state.config.header_weight,
                        "signal_lines":  1.0 - st.session_state.config.header_weight}
        doc_scores: Dict[int, Dict[str, float]] = {}

        for qname, qvec in qviews.items():
            k = min(max(top_k*6, 30), len(self.vec_meta))
            D, I = self.index.search(qvec, k)
            for idx, score in zip(I[0], D[0]):
                if idx == -1:
                    continue
                vmeta = self.vec_meta[idx]
                doc_idx = vmeta["doc_idx"]
                vname = vmeta["view"] 
                d = doc_scores.setdefault(doc_idx, {})
                d[vname] = max(d.get(vname, -1.0), float(score))

        def _combine_views(d: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
            if "single" in d or not view_weights or not st.session_state.config.use_multiview:
                return max(d.values()), d
            h = max(0.0, d.get("signal_header", 0.0))
            l = max(0.0, d.get("signal_lines", 0.0))
            overall = view_weights["signal_header"]*h + view_weights["signal_lines"]*l
            return overall, {"header": h, "lines": l}

        ranked = []
        subscores_by_doc: Dict[int, Dict[str, float]] = {}
        for di, dv in doc_scores.items():
            overall, subs = _combine_views(dv)
            ranked.append((di, overall))
            subscores_by_doc[di] = subs
        ranked.sort(key=lambda x: x[1], reverse=True)

        #building final resuults
        results, seen_customers = [], set()
        cross_format_matches = 0
        same_format_matches = 0

        for doc_idx, score in ranked:
            doc = self.documents[doc_idx]
            self._ensure_customer_info(doc)

            dm = doc.get('metadata', {}) if isinstance(doc.get('metadata'), dict) else {}
            d_sem = dm.get('semantic_type','')
            d_fmt = dm.get('format','UNKNOWN')
            d_type = dm.get('message_type','')

            keep = False
            if q_sem and d_sem:
                keep = (q_sem == d_sem)
            else:
                pairs = {('850','ORDERS'), ('855','ORDRSP'), ('860','ORDCHG')}
                keep = (q_type == d_type) or ((q_type, d_type) in pairs) or ((d_type, q_type) in pairs)
            if not keep:
                continue

            customer = (doc.get('customer_info') or {}).get('customer_name','Unknown')
            if (not st.session_state.config.skip_customer_identification) and customer != 'Unknown':
                if customer in seen_customers:
                    continue
                seen_customers.add(customer)

            if q_fmt != d_fmt:
                cross_format_matches += 1
            else:
                same_format_matches += 1

            results.append({
                "document": doc,
                "vector_score": float(score),                         
                "subscores": subscores_by_doc.get(doc_idx, {}),        
                "metadata": dm,
                "customer_info": doc.get('customer_info', {}),
                "is_cross_format": q_fmt != d_fmt,
                "format_pair": f"{q_fmt}↔{d_fmt}" if q_fmt != d_fmt else d_fmt
            })
            if len(results) >= top_k: break

        if cross_format_matches or same_format_matches:
            st.success(f"✨ Found {cross_format_matches} cross-format and {same_format_matches} same-format match(es).")

        return results

    def search_gap(self, gap_text: str, top_k: int = 5, exclude_customer: str = None) -> List[Dict[str, Any]]:
        if self.index is None or not self.documents or not (gap_text or "").strip():
            return []
        qvec = st.session_state.llm_engine.create_embedding(gap_text).reshape(1,-1)
        k = min(top_k*3, len(self.vec_meta))
        D, I = self.index.search(qvec, k)
        rows = []
        for idx, score in zip(I[0], D[0]):
            if idx == -1: continue
            doc_idx = self.vec_meta[idx]["doc_idx"]
            doc = self.documents[doc_idx]
            cust = (doc.get('customer_info') or {}).get('customer_name', 'Unknown')
            if exclude_customer and cust == exclude_customer:
                continue
            rows.append({"customer": cust, "score": float(score), "filename": doc.get('filename')})
        best: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            if r["customer"] not in best or r["score"] > best[r["customer"]]["score"]:
                best[r["customer"]] = r
        out = sorted(best.values(), key=lambda x: x["score"], reverse=True)[:top_k]
        return out
    def search_gap_distribution(self, gap_pieces: List[str], *, top_customers: int = 3,
                                exclude_customer: str = None, exclude_unknown: bool = True) -> List[Dict[str, Any]]:
        if self.index is None or not self.documents or not gap_pieces:
            return []
        totals: Dict[str, Dict[str, Any]] = {}
        total_mass = 0.0
        for piece in gap_pieces:
            qvec = st.session_state.llm_engine.create_embedding(_mask_noise(piece)).reshape(1, -1)
            D, I = self.index.search(qvec, min(10, len(self.vec_meta)))
            best = None
            for idx, score in zip(I[0], D[0]):
                if idx == -1: continue
                doc_idx = self.vec_meta[idx]["doc_idx"]
                doc = self.documents[doc_idx]
                cust = (doc.get('customer_info') or {}).get('customer_name', 'Unknown')
                if exclude_customer and cust == exclude_customer:
                    continue
                if exclude_unknown and cust == 'Unknown':
                    continue
                if best is None or score > best["score"]:
                    best = {"customer": cust, "score": float(score), "filename": doc.get('filename')}
            if best and best["score"] >= 0.18:
                entry = totals.setdefault(best["customer"], {"sum": 0.0, "filename": best["filename"]})
                entry["sum"] += best["score"]
                total_mass += best["score"]

        if not totals or total_mass <= 0:
            return []

        rows = [{"customer": c, "share": v["sum"] / total_mass, "filename": v["filename"]} for c, v in totals.items()]
        rows.sort(key=lambda r: r["share"], reverse=True)
        return rows[:top_customers]


class LLMComparator:
    def __init__(self, llm_engine: LLMEngine):
        self.llm = llm_engine

    def _fmt(self, s: str) -> str:
        return detect_standard(s)

    def compare_similarity(self, a: str, b: str) -> Dict:
        pa = fill_prompt(PROMPTS["compare_similarity"],
                         doc1_format=self._fmt(a), doc2_format=self._fmt(b),
                         doc1_content=a[:4000], doc2_content=b[:4000],
                         cross_format_rules=CROSS_FORMAT_RULES)
        return self.llm.call_llm(pa)

    def replace_values(self, edi: str, xslt: str) -> str:
        pa = fill_prompt(PROMPTS["replace_values"],
                         edi_content=edi[:12000],
                         xslt_content=xslt[:12000],
                         cross_format_rules=CROSS_FORMAT_RULES)
        rsp = self.llm.call_llm(pa, json_mode=False)
        raw = rsp.get("response", "")
        return _strip_code_fences(raw) or raw


def init_session_state():
    if 'rag_db' not in st.session_state: st.session_state.rag_db = None
    if 'config' not in st.session_state: st.session_state.config = Config()
    if 'llm_engine' not in st.session_state: st.session_state.llm_engine = None
    if 'database_ready' not in st.session_state: st.session_state.database_ready = False
    if 'customer_mapping' not in st.session_state: st.session_state.customer_mapping = {}
    if 'query_content' not in st.session_state: st.session_state.query_content = None
    if 'search_results' not in st.session_state: st.session_state.search_results = []
    if 'analysis_cache' not in st.session_state: st.session_state.analysis_cache = {}

def load_customer_mapping(file_obj) -> Dict[str, str]:
    try:
        df = pd.read_csv(file_obj, dtype=str)
    except:
        file_obj.seek(0)
        df = pd.read_excel(file_obj, dtype=str)
    mapping = {}
    if not df.empty and len(df.columns) >= 2:
        for _, row in df.iterrows():
            key_raw = str(row.iloc[0]) if pd.notna(row.iloc[0]) else ""
            value = str(row.iloc[1]).strip() if pd.notna(row.iloc[1]) else ""
            key = _normalize_id(key_raw)
            if key and key.lower() not in ['nan', 'none']:
                mapping[key] = value
    return mapping

def calibrate_cos(x: float, floor: float = 0.90) -> float:
    """Map cosine in [floor..1] to [0..1], clamp outside."""
    y = (x - floor) / max(1e-6, (1.0 - floor))
    return float(np.clip(y, 0.0, 1.0))

def main():
    init_session_state()
    st.title("🤖 LLM-Based EDI Analyzer")
    st.markdown("*Optimized for Large-Scale Processing. Now with high-signal, multi-view retrieval and weighted scoring.*")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Azure OpenAI")
        st.session_state.config.azure_endpoint = st.text_input("Endpoint", type="password", value=st.session_state.config.azure_endpoint)
        st.session_state.config.api_key = st.text_input("API Key", type="password", value=st.session_state.config.api_key)
        st.session_state.config.embedding_model = st.text_input("Embedding Deployment", value=st.session_state.config.embedding_model)
        st.session_state.config.llm_model = st.text_input("LLM Deployment (e.g.,gpt-4.1)", value=st.session_state.config.llm_model)
        st.session_state.config.indexing_model = st.text_input("Indexing Deployment (e.g.,gpt-4.1)", value=st.session_state.config.indexing_model)
        st.session_state.config.temperature = st.slider("Temperature", 0.0, 1.0, 0.2)

        st.header("⚡ Optimization")
        st.session_state.config.batch_size = st.slider("Batch Size", 5, 50, 10)
        st.session_state.config.cache_embeddings = st.checkbox("Enable Caching", value=True)
        st.session_state.config.use_simple_summary = st.checkbox("Use Simple Summary (for display only)", value=False)
        st.session_state.config.skip_metadata_extraction = st.checkbox("Skip Metadata Extraction", value=False)
        st.session_state.config.skip_customer_identification = st.checkbox("Skip Customer Dedup", value=True)

        st.markdown("**Vector Similarity Settings**")
        st.session_state.config.use_signal_embeddings = st.checkbox("Use High-Signal Embeddings", value=True)
        st.session_state.config.use_multiview = st.checkbox("Enable Multi-View Retrieval (header + lines)", value=True)
        st.session_state.config.header_weight = st.slider("Header weight (blending)", 0.0, 1.0, 0.65)
        st.session_state.config.calibrate_display = st.checkbox("Calibrate displayed vector %", value=False)
        st.session_state.config.calibrate_floor = st.slider("Calibration floor", 0.80, 0.98, 0.90)

        if st.button("🔗 Connect to LLM"):
            st.session_state.llm_engine = LLMEngine(st.session_state.config)
            st.success("Connected.")

        st.markdown("---")
        st.header("🗄️ Index")
        if st.button("💾 Save Index"):
            if st.session_state.rag_db and st.session_state.rag_db.save_index():
                st.success("Index saved.")
            else:
                st.error("Nothing to save.")

        if st.button("📂 Load Index"):
            if not st.session_state.llm_engine:
                st.error("Connect to LLM first.")
            else:
                st.session_state.rag_db = RAGDatabase(st.session_state.llm_engine, st.session_state.customer_mapping)
                if st.session_state.rag_db.load_index():
                    st.session_state.database_ready = True
                    st.success(f"Loaded {len(st.session_state.rag_db.documents)} docs.")
                else:
                    st.error("No saved index found.")

        if st.button("🧹 Clear Cache"):
            d = "edi_cache"
            if os.path.exists(d):
                import shutil
                try:
                    shutil.rmtree(d); os.makedirs(d); st.success("Cache cleared.")
                except PermissionError as e:
                    st.error(f"Permission denied while clearing cache: {str(e)}.")
                except Exception as e:
                    st.error(f"Failed to clear cache: {str(e)}")
            else:
                st.info("No cache folder.")

        if st.session_state.llm_engine:
            stats = st.session_state.llm_engine.get_stats()
            st.metric("API Calls", stats["total_calls"])

    tab1, tab2 = st.tabs(["📚 Build Database", "🔍 Search & Compare"])

   
    with tab1:
        st.header("Build RAG Database")
        st.subheader("1) Optional Customer Mapping")
        mapping_file = st.file_uploader("Upload CSV/Excel (sender_id → name)", type=["csv","xlsx"], key="mapping")
        if mapping_file:
            st.session_state.customer_mapping = load_customer_mapping(mapping_file)
            st.success(f"Loaded {len(st.session_state.customer_mapping)} mappings.")

        st.subheader("2) EDI Files")
        edi_files = st.file_uploader("Upload EDI files", type=["edi","txt","x12"], accept_multiple_files=True, key="edi_uploader")
        if edi_files: st.info(f"{len(edi_files)} EDI files ready.")

        st.subheader("3) XSLT Files (Optional)")
        xslt_files = st.file_uploader("Upload XSLT files", type=["xslt","xsl"], accept_multiple_files=True, key="xslt_uploader")
        if xslt_files: st.info(f"{len(xslt_files)} XSLT files ready.")

        if edi_files and st.button("🚀 Build Database", type="primary"):
            if not st.session_state.llm_engine:
                st.error("Connect to LLM first.")
            else:
                edi_data = [(f.name, f.read().decode("utf-8","ignore")) for f in edi_files]
                xslt_data = [(f.name, f.read().decode("utf-8","ignore")) for f in (xslt_files or [])]
                st.session_state.rag_db = RAGDatabase(st.session_state.llm_engine, st.session_state.customer_mapping)
                with st.spinner("Building index..."):
                    st.session_state.rag_db.build_index(edi_data, xslt_data)
                    st.session_state.database_ready = True

    #search
    with tab2:
        st.header("Search & Compare")
        if not st.session_state.database_ready:
            st.warning("⚠️ Please build database first")
            st.stop()

        qfile = st.file_uploader("Upload query EDI file", type=['edi','txt','x12'], key="query")
        top_k = st.slider("Number of results", 1, 10, 3, key="k_slider")

        if qfile and st.button("🔍 Find Similar", type="primary", key="btn_find_similar"):
            st.session_state.query_content = qfile.read().decode('utf-8', errors='ignore')
            with st.spinner("Searching with RAG..."):
                st.session_state.search_results = st.session_state.rag_db.search(st.session_state.query_content, top_k)
            st.session_state.analysis_cache = {}

        results = st.session_state.search_results
        if not results:
            st.info("Upload a query file and click **Find Similar** to see matches.")
            st.stop()

        st.success(f"✅ Found {len(results)} similar documents")
        st.markdown("---")

        def _render_analysis(i: int, query_content: str, candidate_content: str, top_customer: str):
            if i not in st.session_state.analysis_cache:
                comp = LLMComparator(st.session_state.llm_engine)
                with st.spinner("Analyzing with LLM..."):
                    sim = comp.compare_similarity(query_content, candidate_content)
                    if isinstance(sim, dict) and 'parse_error' in sim:
                        st.error(f"Similarity analysis failed: {sim['parse_error']}")
                        st.text(sim['raw_content']); return
                st.session_state.analysis_cache[i] = {"sim": sim}
            sim = st.session_state.analysis_cache[i]["sim"]
            if not isinstance(sim, dict):
                st.error("Unexpected similarity response"); st.text(str(sim)); return

            st.markdown("### 📊 Similarity Analysis")
            st.markdown(f"<div class='analysis-box'>", unsafe_allow_html=True)
            st.write(f"**Overall Score:** {sim.get('similarity_score', 0)}%")
            st.write(f"**Structural Compatibility:** {sim.get('structural_compatibility', 'Unknown')}")
            st.write(f"**Template Compatible:** {'✅ Yes' if sim.get('template_compatible') else '❌ No'}")
            st.write(f"**Replaceable:** {'✅ Yes' if sim.get('is_replaceable') else '❌ No'}")
            xmaps = sim.get('cross_format_mappings', [])
            xm_list = [f"{k} ↔ {v}" for k, v in xmaps.items()] if isinstance(xmaps, dict) else list(_iter_str(xmaps))
            if xm_list: st.write("**Cross-Format Mappings:** " + ", ".join(xm_list))
            st.markdown("</div>", unsafe_allow_html=True)

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**✅ Similarities:**")
                for s in _iter_str(sim.get('key_similarities', [])): st.write("• " + s)
            with c2:
                st.markdown("**⚠️ Differences:**")
                for d in _iter_str(sim.get('key_differences', [])): st.write("• " + d)

            st.markdown("**📝 Analysis:**")
            st.info(sim.get('difference_analysis', 'No analysis available'))

            mismatches = sim.get('key_differences', [])
            if mismatches:
                try:
                    mismatch_score = 100 - float(sim.get('similarity_score', 0) or 0)
                except Exception:
                    mismatch_score = None
                st.markdown(f"### 🔍 Mismatches{f' ({mismatch_score:.0f}% of Differences)' if mismatch_score is not None else ''}")
                st.table(pd.DataFrame([{"Mismatch": m} for m in mismatches]))
            else:
                st.info("No structural mismatches detected (tags/qualifiers fully match).")

            if mismatches:
                tags, quals_by_tag = _extract_unmatched_signature(mismatches, query_content)
                gap_pieces = _build_gap_pieces_from_query(query_content, tags, quals_by_tag) or ["\n".join(mismatches)]
                dist_rows = st.session_state.rag_db.search_gap_distribution(
                    gap_pieces, top_customers=3, exclude_customer=top_customer, exclude_unknown=True
                )
                st.markdown("### 🧩 Where the unmatched parts likely belong")
                overall_unmatched_pct = max(0.0, 100.0 - _safe_percent(sim.get('similarity_score', 0)))
                if dist_rows:
                    st.table(pd.DataFrame([{
                        "Customer": r["customer"],
                        "Share of unmatched %": f"{overall_unmatched_pct * r['share']:.0f}%",
                        "Sample doc": r["filename"]
                    } for r in dist_rows]))
                else:
                    st.info("No customer found for the unmatched parts.")


        for i, result in enumerate(results):
            top_customer = result['customer_info'].get('customer_name', 'Unknown')
            with st.expander(f"📄 Match #{i+1}: {top_customer}", expanded=(i == 0)):
                col1, col2 = st.columns([1, 3])
                with col1:
                    raw_score = float(result['vector_score'])
                    if st.session_state.config.calibrate_display:
                        raw_score = calibrate_cos(raw_score, st.session_state.config.calibrate_floor)
                    pct = max(0.0, min(100.0, raw_score * 100.0))
                    st.markdown(f"<div class='match-score'>{pct:.1f}%</div>", unsafe_allow_html=True)
                    sub = result.get("subscores", {})
                    if sub:
                        if "header" in sub or "lines" in sub:
                            st.caption(f"header: {sub.get('header', 0.0):.3f} • lines: {sub.get('lines', 0.0):.3f}")
                        elif "single" in sub:
                            st.caption(f"single-view: {sub.get('single', 0.0):.3f}")
                    st.caption("Vector similarity")
                with col2:
                    metadata = result['metadata']
                    st.write(f"**Format:** {metadata.get('format', 'Unknown')}")
                    st.write(f"**Type:** {metadata.get('message_type', 'Unknown')}")
                    st.write(f"**Semantic Type:** {metadata.get('semantic_type', 'Unknown')}")
                    st.write(f"**Customer:** {top_customer}")
                    if result.get('is_cross_format'):
                        st.success(f"🔄 Cross-Format: {result.get('format_pair', '')}")

                flag_key = f"show_analysis_{i}"
                if flag_key not in st.session_state: st.session_state[flag_key] = False
                if st.button("🔬 Detailed Analysis", key=f"btn_analyze_{i}"): st.session_state[flag_key] = True
                if st.session_state[flag_key]:
                    _render_analysis(i, st.session_state.query_content, result['document']['content'], top_customer)

                xslt_content = result['document'].get('xslt_content')
                if xslt_content:
                    col_view, col_replace = st.columns(2)
                    with col_view:
                        view_key = f"show_xslt_{i}"
                        if view_key not in st.session_state: st.session_state[view_key] = False
                        if st.button("👀 View XSLT", key=f"btn_view_xslt_{i}"): st.session_state[view_key] = not st.session_state[view_key]
                        if st.session_state[view_key]: st.code(xslt_content, language="xml")
                    with col_replace:
                        replace_key = f"show_replaced_{i}"
                        if replace_key not in st.session_state: st.session_state[replace_key] = False
                        if st.button("🔄 Replace Values", key=f"btn_replace_{i}"): st.session_state[replace_key] = True
                        if st.session_state[replace_key]:
                            if i not in st.session_state.analysis_cache or "modified_xslt" not in st.session_state.analysis_cache[i]:
                                comp = LLMComparator(st.session_state.llm_engine)
                                with st.spinner("Replacing values with LLM..."):
                                    modified = comp.replace_values(st.session_state.query_content, xslt_content)
                                st.session_state.analysis_cache.setdefault(i, {})["modified_xslt"] = modified
                            st.code(st.session_state.analysis_cache[i]["modified_xslt"], language="xml")
                            original_fname = result['document']['filename']
                            download_fname = f"modified_{get_base_filename(original_fname)}.xslt"
                            st.download_button("📥 Download Modified XSLT",
                                               data=st.session_state.analysis_cache[i]["modified_xslt"].encode(),
                                               file_name=download_fname)
                else:
                    st.info("No XSLT associated with this match.")

if __name__ == "__main__":
    main()