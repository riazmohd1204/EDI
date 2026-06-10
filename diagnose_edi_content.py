#!/usr/bin/env python3
"""
Diagnostic Script: Check EDIDATA Status for INTERCHANGENOs

This script queries the HANA database to check:
- Whether rows exist for specific INTERCHANGENOs
- Whether EDIDATA column is NULL, EMPTY, or PRESENT
- EDIMESSAGE values
- Other metadata fields

Usage:
    python diagnose_edi_content.py
    python diagnose_edi_content.py 000000280 000000002 000139061
"""

import sys
import os
from pathlib import Path

# Add fastapi-backend to path
# Script can be in root or in fastapi-backend directory
script_dir = Path(__file__).parent
if (script_dir / "fastapi-backend").exists():
    backend_root = script_dir / "fastapi-backend"
else:
    backend_root = script_dir
sys.path.insert(0, str(backend_root))

from sqlalchemy import create_engine, text
from app.config import settings
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def diagnose_interchangeno(interchangeno: str, engine, archive_table: str):
    """
    Query database for a specific INTERCHANGENO and return diagnostic info.
    """
    logger.info("=" * 80)
    logger.info(f"DIAGNOSING INTERCHANGENO: {interchangeno}")
    logger.info("=" * 80)
    
    # Query 1: Check if row exists and get EDIDATA status
    sql = text(f"""
        SELECT 
            INTERCHANGENO,
            DIRECTION,
            EDIFORMAT,
            EDIMESSAGE,
            EDIVERSION,
            SENDERID,
            RECEIVERID,
            CUSTOMERNAME,
            CREATEDON,
            CHANGEDON,
            CASE 
                WHEN EDIDATA IS NULL THEN 'NULL'
                WHEN LENGTH(EDIDATA) = 0 THEN 'EMPTY'
                ELSE 'PRESENT'
            END AS EDIDATA_STATUS,
            CASE 
                WHEN EDIDATA IS NULL THEN 0
                ELSE LENGTH(EDIDATA)
            END AS EDIDATA_LENGTH
        FROM {archive_table}
        WHERE INTERCHANGENO = :interchangeno
        ORDER BY CREATEDON DESC
    """)
    
    try:
        with engine.connect() as conn:
            rows = conn.execute(sql, {"interchangeno": interchangeno}).mappings().all()
            
            if not rows:
                logger.warning(f"❌ NO ROWS FOUND for INTERCHANGENO={interchangeno}")
                return {
                    "interchangeno": interchangeno,
                    "status": "NOT_FOUND",
                    "rows": []
                }
            
            logger.info(f"✅ Found {len(rows)} row(s) for INTERCHANGENO={interchangeno}")
            
            row_list = []
            for idx, row in enumerate(rows):
                row_dict = dict(row.items())
                
                logger.info("")
                logger.info(f"  ROW #{idx + 1}:")
                logger.info(f"    INTERCHANGENO: {row_dict.get('INTERCHANGENO', 'N/A')}")
                logger.info(f"    DIRECTION: {row_dict.get('DIRECTION', 'N/A')}")
                logger.info(f"    EDIFORMAT: {row_dict.get('EDIFORMAT', 'N/A')}")
                logger.info(f"    EDIMESSAGE: {row_dict.get('EDIMESSAGE', 'N/A')}")
                logger.info(f"    EDIVERSION: {row_dict.get('EDIVERSION', 'N/A')}")
                logger.info(f"    SENDERID: {row_dict.get('SENDERID', 'N/A')}")
                logger.info(f"    RECEIVERID: {row_dict.get('RECEIVERID', 'N/A')}")
                logger.info(f"    CUSTOMERNAME: {row_dict.get('CUSTOMERNAME', 'N/A')}")
                logger.info(f"    CREATEDON: {row_dict.get('CREATEDON', 'N/A')}")
                logger.info(f"    CHANGEDON: {row_dict.get('CHANGEDON', 'N/A')}")
                logger.info(f"    EDIDATA_STATUS: {row_dict.get('EDIDATA_STATUS', 'UNKNOWN')}")
                logger.info(f"    EDIDATA_LENGTH: {row_dict.get('EDIDATA_LENGTH', 0)} bytes")
                
                # If EDIDATA is present, try to decode a sample
                if row_dict.get('EDIDATA_STATUS') == 'PRESENT':
                    edidata_length = row_dict.get('EDIDATA_LENGTH', 0)
                    logger.info(f"    ⚠️  EDIDATA is PRESENT ({edidata_length} bytes) but cannot decode in this query (LOB column)")
                    logger.info(f"    → Need to use _fetch_edidata_by_locator() to actually read the content")
                
                row_list.append({
                    "interchangeno": row_dict.get("INTERCHANGENO", ""),
                    "direction": row_dict.get("DIRECTION", ""),
                    "ediformat": row_dict.get("EDIFORMAT", ""),
                    "edimessage": row_dict.get("EDIMESSAGE", ""),
                    "ediversion": row_dict.get("EDIVERSION", ""),
                    "senderid": row_dict.get("SENDERID", ""),
                    "receiverid": row_dict.get("RECEIVERID", ""),
                    "customername": row_dict.get("CUSTOMERNAME", ""),
                    "createdon": str(row_dict.get("CREATEDON", "")),
                    "changedon": str(row_dict.get("CHANGEDON", "")),
                    "edidata_status": row_dict.get("EDIDATA_STATUS", ""),
                    "edidata_length": row_dict.get("EDIDATA_LENGTH", 0),
                })
            
            # Summary
            total_rows = len(row_list)
            null_count = sum(1 for r in row_list if r["edidata_status"] == "NULL")
            empty_count = sum(1 for r in row_list if r["edidata_status"] == "EMPTY")
            present_count = sum(1 for r in row_list if r["edidata_status"] == "PRESENT")
            
            logger.info("")
            logger.info("  SUMMARY:")
            logger.info(f"    Total rows: {total_rows}")
            logger.info(f"    EDIDATA NULL: {null_count} ({null_count*100//max(total_rows,1)}%)")
            logger.info(f"    EDIDATA EMPTY: {empty_count} ({empty_count*100//max(total_rows,1)}%)")
            logger.info(f"    EDIDATA PRESENT: {present_count} ({present_count*100//max(total_rows,1)}%)")
            
            # Check EDIMESSAGE distribution
            edimessage_counts = {}
            for r in row_list:
                msg = r.get("edimessage", "NULL") or "NULL"
                edimessage_counts[msg] = edimessage_counts.get(msg, 0) + 1
            
            logger.info("")
            logger.info("  EDIMESSAGE DISTRIBUTION:")
            for msg, count in sorted(edimessage_counts.items()):
                logger.info(f"    {msg}: {count} row(s)")
            
            return {
                "interchangeno": interchangeno,
                "status": "FOUND",
                "total_rows": total_rows,
                "edidata_summary": {
                    "null": null_count,
                    "empty": empty_count,
                    "present": present_count
                },
                "edimessage_distribution": edimessage_counts,
                "rows": row_list
            }
            
    except Exception as e:
        logger.error(f"❌ ERROR querying INTERCHANGENO={interchangeno}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "interchangeno": interchangeno,
            "status": "ERROR",
            "error": str(e)
        }


def main():
    """Main diagnostic function."""
    # INTERCHANGENOs to check (from the logs)
    default_interchangenos = ["000000280", "000000002", "000139061"]
    
    # Get INTERCHANGENOs from command line or use defaults
    if len(sys.argv) > 1:
        interchangenos = sys.argv[1:]
    else:
        interchangenos = default_interchangenos
        logger.info(f"No INTERCHANGENOs provided, using defaults: {interchangenos}")
    
    logger.info("=" * 80)
    logger.info("EDI CONTENT DIAGNOSTIC SCRIPT")
    logger.info("=" * 80)
    logger.info(f"Checking {len(interchangenos)} INTERCHANGENO(s): {interchangenos}")
    logger.info("")
    
    # Initialize database connection
    if not settings.HANA_URL:
        logger.error("❌ HANA_URL not configured. Please set it in .env file or environment variables.")
        return
    
    try:
        engine = create_engine(settings.HANA_URL)
        logger.info(f"✅ Connected to HANA database")
    except Exception as e:
        logger.error(f"❌ Failed to connect to HANA: {e}")
        return
    
    # Build archive table name
    archive_schema = settings.HANA_ARCHIVE_SCHEMA
    archive_table = settings.HANA_ARCHIVE_TABLE
    archive_fq = f'"{archive_schema}"."{archive_table}"'
    
    logger.info(f"Archive table: {archive_fq}")
    logger.info("")
    
    # Diagnose each INTERCHANGENO
    results = []
    for icn in interchangenos:
        result = diagnose_interchangeno(icn, engine, archive_fq)
        results.append(result)
        logger.info("")
    
    # Final summary
    logger.info("=" * 80)
    logger.info("FINAL SUMMARY")
    logger.info("=" * 80)
    
    for result in results:
        icn = result.get("interchangeno", "unknown")
        status = result.get("status", "UNKNOWN")
        
        if status == "FOUND":
            summary = result.get("edidata_summary", {})
            logger.info(f"  {icn}: {status} - NULL={summary.get('null',0)}, EMPTY={summary.get('empty',0)}, PRESENT={summary.get('present',0)}")
        else:
            logger.info(f"  {icn}: {status}")
    
    logger.info("=" * 80)
    logger.info("Diagnostic complete!")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()

