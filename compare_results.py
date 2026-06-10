"""
Quick script to compare Streamlit vs FastAPI results for the same EDI input.
Run this to verify output parity.
"""

import requests
import json
import sys

def compare_matches(edi_file="fixtures/sample.edi"):
    """Compare match results from FastAPI with expected results."""
    
    print("=" * 80)
    print("PARITY VERIFICATION: Streamlit <-> FastAPI Results")
    print("=" * 80)
    print()
    
    # Read test EDI
    try:
        with open(edi_file, "r", encoding="utf-8") as f:
            edi_content = f.read()
        print(f"[OK] Loaded EDI file: {edi_file}")
    except FileNotFoundError:
        print(f"[ERROR] Could not find {edi_file}")
        print("   Please run this script from the project root directory.")
        return
    
    print()
    print("-" * 80)
    print("Testing FastAPI Backend (http://localhost:8000)")
    print("-" * 80)
    
    # Test FastAPI
    try:
        # Step 1: Upload EDI file to create session
        print("Step 1: Uploading EDI file...")
        upload_response = requests.post(
            "http://localhost:8000/api/edi/upload",
            files={"file": ("test.edi", edi_content.encode('utf-8'), "text/plain")},
            timeout=30
        )
        
        if upload_response.status_code != 200:
            print(f"[ERROR] Upload failed with status {upload_response.status_code}")
            print(f"   Response: {upload_response.text[:200]}")
            return
        
        upload_data = upload_response.json()
        session_id = upload_data.get('session_id')
        print(f"   Session ID: {session_id}")
        print()
        
        # Step 2: Find matches
        print("Step 2: Finding matches...")
        response = requests.post(
            "http://localhost:8000/api/edi/find-matches",
            json={"session_id": session_id},
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"[ERROR] FastAPI returned status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return
        
        fastapi_data = response.json()
        matches = fastapi_data.get('matches', [])
        
        print(f"[OK] FastAPI returned {len(matches)} matches")
        print()
        
        if not matches:
            print("[WARNING] No matches found. Possible reasons:")
            print("   1. Database not loaded (check backend logs)")
            print("   2. No matching templates in database")
            print("   3. EDI format not recognized")
            return
        
        print("FastAPI Results:")
        print()
        for i, match in enumerate(matches, 1):
            print(f"  Match {i}:")
            print(f"    Customer: {match.get('customer', 'Unknown')}")
            print(f"    Score:    {match.get('score', 0)}%")
            print(f"    Format:   {match.get('format', 'UNKNOWN')}")
            print(f"    Segments: {match.get('matched_segments_count', 0)}/{match.get('total_segments_count', 0)} matched")
            if match.get('missing_qualifiers'):
                print(f"    Missing:  {', '.join(match['missing_qualifiers'][:5])}")
            print()
        
        print("-" * 80)
        print("Verification Checklist:")
        print("-" * 80)
        print()
        print("Now test with Streamlit:")
        print("  1. Run: streamlit run conversational_edi_streamlit.py")
        print(f"  2. Upload: {edi_file}")
        print("  3. Click 'Show Matches'")
        print("  4. Compare results:")
        print()
        print("     [?] Same customers in same order?")
        print("     [?] Same scores?")
        print("     [?] Same missing qualifiers?")
        print()
        print("If results match --> Parity achieved! [OK]")
        print("If results differ --> See VERIFY_PARITY_RESULTS.md for debugging")
        print()
        
        # Save results for comparison
        with open("fastapi_results.json", "w") as f:
            json.dump(matches, f, indent=2)
        print("[SAVED] Results saved to: fastapi_results.json")
        print()
        
    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to FastAPI backend")
        print("   Make sure the backend is running:")
        print("   - Check http://localhost:8000/docs")
        print("   - Or run: .\\start_all_servers.ps1")
        return
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    edi_file = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sample.edi"
    compare_matches(edi_file)

