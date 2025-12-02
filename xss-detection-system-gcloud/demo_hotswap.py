#!/usr/bin/env python3
"""
MODEL HOT-SWAP DEMONSTRATION SCRIPT
====================================

This script helps you demonstrate model hot-swapping during your presentation.

Usage Examples:
  # Check current model
  python demo_hotswap.py --check
  
  # Swap to version 2
  python demo_hotswap.py --swap v2
  
  # Swap to version 3
  python demo_hotswap.py --swap v3
  
  # Test detection with current model
  python demo_hotswap.py --test "<script>alert(1)</script>"
"""

import requests
import json
import argparse
import time
from datetime import datetime

# API endpoint
ML_API_URL = "http://localhost:8080"

# Color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_header(text):
    """Print colored header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text.center(60)}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")


def check_current_model():
    """Check which model is currently loaded"""
    print_header("CURRENT MODEL STATUS")
    
    try:
        response = requests.get(f"{ML_API_URL}/model/info", timeout=5)
        
        if response.status_code == 200:
            info = response.json()
            
            print(f"{GREEN}✓ ML API is running{RESET}")
            print(f"\n📦 Model Information:")
            print(f"  Version:    {YELLOW}{info['version']}{RESET}")
            print(f"  Status:     {GREEN if info['status'] == 'loaded' else RED}{info['status']}{RESET}")
            print(f"  Loaded at:  {info['loaded_at']}")
            print(f"  Path:       {info['model_path']}")
            return True
        else:
            print(f"{RED}✗ Error: {response.status_code}{RESET}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"{RED}✗ Cannot connect to ML API at {ML_API_URL}{RESET}")
        print(f"  Make sure the ml_api container is running")
        return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


def swap_model(version):
    """Hot-swap to specified model version"""
    print_header(f"HOT-SWAPPING TO VERSION {version}")
    
    # For v1, use the original filename for backward compatibility
    if version == "v1":
        model_path = "/models/xgboost_model.joblib"
    else:
        model_path = f"/models/xgboost_model_{version}.joblib"
    
    scaler_path = "/models/xss_scaler.joblib"
    
    print(f"🔄 Swapping to: {YELLOW}{model_path}{RESET}")
    print(f"   (This happens with ZERO downtime)")
    
    try:
        payload = {
            "model_path": model_path,
            "scaler_path": scaler_path
        }
        
        print(f"\n⏳ Sending reload request...")
        start_time = time.time()
        
        response = requests.post(
            f"{ML_API_URL}/model/reload",
            json=payload,
            timeout=30
        )
        
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\n{GREEN}✓ Model swap successful!{RESET}")
            print(f"\n📊 Swap Details:")
            print(f"  Old version: {result['old_version']}")
            print(f"  New version: {YELLOW}{result['new_version']}{RESET}")
            print(f"  Loaded at:   {result['loaded_at']}")
            print(f"  Swap time:   {elapsed:.2f}s")
            
            print(f"\n{GREEN}The API continued serving requests during this swap!{RESET}")
            return True
        elif response.status_code == 404:
            error = response.json()
            print(f"\n{RED}✗ Model file not found{RESET}")
            print(f"  {error['detail']}")
            print(f"\n💡 Make sure you've trained version {version} first:")
            print(f"  docker exec trainer python train_from_neo4j.py --from-neo4j --version {version}")
            return False
        else:
            error = response.json()
            print(f"\n{RED}✗ Swap failed: {error['detail']}{RESET}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"\n{RED}✗ Cannot connect to ML API{RESET}")
        return False
    except Exception as e:
        print(f"\n{RED}✗ Error: {e}{RESET}")
        return False


def test_detection(payload):
    """Test XSS detection with current model"""
    print_header("TESTING XSS DETECTION")
    
    print(f"🧪 Testing payload: {YELLOW}{payload}{RESET}\n")
    
    try:
        response = requests.post(
            f"{ML_API_URL}/analyze",
            json={"payload": payload},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Determine color based on detection
            status_color = RED if result['is_malicious'] else GREEN
            status_text = "🚨 MALICIOUS" if result['is_malicious'] else "✓ BENIGN"
            
            print(f"Result: {status_color}{status_text}{RESET}")
            print(f"\n📊 Analysis:")
            print(f"  Model version: {YELLOW}{result['model_version']}{RESET}")
            print(f"  Confidence:    {result['confidence']:.2%}")
            print(f"  Patterns:      {len(result['detected_patterns'])} detected")
            
            if result['detected_patterns']:
                print(f"\n🔍 Detected Patterns:")
                for pattern in result['detected_patterns'][:5]:
                    print(f"  • {pattern}")
            
            return True
        else:
            print(f"{RED}✗ Error: {response.status_code}{RESET}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"{RED}✗ Cannot connect to ML API{RESET}")
        return False
    except Exception as e:
        print(f"{RED}✗ Error: {e}{RESET}")
        return False


def demo_workflow():
    """Run a complete demonstration workflow"""
    print_header("COMPLETE HOT-SWAP DEMONSTRATION")
    
    print("This will demonstrate the entire hot-swap workflow:\n")
    print("1. Check current model (should be v1)")
    print("2. Test detection with v1")
    print("3. Hot-swap to v2 (trained on Neo4j logs)")
    print("4. Test detection with v2")
    print("5. Compare results\n")
    
    input(f"{YELLOW}Press Enter to continue...{RESET}")
    
    # Step 1: Check v1
    print("\n" + "─"*60)
    print("STEP 1: Current Model Status")
    print("─"*60)
    check_current_model()
    time.sleep(2)
    
    # Step 2: Test with v1
    print("\n" + "─"*60)
    print("STEP 2: Test Detection with Version 1")
    print("─"*60)
    test_payload = "<script>alert(document.cookie)</script>"
    test_detection(test_payload)
    time.sleep(2)
    
    # Step 3: Swap to v2
    print("\n" + "─"*60)
    print("STEP 3: Hot-Swap to Version 2")
    print("─"*60)
    input(f"\n{YELLOW}Press Enter to perform hot-swap...{RESET}")
    swap_success = swap_model("v2")
    
    if not swap_success:
        print(f"\n{RED}Demo cannot continue without v2 model{RESET}")
        return
    
    time.sleep(2)
    
    # Step 4: Test with v2
    print("\n" + "─"*60)
    print("STEP 4: Test Detection with Version 2")
    print("─"*60)
    test_detection(test_payload)
    time.sleep(2)
    
    # Step 5: Summary
    print("\n" + "─"*60)
    print("STEP 5: Summary")
    print("─"*60)
    print(f"\n{GREEN}✓ Demonstration Complete!{RESET}\n")
    print("Key Points Demonstrated:")
    print(f"  • {GREEN}Zero-downtime hot-swapping{RESET}")
    print(f"  • {GREEN}Model version tracking{RESET}")
    print(f"  • {GREEN}Learning from ModSecurity expert labels{RESET}")
    print(f"  • {GREEN}Continuous improvement capability{RESET}")


# =========================================================
# MAIN
# =========================================================
def main():
    parser = argparse.ArgumentParser(
        description="Demonstrate model hot-swapping",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check current model status"
    )
    
    parser.add_argument(
        "--swap",
        metavar="VERSION",
        help="Swap to specified version (e.g., v2, v3)"
    )
    
    parser.add_argument(
        "--test",
        metavar="PAYLOAD",
        help="Test XSS detection with payload"
    )
    
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run complete demonstration workflow"
    )
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if not any([args.check, args.swap, args.test, args.demo]):
        parser.print_help()
        return
    
    # Execute requested action
    if args.demo:
        demo_workflow()
    elif args.check:
        check_current_model()
    elif args.swap:
        swap_model(args.swap)
    elif args.test:
        test_detection(args.test)


if __name__ == "__main__":
    main()
