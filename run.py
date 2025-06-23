#!/usr/bin/env python3
"""
Cryptography Algorithms TP - Main Entry Point

This script provides multiple ways to interact with the cryptography algorithms:
1. GUI Interface (default)
2. Console Demo
3. Interactive Menu
4. Test Suite

Usage:
    python run.py              # Launch GUI
    python run.py --demo       # Run demo
    python run.py --console    # Interactive console
    python run.py --test       # Run tests
    python run.py --help       # Show help
"""

import sys
import argparse
import os

def main():
    parser = argparse.ArgumentParser(
        description='Cryptography Algorithms TP - Educational Implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py              Launch GUI interface
  python run.py --demo       Run quick demonstration
  python run.py --console    Interactive console menu
  python run.py --test       Run test suite
        """
    )
    
    parser.add_argument('--demo', action='store_true',
                       help='Run quick demonstration of all algorithms')
    parser.add_argument('--console', action='store_true',
                       help='Launch interactive console interface')
    parser.add_argument('--test', action='store_true',
                       help='Run comprehensive test suite')
    parser.add_argument('--version', action='version', version='TP Cryptography v1.0.0')
    
    args = parser.parse_args()
    
    # Set up path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        if args.demo:
            print("🚀 Running Cryptography Algorithms Demo...")
            import demo
            demo.main()
        elif args.console:
            print("🖥️  Launching Interactive Console...")
            import main
            main.main_menu()
        elif args.test:
            print("🧪 Running Test Suite...")
            import tests.test_algorithms as tests
            tests.main()
        else:
            # Default: Launch GUI
            print("🖼️  Launching GUI Interface...")
            try:
                import gui
                gui.main()
            except ImportError as e:
                print(f"Error: Could not launch GUI: {e}")
                print("Falling back to console demo...")
                import demo
                demo.main()
    
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Please check that all dependencies are installed.")
        print("Run: pip install -r requirements.txt")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
