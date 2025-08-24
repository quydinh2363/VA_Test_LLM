"""
Script to run Streamlit UI
"""

import subprocess
import sys
import os

def main():
    """Run Streamlit UI"""
    try:
        # Change to the app/ui directory
        ui_dir = os.path.join(os.path.dirname(__file__), "app", "ui")
        os.chdir(ui_dir)
        
        # Run streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "main.py",
            "--server.port", "8501",
            "--server.address", "0.0.0.0"
        ])
    except KeyboardInterrupt:
        print("\nShutting down Streamlit UI...")
    except Exception as e:
        print(f"Error running Streamlit UI: {e}")

if __name__ == "__main__":
    main()

