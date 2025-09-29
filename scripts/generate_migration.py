#!/usr/bin/env python3
"""Generate Alembic migration."""
import subprocess
import sys
import os

def generate_migration(message: str):
    """Generate a new migration file."""
    try:
        # Run alembic revision command
        cmd = ["alembic", "revision", "--autogenerate", "-m", message]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Migration generated successfully:")
            print(result.stdout)
        else:
            print(f"❌ Error generating migration:")
            print(result.stderr)
            sys.exit(1)
            
    except FileNotFoundError:
        print("❌ Alembic not found. Make sure it's installed:")
        print("pip install alembic")
        sys.exit(1)

def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python generate_migration.py 'migration message'")
        sys.exit(1)
    
    message = sys.argv[1]
    generate_migration(message)

if __name__ == "__main__":
    main()