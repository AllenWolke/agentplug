"""Explicit first-deployment/upgrade entrypoint for this public project."""
import sys
from compose import main

if __name__ == "__main__":
    arguments = sys.argv[1:]
    action = arguments.pop(0) if arguments and arguments[0] in {"init", "upgrade"} else "init"
    sys.argv = [sys.argv[0], action, *arguments]
    raise SystemExit(main())
