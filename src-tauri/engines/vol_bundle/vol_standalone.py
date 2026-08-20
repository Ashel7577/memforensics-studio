import os
import sys

# Volatility renders process names, service descriptions and file paths taken
# straight out of the memory image, so its output routinely contains characters
# outside the console's legacy code page (cp1252 on Windows). When stdout is a
# pipe, Python picks the locale encoding, and the text renderer then raises
# UnicodeEncodeError part way through rendering the grid — which surfaces as a
# non-zero exit with no usable output. Force UTF-8 with replacement on both
# streams before Volatility writes anything.
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

from volatility3.cli import main

if __name__ == '__main__':
    if sys.argv[0].endswith('.exe'):
        sys.argv[0] = sys.argv[0][:-4]
    sys.exit(main())
