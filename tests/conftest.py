import os

# Disable auto-install skill during tests to avoid interference with skill install tests.
os.environ["BN_NO_AUTO_SKILL"] = "1"
