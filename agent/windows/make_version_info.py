"""Genera version_info.txt para PyInstaller (propiedades del .exe en Windows)."""
import re
from pathlib import Path

root = Path(__file__).resolve().parents[2]
version = re.search(r'^VERSION = "([^"]+)"', (root / "agent/th_agent.py").read_text(encoding="utf-8"), re.M).group(1)
nums = tuple((list(map(int, re.findall(r"\d+", version))) + [0, 0, 0, 0])[:4])
(root / "version_info.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Threat Hunting'),
      StringStruct('FileDescription', 'Threat Hunting Agent'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'th_agent'),
      StringStruct('OriginalFilename', 'th_agent.exe'),
      StringStruct('ProductName', 'Threat Hunting Agent'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")
print(f"version_info.txt -> {version} {nums}")
