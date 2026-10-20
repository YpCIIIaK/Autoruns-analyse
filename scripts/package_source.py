"""Package reproducible sources, without caches, local reports, credentials or dependencies."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent.parent
output = root.parent / 'autoruns-lens-source.zip'
excluded = {'node_modules', 'target', 'dist', 'work', '__pycache__', '.git', '.venv'}
with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for file in root.rglob('*'):
        relative = file.relative_to(root)
        if any(part in excluded for part in relative.parts) or not file.is_file():
            continue
        if file.suffix in ('.pyc', '.db'):
            continue
        archive.write(file, Path('autoruns-lens') / relative)
print(output)
