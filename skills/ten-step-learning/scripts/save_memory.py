"""Cooperative, conflict-checked single-file save; Python standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else 'missing'


def save(root, target, expected, content):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root must be an existing directory')
    relative = Path(target)
    if relative.is_absolute() or relative.drive or '..' in relative.parts:
        raise ValueError('target must be a relative path inside root')
    ancestor = root / relative
    missing = []
    while True:
        try:
            ancestor.lstat()
        except FileNotFoundError:
            missing.append(ancestor.name)
            ancestor = ancestor.parent
        else:
            break
    # Resolve existing ancestors strictly; access denial must not hide an escape.
    destination = ancestor.resolve(strict=True).joinpath(*reversed(missing))
    if not destination.is_relative_to(root) or destination == root:
        raise ValueError('target escapes root')
    if destination.name == '.ten-step-write.lock':
        raise ValueError('target cannot be the write lock')
    if expected != 'missing' and (len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected)):
        raise ValueError('expected must be a lowercase SHA-256 or missing')
    data = Path(content).read_bytes()
    data.decode('utf-8-sig')  # Reject non-text payloads before touching the learning directory.
    lock = root / '.ten-step-write.lock'
    temporary = None
    # shortcut: all writers must cooperate; external editors bypass this lock.
    with lock.open('x', encoding='utf-8') as handle:
        try:
            json.dump({'pid': os.getpid(), 'created': datetime.now(timezone.utc).isoformat()}, handle)
            handle.flush()
            if digest(destination) != expected:
                raise ValueError('content changed; reread and merge before retrying')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.ten-step-', delete=False) as output:
                temporary = Path(output.name)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            # Windows requires closing the lock handle before removing it.
            handle.close()
            lock.unlink()
    return {'target': relative.as_posix(), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--expected', required=True)
    parser.add_argument('--content', required=True)
    args = parser.parse_args()
    try:
        result = save(args.root, args.target, args.expected, args.content)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Save incomplete; reread target before retrying ({type(error).__name__}): {error}\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
