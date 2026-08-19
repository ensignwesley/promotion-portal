import argparse
import json
import os
from pathlib import Path

from .security import PRINCIPALS, b64e, generate_plain_secret, hash_secret
from .storage import MessageStore


def create_instance(instance: Path, force: bool = False) -> dict:
    instance.mkdir(parents=True, exist_ok=True)
    config_path = instance / 'config.json'
    if config_path.exists() and not force:
        raise SystemExit(f'{config_path} already exists; use --force to rotate local dev credentials')

    plaintext = {}
    config = {
        'session_signing_key': b64e(os.urandom(32)),
        'message_encryption_key': b64e(os.urandom(32)),
        'principals': {},
    }
    for name in sorted(PRINCIPALS):
        password = generate_plain_secret(f'{name}_password')
        api_token = generate_plain_secret(f'{name}_api')
        plaintext[name] = {'password': password, 'api_token': api_token}
        config['principals'][name] = {
            'password': hash_secret(password),
            'api_token': hash_secret(api_token),
        }

    config_path.write_text(json.dumps(config, indent=2) + '\n')
    os.chmod(config_path, 0o600)
    creds_path = instance / 'credentials.generated.json'
    creds_path.write_text(json.dumps(plaintext, indent=2) + '\n')
    os.chmod(creds_path, 0o600)
    MessageStore(instance / 'messages.sqlite3')
    os.chmod(instance / 'messages.sqlite3', 0o600)
    return {'config': str(config_path), 'credentials': str(creds_path), 'database': str(instance / 'messages.sqlite3')}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Create Promotion Portal Phase 0 instance credentials')
    parser.add_argument('--instance', default='./instance')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args(argv)
    result = create_instance(Path(args.instance), args.force)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
