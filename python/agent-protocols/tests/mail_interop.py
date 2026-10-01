"""stdin/stdout interop adapter for public Mail fixtures; no development verifier."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from agent_protocols.identity import AgentSigner
from agent_protocols.mail import MailEncryptionKey, decrypt_mail, encrypt_mail


def main():
    vectors = json.loads((Path(__file__).resolve().parents[3] / 'docs/protocols/agent-mail/1.0.vectors.json').read_text())
    request = json.load(sys.stdin)
    card = vectors['envelopes']['card']
    if request['op'] == 'seal':
        result = encrypt_mail(vectors['messages']['message'], card, AgentSigner.from_seed(bytes.fromhex(vectors['keys']['sender_seed_hex'])), request.get('nonce', 700), now_ms=vectors['now'])
    elif request['op'] == 'open':
        key = MailEncryptionKey.from_private_bytes(bytes.fromhex(vectors['keys']['recipient_secret_hex']))
        result = decrypt_mail(request['packet'], card, key, vectors['keys']['recipient_agent_id'], now_ms=vectors['now'])
    else:
        raise ValueError('unknown interop operation')
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
