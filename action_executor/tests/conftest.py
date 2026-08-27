from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger_core import Ledger
from poi_generator import build_poi, sign_poi


def email_payload() -> dict[str, str]:
    return {
        "to": "bob@example.com",
        "subject": "Approved update",
        "body": "The approved project update is attached.",
    }


def signed_email_poi():
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved email."})
    ledger.append("user_prompt", {"text": "Send Bob an approved update."})
    private_key = Ed25519PrivateKey.generate()
    poi = sign_poi(
        build_poi(
            "Send Bob an approved update.",
            "Only send approved email.",
            ledger,
            email_payload(),
            "demo-model",
        ),
        private_key,
    )
    return poi, private_key
