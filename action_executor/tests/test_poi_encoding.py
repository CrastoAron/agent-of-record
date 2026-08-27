import base64

from action_executor.poi_encoding import (
    build_agent_cert_header,
    build_signature_header,
    decode_poi_header,
    encode_poi_header,
)
from action_executor.tests.conftest import signed_email_poi


def test_poi_header_round_trips_without_losing_signature() -> None:
    poi, _ = signed_email_poi()

    assert decode_poi_header(encode_poi_header(poi)) == poi
    assert base64.urlsafe_b64decode(build_signature_header(poi)) == bytes.fromhex(poi.agent_signature)
    assert build_agent_cert_header(poi.agent_pubkey_id) == poi.agent_pubkey_id
