# ============================================================
# вот
# ============================================================
from hash_decoder import decode_hash

test = decode_hash(
    "dbcd69f027ef55c79dbcc920e282cda9",                               # Hash to string
    hash_type="md5",                                                  # Unhash method - ONLY CHECKS MD5
    save_to_file=False,                                               # True/False
    description="dbcd69f027ef55c79dbcc920e282cda9 to unhash."         # Description of the action to print
)