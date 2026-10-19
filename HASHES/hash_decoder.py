"""
ULTRA FAST Hash Cracker - Check only the hash type you specify
"""

import os
import hashlib
import base64
import time
import platform

# Try to import optional modules
try:
    import bcrypt

    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

if platform.system() == "Windows":
    CRYPT_AVAILABLE = False
else:
    try:
        import crypt

        CRYPT_AVAILABLE = True
    except ImportError:
        CRYPT_AVAILABLE = False


class UltraFastCracker:
    def __init__(self, wordlist_paths=None):
        # Default wordlists to search (in order), anchored to this file's folder
        _here = os.path.dirname(os.path.abspath(__file__))
        if wordlist_paths is None:
            self.wordlist_paths = [
                os.path.join(_here, "wordlists", "wordlist_2.lst"),
                os.path.join(_here, "wordlists", "wordlist_3.lst"),
            ]
        else:
            self.wordlist_paths = wordlist_paths
        self.total_attempts = 0

    def hash_string(self, text: str, hash_type: str) -> str:
        """Hash a string with the specified hash type"""
        text_bytes = text.encode("utf-8")

        # ============ MD5 Family ============
        if hash_type == "md5":
            return hashlib.md5(text_bytes).hexdigest()

        elif hash_type == "md5($pass.$salt)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(text_bytes + salt_bytes).hexdigest()

        elif hash_type == "md5($salt.$pass)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(salt_bytes + text_bytes).hexdigest()

        elif hash_type == "md5($pass.$salt.$pass)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(text_bytes + salt_bytes + text_bytes).hexdigest()

        elif hash_type == "md5(md5($pass))":
            return hashlib.md5(hashlib.md5(text_bytes).hexdigest().encode()).hexdigest()

        elif hash_type == "md5(md5(md5($pass)))":
            first = hashlib.md5(text_bytes).hexdigest()
            second = hashlib.md5(first.encode()).hexdigest()
            return hashlib.md5(second.encode()).hexdigest()

        elif hash_type == "md5(sha1($pass))":
            return hashlib.md5(
                hashlib.sha1(text_bytes).hexdigest().encode()
            ).hexdigest()

        elif hash_type == "md5($salt.md5($pass))":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            inner = hashlib.md5(text_bytes).hexdigest()
            return hashlib.md5(salt_bytes + inner.encode()).hexdigest()

        elif hash_type == "md5(md5($pass).$salt)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            inner = hashlib.md5(text_bytes).hexdigest()
            return hashlib.md5(inner.encode() + salt_bytes).hexdigest()

        elif hash_type == "md5($salt.$pass.$salt)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(salt_bytes + text_bytes + salt_bytes).hexdigest()

        # ============ SHA Family ============
        elif hash_type == "sha1":
            return hashlib.sha1(text_bytes).hexdigest()

        elif hash_type == "sha1($pass.$salt)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha1(text_bytes + salt_bytes).hexdigest()

        elif hash_type == "sha1($salt.$pass)":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha1(salt_bytes + text_bytes).hexdigest()

        elif hash_type == "sha1(md5($pass))":
            return hashlib.sha1(
                hashlib.md5(text_bytes).hexdigest().encode()
            ).hexdigest()

        elif hash_type == "sha1(sha1($pass))":
            return hashlib.sha1(
                hashlib.sha1(text_bytes).hexdigest().encode()
            ).hexdigest()

        elif hash_type == "sha1(sha1(sha1($pass)))":
            first = hashlib.sha1(text_bytes).hexdigest()
            second = hashlib.sha1(first.encode()).hexdigest()
            return hashlib.sha1(second.encode()).hexdigest()

        elif hash_type == "sha256":
            return hashlib.sha256(text_bytes).hexdigest()

        elif hash_type == "sha256($pass.$salt)":
            salt = os.urandom(16).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha256(text_bytes + salt_bytes).hexdigest()

        elif hash_type == "sha256($salt.$pass)":
            salt = os.urandom(16).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha256(salt_bytes + text_bytes).hexdigest()

        elif hash_type == "sha512":
            return hashlib.sha512(text_bytes).hexdigest()

        elif hash_type == "sha512($pass.$salt)":
            salt = os.urandom(16).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha512(text_bytes + salt_bytes).hexdigest()

        elif hash_type == "sha512($salt.$pass)":
            salt = os.urandom(16).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.sha512(salt_bytes + text_bytes).hexdigest()

        # ============ bcrypt ============
        elif hash_type in ["bcrypt", "bcrypt($pass)"]:
            if not BCRYPT_AVAILABLE:
                return "NOT_AVAILABLE"
            salt_bytes = bcrypt.gensalt()
            return bcrypt.hashpw(text_bytes, salt_bytes).decode()

        # ============ NTLM ============
        elif hash_type == "ntlm":
            try:
                return hashlib.new("md4", text_bytes).hexdigest()
            except:
                return "NOT_AVAILABLE"

        # ============ MySQL ============
        elif hash_type == "mysql":
            return hashlib.sha1(hashlib.sha1(text_bytes).digest()).hexdigest()

        elif hash_type == "mysql_sha1":
            return hashlib.sha1(text_bytes).hexdigest()

        # ============ PostgreSQL ============
        elif hash_type == "postgresql":
            salt = os.urandom(4).hex()
            salt_bytes = salt.encode("utf-8")
            return "md5" + hashlib.md5(text_bytes + salt_bytes).hexdigest()

        # ============ WordPress ============
        elif hash_type == "wordpress":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(text_bytes + salt_bytes).hexdigest()

        # ============ Joomla ============
        elif hash_type == "joomla":
            salt = os.urandom(8).hex()
            salt_bytes = salt.encode("utf-8")
            return hashlib.md5(text_bytes + salt_bytes).hexdigest() + ":" + salt

        # ============ Django ============
        elif hash_type == "django":
            salt = os.urandom(12).hex()
            iterations = 100000
            hash_value = hashlib.pbkdf2_hmac(
                "sha256", text_bytes, salt.encode(), iterations
            )
            return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(hash_value).decode()}"

        # ============ Unix Crypt ============
        elif hash_type == "crypt_md5":
            if not CRYPT_AVAILABLE:
                return "NOT_AVAILABLE"
            salt = os.urandom(8).hex()[:8]
            return crypt.crypt(text, f"$1${salt}$")

        elif hash_type == "crypt_sha256":
            if not CRYPT_AVAILABLE:
                return "NOT_AVAILABLE"
            salt = os.urandom(16).hex()[:16]
            return crypt.crypt(text, f"$5${salt}$")

        elif hash_type == "crypt_sha512":
            if not CRYPT_AVAILABLE:
                return "NOT_AVAILABLE"
            salt = os.urandom(16).hex()[:16]
            return crypt.crypt(text, f"$6${salt}$")

        return "UNKNOWN"

    def search_wordlist(self, wordlist_path, target_hash, hash_type, max_lines=None):
        """Search a single wordlist with only the specified hash type"""

        if not os.path.exists(wordlist_path):
            print(f"  ⚠️  Wordlist not found: {wordlist_path}")
            return {
                "password": None,
                "hash_type": None,
                "attempts": 0,
                "wordlist": wordlist_path,
            }

        print(f"\n📂 Searching: {wordlist_path}")
        print(f"   File size: {os.path.getsize(wordlist_path) / (1024*1024):.2f} MB")

        # Count lines if needed
        if max_lines is None:
            print("   Counting lines...")
            max_lines = sum(
                1 for _ in open(wordlist_path, "r", encoding="utf-8", errors="ignore")
            )
            print(f"   Total: {max_lines:,} words")

        line_count = 0
        start_time = time.time()

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if not word:
                        continue

                    line_count += 1
                    self.total_attempts += 1

                    # Show progress every 100,000 words
                    if line_count % 100000 == 0:
                        elapsed = time.time() - start_time
                        speed = self.total_attempts / elapsed if elapsed > 0 else 0
                        percent = (line_count / max_lines) * 100 if max_lines else 0
                        print(
                            f"  📊 {line_count:,}/{max_lines:,} ({percent:.1f}%) | {self.total_attempts:,} attempts | {speed:,.0f} h/s"
                        )

                    # Generate hash with the specified type ONLY
                    hash_result = self.hash_string(word, hash_type)

                    # Skip if not available
                    if hash_result in ["NOT_AVAILABLE", "UNKNOWN"]:
                        continue

                    # Check if match
                    if hash_result == target_hash:
                        elapsed = time.time() - start_time
                        print(f"\n🎯 FOUND! at {elapsed:.2f} seconds")
                        print(f"   Password: '{word}'")
                        print(f"   Hash Type: {hash_type}")
                        print(f"   Position: {line_count:,}")
                        print(f"   Attempts: {self.total_attempts:,}")
                        print(f"   Wordlist: {os.path.basename(wordlist_path)}")
                        return {
                            "password": word,
                            "hash_type": hash_type,
                            "attempts": self.total_attempts,
                            "time": elapsed,
                            "wordlist": wordlist_path,
                            "position": line_count,
                        }

                    # Stop if max reached
                    if max_lines and line_count >= max_lines:
                        break

        except Exception as e:
            print(f"  ❌ Error: {e}")

        elapsed = time.time() - start_time
        print(f"  ❌ Not found in {line_count:,} words")
        print(f"  ⏱️  Time: {elapsed:.2f} seconds")
        print(f"  📊 Speed: {self.total_attempts/max(elapsed, 0.001):,.0f} h/s")

        return {
            "password": None,
            "hash_type": None,
            "attempts": self.total_attempts,
            "wordlist": wordlist_path,
        }

    def crack_hash(
        self, target_hash: str, hash_type: str, max_lines: int = None
    ) -> dict:
        """
        Crack a hash by searching multiple wordlists with ONLY the specified hash type

        Args:
            target_hash: The hash to crack
            hash_type: The hash type to use (e.g., 'md5', 'sha1', 'sha256')
            max_lines: Maximum number of lines to search per wordlist
        """

        print("=" * 70)
        print(f"🚀 ULTRA FAST CRACKER")
        print(f"🎯 Target Hash: {target_hash}")
        print(f"🔑 Hash Type: {hash_type}")
        print(f"📂 Wordlists: {len(self.wordlist_paths)}")
        for i, path in enumerate(self.wordlist_paths, 1):
            print(f"   {i}. {path}")
        print("=" * 70)

        # Reset attempts
        self.total_attempts = 0

        # Search each wordlist in order
        for wordlist_path in self.wordlist_paths:
            result = self.search_wordlist(
                wordlist_path, target_hash, hash_type, max_lines
            )

            if result["password"]:
                print("\n" + "=" * 70)
                print("✅ HASH CRACKED!")
                print(f"   Password: {result['password']}")
                print(f"   Hash Type: {result['hash_type']}")
                print(f"   Wordlist: {os.path.basename(result['wordlist'])}")
                print(f"   Position: {result.get('position', 'N/A'):,}")
                print(f"   Attempts: {result['attempts']:,}")
                print(f"   Time: {result.get('time', 0):.2f} seconds")
                print("=" * 70)
                return result

        print("\n" + "=" * 70)
        print(f"❌ Password NOT FOUND in any wordlist")
        print(f"📊 Total attempts across all wordlists: {self.total_attempts:,}")
        print("=" * 70)

        return {"password": None, "hash_type": None, "attempts": self.total_attempts}


# ============================================================
# USAGE - EXACT FORMAT YOU WANT
# ============================================================


def decode_hash(
    hash_to_crack: str,
    hash_type: str,
    save_to_file: bool = False,
    description: str = "",
) -> str:
    """
    Attempt to crack/decode a hash

    Args:
        hash_to_crack: The hash to crack
        hash_type: Type of hash (e.g., 'md5', 'sha1', 'sha256')
        save_to_file: Whether to save results to file
        description: Description of the action to print

    Returns:
        Cracked password or error message
    """
    # Print description if provided
    if description:
        print(description)

    # Anchor wordlists to this file's folder, not the caller's cwd
    _here = os.path.dirname(os.path.abspath(__file__))
    cracker = UltraFastCracker(
        [
            os.path.join(_here, "wordlists", "wordlist_2.lst"),
            os.path.join(_here, "wordlists", "wordlist_3.lst"),
        ]
    )

    # Crack the hash with the specified type ONLY
    result = cracker.crack_hash(hash_to_crack, hash_type)

    # Save to file if requested and found
    if save_to_file and result["password"]:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"cracked_{hash_type}_{timestamp}.txt"

        with open(filename, "w") as f:
            f.write(f"Hash: {hash_to_crack}\n")
            f.write(f"Hash Type: {hash_type}\n")
            f.write(f"Cracked Password: {result['password']}\n")
            f.write(
                f"Wordlist: {os.path.basename(result.get('wordlist', 'unknown'))}\n"
            )
            f.write(f"Position: {result.get('position', 'N/A')}\n")
            f.write(f"Attempts: {result.get('attempts', 'N/A')}\n")
            f.write(f"Time: {result.get('time', 0):.2f} seconds\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        print(f"💾 Saved to: {filename}")

    return result["password"] if result["password"] else "NOT_CRACKED"


# ============================================================
# TEST - EXACTLY AS YOU WANTED
# ============================================================

# test = decode_hash(
#     "dbcd69f027ef55c79dbcc920e282cda9",                               # Hash to string
#     hash_type="md5",                                                  # Unhash method - ONLY CHECKS MD5
#     save_to_file=False,                                               # True/False
#     description="dbcd69f027ef55c79dbcc920e282cda9 to unhash."         # Description of the action to print
# )

# print(f"\n✅ Result: {test}")
