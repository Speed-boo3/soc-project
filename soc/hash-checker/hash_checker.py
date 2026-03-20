import hashlib
import argparse
import os

KNOWN_MALWARE = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file - often used in testing",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file",
    "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Known malware sample",
}

HASH_PATTERNS = {
    32:  "MD5",
    40:  "SHA-1",
    56:  "SHA-224",
    64:  "SHA-256",
    96:  "SHA-384",
    128: "SHA-512",
}


def identify_hash(h):
    return HASH_PATTERNS.get(len(h.strip()), "Unknown")


def check_hash(h):
    return KNOWN_MALWARE.get(h.lower().strip())


def hash_file(filepath):
    results = {}
    with open(filepath, "rb") as f:
        data = f.read()
    results["md5"]    = hashlib.md5(data).hexdigest()
    results["sha1"]   = hashlib.sha1(data).hexdigest()
    results["sha256"] = hashlib.sha256(data).hexdigest()
    return results


def main():
    parser = argparse.ArgumentParser(description="Identify hash type and check against known malware")
    parser.add_argument("--hash", help="Hash string to check")
    parser.add_argument("--file", help="File to hash and check")
    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            return
        hashes = hash_file(args.file)
        print(f"\nFile     : {args.file}")
        for algo, h in hashes.items():
            match = check_hash(h)
            status = f"MALWARE DETECTED - {match}" if match else "Clean"
            print(f"{algo.upper():<8} : {h}  [{status}]")
    elif args.hash:
        h = args.hash.strip()
        algo = identify_hash(h)
        match = check_hash(h)
        print(f"\nHash     : {h}")
        print(f"Type     : {algo}")
        if match:
            print(f"Status   : MALWARE DETECTED - {match}")
        else:
            print(f"Status   : Clean - not found in database")
    else:
        print("Use --hash or --file")


if __name__ == "__main__":
    main()
