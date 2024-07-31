import sys
import hashlib

def main():
    BUFFER = 1048576 # lets read stuff in 1MB chunks

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(sys.argv[1], 'rb') as f:
        while True:
            data = f.read(BUFFER)
            if not data:
                break
            sha1.update(data)
            sha256.update(data)
            md5.update(data)

    print(f"MD5: {md5.hexdigest()}")
    print(f"SHA-1: {sha1.hexdigest()}")
    print(f"SHA-256: {sha256.hexdigest()}")



if __name__ == "__main__":
    main()
