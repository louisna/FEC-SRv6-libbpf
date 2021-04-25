import sys

def convert(mac):
    out = ""
    for h in mac.split(":"):
        out += f"0x{h}, "
    return out[:-1]

if __name__ == "__main__":
    mac = sys.argv[1]
    print(convert(mac))