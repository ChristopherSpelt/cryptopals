import base64
import binascii


def hex_to_base64(input):
    hex_string = str(hex(input))[2:]
    return base64.b64encode(binascii.unhexlify(hex_string))


if __name__ == "__main__":
    input = 0x49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D
    output = hex_to_base64(input)
    print(output)
