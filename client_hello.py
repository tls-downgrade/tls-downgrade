 # https://gist.github.com/dholth/b766f20cdab26cee082f3f58d7c015d7
import struct
import binascii


_int16 = struct.Struct(">H")


def int16(b):
    """
    Return first two bytes of b as an unsigned integer.
    """
    return _int16.unpack(b[:2])[0]


def take(data, count):
    prefix = data[:count]
    data = data[count:]
    return prefix, data


# Handshake, 3, 1 (TLS 1.0)
HEADER = b"\x16\x03\x01"
TYPE_ALPN = b"\x00\x10"


def parseHello(data):
    """
    Parse TLS 1.2 ClientHello from data, return the extensions as binary data
    or None if not found.
    Likely to raise struct.error or IndexError on error.
    """
    # if not data.startswith(HEADER):
    #     return
    ciphersuite_location = 7
    header, data = take(data, 7)
    messageId, major, minor, l1, l2 = struct.unpack(">BBBHH", header)
    # print(messageId, major, minor, l1, l2)
    # if not data.startswith(b"\x01"):  # ClientHello
    #     return
    header2, data = take(data, 4)
    ciphersuite_location += 4
    # print(struct.unpack(">HBB", header2))  # inner length; 3; 3
    # random
    random, data = take(data, 32)
    # session identifier
    slen, data = take(data, 1)
    slen = slen[0]
    session, data = take(data, slen)
    ciphersuite_location += 32 + 1 + slen
    # ciphers list
    clen, data = take(data, 2)
    clen = int16(clen)
    ciphersuite_location += 2
    ciphersuite_length = clen
    ciphers, data = take(data, clen)
    # compression methods (should always be an array of length 1, with one 0 element)
    compression_length, data = take(data, 1)
    compression_methods, data = take(data, compression_length[0])
    # extensions
    if data:
        extlen, data = take(data, 2)
        extensions, data = take(data, int16(extlen))
    else:
        extensions = []
    return extensions, ciphers, (ciphersuite_location, ciphersuite_length)

def parseServerHello(data):
    header, data = take(data, 7)
    messageId, major, minor, l1, l2 = struct.unpack(">BBBHH", header)
    header2, data = take(data, 4)
    random, data = take(data, 32)
    # session identifier
    slen, data = take(data, 1)
    slen = slen[0]
    session, data = take(data, slen)
    # ciphers list
    ciphers, data = take(data, 2)
    # compression methods (should always be an array of length 1, with one 0 element)
    compression_length, data = take(data, 1)
    compression_methods, data = take(data, compression_length[0])
    # extensions
    extlen, data = take(data, 2)
    extensions, data = take(data, int16(extlen))
    return extensions

def parseExtensions(data):
    """
    Yield (type, body) for TLS extensions in data, as binary data.
    """
    while data:
        type, data = take(data, 2)
        length, data = take(data, 2)
        body, data = take(data, int16(length))
        yield (type, body)


def parseAlpn(body):
    """
    Parse array of Pascal strings, ignore a 16-bit length header.
    """
    length, body = take(body, 2)
    while body:
        protocol, body = take(body[1:], body[0])
        yield protocol

def parseSupportedVersion(body):
    length, body = take(body, 1)
    while body:
        ver, body = take(body, 2)
        yield ver

if __name__ == "__main__":
    sample_hello = b"FgMBAgABAAH8AwN3t6WJKcsKcWo+roqQX7Nuc8SYCUAKTIkINuDoJm4ooiDRiC2236q0JY/NewWV9KcViEzk7S03gwwUSioSOKbOcAAkEwETAxMCwCvAL8ypzKjALMAwwArACcATwBQAMwA5AC8ANQAKAQABjwAAAA4ADAAACWxvY2FsaG9zdAAXAAD/AQABAAAKAA4ADAAdABcAGAAZAQABAQALAAIBAAAjAAAAEAAOAAwCaDIIaHR0cC8xLjEABQAFAQAAAAAAMwBrAGkAHQAgcqzbr+1AYblh6qcR+qvjokWhIpbChkaqpXuDY9uHhVoAFwBBBAq/uAsPt0n3lc9MGArs6RqLoQE+1eWkstNR0zPjxlQcqGSD+1mKyvSCGEwU0DCZAEFEvhnj5YxSyqcAFODwnp4AKwAJCAMEAwMDAgMBAA0AGAAWBAMFAwYDCAQIBQgGBAEFAQYBAgMCAQAtAAIBAQAcAAJAAQAVAJUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

    import base64
    import pprint

    data = bytearray(base64.b64decode(sample_hello))
    extensions = parseHello(data)
    for (type, body) in parseExtensions(extensions):
        if type == TYPE_ALPN:
            pprint.pprint(list(parseAlpn(body)))
