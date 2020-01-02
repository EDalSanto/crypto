"""
Decode the two ciphertexts from the Instructors Box below,
or the C1, C2 variables - which are the same

We highly recommend that you run your decoding code in the
programming language of your choice outside of the
this environment, as this system does not provide enough
computational resources to successfully decode

After decoding the two ciphertexts,
replace the plaintext1 and plaintext2 variables below
with the decoded ciphertexts

C1 and C2 are messages in english,
encoded using string_to_bits, with 7bit ASCII
and then XOR'd with a secret key

In pseudo-code:
C1 = XOR(string_to_bits(plaintext1), secret_key)
C2 = XOR(string_to_bits(plaintext2), secret_key)
"""

C1 = "1010110010011110011111101110011001101100111010001111011101101011101000110010011000000101001110111010010111100100111101001010000011000001010001001001010000000010101001000011100100010011011011011011010111010011000101010111111110010011010111001001010101110001111101010000001011110100000000010010111001111010110000001101010010110101100010011111111011101101001011111001101111101111000100100001000111101111011011001011110011000100011111100001000101111000011101110101110010010100010111101111110011011011001101110111011101100110010100010001100011001010100110001000111100011011001000010101100001110011000000001110001011101111010100101110101000100100010111011000001111001110000011111111111110010111111000011011001010010011100011100001011001101110110001011101011101111110100001111011011000110001011111111101110110101101101001011110110010111101000111011001111"

C2 = "1011110110100110000001101000010111001000110010000110110001101001111101010000101000110100111010000010011001100100111001101010001001010001000011011001010100001100111011010011111100100101000001001001011001110010010100101011111010001110010010101111110001100010100001110000110001111111001000100001001010100011100100001101010101111000100001111101111110111001000101111111101011001010000100100000001011001001010000101001110101110100001111100001011101100100011000110111110001000100010111110110111010010010011101011111111001011011001010010110100100011001010110110001001000100011011001110111010010010010110100110100000111100001111101111010011000100100110011111011001010101000100000011111010010110111001100011100001111100100110010010001111010111011110110001000111101010110101001110111001110111010011111111010100111000100111001011000111101111101100111011001111"

# 111011001111

#####
# CHANGE THESE VARIABLES

# plaintext1 = ""
# plaintext2 = ""

# END
#############

#############
# Below is some code that might be useful
#

BITS = ('0', '1')
ASCII_BITS = 7

def display_bits(bits):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[bit] for bit in bits])

def seq_to_bits(seq_of_bits):
    """converts string of bits to list"""
    return [0 if bit == '0' else 1 for bit in seq_of_bits]

def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits

def convert_to_bits(number):
    """converts an integer `n` to bit array"""
    result = []
    if number == 0:
        return [0]
    while number > 0:
        result = [(number % 2)] + result
        number = number / 2
    return result

def string_to_bits(string):
    """convert string to bits"""
    def chr_to_bit(char):
        return pad_bits(convert_to_bits(ord(char)), ASCII_BITS)
    return [b for group in
            map(chr_to_bit, string)
            for b in group]

def bits_to_char(bits):
    """bits to char"""
    assert len(bits) == ASCII_BITS
    value = 0
    for bit in bits:
        value = (value * 2) + bit
    return chr(value)

def list_to_string(p):
    return ''.join(p)

def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS])
                    for i in range(0, len(b), ASCII_BITS)])

secret_key = "1" * 847
c1_guess = int(C1, 2) ^ int(secret_key, 2)
c1_guess = '{0:b}'.format(c1_guess)
m1 = bits_to_string([int(b) for b in c1_guess])
print(m1)
c2_guess = int(C2, 2) ^ int(secret_key, 2)
c2_guess = '{0:b}'.format(c2_guess)
m2 = bits_to_string([int(b) for b in c2_guess])
print(m2)
