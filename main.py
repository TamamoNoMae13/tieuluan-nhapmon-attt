import math
# Parity-bit Drop
PC1 = [57, 49, 41, 33, 25, 17, 9, 1,
       58, 50, 42, 34, 26, 18, 10, 2,
       59, 51, 43, 35, 27, 19, 11, 3,
       60, 52, 44, 36, 63, 55, 47, 39,
       31, 23, 15, 7, 62, 54, 46, 38,
       30, 22, 14, 6, 61, 53, 45, 37,
       29, 21, 13, 5, 28, 20, 12, 4]
# Number of bit(s) get left-shift (base on current round)
SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2,
               1, 2, 2, 2, 2, 2, 2, 1]
# Key-compression D-box
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]
# Initial permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]
# Expansion D-Box
EXP_D = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]
# S-box
S_BOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

         [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

         [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

         [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

         [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

         [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

         [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
# Straight Permutation
D_BOX = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]
# Final Permutation
IP1 = [40, 8, 48, 16, 56, 24, 64, 32,
       39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30,
       37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28,
       35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26,
       33, 1, 41, 9, 49, 17, 57, 25]
HEX_CHAR = ['0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
SUPPORTED_ENC = ["bin", "hex", "utf8"]


def permute(s, matrix):
    output = ""
    for x in matrix:
        output += s[x - 1]
    return output


def left_shift(s, k):  # shift left k times
    return s[k:len(s)] + s[0:k]


def gen_subkeys(k):
    # 64-bit key ----PC1----> 56-bit ----> 2 halves (28-bit each)
    k_c = permute(k, PC1[:28])
    k_d = permute(k, PC1[28:])
    # Generate subkeys
    sub_keys = []
    for i in range(16):
        # Left shift i-bit, base on current round
        k_c = left_shift(k_c, SHIFT_TABLE[i])
        k_d = left_shift(k_d, SHIFT_TABLE[i])
        # Join 2 halves ----PC2----> 48-bit, add to List
        sub_keys.append(permute(k_c + k_d, PC2))
    return sub_keys


def dec_to_bin(dec_num):  # decimal to 4-bit binary
    output = ""
    for i in range(4):
        output = str(dec_num % 2) + output
        dec_num //= 2
    return output


def s_boxes(s):
    output = ""
    for i in range(8):  # Go through 8 S-boxes
        row = 2 * int(s[(6 * i)]) + int(s[(6 * i + 5)])  # 1st & 6th bit
        # 2nd-5th bit
        column = 8 * int(s[(6 * i + 1)]) + 4 * int(s[(6 * i + 2)]) + \
            2 * int(s[(6 * i + 3)]) + int(s[(6 * i + 4)])
        # Check value in S-box[i] & put 4-bit result from S-box to arrS
        output += dec_to_bin(S_BOX[i][row][column])
    return output


def calc_xor(bin_str1, bin_str2):
    output = ""
    for i in range(len(bin_str1)):
        output += str(int(bin_str1[i]) ^ int(bin_str2[i]))
    return output


def des_core(x, k, crypt):
    # Encrypt: Use sub-keys in original order
    # Decrypt: Reverse the order of sub-keys
    key_ord = range(16)
    if crypt == 'd':
        key_ord = reversed(range(16))
    # Get keys for 16 rounds of DES
    sub_keys = gen_subkeys(k)
    # Text ----IP----> 64-bit ----> 2 halves (32-bit each)
    left_half = permute(x, IP[:32])
    right_half = permute(x, IP[32:])
    # Starting 16 rounds of Feistel cipher
    for r in key_ord:
        # Right-half (32-bit) ---expand---> 48-bit ---XOR with sub-key--->
        # 48-bit ---S_BOX---> 32-bit ---D_BOX---> 32-bit
        # ---XOR with left-half---> New right-half (32-bit)
        new_r_half = calc_xor(left_half,
                              permute(
                                  s_boxes(
                                      calc_xor(
                                          permute(right_half, EXP_D),
                                          sub_keys[r])
                                  ),
                                  D_BOX)
                              )
        left_half = right_half  # New left-half <-- old right-half
        right_half = new_r_half  # Assign new right-half
    # Join 2 halves and permute with inverse IP
    return permute(right_half + left_half, IP1)


def tdes_core(msg, k1, k2, k3, crypt):
    if crypt == 'e':
        return des_core(des_core(des_core(msg, k1, "e"), k2, "d"), k3, "e")
    return des_core(des_core(des_core(msg, k3, "d"), k2, "e"), k1, "d")


def add_trailing_zero(s):
    if len(s) % 64 != 0:
        return s + '0' * (64 - len(s) % 64)
    return s


def split_block(bin_str):  # input is a multiple-of-64 bit string
    output = []
    for i in range(len(bin_str) // 64):
        output.append(bin_str[64*i:64*i+64])
    return output


CRYPT_MODE = ['e', 'd']
SUPPORTED_MODE = ["ecb", "cbc", "cfb", "ofb", "ctr"]
BIN_CHAR = ['0', '1']


def check_before_crypt(crypt, mode, x, k_arr, iv):
    if crypt not in CRYPT_MODE:
        return "Please specify if you want to \'e\'ncrypt or \'d\'ecrypt!"
    if mode not in SUPPORTED_MODE:
        return "Only \"ecb\", \"cbc\", \"cfb\", " + \
                "\"ofb\" and \"ctr\" modes are supported!"
    bin_str_arr = [x]
    if mode != "ecb":
        if iv is None:
            return "This mode requires an IV."
        else:
            bin_str_arr += k_arr
            bin_str_arr.append(iv)
    else:
        bin_str_arr += k_arr
    for i in range(len(bin_str_arr)):
        for c in bin_str_arr[i]:
            if c not in BIN_CHAR:
                return "Text, Key, or IV is not binary."
        # Ignore 1st element (text) when checking 64-bit requirement
        if i != 0 and len(bin_str_arr[i]) != 64:
            return "Your Key or IV is not 64-bit!"
    return True


def convert_text(text, i_enc, o_enc):
    i_enc = i_enc.lower()
    o_enc = o_enc.lower()
    if (i_enc not in SUPPORTED_ENC) or (o_enc not in SUPPORTED_ENC):
        return "Only \"bin\", \"hex\" and \"utf8\" are supported!"
    if i_enc == o_enc:
        return "Input and output encoders should not be the same!"
    if i_enc == "bin":
        for c in text:
            if c not in BIN_CHAR:
                return "Input is not binary!"
        if o_enc == "hex":
            return b2h(text)
        return b2t(text)
    if i_enc == "hex":
        for c in text:
            if c not in HEX_CHAR:
                return "Input is not hexadecimal!"
        if o_enc == "bin":
            return h2b(text)
        return h2t(text)
    if o_enc == "bin":
        return t2b(text)
    return t2h(text)


def h2b(s):
    return ''.join(["{0:04b}".format(int(char, 16)) for char in s])


def b2h(s):
    output = ""
    # Handle 0s at the beginning
    for i in range(len(s) // 4 - 1):
        if s[4*i:4*i+4] != "0000":
            break
        else:
            output += '0'
    output += hex(int(s, 2))[2:]
    return output


def t2b(s):
    return ''.join(bin(char)[2:].zfill(8) for char in s.encode('utf-8'))


def b2t(s):
    return int(s, 2).to_bytes(math.ceil(len(s) / 8), 'big').decode('utf-8')


def t2h(s):
    return b2h(t2b(s))


def h2t(s):
    return b2t(h2b(s))


def long_text_des(x, mode, k, iv, crypt):
    chk = check_before_crypt(crypt, mode, x, [k], iv)
    if not chk:
        return chk
    # Add 0-trail and split to multiple 64-bit blocks
    text_blocks = split_block(add_trailing_zero(x))
    vec = iv
    output = ""
    # Enc/Dec with DES
    if mode == "ecb":
        for i in range(len(text_blocks)):
            output += des_core(text_blocks[i], k, crypt)
    elif mode == "cbc":
        if crypt == 'e':
            for i in range(len(text_blocks)):
                vec = des_core(calc_xor(vec, text_blocks[i]), k, crypt)
                output += vec
        else:
            for i in range(len(text_blocks)):
                output += calc_xor(vec, des_core(text_blocks[i], k, crypt))
                vec = text_blocks[i]
    elif mode == "cfb":
        if crypt == 'e':
            for i in range(len(text_blocks)):
                vec = calc_xor(text_blocks[i], des_core(vec, k, crypt))
                output += vec
        else:
            for i in range(len(text_blocks)):
                output += calc_xor(des_core(vec, k, 'e'), text_blocks[i])
                vec = text_blocks[i]
    elif mode == "ofb":
        for i in range(len(text_blocks)):
            vec = des_core(vec, k, 'e')
            output += calc_xor(text_blocks[i], vec)
    else:
        for i in range(len(text_blocks)):
            output += calc_xor(des_core(vec, k, 'e'), text_blocks[i])
            vec = left_shift(vec, 1)
    return output


def long_text_tdes(x, mode, k1, k2, k3, iv, crypt):
    chk = check_before_crypt(crypt, mode, x, [k1, k2, k3], iv)
    if not chk:
        return chk
    # Add 0-trail and split to multiple 64-bit blocks
    text_blocks = split_block(add_trailing_zero(x))
    vec = iv
    output = ""
    # Enc/Dec with TDES
    if mode == "ecb":
        for i in range(len(text_blocks)):
            output += tdes_core(text_blocks[i], k1, k2, k3, crypt)
    elif mode == "cbc":
        if crypt == 'e':
            for i in range(len(text_blocks)):
                vec = tdes_core(calc_xor(vec, text_blocks[i]), k1, k2, k3, crypt)
                output += vec
        else:
            for i in range(len(text_blocks)):
                output += calc_xor(vec, tdes_core(text_blocks[i], k1, k2, k3, crypt))
                vec = text_blocks[i]
    elif mode == "cfb":
        if crypt == 'e':
            for i in range(len(text_blocks)):
                vec = calc_xor(text_blocks[i], tdes_core(vec, k1, k2, k3, crypt))
                output += vec
        else:
            for i in range(len(text_blocks)):
                output += calc_xor(tdes_core(vec, k1, k2, k3, 'e'), text_blocks[i])
                vec = text_blocks[i]
    elif mode == "ofb":
        for i in range(len(text_blocks)):
            vec = tdes_core(vec, k1, k2, k3, 'e')
            output += calc_xor(text_blocks[i], vec)
    else:
        for i in range(len(text_blocks)):
            output += calc_xor(tdes_core(vec, k1, k2, k3, 'e'), text_blocks[i])
            vec = left_shift(vec, 1)
    return output


# Press the green button in the gutter to run the script.

if __name__ == '__main__':
    print("Test 1:")
    plaintext = "8cffc8b2ef4ee5023dddd4a38cffc8b2ef4ee5023dddd4a3"
    x_b = convert_text(plaintext, "hex", "bin")
    key = convert_text("3ee6be37cc6646e7", "hex", "bin")
    # work as nonce in CTR
    init_vec = convert_text("e4520a2119f51114", "hex", "bin")
    print("  Plaintext:  " + plaintext)
    for split_block_mode in SUPPORTED_MODE:
        print(split_block_mode + " mode:")
        # ECB mode ignores IV
        y_b = long_text_des(x_b, split_block_mode, key, init_vec, 'e')
        y = convert_text(y_b, "bin", "hex")
        d_y_b = long_text_des(y_b, split_block_mode, key, init_vec, 'd')
        d_y = convert_text(d_y_b, "bin", "hex")
        print("  Ciphertext: " + y,
              "  Decrypt C:  " + d_y, sep='\n')

    print("Test 2:")
    plaintext = "Nhập môn an toàn thông tin Kỳ 1 năm 2021-2022"
    x_b = convert_text(plaintext, "utf8", "bin")
    key = convert_text("01234567", "utf8", "bin")
    # work as nonce in CTR
    init_vec = convert_text("INT32131", "utf8", "bin")
    print("  Plaintext:  " + plaintext)
    for split_block_mode in SUPPORTED_MODE:
        print(split_block_mode + " mode:")
        # ECB mode ignores IV
        y_b = long_text_des(x_b, split_block_mode, key, init_vec, 'e')
        y = convert_text(y_b, "bin", "hex")
        d_y_b = long_text_des(y_b, split_block_mode, key, init_vec, 'd')
        d_y = convert_text(d_y_b, "bin", "utf8")
        print("  Ciphertext: " + y,
              "  Decrypt C:  " + d_y, sep='\n')

    print("Test 3:")
    plaintext = "0caa08cea44b26a09ca2a26858ee38c2"
    x_b = convert_text(plaintext, "hex", "bin")
    key1 = convert_text("5ceea80e4b0b3130", "hex", "bin")
    key2 = convert_text("c59d20ace68163f3", "hex", "bin")
    key3 = convert_text("b0b31c48f089bf23", "hex", "bin")
    # work as nonce in CTR
    init_vec = convert_text("2276e866286e86e7", "hex", "bin")
    print("  Plaintext:  " + plaintext)
    for split_block_mode in SUPPORTED_MODE:
        print(split_block_mode + " mode:")
        # ECB mode ignores IV
        y_b = long_text_tdes(x_b, split_block_mode, key1, key2, key3,
                             init_vec, 'e')
        y = convert_text(y_b, "bin", "hex")
        d_y_b = long_text_tdes(y_b, split_block_mode, key1, key2, key3,
                               init_vec, 'd')
        d_y = convert_text(d_y_b, "bin", "hex")
        print("  Ciphertext: " + y,
              "  Decrypt C:  " + d_y, sep='\n')

    print("Test 4:")
    plaintext = "ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"
    x_b = convert_text(plaintext, "utf8", "bin")
    key1 = convert_text("6ff2a6d15a0abfa3", "hex", "bin")
    key2 = convert_text("0ee0d07721798c15", "hex", "bin")
    key3 = convert_text("e80d90476a1eeac4", "hex", "bin")
    # work as nonce in CTR
    init_vec = convert_text("_Nhom_2_", "utf8", "bin")
    print("  Plaintext:  " + plaintext)
    for split_block_mode in SUPPORTED_MODE:
        print(split_block_mode + " mode:")
        # ECB mode ignores IV
        y_b = long_text_tdes(x_b, split_block_mode, key1, key2, key3,
                             init_vec, 'e')
        y = convert_text(y_b, "bin", "hex")
        d_y_b = long_text_tdes(y_b, split_block_mode, key1, key2, key3,
                               init_vec, 'd')
        d_y = convert_text(d_y_b, "bin", "utf8")
        print("  Ciphertext: " + y,
              "  Decrypt C:  " + d_y, sep='\n')
