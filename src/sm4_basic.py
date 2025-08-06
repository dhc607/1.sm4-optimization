# SM4加密算法基本实现
# 参考GB/T 32907-2016《信息安全技术 SM4分组密码算法》

class SM4:
    def __init__(self, key):
        """初始化SM4加密器/解密器

        Args:
            key: 16字节的密钥
        """
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")

        self.key = key
        self.Sbox = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x0d, 0x2d, 0x02,
            0x1f, 0x55, 0x82, 0xd5, 0x40, 0xc7, 0x31, 0xa1, 0x74, 0x03, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
            0xa0, 0x38, 0xe0, 0x41, 0x7f, 0x00, 0x2e, 0xee, 0xb8, 0x56, 0x0c, 0xbc, 0xd2, 0x79, 0x20, 0x9f,
            0xb4, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0x27, 0x31, 0xd6, 0x1e, 0x14, 0x6c, 0x48,
            0x97, 0xc2, 0x0a, 0xf1, 0x6e, 0x3d, 0x29, 0x2b, 0x07, 0x5b, 0xbb, 0x43, 0x96, 0x42, 0x06, 0x8f,
            0x0c, 0x7d, 0x37, 0x21, 0x12, 0x7a, 0x60, 0x59, 0xcb, 0xcc, 0x83, 0x3e, 0x0b, 0x49, 0x03, 0xf0,
            0x13, 0x8a, 0x9d, 0x81, 0x5f, 0xdb, 0xa4, 0x45, 0x9b, 0x73, 0x28, 0x20, 0x95, 0x66, 0x94, 0x3b,
            0x09, 0xe3, 0x6f, 0x57, 0x44, 0x5c, 0x36, 0x02, 0xe0, 0x01, 0x11, 0x72, 0x90, 0xd8, 0x84, 0x10,
            0x87, 0xec, 0x1f, 0x88, 0x05, 0x5a, 0x65, 0x89, 0x51, 0x92, 0x1c, 0x75, 0xca, 0x1d, 0x04, 0x2f,
            0x2a, 0x50, 0x86, 0x9a, 0x1b, 0x7b, 0x46, 0x47, 0x98, 0xa3, 0x6d, 0x23, 0x0f, 0x5e, 0x7e, 0xc1
        ]

        # 系统参数FK
        self.FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

        # 固定参数CK
        self.CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        ]

        # 生成轮密钥
        self.round_keys = self._generate_round_keys()

    def _rotate_left(self, x, n):
        """循环左移n位"""
        return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)

    def _sbox(self, x):
        """S盒置换"""
        return self.Sbox[x]

    def _t_function(self, x):
        """T函数：非线性变换和线性变换的组合"""
        # 非线性变换：字节替换
        x0 = (x >> 24) & 0xFF
        x1 = (x >> 16) & 0xFF
        x2 = (x >> 8) & 0xFF
        x3 = x & 0xFF

        x0 = self._sbox(x0)
        x1 = self._sbox(x1)
        x2 = self._sbox(x2)
        x3 = self._sbox(x3)

        x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3

        # 线性变换L
        return x ^ self._rotate_left(x, 2) ^ self._rotate_left(x, 10) ^ self._rotate_left(x, 18) ^ self._rotate_left(x,
                                                                                                                     24)

    def _generate_round_keys(self):
        """生成32轮轮密钥"""
        # 将密钥转换为4个32位字
        K = []
        for i in range(4):
            K.append((self.key[4 * i] << 24) | (self.key[4 * i + 1] << 16) |
                     (self.key[4 * i + 2] << 8) | self.key[4 * i + 3])

        # 与系统参数FK异或
        K[0] ^= self.FK[0]
        K[1] ^= self.FK[1]
        K[2] ^= self.FK[2]
        K[3] ^= self.FK[3]

        # 生成32轮密钥
        round_keys = []
        for i in range(32):
            # 计算轮密钥
            rk = K[0] ^ self._t_function(K[1] ^ K[2] ^ K[3] ^ self.CK[i])
            round_keys.append(rk)

            # 更新寄存器
            K[0], K[1], K[2], K[3] = K[1], K[2], K[3], rk

        return round_keys

    def encrypt_block(self, plaintext):
        """加密一个16字节的数据块"""
        if len(plaintext) != 16:
            raise ValueError("SM4加密的数据块必须是16字节")

        # 将明文转换为4个32位字
        X = []
        for i in range(4):
            X.append((plaintext[4 * i] << 24) | (plaintext[4 * i + 1] << 16) |
                     (plaintext[4 * i + 2] << 8) | plaintext[4 * i + 3])

        # 32轮迭代
        for i in range(32):
            X[0], X[1], X[2], X[3] = X[1], X[2], X[3], X[0] ^ self._t_function(X[1] ^ X[2] ^ X[3] ^ self.round_keys[i])

        # 反序变换
        ciphertext = (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]

        # 转换为字节数组
        return bytes([
            (ciphertext >> 120) & 0xFF, (ciphertext >> 112) & 0xFF,
            (ciphertext >> 104) & 0xFF, (ciphertext >> 96) & 0xFF,
            (ciphertext >> 88) & 0xFF, (ciphertext >> 80) & 0xFF,
            (ciphertext >> 72) & 0xFF, (ciphertext >> 64) & 0xFF,
            (ciphertext >> 56) & 0xFF, (ciphertext >> 48) & 0xFF,
            (ciphertext >> 40) & 0xFF, (ciphertext >> 32) & 0xFF,
            (ciphertext >> 24) & 0xFF, (ciphertext >> 16) & 0xFF,
            (ciphertext >> 8) & 0xFF, ciphertext & 0xFF
        ])

    def decrypt_block(self, ciphertext):
        """解密一个16字节的数据块"""
        if len(ciphertext) != 16:
            raise ValueError("SM4解密的数据块必须是16字节")

        # 将密文转换为4个32位字
        X = []
        for i in range(4):
            X.append((ciphertext[4 * i] << 24) | (ciphertext[4 * i + 1] << 16) |
                     (ciphertext[4 * i + 2] << 8) | ciphertext[4 * i + 3])

        # 32轮迭代，使用逆序的轮密钥
        for i in range(32):
            X[0], X[1], X[2], X[3] = X[1], X[2], X[3], X[0] ^ self._t_function(
                X[1] ^ X[2] ^ X[3] ^ self.round_keys[31 - i])

        # 反序变换
        plaintext = (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]

        # 转换为字节数组
        return bytes([
            (plaintext >> 120) & 0xFF, (plaintext >> 112) & 0xFF,
            (plaintext >> 104) & 0xFF, (plaintext >> 96) & 0xFF,
            (plaintext >> 88) & 0xFF, (plaintext >> 80) & 0xFF,
            (plaintext >> 72) & 0xFF, (plaintext >> 64) & 0xFF,
            (plaintext >> 56) & 0xFF, (plaintext >> 48) & 0xFF,
            (plaintext >> 40) & 0xFF, (plaintext >> 32) & 0xFF,
            (plaintext >> 24) & 0xFF, (plaintext >> 16) & 0xFF,
            (plaintext >> 8) & 0xFF, plaintext & 0xFF
        ])
