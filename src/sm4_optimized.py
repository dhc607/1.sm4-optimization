# 优化的SM4实现（T-table优化）
from sm4_basic import SM4 as SM4Basic


class SM4Optimized(SM4Basic):
    def __init__(self, key):
        """初始化优化的SM4加密器/解密器，使用T-table优化

        Args:
            key: 16字节的密钥
        """
        super().__init__(key)

        # 预计算T-table以加速加密过程
        self._precompute_tables()

    def _precompute_tables(self):
        """预计算T变换的查找表，加速加密过程"""
        # T-table是4个256项的表，对应四个字节位置
        self.T_table = [[0] * 256 for _ in range(4)]

        for i in range(256):
            # 计算每个字节经过S盒和线性变换后的结果
            s = self._sbox(i)

            # 对于每个位置，计算完整的T变换结果
            # 位置0: 字节在最高位(24-31位)
            val0 = (s << 24)
            val0 ^= self._rotate_left(val0, 2) ^ self._rotate_left(val0, 10) ^ self._rotate_left(val0,
                                                                                                 18) ^ self._rotate_left(
                val0, 24)
            self.T_table[0][i] = val0

            # 位置1: 字节在次高位(16-23位)
            val1 = (s << 16)
            val1 ^= self._rotate_left(val1, 2) ^ self._rotate_left(val1, 10) ^ self._rotate_left(val1,
                                                                                                 18) ^ self._rotate_left(
                val1, 24)
            self.T_table[1][i] = val1

            # 位置2: 字节在次低位(8-15位)
            val2 = (s << 8)
            val2 ^= self._rotate_left(val2, 2) ^ self._rotate_left(val2, 10) ^ self._rotate_left(val2,
                                                                                                 18) ^ self._rotate_left(
                val2, 24)
            self.T_table[2][i] = val2

            # 位置3: 字节在最低位(0-7位)
            val3 = s
            val3 ^= self._rotate_left(val3, 2) ^ self._rotate_left(val3, 10) ^ self._rotate_left(val3,
                                                                                                 18) ^ self._rotate_left(
                val3, 24)
            self.T_table[3][i] = val3

    def _t_function(self, x):
        """优化的T函数：使用预计算的T-table加速计算"""
        x0 = (x >> 24) & 0xFF
        x1 = (x >> 16) & 0xFF
        x2 = (x >> 8) & 0xFF
        x3 = x & 0xFF

        # 通过查找表获取结果并异或
        return self.T_table[0][x0] ^ self.T_table[1][x1] ^ self.T_table[2][x2] ^ self.T_table[3][x3]


# 尝试使用NumPy进行向量化优化（需要安装numpy）
try:
    import numpy as np


    class SM4Vectorized(SM4Optimized):
        def __init__(self, key):
            """使用NumPy向量化操作的SM4实现"""
            super().__init__(key)

            # 将T_table转换为numpy数组以加速计算
            self.T_table_np = np.array(self.T_table, dtype=np.uint32)
            self.round_keys_np = np.array(self.round_keys, dtype=np.uint32)

        def encrypt_block(self, plaintext):
            """使用向量化操作加密一个16字节的数据块"""
            if len(plaintext) != 16:
                raise ValueError("SM4加密的数据块必须是16字节")

            # 将明文转换为4个32位字的numpy数组
            X = np.zeros(4, dtype=np.uint32)
            for i in range(4):
                X[i] = (plaintext[4 * i] << 24) | (plaintext[4 * i + 1] << 16) | \
                       (plaintext[4 * i + 2] << 8) | plaintext[4 * i + 3]

            # 32轮迭代，使用向量化操作
            for i in range(32):
                # 提取各个字节
                x = X[1] ^ X[2] ^ X[3] ^ self.round_keys_np[i]
                x0 = (x >> 24) & 0xFF
                x1 = (x >> 16) & 0xFF
                x2 = (x >> 8) & 0xFF
                x3 = x & 0xFF

                # 使用预计算的T-table
                t_val = self.T_table_np[0, x0] ^ self.T_table_np[1, x1] ^ \
                        self.T_table_np[2, x2] ^ self.T_table_np[3, x3]

                # 更新寄存器
                X = np.roll(X, -1)
                X[3] = X[0] ^ t_val

            # 反序变换并转换为字节数组
            ciphertext = (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]

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

except ImportError:
    # 如果没有安装numpy，则不定义向量化版本
    pass
