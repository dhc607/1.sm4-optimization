# SM4-GCM工作模式实现
import os
from .sm4_optimized import SM4Optimized


class SM4GCM:
    def __init__(self, key, nonce=None, tag_length=16):
        """初始化SM4-GCM加密器/解密器

        Args:
            key: 16字节的密钥
            nonce: 可选的随机数，如不提供将自动生成
            tag_length: 认证标签的长度，默认16字节
        """
        self.sm4 = SM4Optimized(key)
        self.tag_length = tag_length

        # 生成或使用提供的nonce
        if nonce is None:
            self.nonce = os.urandom(12)  # GCM推荐使用12字节nonce
        else:
            self.nonce = nonce

        # 生成初始计数器
        self.initial_counter = self._generate_initial_counter()

        # 生成哈希密钥H
        self.H = self.sm4.encrypt_block(b'\x00' * 16)

    def _generate_initial_counter(self):
        """生成初始计数器值"""
        if len(self.nonce) == 12:
            # 对于12字节nonce，按照GCM推荐方式生成初始计数器
            return self.nonce + b'\x00\x00\x00\x01'
        else:
            # 对于其他长度nonce，使用GHASH生成初始计数器
            return self._ghash(self.nonce, b'', self.H)

    def _increment_counter(self, counter):
        """递增计数器"""
        # 将计数器视为大端格式的32位整数并递增
        counter_int = int.from_bytes(counter[12:16], byteorder='big')
        counter_int += 1
        return counter[:12] + counter_int.to_bytes(4, byteorder='big')

    def _ghash(self, auth_data, ciphertext, H):
        """伽罗瓦哈希函数，用于计算认证标签"""
        # 将数据分块为16字节的块
        blocks = []

        # 处理认证数据
        for i in range(0, len(auth_data), 16):
            block = auth_data[i:i + 16]
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            blocks.append(int.from_bytes(block, byteorder='big'))

        # 处理密文
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            blocks.append(int.from_bytes(block, byteorder='big'))

        # 添加长度块：(len(auth_data) * 8) || (len(ciphertext) * 8)
        len_auth = len(auth_data) * 8
        len_cipher = len(ciphertext) * 8
        len_block = (len_auth << 64) | len_cipher
        blocks.append(len_block)

        # 计算GHASH
        y = 0
        h = int.from_bytes(H, byteorder='big')

        for block in blocks:
            y ^= block
            y = self._galois_multiply(y, h)

        return y.to_bytes(16, byteorder='big')

    def _galois_multiply(self, x, h):
        """伽罗瓦域GF(2^128)上的乘法"""
        p = 0x87 | (1 << 128)  # 不可约多项式 x^128 + x^7 + x^2 + x + 1
        y = 0

        for i in range(127, -1, -1):
            y <<= 1

            if (x >> i) & 1:
                y ^= h

            if y >> 128:
                y ^= p

        return y

    def encrypt(self, plaintext, auth_data=b''):
        """加密并生成认证标签

        Args:
            plaintext: 要加密的明文
            auth_data: 要认证的数据（不加密）

        Returns:
            密文和认证标签的元组 (ciphertext, tag)
        """
        # 使用CTR模式加密
        ciphertext = b''
        counter = self.initial_counter

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]

            # 加密计数器值
            keystream = self.sm4.encrypt_block(counter)

            # 与明文异或得到密文
            encrypted_block = bytes([b ^ k for b, k in zip(block, keystream)])
            ciphertext += encrypted_block

            # 递增计数器
            counter = self._increment_counter(counter)

        # 计算认证标签
        tag = self._ghash(auth_data, ciphertext, self.H)

        # 使用初始计数器加密标签
        tag_encrypted = self.sm4.encrypt_block(self.initial_counter)
        tag = bytes([t ^ te for t, te in zip(tag, tag_encrypted)])

        # 返回指定长度的标签
        return ciphertext, tag[:self.tag_length]

    def decrypt(self, ciphertext, tag, auth_data=b''):
        """解密并验证认证标签

        Args:
            ciphertext: 要解密的密文
            tag: 认证标签
            auth_data: 已认证的数据

        Returns:
            解密后的明文

        Raises:
            ValueError: 如果认证失败
        """
        # 验证标签长度
        if len(tag) != self.tag_length:
            raise ValueError(f"标签长度必须为{self.tag_length}字节")

        # 使用初始计数器解密标签
        tag_encrypted = self.sm4.encrypt_block(self.initial_counter)
        tag_decrypted = bytes([t ^ te for t, te in zip(tag, tag_encrypted)])

        # 如果标签长度不足16字节，补全
        if len(tag_decrypted) < 16:
            tag_decrypted += b'\x00' * (16 - len(tag_decrypted))

        # 计算GHASH值进行验证
        computed_tag = self._ghash(auth_data, ciphertext, self.H)

        # 验证标签
        if not self._constant_time_compare(tag_decrypted, computed_tag):
            raise ValueError("认证失败：标签不匹配")

        # 使用CTR模式解密
        plaintext = b''
        counter = self.initial_counter

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]

            # 加密计数器值
            keystream = self.sm4.encrypt_block(counter)

            # 与密文异或得到明文
            decrypted_block = bytes([b ^ k for b, k in zip(block, keystream)])
            plaintext += decrypted_block

            # 递增计数器
            counter = self._increment_counter(counter)

        return plaintext

    def _constant_time_compare(self, a, b):
        """恒定时间比较，防止时序攻击"""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0
