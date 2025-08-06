# SM4及SM4-GCM测试代码
import time
import os
import unittest
from sm4_basic import SM4 as SM4Basic
from sm4_optimized import SM4Optimized

try:
    from sm4_optimized import SM4Vectorized

    has_vectorized = True
except ImportError:
    has_vectorized = False
from sm4_gcm import SM4GCM

# 测试向量来自GB/T 32907-2016
TEST_VECTORS = [
    {
        "key": bytes.fromhex("0123456789abcdeffedcba9876543210"),
        "plaintext": bytes.fromhex("0123456789abcdeffedcba9876543210"),
        "ciphertext": bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    },
    {
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "plaintext": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "ciphertext": bytes.fromhex("595298c7c6fd271f0a8c988149b7ef63")
    }
]


class TestSM4(unittest.TestCase):
    """测试SM4加密算法"""

    def test_basic_encrypt_decrypt(self):
        """测试基本的加密解密功能"""
        for vector in TEST_VECTORS:
            sm4 = SM4Basic(vector["key"])

            # 测试加密
            ciphertext = sm4.encrypt_block(vector["plaintext"])
            self.assertEqual(ciphertext, vector["ciphertext"],
                             f"加密失败，向量: {vector}")

            # 测试解密
            plaintext = sm4.decrypt_block(vector["ciphertext"])
            self.assertEqual(plaintext, vector["plaintext"],
                             f"解密失败，向量: {vector}")

    def test_optimized_encrypt_decrypt(self):
        """测试优化版本的加密解密功能"""
        for vector in TEST_VECTORS:
            sm4 = SM4Optimized(vector["key"])

            # 测试加密
            ciphertext = sm4.encrypt_block(vector["plaintext"])
            self.assertEqual(ciphertext, vector["ciphertext"],
                             f"优化版加密失败，向量: {vector}")

            # 测试解密
            plaintext = sm4.decrypt_block(vector["ciphertext"])
            self.assertEqual(plaintext, vector["plaintext"],
                             f"优化版解密失败，向量: {vector}")

    @unittest.skipUnless(has_vectorized, "NumPy not installed")
    def test_vectorized_encrypt(self):
        """测试向量化版本的加密功能"""
        for vector in TEST_VECTORS:
            sm4 = SM4Vectorized(vector["key"])

            # 测试加密
            ciphertext = sm4.encrypt_block(vector["plaintext"])
            self.assertEqual(ciphertext, vector["ciphertext"],
                             f"向量化版加密失败，向量: {vector}")

    def test_performance(self):
        """测试不同版本的性能"""
        key = os.urandom(16)
        plaintext = os.urandom(16)

        # 测试基本版本
        sm4_basic = SM4Basic(key)
        start_time = time.time()
        for _ in range(10000):
            sm4_basic.encrypt_block(plaintext)
        basic_time = time.time() - start_time

        # 测试优化版本
        sm4_opt = SM4Optimized(key)
        start_time = time.time()
        for _ in range(10000):
            sm4_opt.encrypt_block(plaintext)
        opt_time = time.time() - start_time

        print(f"\n性能测试结果:")
        print(f"基本版本: {basic_time:.4f}秒")
        print(f"优化版本: {opt_time:.4f}秒")
        print(f"优化版本速度提升: {basic_time / opt_time:.2f}x")

        # 确保优化版本确实更快
        self.assertLess(opt_time, basic_time)

        # 测试向量化版本（如果可用）
        if has_vectorized:
            sm4_vec = SM4Vectorized(key)
            start_time = time.time()
            for _ in range(10000):
                sm4_vec.encrypt_block(plaintext)
            vec_time = time.time() - start_time

            print(f"向量化版本: {vec_time:.4f}秒")
            print(f"向量化版本速度提升: {basic_time / vec_time:.2f}x")
            self.assertLess(vec_time, opt_time)


class TestSM4GCM(unittest.TestCase):
    """测试SM4-GCM工作模式"""

    def test_gcm_encrypt_decrypt(self):
        """测试GCM模式的加密解密功能"""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"这是一个测试消息，用于测试SM4-GCM模式的加密和解密功能。"
        auth_data = b"这是需要认证但不需要加密的数据"

        # 创建GCM实例
        gcm = SM4GCM(key, nonce)

        # 加密
        ciphertext, tag = gcm.encrypt(plaintext, auth_data)

        # 解密
        gcm_decrypt = SM4GCM(key, nonce)
        decrypted_text = gcm_decrypt.decrypt(ciphertext, tag, auth_data)

        # 验证解密结果
        self.assertEqual(decrypted_text, plaintext)

    def test_gcm_authentication(self):
        """测试GCM模式的认证功能"""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"测试认证功能的消息"
        auth_data = b"需要认证的数据"

        # 加密
        gcm = SM4GCM(key, nonce)
        ciphertext, tag = gcm.encrypt(plaintext, auth_data)

        # 测试篡改密文
        if len(ciphertext) > 0:
            # 篡改一个字节
            ciphertext_tampered = bytearray(ciphertext)
            ciphertext_tampered[0] ^= 0x01
            ciphertext_tampered = bytes(ciphertext_tampered)

            # 尝试解密篡改后的密文，应该失败
            gcm_decrypt = SM4GCM(key, nonce)
            with self.assertRaises(ValueError):
                gcm_decrypt.decrypt(ciphertext_tampered, tag, auth_data)

        # 测试篡改认证数据
        auth_data_tampered = auth_data + b"额外数据"
        gcm_decrypt = SM4GCM(key, nonce)
        with self.assertRaises(ValueError):
            gcm_decrypt.decrypt(ciphertext, tag, auth_data_tampered)

        # 测试篡改标签
        if len(tag) > 0:
            tag_tampered = bytearray(tag)
            tag_tampered[0] ^= 0x01
            tag_tampered = bytes(tag_tampered)

            gcm_decrypt = SM4GCM(key, nonce)
            with self.assertRaises(ValueError):
                gcm_decrypt.decrypt(ciphertext, tag_tampered, auth_data)


if __name__ == "__main__":
    unittest.main()
