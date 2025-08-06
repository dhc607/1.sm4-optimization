# SM4和SM4-GCM使用示例

import os
from src.sm4_basic import SM4 as SM4Basic
from src.sm4_optimized import SM4Optimized
from src.sm4_gcm import SM4GCM

def example_sm4_basic():
    """SM4基本用法示例"""
    print("=== SM4基本用法示例 ===")

    # 生成16字节密钥
    key = os.urandom(16)
    print(f"密钥: {key.hex()}")

    # 明文（必须是16字节的倍数，这里使用16字节）
    plaintext = b"Hello, SM4! 123"
    print(f"明文: {plaintext.decode()}")

    # 创建SM4实例
    sm4 = SM4Basic(key)

    # 加密
    ciphertext = sm4.encrypt_block(plaintext)
    print(f"密文: {ciphertext.hex()}")

    # 解密
    decrypted = sm4.decrypt_block(ciphertext)
    print(f"解密后: {decrypted.decode()}")

    # 验证解密结果
    assert decrypted == plaintext, "解密失败"
    print("解密验证成功\n")


def example_sm4_optimized():
    """优化的SM4用法示例"""
    print("=== 优化的SM4用法示例 ===")

    # 生成16字节密钥
    key = os.urandom(16)
    print(f"密钥: {key.hex()}")

    # 明文
    plaintext = b"Optimized SM4!"
    print(f"明文: {plaintext.decode()}")

    # 创建优化的SM4实例
    sm4 = SM4(key)

    # 加密
    ciphertext = sm4.encrypt_block(plaintext)
    print(f"密文: {ciphertext.hex()}")

    # 解密
    decrypted = sm4.decrypt_block(ciphertext)
    print(f"解密后: {decrypted.decode()}")

    # 验证解密结果
    assert decrypted == plaintext, "解密失败"
    print("解密验证成功\n")


def example_sm4_gcm():
    """SM4-GCM用法示例"""
    print("=== SM4-GCM用法示例 ===")

    # 生成16字节密钥
    key = os.urandom(16)
    print(f"密钥: {key.hex()}")

    # 生成12字节nonce（GCM推荐）
    nonce = os.urandom(12)
    print(f"Nonce: {nonce.hex()}")

    # 明文（可以是任意长度）
    plaintext = b"这是一个较长的消息，用于测试SM4-GCM模式。GCM模式可以处理任意长度的消息，并且提供认证功能。"
    print(f"明文: {plaintext.decode()}")

    # 认证数据（不加密但会被认证）
    auth_data = b"这是一些需要认证但不需要加密的数据"
    print(f"认证数据: {auth_data.decode()}")

    # 创建GCM实例
    gcm = SM4(key, nonce)

    # 加密并生成标签
    ciphertext, tag = gcm.encrypt(plaintext, auth_data)
    print(f"密文: {ciphertext.hex()}")
    print(f"认证标签: {tag.hex()}")

    # 解密并验证
    gcm_decrypt = SM4(key, nonce)
    decrypted = gcm_decrypt.decrypt(ciphertext, tag, auth_data)
    print(f"解密后: {decrypted.decode()}")

    # 验证解密结果
    assert decrypted == plaintext, "解密失败"
    print("解密验证成功")

    # 测试认证失败的情况
    try:
        # 尝试使用错误的标签解密
        gcm_decrypt.decrypt(ciphertext, b"wrong_tag" + tag[9:], auth_data)
        print("错误：使用错误的标签解密竟然成功了！")
    except ValueError as e:
        print(f"认证失败测试成功: {str(e)}")


if __name__ == "__main__":
    example_sm4_basic()
    example_sm4_optimized()
    example_sm4_gcm()
