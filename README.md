
# SM4加密算法及其GCM模式的实现与优化

本项目实现了SM4分组密码算法及其GCM工作模式，并进行了多种优化以提高执行效率。

## 项目介绍

SM4是中国国家密码管理局发布的分组密码算法，用于无线局域网等领域。本项目包括：

1. SM4算法的基本实现
2. 基于T-table的优化实现
3. 基于SM4的GCM工作模式实现
4. 完整的测试代码和使用示例

## 算法说明

SM4是一种32轮迭代的Feistel结构，密钥长度和分组长度均为128位。其加密和解密过程类似，只是轮密钥的使用顺序相反。

GCM（Galois/Counter Mode）是一种认证加密模式，结合了计数器模式（CTR）的加密和Galois模式的认证，可以同时提供机密性和完整性。

## 优化说明

本项目主要采用了以下优化方法：

1. **T-table优化**：预计算T变换的结果，将复杂的非线性变换和线性变换转换为查表操作，显著提高加密速度。
2. **向量化操作**（可选）：使用NumPy库进行向量化计算，进一步提高处理效率（需要安装NumPy）。

## 安装与使用

### 环境要求

- Python 3.6+
- 可选：NumPy（用于向量化优化）

### 安装依赖
pip install -r requirements.txt
### 运行测试
python -m src.test
### 运行示例
python examples/example.py
## 代码结构

- `src/sm4_basic.py`: SM4算法的基本实现
- `src/sm4_optimized.py`: 优化的SM4实现（T-table和向量化）
- `src/sm4_gcm.py`: SM4-GCM工作模式的实现
- `src/test.py`: 测试代码
- `examples/example.py`: 使用示例
- `docs/`: 算法说明文档
