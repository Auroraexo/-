# Git 合并冲突解决指南

## 什么是合并冲突？

当两个分支修改了同一文件的同一部分时，Git 无法自动决定保留哪个版本，就会产生合并冲突。

## 冲突标记说明

Git 使用以下标记标识冲突区域：

```
<<<<<<< HEAD
当前分支（你正在合并到的分支）的代码
=======
要合并进来的分支的代码
>>>>>>> branch-name
```

## 当前项目中的冲突示例

### 1. `BranchEncryptConsoleAppH2.java` 中的冲突

#### 冲突1: `buildKey` 方法实现冲突

**位置**: 第 223-248 行

**冲突内容**:
- **HEAD (当前分支)**: 自动调整 Key 长度，支持填充和截取
- **feature/strict-validation**: 严格验证，不符合要求则抛出异常

**解决方案选择**:
- **保留自动调整版本**: 更用户友好，适合演示环境
- **保留严格验证版本**: 更安全，适合生产环境
- **合并两者**: 先验证，不符合则自动调整（推荐）

#### 冲突2: 配置常量冲突

**位置**: 第 34-40 行

**冲突内容**:
- **HEAD**: 硬编码的简单密钥
- **feature/security-hardening**: 从系统属性读取密钥，更安全

**解决方案**: 
- 生产环境：使用系统属性版本
- 演示环境：保留硬编码版本，但添加注释说明

## 解决冲突的步骤

### 方法1: 使用 IDE（推荐）

1. **IntelliJ IDEA / VS Code**:
   - 打开冲突文件
   - IDE 会高亮显示冲突区域
   - 点击冲突区域，选择：
     - `Accept Yours` - 保留当前分支
     - `Accept Theirs` - 保留合并分支
     - `Merge` - 手动合并

2. **操作示例**:
   ```
   在 IntelliJ IDEA 中：
   - 打开 BranchEncryptConsoleAppH2.java
   - 找到红色标记的冲突区域
   - 右键点击冲突区域
   - 选择 "Resolve Conflict" -> "Accept Yours" 或 "Accept Theirs"
   ```

### 方法2: 手动编辑

1. **打开冲突文件**
   ```bash
   # 查看冲突文件列表
   git status
   ```

2. **编辑文件，删除冲突标记**
   - 找到 `<<<<<<< HEAD`
   - 找到 `=======`
   - 找到 `>>>>>>> branch-name`
   - 选择要保留的代码
   - 删除所有冲突标记和不需要的代码

3. **示例：解决 buildKey 方法冲突**

   **选项A: 保留自动调整版本**
   ```java
   private static SecretKeySpec buildKey(String keyText) {
       byte[] bytes = keyText.getBytes(StandardCharsets.UTF_8);
       // 自动调整 Key 长度：如果不符合 16/24/32，则截取或填充
       if (bytes.length < 16) {
           // ... 自动调整代码 ...
       }
       return new SecretKeySpec(bytes, "AES");
   }
   ```

   **选项B: 保留严格验证版本**
   ```java
   private static SecretKeySpec buildKey(String keyText) {
       byte[] bytes = keyText.getBytes(StandardCharsets.UTF_8);
       // 严格验证 Key 长度
       if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
           throw new IllegalArgumentException(
               String.format("AES Key 必须为 16/24/32 字节，当前为 %d 字节", bytes.length)
           );
       }
       return new SecretKeySpec(bytes, "AES");
   }
   ```

   **选项C: 合并两者（推荐）**
   ```java
   private static SecretKeySpec buildKey(String keyText) {
       byte[] bytes = keyText.getBytes(StandardCharsets.UTF_8);
       // 先验证，不符合则自动调整
       if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
           System.out.println("警告: AES Key 长度不符合要求，将自动调整");
           // 自动调整逻辑...
       }
       return new SecretKeySpec(bytes, "AES");
   }
   ```

4. **标记冲突已解决**
   ```bash
   git add BranchEncryptConsoleAppH2.java
   ```

5. **完成合并**
   ```bash
   git commit
   # 或如果使用默认合并消息
   git commit -m "解决合并冲突：保留自动调整 Key 长度的实现"
   ```

## 冲突解决最佳实践

1. **理解两个版本的差异**
   - 阅读冲突双方的代码
   - 理解各自的意图和优势

2. **选择最合适的方案**
   - 不要盲目选择"我的版本"或"他们的版本"
   - 考虑合并两者的优点

3. **测试解决后的代码**
   - 编译检查：`javac BranchEncryptConsoleAppH2.java`
   - 运行测试：确保功能正常

4. **添加注释说明**
   - 如果选择了某个特定版本，添加注释说明原因

## 预防冲突

1. **频繁合并主分支**
   ```bash
   git checkout main
   git pull
   git checkout your-branch
   git merge main
   ```

2. **小步提交**
   - 避免大文件的大幅修改
   - 将大改动拆分成多个小提交

3. **团队沟通**
   - 修改公共文件前先沟通
   - 使用 Pull Request 进行代码审查

## 当前项目的冲突解决建议

### 对于 `buildKey` 方法冲突：
**推荐方案**: 保留自动调整版本（当前 HEAD 版本）
- 理由：演示项目，用户友好更重要
- 如果用于生产，考虑添加配置开关

### 对于配置常量冲突：
**推荐方案**: 合并两者
```java
// 优先从系统属性读取，否则使用默认值
private static final String AES_KEY_TEXT = 
    System.getProperty("aes.key", "1234567890abcdef");
private static final String AES_IV_TEXT = 
    System.getProperty("aes.iv", "abcdef1234567890");
```

## 快速解决当前冲突的命令

```bash
# 1. 查看冲突文件
git status

# 2. 打开文件手动解决（或使用 IDE）

# 3. 解决后标记
git add BranchEncryptConsoleAppH2.java

# 4. 完成合并
git commit
```

## 需要帮助？

如果遇到复杂的冲突，可以：
1. 使用 `git mergetool` 打开可视化合并工具
2. 查看 `MergeConflictExample.java` 了解更多冲突场景
3. 参考 Git 官方文档：https://git-scm.com/docs/git-merge

