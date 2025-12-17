/**
 * Git 合并冲突示例文件
 * 此文件展示了典型的 Git 合并冲突标记和场景
 * 
 * ⚠️ 注意: 此文件包含模拟的 Git 合并冲突标记
 * 在解决冲突之前，此文件无法编译
 * 这些语法错误是预期的，用于演示合并冲突的场景
 * 
 * 请参考 MERGE_CONFLICT_GUIDE.md 了解如何解决冲突
 */
public class MergeConflictExample {
    
    // ========== 场景1: 方法实现冲突 ==========
    public String processData(String input) {
        // <<<<<<< HEAD (当前分支 - main)
        // 当前分支的实现：简单处理
        return input.trim().toLowerCase();
        // =======
        // 合并分支的实现：复杂处理（来自 feature/advanced-processing）
        if (input == null || input.isEmpty()) {
            return "";
        }
        return input.trim().toUpperCase().replaceAll("\\s+", "_");
        // >>>>>>> feature/advanced-processing
    }
    
    // ========== 场景2: 配置常量冲突 ==========
    // <<<<<<< HEAD
    private static final int MAX_RETRY_COUNT = 3;
    private static final int TIMEOUT_SECONDS = 30;
    // =======
    private static final int MAX_RETRY_COUNT = 5;
    private static final int TIMEOUT_SECONDS = 60;
    private static final boolean ENABLE_LOGGING = true;
    // >>>>>>> feature/config-update
    
    // ========== 场景3: 导入语句冲突 ==========
    // <<<<<<< HEAD
    import java.util.ArrayList;
    import java.util.List;
    // =======
    import java.util.*;
    import java.util.stream.Collectors;
    // >>>>>>> feature/java8-upgrade
    
    // ========== 场景4: 类字段冲突 ==========
    public class DataProcessor {
        // <<<<<<< HEAD
        private String name;
        private int age;
        // =======
        private String name;
        private int age;
        private String email;
        private String phone;
        // >>>>>>> feature/add-contact-info
    }
    
    // ========== 场景5: 方法参数冲突 ==========
    // <<<<<<< HEAD
    public void saveData(String data, boolean encrypt) {
        // 保存数据，可选加密
    }
    // =======
    public void saveData(String data, String format, int compressionLevel) {
        // 保存数据，支持格式和压缩级别
    }
    // >>>>>>> feature/enhanced-save
    
    // ========== 场景6: 注释冲突 ==========
    /**
     * <<<<<<< HEAD
     * 计算两个数的和
     * @param a 第一个数
     * @param b 第二个数
     * @return 两数之和
     * =======
     * 计算多个数的和（支持可变参数）
     * @param numbers 要相加的数字
     * @return 所有数字之和
     * >>>>>>> feature/variadic-sum
     */
    public int sum(int... numbers) {
        // 实现代码
        return 0;
    }
    
    // ========== 如何解决合并冲突 ==========
    /*
     * 解决步骤：
     * 1. 打开冲突文件，找到 <<<<<<< HEAD 和 >>>>>>> 标记
     * 2. 查看两个版本的差异
     * 3. 选择保留哪个版本，或合并两个版本
     * 4. 删除所有冲突标记（<<<<<<<, =======, >>>>>>>）
     * 5. 保存文件
     * 6. 使用 git add 标记冲突已解决
     * 7. 继续合并：git commit
     * 
     * IDE 工具（如 IntelliJ IDEA）通常提供可视化界面：
     * - 点击 "Accept Yours" 保留当前分支
     * - 点击 "Accept Theirs" 保留合并分支
     * - 点击 "Merge" 手动合并
     */
}

