import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

/**
 * 幸福路支行加密交易入库测试(控制台版,JDK17,H2数据库)。
 * 功能:
 * 1. 创建数据库/表:xx_branch_trans.xx_customer_trans
 * 2. 生成 10 笔交易,对敏感字段做 AES/CBC/PKCS5Padding 加密,Base64 存储 enc_ 字段
 * 3. 对每笔交易计算 SHA-256 哈希,并用占位签名存到 server_sign
 * 4. 查询最近记录,并估算"日均500笔、3年"的存储量
 * 
 * 运行前准备: 将 h2-*.jar 添加到 classpath
 * 
 * ⚠️ 注意: 此文件包含模拟的 Git 合并冲突标记
 * 在解决冲突之前，此文件无法编译
 * 请参考 MERGE_CONFLICT_GUIDE.md 了解如何解决冲突
 */
public class BranchEncryptConsoleAppH2 {
    // ========== 配置区:根据实际环境修改 ==========
    private static final String DB_URL = "jdbc:h2:./xx_branch_trans;AUTO_SERVER=TRUE";
    private static final String DB_USER = "sa";
    private static final String DB_PASS = "";

    // <<<<<<< HEAD
    private static final String AES_KEY_TEXT = "1234567890abcdef"; // 16/24/32 字节
    private static final String AES_IV_TEXT = "abcdef1234567890";  // 16 字节
    // =======
    // 来自 feature/security-hardening 分支：使用更安全的默认密钥
    private static final String AES_KEY_TEXT = System.getProperty("aes.key", "defaultSecureKey123456789012345678901234"); // 32 字节默认密钥
    private static final String AES_IV_TEXT = System.getProperty("aes.iv", "secureIV12345678");  // 16 字节
    // >>>>>>> feature/security-hardening

    public static void main(String[] args) {
        System.out.println("=== 幸福路支行加密交易入库测试（H2数据库版，JDK17） ===");
        Connection conn = null;
        try {
            // 测试连接
            conn = openConnection();
            System.out.println("H2 数据库连接成功");

            // 创建表
            createTable();
            System.out.println("数据表已准备完毕");

            // 插入 10 笔加密交易
            insertEncryptedTransactions();
            System.out.println("10 笔加密交易插入完成");

            // 查询前 20 条记录
            queryTopRecords();

            // 估算 3 年存储
            estimateStorage3Years();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            closeQuietly(conn);
        }
    }

    private static Connection openConnection() throws SQLException, ClassNotFoundException {
        Class.forName("org.h2.Driver");
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }

    private static void createTable() throws Exception {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            String ddl = "CREATE TABLE IF NOT EXISTS xx_customer_trans ("
                    + "id BIGINT PRIMARY KEY AUTO_INCREMENT,"
                    + "customer_name VARCHAR(64),"
                    + "enc_idcard TEXT,"
                    + "enc_from_card TEXT,"
                    + "enc_to_card TEXT,"
                    + "enc_phone TEXT,"
                    + "enc_amount TEXT,"
                    + "hash_value VARCHAR(128),"
                    + "server_sign TEXT,"
                    + "create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    + ")";
            stmt.executeUpdate(ddl);
        } finally {
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private static void insertEncryptedTransactions() throws Exception {
        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = openConnection();
            String sql = "INSERT INTO xx_customer_trans "
                    + "(customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign) "
                    + "VALUES (?,?,?,?,?,?,?,?)";
            ps = conn.prepareStatement(sql);

            List<TransactionData> samples = sampleTransactions();
            SecretKeySpec key = buildKey(AES_KEY_TEXT);
            IvParameterSpec iv = buildIv(AES_IV_TEXT);

            int totalBytes = 0;

            for (TransactionData t : samples) {
                String encId = encryptToBase64(t.idCard, key, iv);
                String encFrom = encryptToBase64(t.fromCard, key, iv);
                String encTo = encryptToBase64(t.toCard, key, iv);
                String encPhone = encryptToBase64(t.phone, key, iv);
                String encAmount = encryptToBase64(t.amount, key, iv);

                String hash = sha256Hex(t.concatenated());
                String sign = sha256Hex(hash + "|server-sim"); // placeholder sign

                ps.setString(1, t.name);
                ps.setString(2, encId);
                ps.setString(3, encFrom);
                ps.setString(4, encTo);
                ps.setString(5, encPhone);
                ps.setString(6, encAmount);
                ps.setString(7, hash);
                ps.setString(8, sign);
                ps.addBatch();

                totalBytes += utf8Size(encId) + utf8Size(encFrom) + utf8Size(encTo)
                        + utf8Size(encPhone) + utf8Size(encAmount)
                        + utf8Size(hash) + utf8Size(sign);
            }

            ps.executeBatch();

            System.out.println("已插入 " + samples.size() + " 笔交易，加密字段均为 Base64 密文。");
            System.out.println("本次插入大致存储字节: " + totalBytes + "B (~" + (totalBytes / 1024.0) + "KB)");
        } finally {
            closeQuietly(ps);
            closeQuietly(conn);
        }
    }

    private static void queryTopRecords() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            String sql = "SELECT id, customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign, create_time "
                    + "FROM xx_customer_trans ORDER BY id DESC LIMIT 20";
            rs = stmt.executeQuery(sql);
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            System.out.println("=== 最近 20 条加密交易（只展示部分字段） ===");
            while (rs.next()) {
                System.out.println(
                        "id=" + rs.getLong("id")
                                + ", name=" + rs.getString("customer_name")
                                + ", enc_amount=" + trimForLog(rs.getString("enc_amount"))
                                + ", hash=" + trimForLog(rs.getString("hash_value"))
                                + ", time=" + fmt.format(rs.getTimestamp("create_time"))
                );
            }
        } catch (Exception e) {
            System.err.println("查询失败: " + e.getMessage());
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private static void estimateStorage3Years() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign "
                    + "FROM xx_customer_trans LIMIT 200");

            int rows = 0;
            int bytes = 0;
            while (rs.next()) {
                bytes += utf8Size(rs.getString(1))
                        + utf8Size(rs.getString(2))
                        + utf8Size(rs.getString(3))
                        + utf8Size(rs.getString(4))
                        + utf8Size(rs.getString(5))
                        + utf8Size(rs.getString(6))
                        + utf8Size(rs.getString(7));
                rows++;
            }

            if (rows == 0) {
                System.out.println("估算失败：表中没有数据，请先插入样例。");
                return;
            }

            double avgPerRow = bytes / (double) rows;
            double perDay = avgPerRow * 500; // 日均 500 笔
            double threeYears = perDay * 365 * 3;

            System.out.println("=== 存储估算（基于样本数据） ===");
            System.out.println(String.format("平均单条大小约 %.2f 字节", avgPerRow));
            System.out.println(String.format("500 笔/日 -> %.2f KB/日", perDay / 1024));
            System.out.println(String.format("3 年总量 -> %.2f MB（远小于 30GB）", threeYears / (1024 * 1024)));
        } catch (Exception e) {
            System.err.println("估算失败: " + e.getMessage());
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    // ===== 加密 / 工具方法 =====

    private static SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(StandardCharsets.UTF_8);
        // ========== 合并冲突开始 ==========
        // <<<<<<< HEAD (当前分支)
        // 自动调整 Key 长度：如果不符合 16/24/32，则截取或填充
        if (bytes.length < 16) {
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            System.out.println("提示: AES Key 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16 && bytes.length < 24) {
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度在 16-24 之间，已自动截取到 16 字节");
        } else if (bytes.length > 24 && bytes.length < 32) {
            byte[] trimmed = new byte[24];
            System.arraycopy(bytes, 0, trimmed, 0, 24);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度在 24-32 之间，已自动截取到 24 字节");
        } else if (bytes.length > 32) {
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 0, trimmed, 0, 32);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度超过 32 字节，已自动截取到 32 字节");
        }
        // =======
        // 严格验证 Key 长度，不符合要求则抛出异常（来自 feature/strict-validation 分支）
        if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
            throw new IllegalArgumentException(
                String.format("AES Key 必须为 16/24/32 字节，当前为 %d 字节", bytes.length)
            );
        }
        // >>>>>>> feature/strict-validation (合并的分支)
        // ========== 合并冲突结束 ==========
        return new SecretKeySpec(bytes, "AES");
    }

    private static IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(StandardCharsets.UTF_8);
        // 自动调整 IV 长度：必须是 16 字节
        if (bytes.length < 16) {
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            System.out.println("提示: AES IV 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16) {
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            System.out.println("提示: AES IV 长度超过 16 字节，已自动截取前 16 字节");
        }
        return new IvParameterSpec(bytes);
    }

    private static String encryptToBase64(String plain, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] out = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(out);
    }

    private static String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest).toLowerCase();
    }

    // 字节数组转十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private static int utf8Size(String text) {
        if (text == null) return 0;
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static String trimForLog(String value) {
        if (value == null) return "";
        if (value.length() > 40) {
            return value.substring(0, 40) + "...";
        }
        return value;
    }

    private static void closeQuietly(Connection c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void closeQuietly(Statement s) {
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void closeQuietly(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Exception ignored) {
            }
        }
    }

    // ===== 样例交易数据结构与生成 =====

    private static class TransactionData {
        String name;
        String idCard;
        String fromCard;
        String toCard;
        String phone;
        String amount;

        String concatenated() {
            return name + "|" + idCard + "|" + fromCard + "|" + toCard + "|" + phone + "|" + amount;
        }
    }

    private static List<TransactionData> sampleTransactions() {
        List<TransactionData> list = new ArrayList<TransactionData>();
        Random r = new Random();
        for (int i = 0; i < 10; i++) {
            TransactionData t = new TransactionData();
            t.name = "客户" + (i + 1);
            t.idCard = "4101" + (1000000000000L + r.nextInt(9999999));
            t.fromCard = "6222" + (1000000000000L + r.nextInt(9999999));
            t.toCard = "6217" + (1000000000000L + r.nextInt(9999999));
            t.phone = "138" + (10000000 + r.nextInt(8999999));
            t.amount = String.format("%.2f", 100 + r.nextInt(900) + r.nextDouble());
            list.add(t);
        }
        return list;
    }
}

