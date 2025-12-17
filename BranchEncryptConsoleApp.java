import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 幸福路支行加密交易入库测试（控制台版，JDK7）。
 * 功能：
 * 1. 创建数据库/表：xx_branch_trans.xx_customer_trans
 * 2. 生成 10 笔交易，对敏感字段做 AES/CBC/PKCS5Padding 加密，Base64 存储 enc_ 字段
 * 3. 对每笔交易计算 SHA-256 哈希，并用 RSA 私钥对哈希做 SHA256withRSA 签名，Base64 存到 server_sign
 * 4. 查询最近记录，并估算“日均 500 笔、3 年”的存储量
 *
 * 运行前准备：
 * - 引入 mysql-connector-java-5.1.x.jar
 * - 准备 RSA 私钥文件（PKCS#8，PEM，-----BEGIN PRIVATE KEY-----）
 */
public class BranchEncryptConsoleApp {

    // ========== 配置区：根据实际环境修改 ==========
    private static final String MYSQL_HOST = "127.0.0.1";
    private static final String MYSQL_PORT = "3306";
    private static final String MYSQL_USER = "root";
    private static final String MYSQL_PASS = ""; // TODO: 填你的密码

    private static final String DB_NAME = "xx_branch_trans";
    private static final String TABLE_NAME = "xx_customer_trans";

    // AES 密钥与 IV（示例值，建议改为你自己的安全随机值）
    private static final String AES_KEY_TEXT = "1234567890abcdef"; // 16/24/32 字节
    private static final String AES_IV_TEXT = "abcdef1234567890";  // 16 字节

    // RSA 私钥路径（PKCS#8 PEM）
    private static final String PRIVATE_KEY_PATH = "branch_private_pkcs8.pem";

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static void main(String[] args) {
        System.out.println("=== 幸福路支行加密交易入库测试（控制台 + 真正 RSA 签名） ===");
        Connection conn = null;
        try {
            // 1. 测试连接（系统库）
            conn = openConnection(null);
            System.out.println("MySQL 连接成功（系统库）");
            closeQuietly(conn);

            // 2. 创建数据库和表
            createDbAndTable();
            System.out.println("数据库与表已准备完毕");

            // 3. 插入 10 笔加密交易（含 RSA 签名）
            insertEncryptedTransactions();
            System.out.println("10 笔加密交易插入完成（server_sign 为 RSA 签名 Base64）");

            // 4. 查询前 20 条记录
            queryTopRecords();

            // 5. 估算 3 年存储
            estimateStorage3Years();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            closeQuietly(conn);
        }
    }

    // ========== 数据库相关 ==========

    private static Connection openConnection(String dbName) throws Exception {
        Class.forName("com.mysql.jdbc.Driver");
        String url = "jdbc:mysql://" + MYSQL_HOST + ":" + MYSQL_PORT + "/"
                + (dbName == null ? "" : dbName)
                + "?useUnicode=true&characterEncoding=utf8";
        return DriverManager.getConnection(url, MYSQL_USER, MYSQL_PASS);
    }

    private static void createDbAndTable() throws Exception {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = openConnection(null);
            stmt = conn.createStatement();
            stmt.executeUpdate("CREATE DATABASE IF NOT EXISTS `" + DB_NAME + "` CHARACTER SET utf8mb4");
        } finally {
            closeQuietly(stmt);
            closeQuietly(conn);
        }

        try {
            conn = openConnection(DB_NAME);
            stmt = conn.createStatement();
            String ddl = "CREATE TABLE IF NOT EXISTS `" + TABLE_NAME + "` ("
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
                    + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
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
            conn = openConnection(DB_NAME);
            String sql = "INSERT INTO `" + TABLE_NAME + "` "
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

                // 交易哈希（明文拼接后 SHA-256）
                String hash = sha256Hex(t.concatenated());
                // 使用 RSA 私钥对哈希做 SHA256withRSA 签名
                String sign = rsaSignBase64(hash, PRIVATE_KEY_PATH);

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

            System.out.println("已插入 " + samples.size() + " 笔交易，加密字段为 Base64 密文，server_sign 为 RSA 签名。");
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
            conn = openConnection(DB_NAME);
            stmt = conn.createStatement();
            String sql = "SELECT id, customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign, create_time "
                    + "FROM `" + TABLE_NAME + "` ORDER BY id DESC LIMIT 20";
            rs = stmt.executeQuery(sql);
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            System.out.println("=== 最近 20 条加密交易（展示部分字段） ===");
            while (rs.next()) {
                System.out.println(
                        "id=" + rs.getLong("id")
                                + ", name=" + rs.getString("customer_name")
                                + ", enc_amount=" + trimForLog(rs.getString("enc_amount"))
                                + ", hash=" + trimForLog(rs.getString("hash_value"))
                                + ", sign=" + trimForLog(rs.getString("server_sign"))
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
            conn = openConnection(DB_NAME);
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign "
                    + "FROM `" + TABLE_NAME + "` LIMIT 200");

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
            System.out.println(String.format("3 年总量 -> %.2f MB（远小于 30GB 预留）", threeYears / (1024 * 1024)));
        } catch (Exception e) {
            System.err.println("估算失败: " + e.getMessage());
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    // ========== AES / RSA / 工具方法 ==========

    private static SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(UTF8);
        if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
            throw new IllegalArgumentException("AES Key 需 16/24/32 字节，当前=" + bytes.length);
        }
        return new SecretKeySpec(bytes, "AES");
    }

    private static IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(UTF8);
        if (bytes.length != 16) {
            throw new IllegalArgumentException("IV 需 16 字节，当前=" + bytes.length);
        }
        return new IvParameterSpec(bytes);
    }

    private static String encryptToBase64(String plain, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] out = cipher.doFinal(plain.getBytes(UTF8));
        return encodeBase64(out);
    }

    private static String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(UTF8));
        return toHexLower(digest);
    }

    private static int utf8Size(String text) {
        if (text == null) {
            return 0;
        }
        return text.getBytes(UTF8).length;
    }

    private static String trimForLog(String value) {
        if (value == null) {
            return "";
        }
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

    // 读取 PEM 文件中的 Base64 主体内容
    private static String readPemBody(String path, String keyword) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(new File(path)));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("-----BEGIN") || line.startsWith("-----END")) {
                if (!line.contains(keyword)) {
                    // 非期望类型的 PEM，继续读取
                }
                continue;
            }
            if (line.length() > 0) {
                sb.append(line);
            }
        }
        br.close();
        return sb.toString();
    }

    /**
     * 对 data 文本做 SHA256withRSA 签名，返回 Base64 字符串。
     */
    private static String rsaSignBase64(String data, String privateKeyPath) throws Exception {
        String pem = readPemBody(privateKeyPath, "PRIVATE KEY");
        byte[] der = decodeBase64(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pri = kf.generatePrivate(spec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pri);
        sig.update(data.getBytes(UTF8));
        byte[] signBytes = sig.sign();
        return encodeBase64(signBytes);
    }

    // 简单 Base64 编解码（不依赖 javax.xml.bind）
    // 简易 Base64 实现（只覆盖本示例用到的功能）
    private static final char[] B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    private static String encodeBase64(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 4 + 2) / 3);
        int i = 0;
        while (i < data.length) {
            int b0 = data[i++] & 0xFF;
            int b1 = (i < data.length) ? data[i++] & 0xFF : 0;
            int b2 = (i < data.length) ? data[i++] & 0xFF : 0;

            int out0 = b0 >>> 2;
            int out1 = ((b0 & 0x03) << 4) | (b1 >>> 4);
            int out2 = ((b1 & 0x0F) << 2) | (b2 >>> 6);
            int out3 = b2 & 0x3F;

            sb.append(B64_CHARS[out0]);
            sb.append(B64_CHARS[out1]);
            sb.append((i - 1) < data.length + 1 ? B64_CHARS[out2] : '=');
            sb.append(i <= data.length ? B64_CHARS[out3] : '=');
        }
        int mod = data.length % 3;
        if (mod == 1) {
            sb.setCharAt(sb.length() - 1, '=');
            sb.setCharAt(sb.length() - 2, '=');
        } else if (mod == 2) {
            sb.setCharAt(sb.length() - 1, '=');
        }
        return sb.toString();
    }

    private static byte[] decodeBase64(String text) {
        // 简单实现：忽略非 Base64 字符和换行，仅用于读取 PEM 中的连续 Base64
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if ((c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '+' || c == '/' || c == '=') {
                sb.append(c);
            }
        }
        String clean = sb.toString();
        int len = clean.length();
        if (len == 0) {
            return new byte[0];
        }
        int pad = 0;
        if (clean.charAt(len - 1) == '=') pad++;
        if (clean.charAt(len - 2) == '=') pad++;
        int outLen = (len * 3) / 4 - pad;
        byte[] out = new byte[outLen];

        int outIndex = 0;
        for (int i = 0; i < len; i += 4) {
            int c0 = b64Index(clean.charAt(i));
            int c1 = b64Index(clean.charAt(i + 1));
            int c2 = b64Index(clean.charAt(i + 2));
            int c3 = b64Index(clean.charAt(i + 3));

            int b0 = (c0 << 2) | (c1 >>> 4);
            int b1 = ((c1 & 0x0F) << 4) | (c2 >>> 2);
            int b2 = ((c2 & 0x03) << 6) | c3;

            out[outIndex++] = (byte) b0;
            if (outIndex < outLen) {
                out[outIndex++] = (byte) b1;
            }
            if (outIndex < outLen) {
                out[outIndex++] = (byte) b2;
            }
        }
        return out;
    }

    private static int b64Index(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return 0;
    }

    private static String toHexLower(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // ========== 样例交易数据结构与生成 ==========

    private static class TransactionData {
        String name;
        String idCard;
        String fromCard;
        String toCard;
        String phone;
        String amount;

        String concatenated() {
            // 用于计算哈希：确保顺序固定
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


