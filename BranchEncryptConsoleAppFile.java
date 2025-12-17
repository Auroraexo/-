import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * 幸福路支行加密交易入库测试(控制台版,JDK7,文件存储,无需数据库)。
 * 功能:
 * 1. 创建数据文件(CSV格式):xx_customer_trans.csv
 * 2. 生成 10 笔交易,对敏感字段做 AES/CBC/PKCS5Padding 加密,Base64 存储 enc_ 字段
 * 3. 对每笔交易计算 SHA-256 哈希,并用占位签名存到 server_sign
 * 4. 查询最近记录,并估算"日均500笔、3年"的存储量
 */
public class BranchEncryptConsoleAppFile {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String DATA_FILE = "xx_customer_trans.csv";
    private static final String HEADER = "id,customer_name,enc_idcard,enc_from_card,enc_to_card,enc_phone,enc_amount,hash_value,server_sign,create_time";

    // ========== 配置区:根据实际环境修改 ==========
    private static final String AES_KEY_TEXT = "1234567890abcdef"; // 16/24/32 字节
    private static final String AES_IV_TEXT = "abcdef1234567890";  // 16 字节

    public static void main(String[] args) {
        System.out.println("=== 幸福路支行加密交易入库测试（文件版，无需数据库） ===");
        try {
            // 初始化文件
            initFile();
            System.out.println("数据文件已准备完毕");

            // 插入 10 笔加密交易
            insertEncryptedTransactions();
            System.out.println("10 笔加密交易插入完成");

            // 查询前 20 条记录
            queryTopRecords();

            // 估算 3 年存储
            estimateStorage3Years();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initFile() throws IOException {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
            writer.write(HEADER);
            writer.newLine();
            writer.close();
            System.out.println("数据文件已创建: " + DATA_FILE);
        } else {
            System.out.println("数据文件已存在: " + DATA_FILE);
        }
    }

    private static void insertEncryptedTransactions() throws Exception {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            throw new IOException("数据文件不存在，请先初始化");
        }

        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
        List<TransactionData> samples = sampleTransactions();
        SecretKeySpec key = buildKey(AES_KEY_TEXT);
        IvParameterSpec iv = buildIv(AES_IV_TEXT);

        int totalBytes = 0;
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        long nextId = getNextId();

        for (TransactionData t : samples) {
            String encId = encryptToBase64(t.idCard, key, iv);
            String encFrom = encryptToBase64(t.fromCard, key, iv);
            String encTo = encryptToBase64(t.toCard, key, iv);
            String encPhone = encryptToBase64(t.phone, key, iv);
            String encAmount = encryptToBase64(t.amount, key, iv);

            String hash = sha256Hex(t.concatenated());
            String sign = sha256Hex(hash + "|server-sim"); // placeholder sign

            String time = fmt.format(new Date());
            String line = nextId + "," + escapeCsv(t.name) + "," + escapeCsv(encId) + ","
                    + escapeCsv(encFrom) + "," + escapeCsv(encTo) + "," + escapeCsv(encPhone) + ","
                    + escapeCsv(encAmount) + "," + escapeCsv(hash) + "," + escapeCsv(sign) + "," + time;
            writer.write(line);
            writer.newLine();

            totalBytes += utf8Size(encId) + utf8Size(encFrom) + utf8Size(encTo)
                    + utf8Size(encPhone) + utf8Size(encAmount) + utf8Size(hash) + utf8Size(sign);
            nextId++;
        }
        writer.close();

        System.out.println("已插入 " + samples.size() + " 笔交易，加密字段均为 Base64 密文。");
        System.out.println("本次插入大致存储字节: " + totalBytes + "B (~" + (totalBytes / 1024.0) + "KB)");
    }

    private static void queryTopRecords() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            System.out.println("数据文件不存在");
            return;
        }

        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            reader.readLine(); // 跳过表头

            List<String> lines = new ArrayList<String>();
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 20) {
                lines.add(0, line); // 倒序插入，最新的在前
                count++;
            }
            reader.close();

            if (lines.isEmpty()) {
                System.out.println("表中无数据");
                return;
            }

            System.out.println("=== 最近 20 条加密交易（只展示部分字段） ===");
            for (String l : lines) {
                String[] parts = parseCsvLine(l);
                if (parts.length >= 10) {
                    System.out.println(
                            "id=" + parts[0]
                                    + ", name=" + parts[1]
                                    + ", enc_amount=" + trimForLog(parts[6])
                                    + ", hash=" + trimForLog(parts[7])
                                    + ", time=" + parts[9]
                    );
                }
            }
        } catch (Exception e) {
            System.err.println("查询失败: " + e.getMessage());
        }
    }

    private static void estimateStorage3Years() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            System.out.println("数据文件不存在");
            return;
        }

        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            reader.readLine(); // 跳过表头

            int rows = 0;
            int bytes = 0;
            String line;
            int maxRows = 200;
            while ((line = reader.readLine()) != null && rows < maxRows) {
                String[] parts = parseCsvLine(line);
                if (parts.length >= 9) {
                    bytes += utf8Size(parts[2]) + utf8Size(parts[3]) + utf8Size(parts[4])
                            + utf8Size(parts[5]) + utf8Size(parts[6]) + utf8Size(parts[7])
                            + utf8Size(parts[8]);
                    rows++;
                }
            }
            reader.close();

            if (rows == 0) {
                System.out.println("估算失败：文件中没有数据，请先插入样例。");
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
        }
    }

    // ===== 加密 / 工具方法 =====

    private static SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(UTF8);
        // 自动调整 Key 长度：如果不符合 16/24/32，则截取或填充
        if (bytes.length < 16) {
            // 不足 16 字节，用 0 填充
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            System.out.println("提示: AES Key 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16 && bytes.length < 24) {
            // 16-23 字节，截取到 16
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度在 16-24 之间，已自动截取到 16 字节");
        } else if (bytes.length > 24 && bytes.length < 32) {
            // 24-31 字节，截取到 24
            byte[] trimmed = new byte[24];
            System.arraycopy(bytes, 0, trimmed, 0, 24);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度在 24-32 之间，已自动截取到 24 字节");
        } else if (bytes.length > 32) {
            // 超过 32 字节，截取到 32
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 0, trimmed, 0, 32);
            bytes = trimmed;
            System.out.println("提示: AES Key 长度超过 32 字节，已自动截取到 32 字节");
        }
        return new SecretKeySpec(bytes, "AES");
    }

    private static IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(UTF8);
        // 自动调整 IV 长度：必须是 16 字节
        if (bytes.length < 16) {
            // 不足 16 字节，用 0 填充
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            System.out.println("提示: AES IV 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16) {
            // 超过 16 字节，截取前 16 个
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
        byte[] out = cipher.doFinal(plain.getBytes(UTF8));
        return base64Encode(out);
    }

    private static String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(UTF8));
        return bytesToHex(digest).toLowerCase();
    }

    // JDK7 兼容的 Base64 编码（简易实现）
    private static String base64Encode(byte[] data) {
        final char[] chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < data.length) {
            int b1 = data[i++] & 0xFF;
            int b2 = i < data.length ? data[i++] & 0xFF : 0;
            int b3 = i < data.length ? data[i++] & 0xFF : 0;
            int bitmap = (b1 << 16) | (b2 << 8) | b3;
            sb.append(chars[(bitmap >> 18) & 0x3F]);
            sb.append(chars[(bitmap >> 12) & 0x3F]);
            sb.append(i - 2 < data.length ? chars[(bitmap >> 6) & 0x3F] : '=');
            sb.append(i - 1 < data.length ? chars[bitmap & 0x3F] : '=');
        }
        return sb.toString();
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
        return text.getBytes(UTF8).length;
    }

    private static String trimForLog(String value) {
        if (value == null) return "";
        if (value.length() > 40) {
            return value.substring(0, 40) + "...";
        }
        return value;
    }

    private static String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private static String[] parseCsvLine(String line) {
        List<String> parts = new ArrayList<String>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                parts.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts.toArray(new String[parts.size()]);
    }

    private static long getNextId() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            return 1;
        }
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            reader.readLine(); // 跳过表头
            String line;
            long maxId = 0;
            while ((line = reader.readLine()) != null) {
                String[] parts = parseCsvLine(line);
                if (parts.length > 0) {
                    try {
                        long id = Long.parseLong(parts[0]);
                        if (id > maxId) {
                            maxId = id;
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            reader.close();
            return maxId + 1;
        } catch (Exception ignored) {
            return 1;
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

