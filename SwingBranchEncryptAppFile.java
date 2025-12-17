import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
 * Swing GUI for "幸福路支行" encrypted transaction storage demo (JDK17 + Swing).
 * 使用文件存储，无需数据库和 JDBC jar 包。
 * - 创建数据文件（CSV 格式）
 * - 插入 10 笔加密交易
 * - 查询记录并估算 3 年存储量
 */
public class SwingBranchEncryptAppFile extends JFrame {
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String DATA_FILE = "xx_customer_trans.csv";
    private static final String HEADER = "id,customer_name,enc_idcard,enc_from_card,enc_to_card,enc_phone,enc_amount,hash_value,server_sign,create_time";

    private JTextField dbField;
    private JTextField tableField;
    private JTextField aesKeyField;
    private JTextField aesIvField;
    private JTextArea logArea;
    private long nextId = 1;

    public SwingBranchEncryptAppFile() {
        super("幸福路支行加密交易入库（文件版，无需数据库）");
        initUI();
        loadNextId();
    }

    private void initUI() {
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        dbField = new JTextField("xx_branch_trans");
        dbField.setEditable(false);
        tableField = new JTextField("xx_customer_trans");
        tableField.setEditable(false);
        aesKeyField = new JTextField("1234567890abcdef"); // 16 bytes demo key
        aesIvField = new JTextField("abcdef1234567890");  // 16 bytes demo IV

        form.add(new JLabel("数据目录（当前目录）"));
        form.add(new JLabel("."));
        form.add(new JLabel("数据文件"));
        form.add(new JLabel(DATA_FILE));
        form.add(new JLabel("AES Key (16/24/32 chars)"));
        form.add(aesKeyField);
        form.add(new JLabel("AES IV (16 chars)"));
        form.add(aesIvField);

        JPanel buttons = new JPanel(new GridLayout(1, 0, 6, 6));
        JButton initBtn = new JButton("初始化文件");
        JButton insertBtn = new JButton("插入10笔加密交易");
        JButton queryBtn = new JButton("查询前20条");
        JButton estimateBtn = new JButton("估算3年存储");
        buttons.add(initBtn);
        buttons.add(insertBtn);
        buttons.add(queryBtn);
        buttons.add(estimateBtn);

        logArea = new JTextArea(18, 80);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        getContentPane().setLayout(new BorderLayout(8, 8));
        getContentPane().add(form, BorderLayout.NORTH);
        getContentPane().add(buttons, BorderLayout.CENTER);
        getContentPane().add(scrollPane, BorderLayout.SOUTH);

        initBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onInitFile();
            }
        });
        insertBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onInsertSample();
            }
        });
        queryBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onQueryTop();
            }
        });
        estimateBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onEstimateStorage();
            }
        });

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
    }

    private void onInitFile() {
        File file = new File(DATA_FILE);
        try {
            if (!file.exists()) {
                BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
                writer.write(HEADER);
                writer.newLine();
                writer.close();
                log("数据文件已创建: " + DATA_FILE);
                JOptionPane.showMessageDialog(this, "文件初始化完成");
            } else {
                log("数据文件已存在: " + DATA_FILE);
                JOptionPane.showMessageDialog(this, "文件已存在");
            }
        } catch (IOException ex) {
            log("初始化失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        }
    }

    private void onInsertSample() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            JOptionPane.showMessageDialog(this, "请先点击\"初始化文件\"");
            return;
        }

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
            List<TransactionData> samples = sampleTransactions();
            SecretKeySpec key = buildKey(aesKeyField.getText().trim());
            IvParameterSpec iv = buildIv(aesIvField.getText().trim());

            int totalBytes = 0;
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

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

            log("已插入 " + samples.size() + " 笔交易，加密字段均为Base64密文。");
            log("本次插入大致存储字节: " + totalBytes + "B (~" + (totalBytes / 1024.0) + "KB)");
            saveNextId();
            JOptionPane.showMessageDialog(this, "插入完成");
        } catch (Exception ex) {
            log("插入失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        }
    }

    private void onQueryTop() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            JOptionPane.showMessageDialog(this, "数据文件不存在");
            return;
        }

        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String header = reader.readLine(); // 跳过表头
            if (header == null) {
                log("表中无数据");
                reader.close();
                return;
            }

            List<String> lines = new ArrayList<String>();
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 20) {
                lines.add(0, line); // 倒序插入，最新的在前
                count++;
            }
            reader.close();

            if (lines.isEmpty()) {
                log("表中无数据");
                return;
            }

            StringBuilder sb = new StringBuilder();
            for (String l : lines) {
                String[] parts = parseCsvLine(l);
                if (parts.length >= 10) {
                    sb.append("id=").append(parts[0])
                            .append(", name=").append(parts[1])
                            .append(", enc_amount=").append(trimForLog(parts[6]))
                            .append(", hash=").append(trimForLog(parts[7]))
                            .append(", time=").append(parts[9])
                            .append("\n");
                }
            }
            log(sb.toString());
        } catch (Exception ex) {
            log("查询失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        }
    }

    private void onEstimateStorage() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            JOptionPane.showMessageDialog(this, "数据文件不存在");
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
                if (parts.length >= 8) {
                    bytes += utf8Size(parts[2]) + utf8Size(parts[3]) + utf8Size(parts[4])
                            + utf8Size(parts[5]) + utf8Size(parts[6]) + utf8Size(parts[7])
                            + utf8Size(parts[8]);
                    rows++;
                }
            }
            reader.close();

            if (rows == 0) {
                log("估算失败：文件中没有数据，请先插入样例");
                return;
            }

            double avgPerRow = bytes / (double) rows;
            double perDay = avgPerRow * 500; // 500笔/日
            double threeYears = perDay * 365 * 3;
            log("平均单条大小约 " + String.format("%.2f", avgPerRow) + " 字节");
            log("500 笔/日 -> " + String.format("%.2f", perDay / 1024) + " KB/日");
            log("3 年总量 -> " + String.format("%.2f", threeYears / (1024 * 1024)) + " MB (远小于30GB)");
        } catch (Exception ex) {
            log("估算失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        }
    }

    private SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(UTF8);
        // 自动调整 Key 长度：如果不符合 16/24/32，则截取或填充
        if (bytes.length < 16) {
            // 不足 16 字节，用 0 填充
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            log("提示: AES Key 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16 && bytes.length < 24) {
            // 16-23 字节，截取到 16
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            log("提示: AES Key 长度在 16-24 之间，已自动截取到 16 字节");
        } else if (bytes.length > 24 && bytes.length < 32) {
            // 24-31 字节，截取到 24
            byte[] trimmed = new byte[24];
            System.arraycopy(bytes, 0, trimmed, 0, 24);
            bytes = trimmed;
            log("提示: AES Key 长度在 24-32 之间，已自动截取到 24 字节");
        } else if (bytes.length > 32) {
            // 超过 32 字节，截取到 32
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 0, trimmed, 0, 32);
            bytes = trimmed;
            log("提示: AES Key 长度超过 32 字节，已自动截取到 32 字节");
        }
        return new SecretKeySpec(bytes, "AES");
    }

    private IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(UTF8);
        // 自动调整 IV 长度：必须是 16 字节
        if (bytes.length < 16) {
            // 不足 16 字节，用 0 填充
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            log("提示: AES IV 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16) {
            // 超过 16 字节，截取前 16 个
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            log("提示: AES IV 长度超过 16 字节，已自动截取前 16 字节");
        }
        return new IvParameterSpec(bytes);
    }

    private String encryptToBase64(String plain, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] out = cipher.doFinal(plain.getBytes(UTF8));
        return base64Encode(out);
    }

    private String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(UTF8));
        return bytesToHex(digest).toLowerCase();
    }

    // JDK7 兼容的 Base64 编码（简易实现）
    private String base64Encode(byte[] data) {
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
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private int utf8Size(String text) {
        if (text == null) {
            return 0;
        }
        return text.getBytes(UTF8).length;
    }

    private String trimForLog(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() > 40) {
            return value.substring(0, 40) + "...";
        }
        return value;
    }

    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private String[] parseCsvLine(String line) {
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

    private void loadNextId() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            nextId = 1;
            return;
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
            nextId = maxId + 1;
        } catch (Exception ignored) {
            nextId = 1;
        }
    }

    private void saveNextId() {
        // nextId 已更新，无需额外保存
    }

    private List<TransactionData> sampleTransactions() {
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

    private void log(String text) {
        logArea.append(text + "\n");
        logArea.setCaretPosition(logArea.getText().length());
    }

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

    public static void main(String[] args) {
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new SwingBranchEncryptAppFile().setVisible(true);
            }
        });
    }
}

