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
 * Swing GUI for "幸福路支行" encrypted transaction storage demo (JDK17 + Swing + H2).
 * 使用内置 H2 数据库，无需外部数据库安装。
 * - 创建数据库/表 (xx_branch_trans.xx_customer_trans)
 * - 插入 10 笔加密交易
 * - 查询记录并估算 3 年存储量
 * 
 * 运行前准备: 将 h2-*.jar 添加到 classpath
 */
public class SwingBranchEncryptAppH2 extends JFrame {
    private static final String DB_USER = "sa";
    private static final String DB_PASS = "";

    private JTextField dbPathField;
    private JTextField tableField;
    private JTextField aesKeyField;
    private JTextField aesIvField;
    private JTextArea logArea;

    public SwingBranchEncryptAppH2() {
        super("幸福路支行加密交易入库（H2数据库版，JDK17）");
        initUI();
    }

    private void initUI() {
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        dbPathField = new JTextField("./xx_branch_trans");
        dbPathField.setEditable(true);
        tableField = new JTextField("xx_customer_trans");
        tableField.setEditable(false);
        aesKeyField = new JTextField("1234567890abcdef"); // 16 bytes demo key
        aesIvField = new JTextField("abcdef1234567890");  // 16 bytes demo IV

        form.add(new JLabel("H2 数据库路径"));
        form.add(dbPathField);
        form.add(new JLabel("表名"));
        form.add(tableField);
        form.add(new JLabel("AES Key (16/24/32 chars)"));
        form.add(aesKeyField);
        form.add(new JLabel("AES IV (16 chars)"));
        form.add(aesIvField);

        JPanel buttons = new JPanel(new GridLayout(1, 0, 6, 6));
        JButton testBtn = new JButton("测试连接");
        JButton createBtn = new JButton("创建库表");
        JButton insertBtn = new JButton("插入10笔加密交易");
        JButton queryBtn = new JButton("查询前20条");
        JButton estimateBtn = new JButton("估算3年存储");
        buttons.add(testBtn);
        buttons.add(createBtn);
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

        testBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onTestConnection();
            }
        });
        createBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCreateTable();
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

    private void onTestConnection() {
        Connection conn = null;
        try {
            conn = openConnection();
            log("H2 数据库连接成功");
            JOptionPane.showMessageDialog(this, "连接成功");
        } catch (Exception ex) {
            log("连接失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "连接失败: " + ex.getMessage());
        } finally {
            closeQuietly(conn);
        }
    }

    private void onCreateTable() {
        Connection conn = null;
        Statement stmt = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            String table = tableField.getText().trim();
            String ddl = "CREATE TABLE IF NOT EXISTS " + table + " ("
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
            log("数据表已创建: " + table);
            JOptionPane.showMessageDialog(this, "库表创建完成");
        } catch (Exception ex) {
            log("创建库表失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        } finally {
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private void onInsertSample() {
        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = openConnection();
            String sql = "INSERT INTO " + tableField.getText().trim() + " "
                    + "(customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign) "
                    + "VALUES (?,?,?,?,?,?,?,?)";
            ps = conn.prepareStatement(sql);

            List<TransactionData> samples = sampleTransactions();
            SecretKeySpec key = buildKey(aesKeyField.getText().trim());
            IvParameterSpec iv = buildIv(aesIvField.getText().trim());

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
                        + utf8Size(encPhone) + utf8Size(encAmount) + utf8Size(hash) + utf8Size(sign);
            }
            ps.executeBatch();

            log("已插入 " + samples.size() + " 笔交易，加密字段均为Base64密文。");
            log("本次插入大致存储字节: " + totalBytes + "B (~" + (totalBytes / 1024.0) + "KB)");
            JOptionPane.showMessageDialog(this, "插入完成");
        } catch (Exception ex) {
            log("插入失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        } finally {
            closeQuietly(ps);
            closeQuietly(conn);
        }
    }

    private void onQueryTop() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            String sql = "SELECT id, customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign, create_time "
                    + "FROM " + tableField.getText().trim() + " ORDER BY id DESC LIMIT 20";
            rs = stmt.executeQuery(sql);
            StringBuilder sb = new StringBuilder();
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            while (rs.next()) {
                sb.append("id=").append(rs.getLong("id"))
                        .append(", name=").append(rs.getString("customer_name"))
                        .append(", enc_amount=").append(trimForLog(rs.getString("enc_amount")))
                        .append(", hash=").append(trimForLog(rs.getString("hash_value")))
                        .append(", time=").append(fmt.format(rs.getTimestamp("create_time")))
                        .append("\n");
            }
            log(sb.length() == 0 ? "表中无数据" : sb.toString());
        } catch (Exception ex) {
            log("查询失败: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, "失败: " + ex.getMessage());
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private void onEstimateStorage() {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = openConnection();
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign FROM "
                    + tableField.getText().trim() + " LIMIT 200");

            int rows = 0;
            int bytes = 0;
            while (rs.next()) {
                bytes += utf8Size(rs.getString(1)) + utf8Size(rs.getString(2)) + utf8Size(rs.getString(3))
                        + utf8Size(rs.getString(4)) + utf8Size(rs.getString(5)) + utf8Size(rs.getString(6))
                        + utf8Size(rs.getString(7));
                rows++;
            }
            if (rows == 0) {
                log("估算失败：表中没有数据，请先插入样例");
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
        } finally {
            closeQuietly(rs);
            closeQuietly(stmt);
            closeQuietly(conn);
        }
    }

    private Connection openConnection() throws SQLException, ClassNotFoundException {
        Class.forName("org.h2.Driver");
        String dbPath = dbPathField.getText().trim();
        String url = "jdbc:h2:" + dbPath + ";AUTO_SERVER=TRUE";
        return DriverManager.getConnection(url, DB_USER, DB_PASS);
    }

    private SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(StandardCharsets.UTF_8);
        // 自动调整 Key 长度：如果不符合 16/24/32，则截取或填充
        if (bytes.length < 16) {
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            log("提示: AES Key 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16 && bytes.length < 24) {
            byte[] trimmed = new byte[16];
            System.arraycopy(bytes, 0, trimmed, 0, 16);
            bytes = trimmed;
            log("提示: AES Key 长度在 16-24 之间，已自动截取到 16 字节");
        } else if (bytes.length > 24 && bytes.length < 32) {
            byte[] trimmed = new byte[24];
            System.arraycopy(bytes, 0, trimmed, 0, 24);
            bytes = trimmed;
            log("提示: AES Key 长度在 24-32 之间，已自动截取到 24 字节");
        } else if (bytes.length > 32) {
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 0, trimmed, 0, 32);
            bytes = trimmed;
            log("提示: AES Key 长度超过 32 字节，已自动截取到 32 字节");
        }
        return new SecretKeySpec(bytes, "AES");
    }

    private IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(StandardCharsets.UTF_8);
        // 自动调整 IV 长度：必须是 16 字节
        if (bytes.length < 16) {
            byte[] padded = new byte[16];
            System.arraycopy(bytes, 0, padded, 0, bytes.length);
            bytes = padded;
            log("提示: AES IV 长度不足，已自动填充到 16 字节");
        } else if (bytes.length > 16) {
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
        byte[] out = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(out);
    }

    private String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest).toLowerCase();
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
        return text.getBytes(StandardCharsets.UTF_8).length;
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

    private void closeQuietly(Connection c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void closeQuietly(Statement s) {
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void closeQuietly(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Exception ignored) {
            }
        }
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
                new SwingBranchEncryptAppH2().setVisible(true);
            }
        });
    }
}

