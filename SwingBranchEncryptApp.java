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
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * Swing GUI for "幸福路支行" encrypted transaction storage demo (JDK7 + Swing).
 * - Creates database/table (xx_branch_trans.xx_customer_trans).
 * - Inserts 10 encrypted sample transactions.
 * - Queries table and estimates 3-year storage footprint.
 *
 * Requirement: add MySQL Connector/J 5.1.x to classpath when running.
 */
public class SwingBranchEncryptApp extends JFrame {
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private JTextField hostField;
    private JTextField portField;
    private JTextField userField;
    private JTextField passField;
    private JTextField dbField;
    private JTextField tableField;
    private JTextField aesKeyField;
    private JTextField aesIvField;
    private JTextArea logArea;

    public SwingBranchEncryptApp() {
        super("幸福路支行加密交易入库（T2-03）");
        initUI();
    }

    private void initUI() {
        JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
        hostField = new JTextField("127.0.0.1");
        portField = new JTextField("3306");
        userField = new JTextField("root");
        passField = new JTextField("123456");
        dbField = new JTextField("xx_branch_trans");
        tableField = new JTextField("xx_customer_trans");
        aesKeyField = new JTextField("1234567890abcdef"); // 16 bytes demo key
        aesIvField = new JTextField("abcdef1234567890");  // 16 bytes demo IV

        form.add(new JLabel("MySQL Host"));
        form.add(hostField);
        form.add(new JLabel("Port"));
        form.add(portField);
        form.add(new JLabel("User"));
        form.add(userField);
        form.add(new JLabel("Password"));
        form.add(passField);
        form.add(new JLabel("DB Name"));
        form.add(dbField);
        form.add(new JLabel("Table Name"));
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
            conn = openConnection(null);
            log("连接成功（系统库）");
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
            conn = openConnection(null);
            stmt = conn.createStatement();
            stmt.executeUpdate("CREATE DATABASE IF NOT EXISTS `" + dbField.getText().trim() + "` CHARACTER SET utf8mb4");
            log("数据库已准备: " + dbField.getText().trim());
            closeQuietly(stmt);

            conn = openConnection(dbField.getText().trim());
            stmt = conn.createStatement();
            String table = tableField.getText().trim();
            String ddl = "CREATE TABLE IF NOT EXISTS `" + table + "` ("
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
            log("数据表已准备: " + table);
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
            conn = openConnection(dbField.getText().trim());
            String sql = "INSERT INTO `" + tableField.getText().trim() + "` "
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
                String sign = sha256Hex(hash + "|server-sim"); // placeholder sign to show anti-repudiation column

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
            conn = openConnection(dbField.getText().trim());
            stmt = conn.createStatement();
            String sql = "SELECT id, customer_name, enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign, create_time "
                    + "FROM `" + tableField.getText().trim() + "` ORDER BY id DESC LIMIT 20";
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
            conn = openConnection(dbField.getText().trim());
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT enc_idcard, enc_from_card, enc_to_card, enc_phone, enc_amount, hash_value, server_sign FROM `"
                    + tableField.getText().trim() + "` LIMIT 200");

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

    private Connection openConnection(String dbName) throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.jdbc.Driver");
        String url = "jdbc:mysql://" + hostField.getText().trim() + ":" + portField.getText().trim()
                + "/" + (dbName == null ? "" : dbName) + "?useUnicode=true&characterEncoding=utf8";
        return DriverManager.getConnection(url, userField.getText().trim(), passField.getText());
    }

    private SecretKeySpec buildKey(String keyText) {
        byte[] bytes = keyText.getBytes(UTF8);
        if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
            throw new IllegalArgumentException("AES Key 需16/24/32字节，当前=" + bytes.length);
        }
        return new SecretKeySpec(bytes, "AES");
    }

    private IvParameterSpec buildIv(String ivText) {
        byte[] bytes = ivText.getBytes(UTF8);
        if (bytes.length != 16) {
            throw new IllegalArgumentException("IV 需16字节，当前=" + bytes.length);
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
                new SwingBranchEncryptApp().setVisible(true);
            }
        });
    }
}

