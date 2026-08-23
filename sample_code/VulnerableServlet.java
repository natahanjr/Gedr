import java.io.*;
import java.sql.*;

public class VulnerableServlet {
    private String secret = "hardcoded_secret_value";

    public void query(String user) throws Exception {
        Statement stmt = DriverManager.getConnection("jdbc:mysql://db").createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    public void exec(String cmd) throws Exception {
        Runtime.getRuntime().exec("cmd /c " + cmd);
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
    }

    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
