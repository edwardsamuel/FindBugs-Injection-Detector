package id.ac.itb.cs.injection.test;

import id.ac.itb.cs.CleanerType;
import id.ac.itb.cs.Vulnerability;
import id.ac.itb.cs.annotation.Cleaner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import java.util.regex.Pattern;

/**
 * Created by Edward Samuel on 30/07/14.
 */
public class SqlRegexFilter extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public static final String url = "jdbc:mysql://localhost:3306/erlangga";
    public static final String user = "progin";
    public static final String password = "progin";

    @Cleaner(type = CleanerType.VALIDATOR, vulnerabilities = {Vulnerability.XSS})
    private static final Pattern ZIP_PATTERN = Pattern.compile("^\\d{5}(-\\d{4})?$");

    @Cleaner(type = CleanerType.VALIDATOR, vulnerabilities = {Vulnerability.SQL_INJECTION})
    private static final Pattern PHONE_PATTERN = Pattern.compile("^\\d{5}(-\\d{4})?$");

    public SqlRegexFilter() {
        super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter writer = response.getWriter();

        Connection con = null;
        Statement st = null;
        ResultSet rs = null;

        String zipCode = request.getParameter("zip_code");
        String phoneNumber = request.getParameter("zip_code");
        if (!(ZIP_PATTERN.matcher(zipCode).matches() && PHONE_PATTERN.matcher(phoneNumber).matches()))  {
            // throw new Exception("Improper zipcode format.");
            return;
        }

        String query = "SELECT * FROM member WHERE zip = '" + zipCode + "' AND phone = '" + phoneNumber + "'";

        try {
            con = DriverManager.getConnection(url, user, password);
            st = con.createStatement();
            rs = st.executeQuery(query);

            if (rs.next()) {
                writer.write(rs.getString(1));
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }

                if (st != null) {
                    st.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException ex) {
                ex.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        File file = new File(args[0]);
        file.exists();

        System.out.println("XXX");
        System.out.println(args[0]);
    }
}
