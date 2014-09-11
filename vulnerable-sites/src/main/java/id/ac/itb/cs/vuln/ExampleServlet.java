package id.ac.itb.cs.vuln;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.MySQLCodec;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;

public class ExampleServlet extends HttpServlet {

    private final static MySQLCodec MY_SQL_CODEC = new MySQLCodec(MySQLCodec.Mode.STANDARD);

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String uname = request.getParameter("uname");

        PrintWriter out = response.getWriter();
        Employee employee = getEmployee(uname);
        out.write("Hello, " + employee.getName() + "!");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String uname = ESAPI.encoder().encodeForSQL(MY_SQL_CODEC, request.getParameter("uname"));

        PrintWriter out = response.getWriter();
        Employee employee = getEmployee(uname);
        out.write("Hello, " + employee.getName() + "!");
    }

    public Employee getEmployee(String uname) {
        Connection con = null; Statement st = null; ResultSet rs = null;
        String query = "SELECT * FROM employee WHERE uname = '" + uname + "'";

        try {
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "");
            st = con.createStatement();
            rs = st.executeQuery(query);

            if (rs.next()) {
                return new Employee(rs.getInt(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        } finally {
            try {
                if (rs != null) { rs.close(); }
                if (st != null) { st.close(); }
                if (con != null) { con.close(); }
            } catch (SQLException ex) {
                ex.printStackTrace();
            }
        }

        return null;
    }
}