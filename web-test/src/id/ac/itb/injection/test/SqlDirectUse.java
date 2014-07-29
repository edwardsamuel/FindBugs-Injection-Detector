package id.ac.itb.injection.test;

import id.ac.itb.cs.annotation.ReturnContaminated;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Created by Edward Samuel on 29/07/14.
 */
public class SqlDirectUse extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public static final String url = "jdbc:mysql://localhost:3306/erlangga";
    public static final String user = "progin";
    public static final String password = "progin";

    /**
     * @see HttpServlet#HttpServlet()
     */
    public SqlDirectUse() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter writer = response.getWriter();

        String out = getUname(request);
        // out = "Hasil : ";
        out += retreiveData(out);
        out += ":";
        // out += request.getParameter("uname");

        writer.write(out);
    }

    public String getUname(HttpServletRequest request) {
        return request.getParameter("uname");
    }

    public String retreiveData(String uname) {
        Connection con = null;
        java.sql.Statement st = null;
        ResultSet rs = null;

        String query = "SELECT * FROM member WHERE MemberFirstName = '" + uname + "'";

        try {
            con = DriverManager.getConnection(url, user, password);
            st = con.createStatement();
            rs = st.executeQuery(query);

            if (rs.next()) {
                return rs.getString(1);
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

        return null;
    }


    @Override
    @ReturnContaminated
    public String getServletName() {
        return "XAMPP";
    }
}
