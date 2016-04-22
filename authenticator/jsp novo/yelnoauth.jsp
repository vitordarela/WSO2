<%@ page import="org.owasp.encoder.Encode" %>
<div id="loginTable1" class="identity-box">
 <% if (Boolean.parseBoolean(loginFailed)) { %>
    <div class="alert alert-danger" id="error-msg"><%= Encode.forHtml(errorMessage) %></div>
    <%}else if((Boolean.TRUE.toString()).equals(request.getParameter("authz_failure"))){%>
    <div class="alert alert-danger" id="error-msg">You are not authorized to login
    </div>
    <%}%>
    <img alt="Google Authenticator" src="http://a4.mzstatic.com/us/r30/Purple69/v4/e1/77/58/e1775847-16d5-eb85-618f-fb3decb720de/icon175x175.png" width="50" height="50">
    Google Authenticator:</br>
	<form action="../commonauth" method="post" id="loginForm">
    <!--Password-->
    <div class="control-group">
        <label class="control-label" for="password">Confirmation code:</label>

        <div class="controls">
            <input type="text" id='confirmationCode' name="confirmationCode"  class="input-xlarge" size='30'/>
            <input type="hidden" name="sessionDataKey" value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/>
         </div>
    </div>
<br>
    <div class="form-actions">
    	<button class="wr-btn grey-bg col-xs-12 col-md-12 col-lg-12 uppercase font-extra-large" type="submit">Confirmation code</button><br>
    	<a  href="https://www.google.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth://totp/admin@localhost%3Fsecret%3DA7SJOX45QFXTY4UA" target="_blank">Gerar QRCode</a>
    </div>

</div>


