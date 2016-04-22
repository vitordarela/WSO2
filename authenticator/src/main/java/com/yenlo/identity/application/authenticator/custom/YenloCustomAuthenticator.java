package com.yenlo.identity.application.authenticator.custom;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import com.yenlo.identity.application.authenticator.custom.internal.YenloCustomAuthenticatorConstants;

/**
 * Created by vitor on 14-04-2016.
 */
public class YenloCustomAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {
	private static final long serialVersionUID = 1L;
	
	private static Log log = LogFactory.getLog(YenloCustomAuthenticator.class);
    
	public static String secret = "A7SJOX45QFXTY4UA";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String confirmationCode = request.getParameter("confirmationCode");


        return confirmationCode != null;

    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
        	try {
        		
        		return super.process(request, response, context);
        	} catch (NullPointerException e) {
        		log.info("NullPointerException: Entrou no Try Catch");
        		return null;
        	}
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = FrameworkUtils
                .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier());

        try {
        	
        	GoogleAuthenticatorClass authenticatorClass = new GoogleAuthenticatorClass();
        	try {
				System.out.println("Secret Key Generated: "+authenticatorClass.geraSecretKey());
				System.out.println(authenticatorClass.getQRBarcodeURL(request.getParameter("username"), "localhost", secret));
				
				
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	
//            YenloCustomAuthenticatorEmailSender.sendEmail(request.getParameter("username"), CONFIRMATION_CODE);

            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                    + "&authenticators=" + getName() + ":" + "LOCAL" + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String confirmationCode = request.getParameter("confirmationCode");
        int code = 0;
        
        if(confirmationCode != null && !"".equals(confirmationCode)) {
        	code = Integer.parseInt(confirmationCode);
        	
        }

        boolean isAuthenticated = false;


        if (confirmationCode != null && !"".equals(confirmationCode)) {
        	GoogleAuthenticatorClass authenticatorClass = new GoogleAuthenticatorClass();
        	try {
				isAuthenticated = authenticatorClass.check_code(secret, code);
				System.out.println(isAuthenticated);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            System.out.println(isAuthenticated); 
        } else {
            throw new AuthenticationFailedException("Can not confirm authorization code.");
        }


        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("user authentication failed due to invalid credentials.");
            }

            throw new InvalidCredentialsException("Can not confirm authorization code.");
        }
       
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {
        return YenloCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return YenloCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}

