package org.projecthaystack.auth;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.projecthaystack.client.CallHttpException;
import org.projecthaystack.client.CallNetworkException;
import org.projecthaystack.util.Base64;
import org.projecthaystack.util.CryptoUtil;

////////////////////////////////////////////////////////////////
// niagara SCRAM
////////////////////////////////////////////////////////////////

final public class NiagaraScheme extends AuthScheme
{
  static class Property
  {
    Property(String key, String value)
    {
      this.key = key;
      this.value = value;
    }

    public String toString()
    {
      return "[Property " +
        "key:" + key + ", " +
        "value:" + value + "]";
    }

    final String key;
    final String value;
  }

  private static final String MIME_TYPE = "application/x-niagara-login-support";
  private static final String SECURITY_CHECK = "/j_security_check/";

  // private final String authUri;
  private final String clientNonce;
  private String firstMsgBare;
  private String firstMsgResult;
  private String sessionId;
  private String baseURL;
  private Property cookieProperty;

  public NiagaraScheme()
  {
    super("n4");
    byte[] array = new byte[16];
    new Random().nextBytes(array);
    this.clientNonce = Base64.STANDARD.encodeBytes(array);
  }

  private void firstMsg(AuthClientContext cx) throws Exception
  {
    // create first message
    this.firstMsgBare = "n=" + cx.user + ",r=" + clientNonce;

    // create request content
    String content = encodePost("sendClientFirstMessage",
                                "clientFirstMessage", "n,," + firstMsgBare);

    // set cookie
    cookieProperty = new Property("Cookie", "niagara_userid=" + cx.user);

    // post
    String res = postString(cx, baseURL + SECURITY_CHECK, content, MIME_TYPE);


    // save the resulting sessionId
    String cookie = cookieProperty.value;
    int a = cookie.indexOf("JSESSIONID=");
    int b = cookie.indexOf(";", a);
    sessionId = (b == -1) ?
    cookie.substring(a + "JSESSIONID=".length()) :
    cookie.substring(a + "JSESSIONID=".length(), b);

    // store response
    this.firstMsgResult = res;
  }

  private void finalMsg(AuthClientContext cx) throws Exception
  {
    // parse first msg response
    Map firstMsg = decodeMsg(firstMsgResult);
    String nonce = (String) firstMsg.get("r");
    int iterations = Integer.parseInt((String) firstMsg.get("i"));
    String salt = (String) firstMsg.get("s");

    // check client nonce
    if (!clientNonce.equals(nonce.substring(0, clientNonce.length())))
      throw new AuthException("Authentication failed");

    // create salted password
    byte[] saltedPassword = CryptoUtil.pbk(
      "PBKDF2WithHmacSHA256",
      strBytes(cx.pass),
      Base64.STANDARD.decodeBytes(salt),
      iterations, 32);

    // create final message
    String finalMsgWithoutProof = "c=biws,r=" + nonce;
    String authMsg = firstMsgBare + "," + firstMsgResult + "," + finalMsgWithoutProof;
    String clientProof = createClientProof(saltedPassword, strBytes(authMsg));
    String clientFinalMsg = finalMsgWithoutProof + ",p=" + clientProof;

    // create request content
    String content = encodePost("sendClientFinalMessage",
                                "clientFinalMessage", clientFinalMsg);

    // set cookie
    cookieProperty = new Property("Cookie",
                                  "JSESSIONID=" + sessionId + "; " +
                                  "niagara_userid=" + cx.user);

    // post
    postString(cx, baseURL + SECURITY_CHECK, content, MIME_TYPE);
  }

  private void upgradeInsecureReqs(AuthClientContext cx)
  {
    try
    {
      HttpURLConnection c = cx.openHttpConnection(baseURL + SECURITY_CHECK, "GET");
      c = cx.prepare(c);
      try
      {
        c.setDoOutput(true);
        c.setDoInput(true);
        c.setRequestProperty("Connection", "Close");
        c.setRequestProperty("Content-Type", "text/plain");
        c.setRequestProperty("Upgrade-Insecure-Requests", "1");
        c.connect();

        // check for 302
        if (c.getResponseCode() != 302)
          throw new CallHttpException(c.getResponseCode(), c.getResponseMessage());

        // discard response
        StringBuffer s = new StringBuffer(1024);
        Reader r = new BufferedReader(new InputStreamReader(c.getInputStream(), "UTF-8"));
        int n;
        while ((n = r.read()) > 0);
      }
      finally
      {
        try { c.disconnect(); } catch(Exception e) {}
      }
    }
    catch (Exception e) { throw new CallNetworkException(e); }
  }

  private String createClientProof(byte[] saltedPassword, byte[] authMsg) throws Exception
  {
    byte[] clientKey = CryptoUtil.hmac("SHA-256", strBytes("Client Key"), saltedPassword);
    byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
    byte[] clientSig = CryptoUtil.hmac("SHA-256", authMsg, storedKey);

    byte[] clientProof = new byte[clientKey.length];
    for (int i = 0; i < clientKey.length; i++)
      clientProof[i] = (byte) (clientKey[i] ^ clientSig[i]);

    return Base64.STANDARD.encodeBytes(clientProof);
  }

  private Map decodeMsg(String str)
  {
    // parse comma-delimited sequence of props formatted "<key>=<value>"
    Map map = new HashMap();
    int a = 0;
    int b = 1;
    while (b < str.length())
    {
      if (str.charAt(b) == ',') {
        String entry = str.substring(a,b);
        int n = entry.indexOf("=");
        map.put(entry.substring(0,n), entry.substring(n+1));
        a = b+1;
        b = a+1;
      }
      else {
        b++;
      }
    }
    String entry = str.substring(a);
    int n = entry.indexOf("=");
    map.put(entry.substring(0,n), entry.substring(n+1));
    return map;
  }

  private String encodePost(String action, String msgKey, String msgVal)
  {
    return "action=" + action + "&" + msgKey + "=" + msgVal;
  }

  private byte[] strBytes(String text) throws Exception
  {
    return text.getBytes("UTF-8");
  }

  @Override
  public AuthMsg onClient(AuthClientContext cx, AuthMsg msg) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean onClientNonStd(AuthClientContext cx, HttpURLConnection resp, String content)
  {
    baseURL = resp.getURL().getProtocol() + "://" + resp.getURL().getHost() + ":"+ resp.getURL().getPort();
    try {
      firstMsg(cx);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }

    try {
      finalMsg(cx);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }

    upgradeInsecureReqs(cx);
    return true;
  }

  private String postString(AuthClientContext cx, String uriStr, String req, String mimeType)
  {
    try
    {
      HttpURLConnection c = cx.openHttpConnection(uriStr, "POST");
      c = cx.prepare(c);
      try
      {
        c.setDoOutput(true);
        c.setDoInput(true);
        c.setRequestProperty("Connection", "Close");
        c.setRequestProperty("Content-Type", mimeType == null ? "text/zinc; charset=utf-8": mimeType);
        c.connect();
        // post expression
        Writer cout = new OutputStreamWriter(c.getOutputStream(), "UTF-8");
        cout.write(req);
        cout.close();


        // check for successful request
        if (c.getResponseCode() != 200) {
          throw new CallHttpException(c.getResponseCode(), c.getResponseMessage());
        }
        else {
          String cookie = c.getHeaderField("Set-Cookie");
          if (cookie != null && !cookie.isEmpty()) {
            cx.headers.put("Cookie", cookie);
          }
        }
        // read response into string
        StringBuffer s = new StringBuffer(1024);
        Reader r = new BufferedReader(new InputStreamReader(c.getInputStream(), "UTF-8"));
        int n;
        while ((n = r.read()) > 0) s.append((char)n);

        return s.toString();
      }
      finally
      {
        try { c.disconnect(); } catch(Exception e) {}
      }
    }
    catch (Exception e) { throw new CallNetworkException(e); }
  }
}
