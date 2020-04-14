//Author : Aden Chung Wee jing
//Email : weejing789@gmail.com

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Management;
using System.Collections;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;

namespace detection
{
   
    class catchAmsiBypass
    {
        static LinkedList <int> listOfProcessId;
        static Semaphore semaphore;

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }


        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModules(
             IntPtr hProcess,
             [Out] IntPtr lphModule,
             UInt32 cb,
             [MarshalAs(UnmanagedType.U4)] out UInt32 lpcbNeeded);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            int dwDesiredAccess, 
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("psapi.dll")]
        static extern uint GetModuleFileNameEx(
            IntPtr hProcess,
            IntPtr hModule,
            [Out] StringBuilder lpBaseName,
            [In] [MarshalAs(UnmanagedType.U4)] int nSize);
       

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            byte[] lpBuffer, 
            int dwSize, 
            ref int lpNumberOfBytesRead);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(
            IntPtr hProcess, 
            IntPtr hModule, 
            out MODULEINFO lpmodinfo, 
            uint cb);


        static void Main(string[] args)
        {
            
            PeHeaderReader amsiReader = new PeHeaderReader("C:/Windows/System32/amsi.dll");
            byte[] amsiModule = amsiReader.allBytes;
            String onDiskAmsiCodehash = getSectionHeaderofAmsi(amsiReader, false, amsiModule);


            ManagementEventWatcher eventWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));       
            eventWatcher.EventArrived += new EventArrivedEventHandler(newEvent);

            listOfProcessId = new LinkedList<int>();
            semaphore = new Semaphore(1, 1);                     
            eventWatcher.Start();

            while (true)
            {
                Thread.Sleep(5000);
                semaphore.WaitOne();
                LinkedListNode<int> headPointer = listOfProcessId.First;

                if (headPointer == null)
                    Console.WriteLine("Empty");

                while(headPointer != null)
                {
                    LinkedListNode<int> nextPointer = headPointer.Next;
                    checkForBypassEvidence(headPointer, onDiskAmsiCodehash);
                    headPointer = nextPointer;
                }
                semaphore.Release();            
            }
             
        }

        // this method returns the hash of Amsi.dll code section.
        static String getSectionHeaderofAmsi(PeHeaderReader amsiReader, Boolean inMemory, byte[] amsiModule)
        {          
            PeHeaderReader.IMAGE_SECTION_HEADER[] amsiSection = amsiReader.ImageSectionHeaders;
            int codeSectionPointer;
            for (int count = 0; count < amsiSection.Length; count++ )
            {                           
                char[] sectionName = amsiSection[count].Name;
                if (sectionName[0] =='.' && sectionName[1] =='t' && sectionName[2] =='e' && sectionName[3] == 'x' && sectionName[4] =='t')
                {
                    if (inMemory)
                        codeSectionPointer = (int)amsiSection[count].VirtualAddress;
                    else
                        codeSectionPointer = (int)amsiSection[count].PointerToRawData;

                    int SizeOfRawData = (int)amsiSection[count].SizeOfRawData;
                    byte[] amsiCodeSection = new byte[SizeOfRawData];
                    Array.Copy(amsiModule, codeSectionPointer, amsiCodeSection, 0, SizeOfRawData);
                    return calculateHash(amsiCodeSection);
                }
            }
            return "error";
        }

        //this method returns the md5 hash of a file
        static String calculateHash(byte [] bytesToHash)
        {
            MD5 md5CheckSum = MD5.Create();
            var hash = md5CheckSum.ComputeHash(bytesToHash);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }



        // this method checks for the creation of new PowerShell events 
        static void newEvent(object sender, EventArrivedEventArgs e)
        { 
            String processName = e.NewEvent.Properties["ProcessName"].Value.ToString();
            bool match = string.Equals(processName, "powershell.exe");
            if (match == true)
            {
                int processId = Int32.Parse(e.NewEvent.Properties["ProcessID"].Value.ToString());
                semaphore.WaitOne();
                listOfProcessId.AddFirst(processId);
                semaphore.Release();
            }

        }

        // this method sets a handle on an identified process
        static void checkForBypassEvidence(LinkedListNode<int> processId, string onDiskAmsiCodehash)
        {
            int PROCESS_VM_READ = (0x0010);
            int PROCESS_QUERY_INFORMATION = (0x0400);
            Console.WriteLine("Analysing process id: " + processId.Value);

            IntPtr processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 
                true, processId.Value);

            if (processHandle != null)
            {
                Boolean bypassFound =  analyseAmsiDLL(processHandle, onDiskAmsiCodehash);
                if(bypassFound == true)
                {
                    Console.WriteLine("Amsi tampering found in " + processId.Value);
                    listOfProcessId.Remove(processId);
                }                
            }
            else
            {
                listOfProcessId.Remove(processId);
            }
        }

        // this method sets a handle on the amsi DLL
        static Boolean analyseAmsiDLL(IntPtr processHandle, String onDiskAmsiCodehash)
        {
            IntPtr[] listOfModules = new IntPtr[1024];
            GCHandle gch = GCHandle.Alloc(listOfModules, GCHandleType.Pinned);
            IntPtr modulePointer = gch.AddrOfPinnedObject();

            uint uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (listOfModules.Length));
            uint cbNeeded = 0;

            if (EnumProcessModules(processHandle, modulePointer, uiSize, out cbNeeded))
            {
                int numOfModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));
                for (int count = 0; count <= numOfModules; count++)
                {
                    StringBuilder moduleName = new StringBuilder(1024);
                    GetModuleFileNameEx(processHandle, listOfModules[count], moduleName, (int)(moduleName.Capacity));
                    if (moduleName.ToString().Contains("amsi.dll"))
                    {
                        Boolean amsiIntegrityCheck = AmsiIntegrityCheck(processHandle, listOfModules[count], onDiskAmsiCodehash);
                        //Boolean bypassFound = checkAmsiScanBufferBypass(processHandle, listOfModules[count]);
                        gch.Free();
                        return amsiIntegrityCheck;
                    }
                }
            }
            gch.Free();
            return false;
        }

        // this method checks if any section of AmsiDll is tampered with by comparing the hash
        static Boolean AmsiIntegrityCheck(IntPtr processHandle, IntPtr amsiModuleHandle, String onDiskAmsiCodehash)
        {
            MODULEINFO amsiDLLInfo = new MODULEINFO();
            GetModuleInformation(processHandle, amsiModuleHandle, out amsiDLLInfo, (uint)(Marshal.SizeOf(typeof(MODULEINFO))));
            byte[] inMemoryAmsiDLL = new byte[amsiDLLInfo.SizeOfImage];
            int bytesRead = 0;

            ReadProcessMemory(processHandle, amsiModuleHandle, inMemoryAmsiDLL, inMemoryAmsiDLL.Length, ref bytesRead);
            PeHeaderReader amsiReader = new PeHeaderReader(inMemoryAmsiDLL);

            String inMemoryAmsiCodehash = getSectionHeaderofAmsi(amsiReader, true, inMemoryAmsiDLL);

            if (inMemoryAmsiCodehash.Equals(onDiskAmsiCodehash))
            {
                Console.WriteLine("hash matches");
                return false;
            }
            else
            {
                Console.WriteLine("Hash does not match");
                return true;
            }
        }

        // this method check if the AmsiScanBuffer is tampered with 
        static Boolean checkAmsiScanBufferBypass(IntPtr processHandle, IntPtr amsiModuleHandle)
        {            
            byte[] amsiBuffer = new byte[3];
            int bytesRead = 0;
            ReadProcessMemory(processHandle, (amsiModuleHandle + 9248 + 27), amsiBuffer, amsiBuffer.Length, ref bytesRead);
            if (amsiBuffer[0] == 49 && amsiBuffer[1] == 255 && amsiBuffer[2] == 144 )
            {
                return true;
            }
            if (amsiBuffer[0] !=65 && amsiBuffer[1] !=139 && amsiBuffer[2] !=248)
            {
                return true;
            }
            return false;
        }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
    }
}


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            