

<p align="center" height="310" border="2px solid #555">
<img src=Screenshots/FaceDancer_logo.png height="310" border="2px solid #555">
<br>
<strong style="font-size: large;">FaceDancer</strong>

</p>


## Description
FaceDancer is an exploitation tool aimed at creating hijackable, proxy-based DLLs. FaceDancer performs two main functions:

* Recon: Scans a given DLL to create the export definition file for proxying.
* Attack: Creates a malicious DLL containing shellcode that can proxy valid function requests to the legitimate DLL.

FaceDancer contains numerous methods for performing DLL hijacking. These DLLs take advantage of either weak permissions on installation folders or COM-based system DLL image loading to load a malicious version of a legitimate DLL. Once loaded, the DLL executes the embedded shellcode while proxying valid requests for DLL functions to the legitimate DLL. This is done using a .def file to map the valid requests to the correct DLL, allowing a low-privilege user to proxy a legitimate DLL through a malicious one. This bypasses application whitelisting controls as FaceDancer targets native processes needed for standard operation, making it effective for initial access or persistence.

FaceDancer contains zero evasion techniques. FaceDancer’s sole focus is discovering and generating DLLs for proxying. It is important that the inputted DLL contains all the necessary evasion techniques. For more information about the techniques and how they are discovered, please see my [blog](https://www.blackhillsinfosec.com/a-different-take-on-dll-hijacking/).



#### Microsoft's Response
As of now, Microsoft has no plans to fix or remediate these issues but acknowledges them as valid vulnerabilities.

## Attack Methods

### DLL Based Proxy

At a high level, this involves exploiting DLLs that reside in folders that are not properly protected when installed, allowing an attacker to abuse the Load Image operation when the application is launched via DLL proxying. The overarching issue is that when Microsoft Teams is configured with an account, the application installs some additional plugins (including an Outlook plugin). Some of these plugins are installed in the user’s AppData folder with overly permissive permissions (i.e., write permission). Because of this, an attacker can rename a valid DLL in one of these directories that a process loads when it first launches and place their own malicious DLL in the same folder to have it automatically load and execute. This does not require admin privileges.

#### Example OneAuth.DLL

When Microsoft Teams v2 (aka Microsoft Teams for Work and School) is configured with a user’s profile, it installs a package called TeamsMeetingAddin into Outlook (if Outlook is installed). The folder containing the associated DLLs for this add-in can be modified by low-privilege users to both rename the legitimate DLLs and add malicious DLLs. This means the next time Outlook is launched, the malicious DLL is loaded by Outlook, leading to code execution as the Outlook process.


<p align="center">
<img src=Screenshots/OneAuth_ImageLoad.png border="2px solid #555">
<br>
</p>

All files in this directory can be modified by a low-privilege user.

<p align="center">
<img src=Screenshots/OneAuth_Permissions.png border="2px solid #555">
<br>
</p>

A DLL proxy attack is necessary to ensure that the original DLL is still loaded, preventing Outlook from crashing. The screenshot below demonstrates using this attack to execute arbitrary code, in this case, a Rust “Hello, World!” program, via Outlook.
<p align="center">
<img src=Screenshots/Hello_World.png border="2px solid #555">
<br>
</p>


### Proxying Function Requests
Using definition files (.def), which are text files containing one or more module statements that describe various attributes of a DLL, we can define all the exported functions and proxy them to the legitimate DLL that contains the requested functions. By using an export.def file, we can rename the legitimate DLL to whatever we want (in the example below, we append -old to the name), place our DLL in the same folder, and when a process loads it, our DLL will proxy any requests for one of the DLL’s functions to the legitimate one. 

```
    EXPORTS
    ?IsZero@UUID@Authentication@Microsoft@@QEBA_NXZ=OneAuth-old.?IsZero@UUID@Authentication@Microsoft@@QEBA_NXZ @1
    GetLastOneAuthError=OneAuth-old.GetLastOneAuthError @2
    InitializeTelemetryCallbacks=OneAuth-old.InitializeTelemetryCallbacks @3
```

Because of this only one DLL is ever loaded (not OneAuth and OneAuth-legitmate) but when we look at the DLL's export functions we can see that each of the proxyed functions call back to OneAuth-legitmate.dll.

<p align="center">
<img src=Screenshots/Process_Running.png border="2px solid #555">
<br>
</p>

### COM based Proxying

COM-based DLL proxying takes a different approach. It exploits dependencies in numerous native Windows and third-party applications. When executed, as these processes start up, they query the registry for COM objects to find the path to certain system DLLs to load. What makes these requests interesting is that they first check the Current User (HKCU) section of the registry. If they are unable to find the values there, they fail over to another section of the registry where the entries exist.
<p align="center">
<img src=Screenshots/Olk_Calling_Com.png border="2px solid #555">
<br>
</p>
<p align="center">
<img src=Screenshots/Com_Value.png border="2px solid #555">
<br>
</p>
By creating the COM entries they look for, we can control which DLLs they load. Using the same proxy technique mentioned previously, we can load a DLL from anywhere as a system DLL and still proxy the traffic to the valid system DLL that resides in system32. This ensures there is no disruption to the process’s operation by still providing the valid functions. This all can be done as a low-privilege user without needing any privilege escalation or elevated permissions.

<p align="center">
<img src=Screenshots/msedge.dll.png border="2px solid #555">
<br>
</p>
<p align="center">
<img src=Screenshots/Beacon.png border="2px solid #555">
<br>
</p>

It works against Microsoft’s WindowsApp-based applications, including the new versions of Outlook (olk.exe) and Teams (ms-teams.exe). Applications in this folder are blocked even from Administrators. Attempting to access the folder to view the contents results in denied access, even when running as an Administrator.
<p align="center">
<img src=Screenshots/WindowApps.png border="2px solid #555">
<br>
</p>

This makes sideloading into these applications extremely difficult; however, they still rely on COM objects to load DLLs.
<p align="center">
<img src=Screenshots/Olk_Loading.png border="2px solid #555">
<br>
</p>

# How To Use

## Recon Mode

This mode allows FaceDancer to scan a specified DLL to generate the .def file for you. With this, you can then generate your own DLLs using FaceDancer rather then the pre-defined ones. 


### Recon
```
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Reconnaissance tools

Usage: FaceDancer recon [OPTIONS]

Options:
  -I, --Input <INPUT>  Path to the DLL to examine.
  -E, --exports        Displays the exported functions for the targeted DLL (only will show the first 20)
  -G, --generate       Generates the necessary .def for proxying
  -h, --help           Print help
```

## Attack Mode

This mode generates the actual DLLs used for proxying attacks. It works by taking an existing malicious DLL containing your shellcode and converting it into shellcode. Since FaceDancer does not contain any EDR evasion techniques, it is important that the inputted DLL includes all the necessary evasion techniques. This also means any type of DLL (not just Rust DLLs) can be used. Additionally, you can select the type of DLL attack you want to execute:
* `DLL` - Generates a DLL to be dropped into a specific folder. Depending on which DLL you generate, you need to navigate to a different directory. Once there, rename the original DLL, paste your DLL in that folder.
* `COM` - Generates a DLL along with the required registry entries to exploit it. With this type of DLL, any process that calls that COM object will load the DLL and execute the shellcode. For this to work, the provided registry keys need to be added to the HKCU section of the registry.
* `Process` -  Generates a DLL along with the required registry entries to exploit it. With this type of DLL, only when the specified process loads the DLL will the shellcode execute. For this to work, the provided registry keys need to be added to the HKCU section of the registry.

### Attack

```
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Attack tools

Usage: FaceDancer attack [OPTIONS]

Options:
  -O, --Output <OUTPUT>    Name of output DLL file.
  -I, --Input <INPUT>      Path to the 64-bit DLL.
  -D, --DLL <DLL>          The DLL to proxy: 
                                               [1] OneAuth.dll
                                               [2] ffmpeg.dll (warning can be unstable)
                                               [3] skypert.dll
                                               [4] SlimCV.dll
  -C, --COM <COM>          The COM-DLL to proxy: 
                                               [1] ExplorerFrame.dll
                                               [2] fastprox.dll
                                               [3] mssprxy.dll
                                               [4] netprofm.dll
                                               [5] npmproxy.dll
                                               [6] OneCoreCommonProxyStub.dll
                                               [7] propsys.dll                                    
                                               [8] stobject.dll
                                               [9] wbemprox.dll
                                               [10] webplatstorageserver.dll
                                               [11] Windows.StateRepositoryPS.dll              
                                               [12] windows.storage.dll
                                               [13] wpnapps.dll
  -P, --PROCESS <PROCESS>  Process to proxy load into: 
                                               [1] Outlook
                                               [2] Excel
                                               [3] svchost
                                               [4] Explorer
                                               [5] sihost
                                               [6] msedge
                                               [7] OneDriveStandaloneUpdater                             
                                               [8] SSearchProtocolHost
                                               [9] Olk
                                               [10] Teams
                                               [11] Werfault            
                                               [12] Sdxhelper
                                               [13] AppHostRegistrationVerifier
                                               [14] rdpclip
                                               [15] Microsoft.SharePoint
                                               [16] MusNotificationUx
                                               [17] PhoneExperienceHost
                                               [18] taskhostw
                                               [19] DllHost      
                                                               
  -s, --sandbox            Enables sandbox evasion by checking:
                                               - Is Endpoint joined to a domain?
                                               - Is the file's name the same as its SHA256 value?
  -h, --help               Print help

```


## Contributing
FaceDancer was developed in Rust.



## Help

```


    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                
Does awesome things

Usage: FaceDancer [COMMAND]

Commands:
  recon   Reconnaissance tools
  attack  Attack tools
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```


## Install

#### Note Please Ensure All Dependencies Are Installed  


If `Rust` and `Rustup` is not installed please install them. If you are compiling it from OSX or Linux sure you have the target "x86_64-pc-windows-gnu" added. To so run the following command:
```
rustup target add x86_64-pc-windows-gnu
```

Once done you can compile FaceDancer, run the following commands, or use the compiled binary (found in the pre-compiled folder):
```
cargo build --release
```
From there the compiled version will be found in in target/release (note if you don't put ```--release``` the file will be in target/debug/ )

### Credit
Special thanks to Teach2Breach for developing [dll2shell](https://github.com/Teach2Breach/dll2shell/tree/main)

