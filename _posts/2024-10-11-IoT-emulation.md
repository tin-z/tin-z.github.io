---
layout: post
title: "Router Emulation - Reproducing a PoC of a CVE through ASUS Firmware Emulation"
author: Altin (tin-z)
categories: [IoT, Emulation]


---

Embedded devices and the IoT ecosystem are becoming more prevalent in everyday
life each year, and, as a result, increasingly relevant in IT security. Before
AI, before the Metaverse, and even before Blockchain protocols, the most
discussed topic in the IT world was smart devices and IoT. We could say that
all the aforementioned technologies could become increasingly interconnected in
the not-too-distant future. Without delving into pros and cons or positive and
negative aspects, but speaking objectively, it all seems very interesting.

In this blog, we will demonstrate how to emulate part of the firmware of ASUS
routers in order to replicate the vulnerabilities CVE-2020-36109 and
CVE-2023-35086.

<br />

----

## Start ##

In this section, we provide an overview of Embedded Devices, QEMU, and GDB. To jump directly to the CVE emulation section, click here: [CVE-2020-36109](#cve-2020-36109).

## Embedded Devices ##

Embedded systems running Linux differ from regular PCs primarily in their hardware, which is specific to a particular domain and relies on sensors and actuators. The trade-off between cost and performance is much more critical compared to PCs, which is why memory and CPU resources tend to be more limited. Because of the specific hardware, manufacturer-specific driver modules and user-level software are required to communicate with the system. The solution is to provide firmware along with the device, which is a compressed file containing the kernel and filesystem files. The kernel can be Linux-based or another OS. The format of the compressed file depends on the vendor and may also be encrypted.

Essentially, for a Linux-based embedded device, the boot process follows similar steps to those of a regular PC.

<p align ="center">
  <img src="/files/2024-10-11/boot1.png">
</p>
<br />

----

## QEMU and GDB ##

QEMU is an emulator that allows emulation of the CPU and hardware via software, enabling an operating system to be emulated as if it were a regular application. QEMU supports various CPU architectures (ISAs), including Intel x86, ARM, and MIPS.

QEMU offers the following emulation modes:

 - QEMU system emulation: Full operating system emulation.

<p align ="center">
  <img src="/files/2024-10-11/qemu1.png">
</p>
<br />

 - QEMU system emulation with KVM: Operating system emulation without ISA translation, meaning the guest machine's ISA must match the host CPU's ISA.

<p align ="center">
  <img src="/files/2024-10-11/qemu2.png">
</p>
<br />

 - QEMU user-mode emulation: User-space emulation, with system calls forwarded to the host kernel.

<p align ="center">
  <img src="/files/2024-10-11/qemu3.png">
</p>
<br />

QEMU also allows debugging of the emulated system through its Gdbstub component, which exposes the GDB protocol. GDB (GNU Project Debugger) is a debugger that enables controlled execution of binaries on Linux. It provides Python APIs that allow for writing extensions, with popular ones being Peda, GEF, and pwndbg. In this case, we are particularly interested in GDB Multiarch, which enables remote debugging of a program compiled for a different CPU architecture than the host.


## Gdb-multiarch + QEMU user-mode ##

With the help of GDB-multiarch and QEMU user-mode, it's possible to monitor the emulation and execution of a program on the same host machine. To avoid reflecting system call operations on our filesystem, we use chroot, which allows us to change the root directory ("/"). We also use qemu-static, which, being statically compiled, doesn't require external libraries.

<br />

----

## CVE-2020-36109 ##

The CVE-2020-36109 vulnerability is described as a buffer overflow within the blocking_request.cgi file/function, exposed by the httpd service. This could allow remote code execution. The disclosure date is 2021-01-04, which helps us identify the correct firmware version.

<p align ="center">
  <img src="/files/2024-10-11/t1.jpg">
</p>
<br />


## Firmware Extraction ##

Based on the CVE disclosure date, we download two firmware versions: an [unpatched version](http://dlcdnet.asus.com/pub/ASUS/wireless/RT-AX86U/FW_RT_AX86U_30043849318.zip) and a [patched version](http://dlcdnet.asus.com/pub/ASUS/wireless/RT-AX86U/FW_RT_AX86U_300438641035.zip). We extract the unpatched firmware, which is in cleartext, using tools like [binwalk](https://github.com/ReFirmLabs/binwalk) and [ubidump](https://github.com/nlitsme/ubidump).

<p align ="center">
  <img src="/files/2024-10-11/t2.png">
</p>
<br />

The `blocking_request.cgi` file is not present in the extracted filesystem, but by running `grep -r blocking_request.cgi`, we find the string in the httpd file. This indicates that the CGI file is implemented directly by the httpd service. The device architecture is ARM.

<p align ="center">
  <img src="/files/2024-10-11/t3.png">
</p>
<br />

## String Analysis ##

We open the unpatched httpd binary with the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) decompiler. Since the service must respond to HTTP client requests, it should provide different responses based on the requested URI. For integrated CGI files, a function table is likely used, with each entry containing a pointer to a string for comparing the URI and a function to invoke if the comparison is successful. To reconstruct the function table and improve the decompiled output, we use the [codatify](https://github.com/grayhatacademy/ida/tree/master/plugins/codatify) script (Ghidra [fix_code](https://github.com/grayhatacademy/ghidra_scripts/blob/master/CodatifyFixupCode.py) version).

<p align ="center">
  <img src="/files/2024-10-11/t4.png">
</p>
<br />

<p align ="center">
  <img src="/files/2024-10-11/t5.png">
</p>
<br />

<p align ="center">
  <img src="/files/2024-10-11/t6.png">
</p>
<br />

We find the string `"do_blocking_request_cgi"`, which leads us to function `0x48df4`. We follow the same process for the patched firmware version and compare the two decompiled files. The patched version's function is more accurate in terms of stack layout, so we rely on it for a closer representation of the source code. What stands out are multiple strlcpy calls in the patched version, related to fields like CName, mac, interval, and timestap. Additionally, there are more field validations, suggesting these fields are likely passed via the client's HTTP request.

<p align ="center">
  <img src="/files/2024-10-11/t7.png">
</p>
<br />

## Binary Diffing ##

To better understand the modifications in the patched binary, we use bindiff, a tool that exposes techniques for binary diffing and highlights differences between two binaries in terms of assembly code and control flow graphs. To use bindiff with Ghidra, we generate the input using [binexport](https://github.com/google/binexport/tree/main/java) (guide available here [link](https://ihack4falafel.github.io/Patch-Diffing-with-Ghidra/)).

<p align ="center">
  <img src="/files/2024-10-11/t8.png">
</p>
<br />

Another method for identifying key differences is checking if new library functions were imported or if they are called more or fewer times in the patched version. We also provide a Python script that performs this task using radare2 [link](https://gist.github.com/tin-z/0df0db7a9c396108e92da418040624c8).

<p align ="center">
  <img src="/files/2024-10-11/t9.png">
</p>
<br />

## Emulation ##

We proceed with Gdb-multiarch + QEMU user-mode + chroot.

<p align ="center">
  <img src="/files/2024-10-11/t10.png">
</p>
<br />

To expose the GDB stub on QEMU, we use the `-g <port>` flag and run the following commands in two separate terminals: `sudo chroot ${PWD} ./qemu-arm-static -g 12345 bin/sh`, `sudo gdb-multiarch ./bin/busybox -q --nx -ex "source ./.gdbinit-gef.py" -ex "target remote 127.0.0.1:12345"`

<p align ="center">
  <img src="/files/2024-10-11/t11.png">
</p>
<br />

When launching httpd, several exceptions occur, so we trace system calls to fix the chrooted filesystem. We use the command: `sudo chroot ${PWD} ./qemu-arm-static -strace -D logstrace.log ./usr/sbin/httpd`. From the log, we extract the missing files, folders, symbolic links, and libraries and fix them.

<p align ="center">
  <img src="/files/2024-10-11/t12.png">
  <img src="/files/2024-10-11/t13.png">
</p>
<br />

<p align ="center">
  <img src="/files/2024-10-11/t14.png">
</p>
<p align ="center">
  <img src="/files/2024-10-11/t15.png">
</p>
<p align ="center">
  <img src="/files/2024-10-11/t16.png">
</p>
<br/>

Once the missing file issues are resolved, we also need to emulate the nvram part, as ASUS routers store and modify configurations in this memory. As noted in the strace log, nvram should be mounted at `/jffs/nvram_war`.

To communicate with nvram, `libnvram` is used, which provides several key functions:

<table>
  <tr>
    <th>Function Name</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>nvram_init()</code></td>
    <td>Initializes the libnvram library.</td>
  </tr>
  <tr>
    <td><code>nvram_get(key)</code></td>
    <td>Retrieves the value associated with <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_set(key, value)</code></td>
    <td>Sets the value for the specified <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_unset(key)</code></td>
    <td>Removes the entry associated with <code>key</code>.</td>
  </tr>
  <tr>
    <td><code>nvram_save()</code></td>
    <td>Saves changes made to the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_load()</code></td>
    <td>Loads the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_list_all()</code></td>
    <td>Lists all entries in the NVRAM configuration.</td>
  </tr>
  <tr>
    <td><code>nvram_reset()</code></td>
    <td>Resets the NVRAM configuration to defaults.</td>
  </tr>
</table>

To address this, we use LD_PRELOAD hooking, cross-compiling the [nvram-faker](https://github.com/tin-z/nvram-faker) library.
Default key entries are taken from the `nvram.ini` file, which is generated from user leaks on forums (e.g., "nvram show" site:pastebin.com). We then run: `sudo chroot <path-rootfs_ubifs> ./qemu-arm-static -E LD_PRELOAD=./libnvram-faker.so -g 12345 ./usr/sbin/httpd -p 12234` and `sudo gdb-multiarch ./usr/sbin/httpd -q --nx -ex 'source ./.gdbinit-gef.py' -ex 'target remote 127.0.0.1:12345'`.

<p align ="center">
  <img src="/files/2024-10-11/t17.png">
</p>
<br/>

At this point, we begin reverse engineering using the debugger. By setting breakpoints, especially on `str*` functions, we trace the binary's control flow. Through this hybrid reverse engineering process, we gather the following notes:

<br/>

 - `0x018dcc` reads the request and performs initial parsing (HEAD section).

<p align ="center">
  <img src="/files/2024-10-11/t18.png">
</p>
<br/>

 - `0x1b79c` extracts the first argument from the POST request payload.
 - `0x1ccb0` takes a string argument and returns the corresponding nvram value.
 - The POST request to `blocking_request.cgi` is used to add MAC addresses to a blacklist, likely for LAN connections.
 - The fields `CName`, `mac`, `interval`, and `timestap` must be passed in the POST request.
 - For the condition to pass, the request's timestap field must be within 21 seconds of the router's `timestamp`, and the `mac` field must be a substring of the nvram `MULTIFILTER_MAC`.

<p align ="center">
  <img src="/files/2024-10-11/t19.png">
</p>
<br/>

## Exploitation ##

The vulnerability lies in the potential execution of two strcat functions into a fixed-size stack buffer, where the input is provided by the client through the POST parameters `mac` and `timestap`.

<p align ="center">
  <img src="/files/2024-10-11/t20.png">
</p>
<br/>

To trigger the vulnerability, we need to craft a request with the following characteristics:
 - The `timestap` parameter must be valid, as it is converted to an integer via the `atol` function.
 - The `mac` parameter must be a substring of `MULTIFILTER_MAC`. Based on information found online, this value initially seems to be NULL (?), so assuming this is true, the `mac` parameter should be set to `%00`.
 - The overflow can only occur through the `timestap` parameter, but it must still be a valid value for `atol`. We resolve this by using the value `"<valid-int>%0a<payload>"`.

<p align ="center">
  <img src="/files/2024-10-11/t21.png">
  <br />
  <img src="/files/2024-10-11/t22.png">
</p>
<br/>


## CVE-2020-36109 Considerations ##

The scripts for replicating the test environment and the PoC are provided at the following links:
 - [PoC](https://github.com/sunn1day/CVE-2020-36109-POC)
 - [IoT toolbox repo](https://github.com/tin-z/IoT_toolbox/tree/main/pocs/ASUS)


Exploit Limitations:
 - The overflow occurs via `str*` functions, meaning null characters cannot be used in the payload.
 - The payload is located right below the stack's epilogue, so we cannot corrupt any data structures other than the return address.
 - There is a stack canary in place, and for the reasons mentioned above, even if we could somehow guess the canary value, if it contains a null byte, it becomes impossible to overwrite the return address.
 - The stack canary contains a null byte.

Making the exploit work:
 - If the `MULTIFILTER_MAC` nvram value contains any ASCII characters, this would allow us to overflow first with the `mac` parameter and then with the `timestap` parameter. Combining these, we could overwrite the return address and create a ROP (Return-Oriented Programming) chain.
 - ASUS routers run httpd as a daemon, meaning the process that handles the client request is a child of the parent process. This implies that it inherits the same address space, making brute-forcing the canary and base addresses for the ROP feasible.


Patch:
 - As mentioned earlier, the patch restricts the size of the POST parameters using `strlcpy`.

<br/>

----

## CVE-2023-35086 ##

CVE-2023-35086 identifies a format string vulnerability in the following router models and versions: RT-AX56U V2: 3.0.0.4.386_50460 and RT-AC86U: 3.0.0.4_386_51529. The report indicates that the vulnerability exists in the do_detwan_cgi function of the httpd service. However, this vulnerability is also present in other ASUS router models.

By following the same steps outlined in the [CVE-2020-36109](#cve-2020-36109) section, we are able to emulate part of the firmware. The string analysis reveals the location of the function that handles GET and POST requests to the `/detwan.cgi` URI, which is located at `0x49258`.

<p align ="center">
  <img src="/files/2024-10-11/t_1.jpg">
</p>
<br />

We attempt to decompile the function using Ghidra's decompiler, which does not display the entire function but reveals the following key points:
 - `FUN_0001b70c` extracts the `action_mode` parameter passed by the client.
 - The parameter is used as the third argument in the call to `logmessage_normal`, which is an external function exposed by libshared.

<p align ="center">
  <img src="/files/2024-10-11/t_2.jpg">
</p>
<br />

By searching on GitHub, we find that the source code for the `logmessage_normal` function is available in the asuswrt-merlin project, specifically in the file `asuswrt-merlin/release/src/router/shared/misc.c`. As we can see, the function saves the content of the `action_mode` HTTP parameter into the local variable `buf`, which is then used as the second argument in the `syslog` call.

<p align ="center">
  <img src="/files/2024-10-11/t_3.jpg">
</p>
<br />

As noted in the manual, the syslog function provided by libc supports format strings. Therefore, by passing a format string in the `action_mode` HTTP parameter, we can trigger this vulnerability.

<p align ="center">
  <img src="/files/2024-10-11/t_4.jpg">
</p>
<br />

To reproduce the PoC, run the following commands in two separate terminals: `sudo chroot <path-rootfs_ubifs> ./qemu-arm-static -E LD_PRELOAD=./libnvram-faker.so -g 12345 ./usr/sbin/httpd -p 12234` and `sudo gdb-multiarch ./usr/sbin/httpd -q --nx -ex 'source ./.gdbinit-gef.py' -ex 'target remote 127.0.0.1:12345'`.

<p align ="center">
  <img src="/files/2024-10-11/poc.gif">
</p>
<br />

## CVE-2023-35086 Considerations ##

The scripts to replicate the test environment and the PoC are provided at the following links:
 - [PoC](https://github.com/tin-z/CVE-2023-35086-POC)
 - [IoT toolbox repo](https://github.com/tin-z/IoT_toolbox/tree/main/pocs/ASUS)

<br />

----

