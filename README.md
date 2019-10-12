# Finding bugs in the D-Link 880 firmware (CVE-2017-14948)

In this brief blogpost I will explain a bug I found in the firmware D-Link 880 v1.08B04 (CVE-2017-14948).

## Firmware Analysis
We downloaded the firmware from the manufacturer website, and unpacked it.
After looking at the contained binary files, we identified the binaries managint the user requests, and identified the binary 'fileaccess.cgi'.

This binary contains a bug at function address 0x0001BDF0, which can be triggered by modyfying the 'content_type' of a user request.
The disassemly is the following:

```c
signed int __fastcall content_type(char *a1)
{
  char *dest; // [sp+4h] [bp-10h]@1
  const char *haystack; // [sp+Ch] [bp-8h]@1
  char *haystacka; // [sp+Ch] [bp-8h]@3

  dest = a1;
  haystack = getenv("CONTENT_TYPE");
  if ( !haystack )
    return -22;
  haystacka = strstr(haystack, "boundary=");
  if ( !haystacka )
    return -22;
  strcpy(dest, haystacka + 9);
  return 0;
}
```

In the above code the content of the variable 'CONTENT_TYPE'  (pointed by the variable haystack) is controlled by a user (through the HTTP request's header).

The content after the keyword 'boundary' is then copied into a buffer 'dest', without checking haystacka's length.
If one takes a look at the caller function (address 0x1CE6C), one can infer that the size of dest is 256 bytes.

As an attacker can control the content of CONTENT_TYPE, they could send the string 'boundary=' followed by as least as 257 characters to trigger a buffer overflow.
