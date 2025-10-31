# 1. Trivial Flag Transfer Protocol

Figure out how they moved the flag.

## Solution:

1.Opened the file in wireshark.
![screenshot of wireshark](./Screenshots/Forensics_Challenge1_Wireshark.jpg)
<br>

2.Found out that TFTP protocol is used(lookied it up and found that it is a protocol used to tranfer files).Used export objects feature to automatically reconstruct transfered files.(Files-->Export Objects-->TFTP)
![screenshot of export objects window](./Screenshots/Forensics_Challenge1_ExportObjects.jpg)
6 files were reconstructed(3 images,2 text files, 1 .deb file,)
<br>

3.Opened file instruction and found the following text with
```
GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA
```
Tried decoding(using cyberchef) using different common ciphers and encodings used,found out that ROT13 cipher was used and the orignal text was
```
TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN
TFTP DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISE OUR FLAG TRANSFER.FIGURE OUT A WAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN.
```
The word "PLAN" leads me to believe that the next clue is in the plan file.Upon opening the file the following text is seen:
```
VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF
```
Seeing how ROT13 cipher was used for the instruction,I assumed the same here and decoded using cyberchef which got me the following result
```
IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
I USED THE PROGRAM AND HID IT WITH-DUE DILIGENCE.CHECK OUT THE PHOTOS
```
<br>

4.The "PROGRAM" is the .deb file,

5.
## Flag:

```
picoCTF{}
```

## Concepts learnt:

- Include the new topics you've come across and explain them in brief
- 

## Notes:

- Include any alternate tangents you went on while solving the challenge, including mistakes & other solutions you found.
- 

## Resources:

- Include the resources you've referred to with links. [example hyperlink](https://google.com)


***

# 2. tunn3l v1s10n

We found this file. Recover the flag.

## Solution:

1.Used file command to determine file type
```
file tunn3l_v1s10n
tunn3l_v1s10n: data
```
This data was not really helpful so i decided to use exiftool on the file.
```
exiftool tunn3l_v1s10n
ExifTool Version Number         : 13.36
File Name                       : tunn3l_v1s10n
Directory                       : .
File Size                       : 2.9 MB
File Modification Date/Time     : 2025:10:30 14:54:28+05:30
File Access Date/Time           : 2025:10:30 14:54:28+05:30
File Inode Change Date/Time     : 2025:10:30 14:54:31+05:30
File Permissions                : -rw-r--r--
File Type                       : BMP
File Type Extension             : bmp
MIME Type                       : image/bmp
BMP Version                     : Unknown (53434)
Image Width                     : 1134
Image Height                    : 306
Planes                          : 1
Bit Depth                       : 24
Compression                     : None
Image Length                    : 2893400
Pixels Per Meter X              : 5669
Pixels Per Meter Y              : 5669
Num Colors                      : Use BitDepth
Num Important Colors            : All
Red Mask                        : 0x27171a23
Green Mask                      : 0x20291b1e
Blue Mask                       : 0x1e212a1d
Alpha Mask                      : 0x311a1d26
Color Space                     : Unknown (,5%()
Rendering Intent                : Unknown (826103054)
Image Size                      : 1134x306
Megapixels                      : 0.347
```
From this I dound that the files was an BMP file.I renamed the file with a .bmp extension at the end and tried opening the image but instead of seeing an iamge,I was being given an error.
![screenshot of error](./Screenshots/Forensics_Challenge2_BMPerror.jpg)
<br>

2.I opened the file in hexedit to view the data in hex format.


## Flag:

```
picoCTF{}
```

## Concepts learnt:

- Include the new topics you've come across and explain them in brief
- 

## Notes:

- Include any alternate tangents you went on while solving the challenge, including mistakes & other solutions you found.
- 

## Resources:

- Include the resources you've referred to with links. [example hyperlink](https://google.com)


***

# 3. m00nwalk

Decode this message from the moon.

## Solution:

1.opened the wav file in audacity to check if any hints are present in the spectrogram.However,I find nothing of use.
![screenshot of audacity](./Screenshots/Forensics_Challenge3_audacity.jpg)
<br>

2.After listening to the audio, I noticed a distinct, repeating pulse.Upon research I find that this is characteristic of an SSTV transmission,so I try to use a SSTV decoder.
![screenshot of decoder](./Screenshots/Forensics_Challenge3_decoder.jpg)
<br>

3.After using the decoder,an image is seen which contains the flag.<br>
![screenshot of decoded image](./Screenshots/Forensics_Challenge3_decoded.jpg)
<br>

## Flag:

```
picoCTF{beep_boop_im_in_space}
```

## Concepts learnt:

- UART Protocol Decoding: Learned how to identify a common digital communication protocol, Async Serial (UART), from its visual waveform.
- Using Protocol Analyzers: An understanding that the specific software, such as Logic 2, includes "analyzers" that could be run on raw signals to instantly decode into readable data formats like text or hex.

## Resources:

-   Online SSTV Decoder(https://sstv-decoder.mathieurenaud.fr/)
-   Slow-scan television(https://en.wikipedia.org/wiki/Slow-scan_television)
 
***