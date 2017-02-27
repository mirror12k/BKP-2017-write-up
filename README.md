# My BKP 2017 Writeup

## Sanity Check
Sanity check.

## Prudential V2
The challenge required two plaintexts that generate a sha1 collision.
Conveniently, Google's SHAttered just published two colliding pdfs this weak.
Taking the blocks that differed and their prefixs, we got a link of
'''
25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 0A 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 57 69 64 74 68 20 32 20 30 20 52 2F 48 65 69 67 68 74 20 33 20 30 20 52 2F 54 79 70 65 20 34 20 30 20 52 2F 53 75 62 74 79 70 65 20 35 20 30 20 52 2F 46 69 6C 74 65 72 20 36 20 30 20 52 2F 43 6F 6C 6F 72 53 70 61 63 65 20 37 20 30 20 52 2F 4C 65 6E 67 74 68 20 38 20 30 20 52 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 3E 3E 0A 73 74 72 65 61 6D 0A FF D8 FF FE 00 24 53 48 41 2D 31 20 69 73 20 64 65 61 64 21 21 21 21 21 85 2F EC 09 23 39 75 9C 39 B1 A1 C6 3C 4C 97 E1 FF FE 01 73 46 DC 91 66 B6 7E 11 8F 02 9A B6 21 B2 56 0F F9 CA 67 CC A8 C7 F8 5B A8 4C 79 03 0C 2B 3D E2 18 F8 6D B3 A9 09 01 D5 DF 45 C1 4F 26 FE DF B3 DC 38 E9 6A C2 2F E7 BD 72 8F 0E 45 BC E0 46 D2 3C 57 0F EB 14 13 98 BB 55 2E F5 A0 A8 2B E3 31 FE A4 80 37 B8 B5 D7 1F 0E 33 2E DF 93 AC 35 00 EB 4D DC 0D EC C1 A8 64 79 0C 78 2C 76 21 56 60 DD 30 97 91 D0 6B D0 AF 3F 98 CD A4 BC 46 29 B1

and

25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 0A 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 57 69 64 74 68 20 32 20 30 20 52 2F 48 65 69 67 68 74 20 33 20 30 20 52 2F 54 79 70 65 20 34 20 30 20 52 2F 53 75 62 74 79 70 65 20 35 20 30 20 52 2F 46 69 6C 74 65 72 20 36 20 30 20 52 2F 43 6F 6C 6F 72 53 70 61 63 65 20 37 20 30 20 52 2F 4C 65 6E 67 74 68 20 38 20 30 20 52 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 3E 3E 0A 73 74 72 65 61 6D 0A FF D8 FF FE 00 24 53 48 41 2D 31 20 69 73 20 64 65 61 64 21 21 21 21 21 85 2F EC 09 23 39 75 9C 39 B1 A1 C6 3C 4C 97 E1 FF FE 01 7F 46 DC 93 A6 B6 7E 01 3B 02 9A AA 1D B2 56 0B 45 CA 67 D6 88 C7 F8 4B 8C 4C 79 1F E0 2B 3D F6 14 F8 6D B1 69 09 01 C5 6B 45 C1 53 0A FE DF B7 60 38 E9 72 72 2F E7 AD 72 8F 0E 49 04 E0 46 C2 30 57 0F E9 D4 13 98 AB E1 2E F5 BC 94 2B E3 35 42 A4 80 2D 98 B5 D7 0F 2A 33 2E C3 7F AC 35 14 E7 4D DC 0F 2C C1 A8 74 CD 0C 78 30 5A 21 56 64 61 30 97 89 60 6B D0 BF 3F 98 CD A8 04 46 29 A1
'''
Submitting that produces the correct answer.

## Wackusensor
The challenge presented a website that claimed it installed acusensor and linked to its sourcecode.
Analyzing the code, it was clear that the acusensor required the 'ACUNETIX_ASPECT' header set to 'enabled' and 'ACUNETIX_ASPECT_PASSWORD' header set to the acusensor password. The password is conveniently extracted from from the end of the acusensor file of '4faa9d4408780ae071ca2708e3f09449'. Finally, it required that the page being accessed cant be the same as the acusensor php file.

Knowing all that, we can visit the index.php and view the acusensor debug info which is prefixed and suffixed as comments to the page. Observing the data, it was clear that it was including a 'super_secret_file_containing_the_flag_you_should_read_it.php' page, however visiting it directly did not produce the flag. Instead we needed to look further to a variable that acusensor was detecting being accessed from $_GET['super_secret_parameter_hahaha'].

A quick test showed that the parameter was being used in a file_get_contents and read to the output. However a check condition prevented getting any php files by looking for the string 'php' in the parameter. The second vulnerability was that weak comparison was used instead of strong comparison, meaning that a 'php' string found at position 0 was the same as no 'php' string. The solution was to prefix a 'php' directory to fool the sensor: '''http://54.200.58.235/index.php?super_secret_parameter_hahaha=php/../super_secret_file_containing_the_flag_you_should_read_it.php'''.

## Sponge
The challenge was to find a second-preimage attack on a specific string with a specificly crafted hash function. The hash function was a using a sponge construction, but a very small sized sponge came to be it's weakness. Although I initially found several 2^48 attacks on the hash function, I determined that it was out of my computational range for 1 day of work, so I instead developed a meet-in-the-middle second-preimage attack which i was able to simplify down to 2^25 operations. This was easily doable in under 4 minutes on a single one of my computer cores. For more information, take a look at my [notes](sponge/notes).
