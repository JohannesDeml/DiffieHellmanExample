:: Name of your certificate
set name=ca-trusted

makecert.exe ^
-n "CN=%name%,O=Johannes Deml,C=Germany" ^
-r ^
-pe ^
-a sha512 ^
-len 4096 ^
-cy authority ^
-sv %name%.pvk ^
%name%.cer

pvk2pfx.exe ^
-pvk %name%.pvk ^
-spc %name%.cer ^
-pfx %name%.pfx ^
-po password123


PAUSE