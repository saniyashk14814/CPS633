# CPS633

PART 1
The program (olmhash.c) takes the user id as input and searches for the id from a table that stores user id-password hash mapping in a text file. If the id is new, then it creates a new account and for known ids it needs to authenticate with the old password first and then only the new password can be set. 
This program is written in C and compiled using the command “gcc -Wall -o olmhash olmhash.c”. The hash value is generated using olmhash() function which uses the provided E() function and it is stored in the format of 24-character hexadecimal string value and hence the password will never be stored in plain text form.


PART2
