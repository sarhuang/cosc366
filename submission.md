# Start Here

`Name`: Sarah Huang 
`NetID`: shuang24

For each problem below, you will,

1. Fill in the the flag
2. List the steps necessary to exploit the binary. *(May be a single line.)*
3. Provide a patch that fixes the exploit. *(Generated using `make diff`.)*
4. An explanation of what the vulnerability was and how the patch fixes it. *(Keep this explanation short and to the point.)*

---

## problem1

### Flag
`flag{366-iNt3G3r5iGNc0nV3r5i0N}`

### Exploit Steps
1. Select withdrawal by entering 1
2. Enter -1000000
3. Enter VIP mode and obtain flag

### Patch
```diff
--- .originals/problem1.c	2023-03-03 22:16:49.000000000 +0000
+++ problem1.c	2023-03-11 17:44:59.403652800 +0000
@@ -1,8 +1,8 @@
 #include <stdio.h>
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 void VIP() {
   printf("Hello VIP user!\n");
@@ -37,14 +37,14 @@
 
 // Handle a large withdraw
 void large_withdraw(struct user_account *u) {
-  unsigned int withdrawal;
+  int withdrawal;
 
   printf("How much would you like to withdraw?\n> ");
   scanf("%u", &withdrawal);
   withdrawal += 50;
 
   // Ensure the user has enough money to complete the transaction
-  if (!check_withdraw_amount(withdrawal, u)) {
+  if (!check_withdraw_amount(withdrawal, u) || withdrawal < 0) {
     printf("Sorry, you do not have enough funds to complete this withdrawal.\n");
     printf("Have a good day!\n");
     return;

```

### Explanation
This code is vulnerable because I attempted to withdraw $-1000000, but the system added the $1000000 into the balance despite it being an invalid input. The withdrawal variable was unsigned, so it would not count the negative. I changed the variable to a regular integer (signed), and I added an additional check to ensure that the withdrawal is greater than zero.

---

## problem2

### Flag
`flag{366-bUFF3r0v3RF10w_r3turn}`

### Exploit Steps
1. Notice that the char array has a size of 32 bytes. Typing 44 a's will cause a seg fault. 
2. Run `objdump -d problem2` and see that the backdoor function has an address of 08049280.
3. Type ./problem2 `python2 -c 'print "a"*44 + "\x80\x92\x04\x08"'` (the address is little-endian).

### Patch
```diff
--- .originals/problem2.c	2023-03-03 22:16:49.000000000 +0000
+++ problem2.c	2023-03-11 19:05:12.764207100 +0000
@@ -7,10 +7,7 @@
 // chatbots have to start somewhere...
 void parrot(char *input) {
   // Take the user input and run it through our chat algorithm
-  char out[32];
-
-  memset(out, 0, sizeof(out));
-  strcpy(out, input);
+  char* out = strdup(input);  
 
   // Copy the user's input and print it out.
   printf("user:   %s\n", input);
@@ -25,9 +22,9 @@
   }
 }
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 // Too bad this function is never called...
 void backdoor() {

```

### Explanation
The code is vulnerable because the user could input a char array with a length of more than 44 bytes. When the program copies the input string into the out buffer using strcpy(), it overwrites the memory space with the address of the backdoor() function. When the program returns from the parrot() function, it jumps to the address of the backdoor() function and executes it. To fix this problem, I created a char pointer rather than an array with a pre-defined size to account for any overflows. Strdup() makes a copy of the input pointer and stores it in the now char pointer algorithm_out.

---

## problem3

### Flag
`flag{366-BufFeR0v3rf10W_C4n4ry}`

### Exploit Steps
1. Pick a character for passwordBuffer ('a'). 
2. Decide which character is the result of the shift ('b').
3. Type "./problem3 aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"

### Patch
```diff
--- .originals/problem3.c	2023-03-03 22:16:49.000000000 +0000
+++ problem3.c	2023-03-11 22:17:30.160059900 +0000
@@ -2,21 +2,20 @@
 #include <stdio.h>
 #include <string.h>
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 // Check the password
 bool checkPassword(char *input) __attribute__((stack_protect));
 bool checkPassword(char *input) {
-  char passwordBuffer[16];
   char secret[16];
- 
+  char* passwordBuffer = strdup(input);
+  
   // Set the secret value. Hidden from prying eyes...
 
   // Check that the passwords match. We're using my super special comparison function that
   // shifts password characters over by 1... throws off the hackers!
-  strcpy(passwordBuffer, input);
 
   for (size_t i = 0; i < sizeof(passwordBuffer); i++) {
     passwordBuffer[i]++;

```

### Explanation
The code is vulnerable because the user could input a char array with a length of more than 16 bytes. In the vulnerability, the attacker could type 16 a's that would shift to become b's and then overflow the `secret` buffer with 16 b's. That way the `passwordBuffer` and `secret` arrays would have the same password. To fix this problem, I created a char pointer rather than an array with a pre-defined size to account for any overflows. Strdup() makes a copy of the input pointer and stores it in the now char pointer `passwordBuffer`.

---

## problem4

### Flag
`flag{366-iNt3g3r0v3rF10w}`

### Exploit Steps
1. Enter an integer that is larger than the max number of an integer
   Ex. 2147483647
2. Enter a multiple of 504

### Patch
```diff
--- .originals/problem4.c	2023-03-03 22:16:49.000000000 +0000
+++ problem4.c	2023-03-11 19:59:54.550404300 +0000
@@ -1,14 +1,14 @@
 #include <stdio.h>
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 // Do not change this value.
 static const int reset_key = -504;
 
 int main() {
-  int value, factor, result, password;
+  long long value, factor, result, password;
 
   // This is a simple calculator with some input checking
   printf("Enter a value: ");
@@ -38,6 +38,6 @@
     // Plus it's not like you can multiple 2 positive numbers to get a negative number anyway...
     flag();
   } else {
-    printf("Product: %d\n", result);
+    printf("Product: %lld\n", result);
   }
 }
\ No newline at end of file


```

### Explanation
The code is vulnerable because the user could calculate a number larger than the maximum integer value. I made the value, factor, result, and password variables all long longs to remove the integer overflow issue. Additionally, you need to update the print statement to use the %lld format specifier so that the input values are read as long long.

---

## problem5

### Flag
`flag{366-r5C3c0nd170n}`

### Exploit Steps
1. Create a bash script that runs the `problem5` and creates the file before `problem5` checks for: 
   #!/bin/bash
   ./problem5 &
   pid=$!
   sleep 0.05
   touch /tmp/$pid

### Patch
```diff
--- .originals/problem5.c	2023-03-03 22:16:49.000000000 +0000
+++ problem5.c	2023-03-12 20:02:38.599461100 +0000
@@ -2,9 +2,9 @@
 #include <stdio.h>
 #include <unistd.h>
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 int main() {
   // Get the name of a tempfile we can use. It won't exist yet.
@@ -19,7 +19,7 @@
 
     // Ok, let's open this file and write the flag to it.
     // Haha... just kidding, the user doesn't have access to the file, so this call will fail.
-    FILE *outFile = fopen(destinationFile, "r");
+    FILE *outFile = fopen(destinationFile, "wx");
     if (outFile == NULL) {
       printf("This is my file... I told you that you couldn't access it. Neener-neener!\n");
       // If the file did exist, we would write to it here.

```

### Explanation
The code is vulnerable because a race condition occurs when an attacker can create a file at `destinationFile` between the time the program checks and when it sleeps. When the attack creates the temp file before the program wakes up, it confuses the program as there should not be an existing file and triggers the flag. I patched it by changing the fopen() mode from 'r' to 'wx'. With 'wx', it will not open the file if it has already been created. In our situation, we want the program to deny opening the file the attacker made because it could be malicious.

---

## problem6

### Flag
`flag{366-1n73g3RUnd3rfl0W}`

### Exploit Steps
1. Create a program to generate every single 3 letter combo and write it into a .txt file
2. Pipe the .txt into the problem6 executable to expose the integer underflow flag
   cat problem6Input.txt | ./problem6

### Patch
```diff
--- .originals/problem6.c	2023-03-03 22:16:49.000000000 +0000
+++ problem6.c	2023-03-12 16:22:41.574119400 +0000
@@ -4,16 +4,16 @@
 #include <string.h>
 #include <time.h>
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 int main() {
   char password[4];
   memset(password, (char)0, sizeof(password));
 
   char input[4];
-  unsigned int remainingGuesses;
+  int remainingGuesses;
 
   // Generate a random string of 3 lowercase letters
   srand((unsigned int)time(NULL));

```

### Explanation
The code is vulnerable because the unsigned int `remainingGuesses` variable can't handle a brute force attack like entering in every single combination. The unsigned variable isn't meant to go below zero, so it suffers from integer underflow after thousands of guesses. Additionally, the user will be unable to quit the program because the prompt only appears if `remainingGuesses` is less than zero which is impossible for an unsigned int. To fix this issue, simply changing the variable from unsigned int to a signed int will not trigger the flag and allow the user to quit the program.

---

## problem7

### Flag
`flag{366-Rac3c0ndi7i0N_2}`

### Exploit Steps
1. Withdraw $1000
2. Withdraw $1000
3. Withdraw $500
4. Run queued transactions
5. Quit with a balance of $-1500

### Patch
```diff
--- .originals/problem7.c	2023-03-03 22:16:49.000000000 +0000
+++ problem7.c	2023-03-12 01:57:36.345890500 +0000
@@ -1,25 +1,29 @@
 #include <limits.h>
-#include <pthread.h>
 #include <stdbool.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#include <pthread.h>
+
 
 static const int MAX_BALANCE = 2000000000;
 
 int accountBalance = 1000;
+pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
 
-void flag() {
-  printf("The flag goes here");
-}
+void flag() {
+  printf("The flag goes here");
+}
 
 // Withdraw an amount from the user's account
 void *withdraw(void *arg) {
   unsigned short amount = *(unsigned short *)arg;
 
   // Ensure the user has enough money to complete this transaction
+  pthread_mutex_lock(&mutex);
   if (amount > accountBalance) {
     printf("Insufficient funds for withdrawal of $%hu\n", amount);
+    pthread_mutex_unlock(&mutex);
     return NULL;
   }
 
@@ -29,6 +33,7 @@
   for (unsigned short i = 0; i < amount; i++) {
     --accountBalance;
   }
+  pthread_mutex_unlock(&mutex);
   return NULL;
 }
 
@@ -37,8 +42,10 @@
   unsigned short amount = *(unsigned short *)arg;
 
   // Ensure that the deposit won't overflow the balance.
+  pthread_mutex_lock(&mutex);
   if ((amount + accountBalance) > MAX_BALANCE) {
     printf("Accounts can at most have $%d. This deposit would put you over that limit!\n", MAX_BALANCE);
+    pthread_mutex_unlock(&mutex);
     return NULL;
   }
 
@@ -48,6 +55,7 @@
   for (unsigned short i = 0; i < amount; i++) {
     ++accountBalance;
   }
+  pthread_mutex_unlock(&mutex);
   return NULL;
 }
 

```

### Explanation
This code is vulnerable because it creates multiple threads since the user can make multiple deposit and withdraw calls. If two threads modify the `accountBalance` variable at the same time, a race condition occurs and leads to unwanted behavior. To prevent race conditions, you can limit only one thread to access the `accountBalance` variable at any given time by using a mutex lock. The shared resource can be locked for one transaction and released ready for another transaction when it finishes.

---
