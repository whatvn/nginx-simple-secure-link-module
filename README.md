# nginx-simple-secure-link 

## configuration 

```
	server {
		...
		secure_link  $arg_token,$arg_ts,$arg_e;
        	secure_link_hmac_secret password; 
        	secure_link_hmac_message $arg_uid$arg_ts$arg_e;
		...
		location / {
			secure_link_enabled on;
			....
		}

```


## usage


This module is use SHA256, it can be an option but i removed to make it simple 

To generate a secure link, please read below.

For example your url has format like this:

```
http://github.com/downloads/document.pdf?ts=1523084400&e=30&uid=328945
```

And you configured secure_link_hmac_message to be: 

```
secure_link $arg_token,$arg_ts,$arg_e;
secure_link_hmac_secret password;
secure_link_hmac_message $arg_uid$arg_ts$arg_e;

```


To generate secure link in php, use following example code: 


```php
<?php
$secret = 'password';
$expire = 30;
$algo = 'sha256';
$uid = 328945 ; 
$timestamp = 1523084400;
$stringtosign = "{$uid}{$timestamp}{$expire}";
$hashmac = base64_encode(hash_hmac($algo, $stringtosign, $secret, true));
$hashmac = strtr($hashmac, '+/', '-_');
$hashmac = str_replace('=', '', $hashmac);
$host = "http://github.com";
$loc = "https://{$host}/downloads/document.pdf?token={$hashmac}&ts={$timestamp}&e={$expire}&uid={$uid}";
```
 

```go
func computeHMac(uid, timeStamp, expire int) string {
    url := "http://github.com/downloads/document.pdf";
    sha256Object := hmac.New(sha256.New, []byte("password"))
    message := fmt.Sprintf("%v%v%v", uid, timeStamp, expire)
    sha256Object.Write([]byte(message))
    hmac := strings.Replace(base64.StdEncoding.EncodeToString(sha256Object.Sum(nil)), "=", "", -1)
    hmac = strings.Replace(hmac, "/", "_", -1)
    return url+"?token="+strings.Replace(hmac, "+", "-", -1)+"&uid="+uid"+"&e="+expire+"&ts="+timeStamp
}

```

