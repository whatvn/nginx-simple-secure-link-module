# nginx-simple-secure-link 

## configuration 

```
	server {
		...
		secure_link  $arg_token,$arg_ts,$arg_e;
        	secure_link_hmac_secret password; 
        	secure_link_hmac_message $arg_something$arg_ts$arg_e;
		...
		location / {
			secure_link_enabled on;
			....
		}

```


## usage

will be updated soon
