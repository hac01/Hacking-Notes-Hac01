# WITH SSH 

There are two ways to do this 

1. Forwarding a specific port on the target 
```
ssh -L 1234:localhost:3306 Ubuntu@IP
```

2. Dynamic ssh port forwarding 

```
ssh -D 9050 -i id_rsa_root root@IP
```
Then simply use proxychains to connect with internal system (make sure that in /etc/proxychains4.conf socks4  127.0.0.1 9050
)

![image](https://user-images.githubusercontent.com/70646122/209807352-2b9b4176-1c7f-4276-99a8-04a2d14c6a84.png)

