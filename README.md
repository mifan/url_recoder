url_recoder
===========

把HTTP请求的URL全部记录下来，我是在vps上用的~~
日志记录在 “/var/log/url_record.txt”

程序守护进程方式运行在后台

<pre><code>
Debian/Ubuntu: apt-get install libpcap-dev -y
CentOS:yum install libpcap-devel -y

然后
gcc url_recoder.c -lpcap -o url_recoder 

命令行参数是网卡名字，我这里是eth0，需要root权限
./url_recoder eth0

</code></pre>
