url_recoder
===========

把HTTP请求的URL全部记录下来，我是在vps上用的~~

<pre><code>
Debian/Ubuntu: apt-get install libpcap-dev -y
CentOS:yum install libpcap-devel -y

然后
gcc url_recoder.c -lpcap -o url_recoder 


</code></pre>
