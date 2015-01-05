#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>

#define PROMISC 1
#define SNAPLEN 1600

char log_file[] = "/var/log/url_record.txt";
char pidfile[] = "/var/run/url_recoder";
FILE* log_fp;

int log_init()
{
	int ret;
	char mode[2] = {0,'+'};
	ret = access(log_file,0);
	if(ret == 0){
		mode[0] = 'a';
	}
	else if(ret == -1){
		mode[0] = 'w';
	}
	else{
		printf("log init error\n");
		exit(0);
	}

	log_fp = fopen(log_file,mode);
	if (log_fp == NULL){
		printf("open log file failed\n");
	}
	
	return 0;
}

int logging(char *data,int len)
{
	time_t timet;
	struct tm *p;
	char str_time[100];

	timet = time(NULL);
	p = localtime(&timet);
	
	strftime(str_time,sizeof(str_time),"<--%m-%d %H:%M:%S-->  ",p);
	fwrite(str_time,strlen(str_time),1,log_fp);
	fwrite(data,len,1,log_fp);
	fputc('\n',log_fp);
	fflush(log_fp);
	
	return 0;
}

int create_pidfile()
{
	return 0;
}

	


int is_http_request(const unsigned char* buf, int len)
{
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T'){
        return 1;
    }

    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T'){
        return 2;
    }

    return 0;
}

int http_hdr_len(const unsigned char* buf, int len)
{
    int i = 0;
    int hdr_len = 0;

    for (i = 0; i < len - 3; i++){
        if (buf[i] == '\r' && buf[i + 1] == '\n'
            && buf[i + 2] == '\r' && buf[i + 3] == '\n'){
            hdr_len = i;
            break;
        }
    }

    return hdr_len;

}

int get_url(unsigned char* buf, int *url_len, const unsigned char *pkt_data, int hdr_len)
{
   const  unsigned char* cur;
    int host_len;
    int uri_len;

    memcpy(buf, "http://", 7);
    buf += 7;
    *url_len = 7;

    cur = strstr(pkt_data, "Host:");
    if (cur == NULL)
        return -1;
    cur += 6;
    host_len = field_len(cur, hdr_len - (cur - pkt_data));

    if (host_len && (*url_len +host_len<1200)){
        memcpy(buf, cur, host_len);
        buf += host_len;
	*url_len += host_len;
    }
    else
    {
        return -1;
    }

    cur = pkt_data;
    if (pkt_data[0] == 'G')
        cur += 4;
    else if (pkt_data[0] == 'P'){
        cur += 5;
    }

    uri_len = field_len(cur, hdr_len - (cur - pkt_data));
    uri_len -= 9;

    if((*url_len + uri_len) < 1200){
	memcpy(buf, cur, uri_len);
    	*url_len += uri_len;
    }
    
    return 0;
    
}



int field_len(const unsigned char* buf, int len)
{
    int i = 0;
    int field_len = 0;
    
    for (i = 0; i < len-1; i++){
        if (buf[i] == '\r' && buf[i + 1] == '\n'){
            field_len = i;
            break;
        }
    }

    return field_len;
}

int is_tcp(const unsigned char* buf, int len)
{
    if (len < 54)
        return 0;

    if (buf[12] != 0x08 || buf[13] != 0x00){
        return 0;
    }
    
    if (buf[23] != 0x06){//tcp flag
        return 0;
    }

    return 1;
}

void callback(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes)
{
    int len;
    const unsigned char *buf;
    const unsigned char *cur;
    unsigned char url[1024];
    int url_len = 0;
    char data[1400];
    int is_req;
    int hdr_len;
    int ret;

    buf = bytes;
    len = h->caplen;
    cur = buf;

    if (!is_tcp(buf, len)){
        return;
    }

    cur += 54;
    len -= 54;//tcp hdr ip hdr

    is_req = is_http_request(cur, len);
    hdr_len = http_hdr_len(cur, len);

    switch (is_req){
    case 0:
        break;
    case 1:
        ret = get_url(url,&url_len, cur, hdr_len);
        if (ret == 0){
		logging(url,url_len);
	//printf("url_len:%d\n",url_len);
        }
        break;
    case 2:
        ret = get_url(url,&url_len, cur, hdr_len);
        if (ret == 0){
		logging(url,url_len);
        }
        //get_data(data, curl, len);
        break;
    default:
        break;
    }

    

}


int main(int argc,char** argv)
{
    pcap_t *pt;
    char dev[10];
    char errbuf[PCAP_ERRBUF_SIZE];


    if(argc != 2){
	printf("./url_recoder eth0\n");
	exit(0);	
    }

    daemon(0,0);
    create_pidfile();
    log_init();
    strcpy(dev,argv[1]);
    dev[9] = 0;
    pt = pcap_open_live(dev, SNAPLEN, PROMISC, -1, errbuf);
    if (pt == NULL){
        printf("open dev failed\n");
        exit(0);
    }

    pcap_loop(pt, -1, callback,NULL);
}
